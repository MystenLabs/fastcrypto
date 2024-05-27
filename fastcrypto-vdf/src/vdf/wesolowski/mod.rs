// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;
use std::ops::ShlAssign;

use num_bigint::BigInt;
use num_integer::Integer;

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use fiat_shamir::{FiatShamir, StrongFiatShamir};

use crate::class_group::QuadraticForm;
use crate::math::parameterized_group::ParameterizedGroupElement;
use crate::vdf::VDF;

mod fiat_shamir;

/// An implementation of Wesolowski's VDF construction (https://eprint.iacr.org/2018/623) over a
/// group of unknown order.
pub struct WesolowskisVDF<
    G: ParameterizedGroupElement,
    F: FiatShamir<G>,
    M: ScalarMultiplier<G, G::ScalarType>,
> {
    group_parameter: G::ParameterType,
    iterations: u64,
    _fiat_shamir: PhantomData<F>,
    _scalar_multiplier: PhantomData<M>,
}

impl<G: ParameterizedGroupElement, F: FiatShamir<G>, M: ScalarMultiplier<G, G::ScalarType>>
    WesolowskisVDF<G, F, M>
{
    /// Create a new VDF using the group defined by the given group parameter. Evaluating this VDF
    /// will require computing `2^iterations * input` which requires `iterations` group operations.
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> Self {
        Self {
            group_parameter,
            iterations,
            _fiat_shamir: PhantomData::<F>,
            _scalar_multiplier: PhantomData::<M>,
        }
    }
}

impl<
        G: ParameterizedGroupElement<ScalarType = BigInt>,
        F: FiatShamir<G>,
        M: ScalarMultiplier<G, BigInt>,
    > VDF for WesolowskisVDF<G, F, M>
{
    type InputType = G;
    type OutputType = G;
    type ProofType = G;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, G)> {
        if !input.is_in_group(&self.group_parameter) || self.iterations == 0 {
            return Err(InvalidInput);
        }

        // Compute output = 2^iterations * input
        let mut output = input.clone();
        for _ in 0..self.iterations {
            output = output.double();
        }

        let multiplier = M::new(input.clone(), G::zero(&self.group_parameter));

        // Algorithm from page 3 on https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
        let challenge = F::compute_challenge(self, input, &output);
        let mut quotient_remainder = (BigInt::from(0), BigInt::from(2));
        let mut proof = multiplier.mul(&quotient_remainder.0);
        for _ in 1..self.iterations {
            quotient_remainder.1.shl_assign(1);
            quotient_remainder = quotient_remainder.1.div_mod_floor(&challenge);
            proof = proof.double() + &multiplier.mul(&quotient_remainder.0);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &G) -> FastCryptoResult<()> {
        if !input.is_in_group(&self.group_parameter)
            || !output.is_in_group(&self.group_parameter)
            || !proof.is_in_group(&self.group_parameter)
        {
            return Err(InvalidInput);
        }

        let challenge = F::compute_challenge(self, input, output);
        let r = BigInt::modpow(&BigInt::from(2), &BigInt::from(self.iterations), &challenge);
        let multiplier = M::new(input.clone(), G::zero(&self.group_parameter));

        if multiplier.two_scalar_mul(&r, proof, &challenge) != *output {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Implementation of Wesolowski's VDF construction over an imaginary class group using a strong
/// Fiat-Shamir implementation.
pub type DefaultVDF = WesolowskisVDF<
    QuadraticForm,
    StrongFiatShamir,
    WindowedScalarMultiplier<QuadraticForm, BigInt, 256, 5>,
>;

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::Parameter;
    use crate::vdf::wesolowski::fiat_shamir::FiatShamir;
    use crate::vdf::wesolowski::{DefaultVDF, WesolowskisVDF};
    use crate::vdf::VDF;
    use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
    use fastcrypto::groups::multiplier::ScalarMultiplier;
    use num_bigint::BigInt;
    use num_traits::Num;
    use std::str::FromStr;

    #[test]
    fn test_prove_and_verify() {
        let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
        let iterations = 1000u64;
        let discriminant = Discriminant::from_seed(&challenge, 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = DefaultVDF::new(discriminant.clone(), iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        // Regression tests
        assert_eq!(bcs::to_bytes(&output).unwrap(), hex::decode("2024ff799e22587cc344b83ace4ce2d814d52aba7dd711591fd407e31a55822a1e20051fa84e09b4bd5a6ee02b6fae24db625863ae31cfaf962f2f490d92dd372e3f2101714cc516048bd26c8788ead8318dcaa0c3fe615ece8164cf56a4bdea90c8fc6f").unwrap());
        assert_eq!(bcs::to_bytes(&proof).unwrap(), hex::decode("2051242499ff4467ba4d9bd858d6609b3a29736a80e09aa3edc6fa4ca49292daae20c066a1b52a8c5a0ff230224fc403dec11ee156e523f22b78ab8abc9706ae38c52100b4c56b5d7815425677bbe0ddc924d6277a237e4c5317b10a1a36039148d1d19c").unwrap());

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // A modified output or proof fails to verify
        let modified_output = &output + &QuadraticForm::generator(&discriminant);
        let modified_proof = &proof + &QuadraticForm::generator(&discriminant);
        assert!(vdf.verify(&input, &modified_output, &proof).is_err());
        assert!(vdf.verify(&input, &output, &modified_proof).is_err());
    }

    #[test]
    fn chia_test_vector() {
        // Test vector from challenge_chain_sp_vdf in block 0 on chiavdf (https://chia.tt/info/block/0xd780d22c7a87c9e01d98b49a0910f6701c3b95015741316b3fda042e5d7b81d2)
        let challenge_hex = "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb";

        let expected_discriminant = Discriminant::try_from(BigInt::from_str("-178333777053301117117702583998161755803539768255026550238546398959430362085160891839143870686333959898768973627501543050673299722162920809872631876535963079708632677960753403482168047846781718043417502562521413075070055588055373173898058979019814085260390558743330450388913014891726165953277341036916349194527").unwrap()).unwrap();
        let discriminant =
            Discriminant::from_seed(&hex::decode(challenge_hex).unwrap(), 1024).unwrap();
        assert_eq!(expected_discriminant, discriminant);

        let iterations = 4194304u64;
        let input = QuadraticForm::generator(&discriminant);

        let output = QuadraticForm::from_a_b_and_discriminant(
            BigInt::from_str("5229738340597739241737971536347978272715235210410923937567237618049037412166200077244995787131087550307523694727956250097277310766933336068474825405652036").unwrap(),
            BigInt::from_str("-3096696303705675681560871524238217371290270541873900921742966946679899781296678313618277916864547545067742976652559823874869615853670880196986766000673113").unwrap(),
            &discriminant,
        ).unwrap();

        let proof = QuadraticForm::from_a_b_and_discriminant(
            BigInt::from_str("269045224950172139388701381657611623403690061497324483767769709486526106374289433207532765507632104438556574675400375880648266212459081029470628330651968").unwrap(),
            BigInt::from_str("-138011067542034487860643678409953738631107554007673747141459530097427412192013567645959803101754265070201162396361305697197871510988607320533641929367439").unwrap(),
            &discriminant,
        ).unwrap();

        let vdf = WesolowskisVDF::<
            QuadraticForm,
            ChiaFiatShamir,
            WindowedScalarMultiplier<QuadraticForm, BigInt, 256, 5>,
        >::new(discriminant.clone(), iterations);

        assert!(vdf.verify(&input, &output, &proof).is_ok());
    }

    // Dummy Fiat-Shamir implementation for the Chia test vector
    struct ChiaFiatShamir {}

    impl FiatShamir<QuadraticForm> for ChiaFiatShamir {
        fn compute_challenge<M: ScalarMultiplier<QuadraticForm, BigInt>>(
            _vdf: &WesolowskisVDF<QuadraticForm, Self, M>,
            _input: &QuadraticForm,
            _output: &QuadraticForm,
        ) -> BigInt {
            // Hardcoded challenge for the test vector
            BigInt::from_str_radix(
                "a8d8728e9942a994a3a1aa3d2fa21549aa1a7b37d3c315c6e705bda590689c640f",
                16,
            )
            .unwrap()
        }
    }
}
