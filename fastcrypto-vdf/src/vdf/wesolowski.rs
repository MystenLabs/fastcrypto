// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;
use std::ops::ShlAssign;

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use num_bigint::BigUint;
use num_integer::Integer;

use crate::class_group::QuadraticForm;
use crate::math::hash_prime::hash_prime;
use crate::math::parameterized_group::ParameterizedGroupElement;
use crate::vdf::VDF;

/// Default size in bytes of the Fiat-Shamir challenge used in proving and verification.
///
/// From Wesolowski (2018), "Efficient verifiable delay functions" (https://eprint.iacr.org/2018/623),
/// we get that the challenge must be a random prime among the first 2^{2k} primes where k is the
/// security parameter in bits. Setting k = 128, and recalling that the prime number theorem states
/// that the n-th prime number is approximately n * ln(n), we can estimate the number of bits required
/// to represent the n-th prime as log2(n * ln(n)). For n = 2^{2*128}, this is approximately 264 bits
/// = 33 bytes. This is also the challenge size used by chiavdf.
pub const DEFAULT_CHALLENGE_SIZE_IN_BYTES: usize = 33;

/// An implementation of Wesolowski's VDF construction (https://eprint.iacr.org/2018/623) over a
/// group of unknown order.
pub struct WesolowskisVDF<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>> {
    group_parameter: G::ParameterType,
    iterations: u64,
    challenge: fn(&Self, &G, &G) -> BigUint,
    _scalar_multiplier: PhantomData<M>,
}

impl<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>> WesolowskisVDF<G, M> {
    /// Create a new VDF using the group defined by the given group parameter. Evaluating this VDF
    /// will require computing `2^iterations * input` which requires `iterations` group operations.
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> Self {
        Self {
            group_parameter,
            iterations,
            challenge: compute_challenge,
            _scalar_multiplier: PhantomData::<M>,
        }
    }

    /// Create a new VDF with a custom challenge function. This is useful for testing.
    #[cfg(test)]
    fn new_with_custom_challenge(
        group_parameter: G::ParameterType,
        iterations: u64,
        challenge: fn(&Self, &G, &G) -> BigUint,
    ) -> Self {
        Self {
            group_parameter,
            iterations,
            challenge,
            _scalar_multiplier: PhantomData::<M>,
        }
    }
}

impl<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>> VDF for WesolowskisVDF<G, M> {
    type InputType = G;
    type OutputType = G;
    type ProofType = G;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, G)> {
        if !input.is_in_group(&self.group_parameter) || self.iterations == 0 {
            return Err(InvalidInput);
        }

        // Compute output = 2^iterations * input
        let output = input.clone().repeated_doubling(self.iterations);

        let multiplier = M::new(input.clone(), G::zero(&self.group_parameter));

        // Algorithm from page 3 on https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
        let challenge = (self.challenge)(self, input, &output);
        let mut quotient_remainder = (BigUint::from(0u8), BigUint::from(2u8));
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

        let challenge = (self.challenge)(self, input, output);
        let r = BigUint::modpow(
            &BigUint::from(2u8),
            &BigUint::from(self.iterations),
            &challenge,
        );
        let multiplier = M::new(input.clone(), G::zero(&self.group_parameter));

        if multiplier.two_scalar_mul(&r, proof, &challenge) != *output {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Implementation of Wesolowski's VDF construction over an imaginary class group using a strong
/// Fiat-Shamir implementation.
pub type DefaultVDF =
    WesolowskisVDF<QuadraticForm, WindowedScalarMultiplier<QuadraticForm, BigUint, 256, 5>>;

fn compute_challenge<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>>(
    vdf: &WesolowskisVDF<G, M>,
    input: &G,
    output: &G,
) -> BigUint {
    let seed = bcs::to_bytes(&(input, output, vdf.iterations, &vdf.group_parameter))
        .expect("Failed to serialize Fiat-Shamir input");
    hash_prime(
        &seed,
        DEFAULT_CHALLENGE_SIZE_IN_BYTES,
        &[0, 8 * DEFAULT_CHALLENGE_SIZE_IN_BYTES - 1],
    )
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::vdf::wesolowski::{DefaultVDF, WesolowskisVDF};
    use crate::vdf::VDF;
    use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
    use num_bigint::{BigInt, BigUint};
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
            WindowedScalarMultiplier<QuadraticForm, BigUint, 256, 5>,
        >::new_with_custom_challenge(
            discriminant.clone(),
            iterations,
            |_, _, _| {
                BigUint::from_str_radix(
                    "a8d8728e9942a994a3a1aa3d2fa21549aa1a7b37d3c315c6e705bda590689c640f",
                    16,
                )
                .unwrap()
            },
        );

        assert!(vdf.verify(&input, &output, &proof).is_ok());
    }
}
