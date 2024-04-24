// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::QuadraticForm;
use crate::math::parameterized_group::{ParameterizedGroupElement, UnknownOrderGroupElement};
use crate::vdf::VDF;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use fiat_shamir::{FiatShamir, StrongFiatShamir};
use num_bigint::BigInt;
use num_integer::Integer;
use std::marker::PhantomData;
use std::ops::ShlAssign;

pub mod fiat_shamir;

/// An implementation of Wesolowski's VDF construction (https://eprint.iacr.org/2018/623) over a
/// group of unknown order.
pub struct WesolowskisVDF<
    G: ParameterizedGroupElement + UnknownOrderGroupElement,
    F: FiatShamir<G>,
    M: ScalarMultiplier<G, G::ScalarType>,
> {
    group_parameter: G::ParameterType,
    iterations: u64,
    _fiat_shamir: PhantomData<F>,
    _scalar_multiplier: PhantomData<M>,
}

impl<
        G: ParameterizedGroupElement + UnknownOrderGroupElement,
        F: FiatShamir<G>,
        M: ScalarMultiplier<G, G::ScalarType>,
    > WesolowskisVDF<G, F, M>
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
        G: ParameterizedGroupElement<ScalarType = BigInt> + UnknownOrderGroupElement,
        F: FiatShamir<G>,
        M: ScalarMultiplier<G, BigInt>,
    > VDF for WesolowskisVDF<G, F, M>
{
    type InputType = G;
    type OutputType = G;
    type ProofType = G;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, G)> {
        if input.parameter() != self.group_parameter {
            return Err(InvalidInput);
        }

        if self.iterations == 0 {
            return Ok((input.clone(), G::zero(&self.group_parameter)));
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
        let mut proof = input.mul(&quotient_remainder.0);
        for _ in 1..self.iterations {
            quotient_remainder.1.shl_assign(1);
            quotient_remainder = quotient_remainder.1.div_mod_floor(&challenge);
            proof = proof.double() + &multiplier.mul(&quotient_remainder.0);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &G) -> FastCryptoResult<()> {
        if input.parameter() != self.group_parameter
            || output.parameter() != self.group_parameter
            || proof.parameter() != self.group_parameter
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
    use crate::math::parameterized_group::{Parameter, ParameterizedGroupElement};
    use crate::vdf::wesolowski::DefaultVDF;
    use crate::vdf::VDF;
    use num_bigint::BigInt;

    #[test]
    fn test_prove_and_verify() {
        let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
        let iterations = 1000u64;
        let discriminant = Discriminant::from_seed(&challenge, 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = DefaultVDF::new(discriminant, iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        // Regression tests
        assert_eq!(bcs::to_bytes(&output).unwrap(), hex::decode("2024ff799e22587cc344b83ace4ce2d814d52aba7dd711591fd407e31a55822a1e20051fa84e09b4bd5a6ee02b6fae24db625863ae31cfaf962f2f490d92dd372e3f2101714cc516048bd26c8788ead8318dcaa0c3fe615ece8164cf56a4bdea90c8fc6f").unwrap());
        assert_eq!(bcs::to_bytes(&proof).unwrap(), hex::decode("206073d81fed637a8640632a41d040c22851cd240eabb1346994bd996e8f018b7620b2a15fe0116fc1dfc6e33088cbd1615423b92fee08ec2077f794df1886436c6721009d1b3148590a3e1097ab83ad6bcceec1fcee78da679bddae9213dbd930b8684d").unwrap());

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // A modified output or proof fails to verify
        let modified_output = output.mul(&BigInt::from(2));
        let modified_proof = proof.mul(&BigInt::from(2));
        assert!(vdf.verify(&input, &modified_output, &proof).is_err());
        assert!(vdf.verify(&input, &output, &modified_proof).is_err());
    }
}
