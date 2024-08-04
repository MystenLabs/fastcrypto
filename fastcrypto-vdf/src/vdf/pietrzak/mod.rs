// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigInt;
use num_integer::Integer;
use num_prime::BitTest;
use num_traits::Zero;
use serde::Serialize;

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Doubling;

use crate::math::parameterized_group::ParameterizedGroupElement;
use crate::vdf::pietrzak::fiat_shamir::{DefaultFiatShamir, FiatShamir};
use crate::vdf::VDF;

/// Default size in bytes of the Fiat-Shamir challenge used in proving and verification.
pub const DEFAULT_CHALLENGE_SIZE_IN_BYTES: usize = 32;

pub mod fiat_shamir;

pub struct PietrzaksVDF<G: ParameterizedGroupElement> {
    group_parameter: G::ParameterType,
    iterations: u64,
}

impl<G: ParameterizedGroupElement> PietrzaksVDF<G> {
    /// Create a new VDF using the group defined by the given group parameter. Evaluating this VDF
    /// will require computing `2^iterations * input` which requires `iterations` group operations.
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> FastCryptoResult<Self> {
        if iterations.is_zero() || iterations.is_odd() {
            return Err(InvalidInput);
        }
        Ok(Self {
            group_parameter,
            iterations,
        })
    }
}

impl<G: ParameterizedGroupElement<ScalarType = BigInt> + Serialize> VDF for PietrzaksVDF<G> {
    type InputType = G;
    type OutputType = G;
    type ProofType = Vec<G>;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, Vec<G>)> {
        if !input.is_in_group(&self.group_parameter) || self.iterations == 0 {
            return Err(InvalidInput);
        }

        // Compute output = 2^iterations * input
        let output = repeated_doubling(input, self.iterations);

        let mut x_i = input.clone();
        let mut y_i = output.clone();
        let mut t_i = self.iterations;

        let mut proof = vec![];

        while t_i != 2 {
            // TODO: iterations not a power of two
            debug_assert!(t_i.is_even());
            t_i >>= 1;

            // TODO: Precompute some of the mu's
            let mu_i = repeated_doubling(&x_i, t_i);

            let r = DefaultFiatShamir::compute_challenge(&x_i, &y_i, self.iterations, &mu_i);
            x_i = multiply(&x_i, &r, G::zero(&self.group_parameter)) + &mu_i;
            y_i = multiply::<G>(&mu_i, &r, G::zero(&self.group_parameter)) + &y_i;

            if t_i.is_odd() {
                t_i += 1;
                y_i = y_i.double();
            }

            proof.push(mu_i);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &Vec<G>) -> FastCryptoResult<()> {
        if !input.is_in_group(&self.group_parameter)
            || !output.is_in_group(&self.group_parameter)
            || proof
                .iter()
                .any(|mu| !mu.is_in_group(&self.group_parameter))
            || self.iterations == 0
        {
            return Err(InvalidInput);
        }

        let mut x_i = input.clone();
        let mut y_i = output.clone();
        let mut t_i = self.iterations;

        for mu_i in proof {
            debug_assert!(t_i.is_even());
            t_i >>= 1;

            let r = DefaultFiatShamir::compute_challenge(&x_i, &y_i, self.iterations, &mu_i);
            x_i = multiply(&x_i, &r, G::zero(&self.group_parameter)) + mu_i;
            y_i = y_i + &multiply::<G>(&mu_i, &r, G::zero(&self.group_parameter));

            if t_i.is_odd() {
                t_i += 1;
                y_i = y_i.double();
            }
        }

        if y_i != x_i.double().double() {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

fn repeated_doubling<G: Doubling>(input: &G, repetitions: u64) -> G {
    debug_assert!(repetitions > 0);
    let mut output = input.double();
    for _ in 1..repetitions {
        output = output.double();
    }
    output
}

fn multiply<G: ParameterizedGroupElement<ScalarType = BigInt>>(
    element: &G,
    scalar: &BigInt,
    zero: G,
) -> G {
    (0..scalar.bits())
        .rev()
        .map(|i| scalar.bit(i))
        .fold(zero, |acc, bit| {
            let mut result = acc.double();
            if bit {
                result = result + element;
            }
            result
        })
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::{Parameter, ParameterizedGroupElement};
    use crate::vdf::pietrzak::{multiply, PietrzaksVDF};
    use crate::vdf::VDF;
    use num_bigint::BigInt;

    #[test]
    fn test_vdf() {
        let iterations = 136u64;
        let discriminant = Discriminant::from_seed(&[0, 1, 2], 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = PietrzaksVDF::<QuadraticForm>::new(discriminant.clone(), iterations).unwrap();
        let (output, proof) = vdf.evaluate(&input).unwrap();

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        let other_input = input.clone() + &input;
        assert!(vdf.verify(&other_input, &output, &proof).is_err())
    }

    #[test]
    fn test_multiply() {
        let discriminant = Discriminant::from_seed(&[1, 2, 3], 512).unwrap();
        let input = QuadraticForm::generator(&discriminant);

        let exponent = 23;
        let output = multiply(
            &input,
            &BigInt::from(exponent),
            QuadraticForm::zero(&discriminant),
        );

        let mut expected_output = input.clone();
        for _ in 1..exponent {
            expected_output = expected_output + &input;
        }

        assert_eq!(output, expected_output);
    }
}
