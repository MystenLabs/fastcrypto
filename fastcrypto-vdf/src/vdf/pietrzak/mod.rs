// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{AddAssign, ShrAssign};

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Signed;
use serde::Serialize;

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;

use crate::math::parameterized_group::ParameterizedGroupElement;
use crate::vdf::pietrzak::fiat_shamir::{DefaultFiatShamir, FiatShamir};
use crate::vdf::VDF;

pub mod fiat_shamir;

/// This implements Pietrzak's VDF construction from https://eprint.iacr.org/2018/627.pdf.
/// Proofs are larger and verification is slower than in Wesolowski's construction, but the
/// output of a VDF is unique, assuming that the used group have no small subgroups, and proving
/// is faster.
pub struct PietrzaksVDF<G: ParameterizedGroupElement> {
    group_parameter: G::ParameterType,
    iterations: u64,
}

impl<G: ParameterizedGroupElement> PietrzaksVDF<G> {
    /// Create a new VDF using the group defined by the given group parameter. Evaluating this VDF
    /// will require computing `2^iterations * input` which requires `iterations` group operations.
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> Self {
        Self {
            group_parameter,
            iterations,
        }
    }
}

/// Replace t with (t+1) >> 1 and return true iff the initial value of t was odd.
fn check_parity_and_iterate(t: &mut u64) -> bool {
    let parity = t.is_odd();
    if parity {
        t.add_assign(1);
    }
    t.shr_assign(1);
    parity
}

impl<G: ParameterizedGroupElement + Serialize> VDF for PietrzaksVDF<G> {
    type InputType = G;
    type OutputType = G;
    type ProofType = Vec<G>;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, Vec<G>)> {
        if !input.is_in_group(&self.group_parameter) || self.iterations == 0 {
            return Err(InvalidInput);
        }

        // Compute output = 2^iterations * input
        let output = input.repeated_doubling(self.iterations);

        let mut x_i = input.clone();
        let mut y_i = output.clone();
        let mut t_i = self.iterations;

        // This is ceil(log_2(iterations)). See also https://oeis.org/A029837.
        let iterations = 64 - (self.iterations - 1).leading_zeros();
        let mut proof = Vec::with_capacity(iterations as usize);

        // Compute the full proof. This loop may stop at any time which will give a shorter proof that is computationally harder to verify.
        while t_i != 1 {
            if check_parity_and_iterate(&mut t_i) {
                y_i = y_i.double();
            }

            // TODO: Precompute some of the mu's
            let mu_i = x_i.repeated_doubling(t_i);

            let r = DefaultFiatShamir::compute_challenge(&x_i, &y_i, self.iterations, &mu_i);
            x_i = multiply(&x_i, &r, G::zero(&self.group_parameter)) + &mu_i;
            y_i = multiply::<G>(&mu_i, &r, G::zero(&self.group_parameter)) + &y_i;

            proof.push(mu_i);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &Vec<G>) -> FastCryptoResult<()> {
        if !input.is_in_group(&self.group_parameter)
            || !output.is_in_group(&self.group_parameter)
            || !proof.iter().all(|mu| mu.is_in_group(&self.group_parameter))
            || self.iterations == 0
        {
            return Err(InvalidInput);
        }

        let mut x_i = input.clone();
        let mut y_i = output.clone();
        let mut t_i = self.iterations;

        for mu_i in proof {
            if check_parity_and_iterate(&mut t_i) {
                y_i = y_i.double();
            }

            let r = DefaultFiatShamir::compute_challenge(&x_i, &y_i, self.iterations, mu_i);
            x_i = multiply(&x_i, &r, G::zero(&self.group_parameter)) + mu_i;
            y_i = y_i + &multiply::<G>(mu_i, &r, G::zero(&self.group_parameter));
        }

        let expected = x_i.repeated_doubling(t_i);
        if y_i != expected {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Compute element * scalar. It is assumed that the scalar is positive.
fn multiply<G: ParameterizedGroupElement>(element: &G, scalar: &BigUint, zero: G) -> G {
    (0..scalar.bits())
        .map(|i| scalar.bit(i))
        .rev()
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
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::{Parameter, ParameterizedGroupElement};
    use crate::vdf::pietrzak::{multiply, PietrzaksVDF};
    use crate::vdf::VDF;

    #[test]
    fn test_vdf() {
        let iterations = 136u64;
        let discriminant = Discriminant::from_seed(&[0, 1, 2], 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = PietrzaksVDF::<QuadraticForm>::new(discriminant.clone(), iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        let other_input = input.clone() + &input;
        assert!(vdf.verify(&other_input, &output, &proof).is_err())
    }

    #[test]
    fn test_multiply() {
        let discriminant = Discriminant::from_seed(&[1, 2, 3], 512).unwrap();
        let input = QuadraticForm::generator(&discriminant);

        assert_eq!(
            QuadraticForm::zero(&discriminant),
            multiply(&input, &BigUint::zero(), QuadraticForm::zero(&discriminant))
        );
        assert_eq!(
            &input,
            &multiply(&input, &BigUint::one(), QuadraticForm::zero(&discriminant))
        );

        let exponent = 23u32;
        let output = multiply(
            &input,
            &BigUint::from(exponent),
            QuadraticForm::zero(&discriminant),
        );

        let mut expected_output = input.clone();
        for _ in 1..exponent {
            expected_output = expected_output + &input;
        }
        assert_eq!(output, expected_output);
    }
}
