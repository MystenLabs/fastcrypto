// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_integer::Integer;
use serde::Serialize;
use std::ops::{AddAssign, ShrAssign};

use crate::math::parameterized_group::{multiply, ParameterizedGroupElement};
use crate::vdf::pietrzak::fiat_shamir::{DefaultFiatShamir, FiatShamir};
use crate::vdf::VDF;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;

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

        let mut x = input.clone();
        let mut y = output.clone();
        let mut t = self.iterations;

        // This is ceil(log_2(iterations)). See also https://oeis.org/A029837.
        let iterations = 64 - (self.iterations - 1).leading_zeros();
        let mut proof = Vec::with_capacity(iterations as usize);

        // Compute the full proof. This loop may stop at any time which will give a shorter proof
        // that is computationally harder to verify.
        while t != 1 {
            if check_parity_and_iterate(&mut t) {
                y = y.double();
            }

            // TODO: Precompute some of the mu's
            let mu = x.repeated_doubling(t);

            let r = DefaultFiatShamir::compute_challenge(&x, &y, self.iterations, &mu);
            x = multiply(&x, &r, &self.group_parameter) + &mu;
            y = multiply(&mu, &r, &self.group_parameter) + &y;

            proof.push(mu);
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

        let mut x = input.clone();
        let mut y = output.clone();
        let mut t = self.iterations;

        for mu in proof {
            if check_parity_and_iterate(&mut t) {
                y = y.double();
            }

            let r = DefaultFiatShamir::compute_challenge(&x, &y, self.iterations, mu);
            x = multiply(&x, &r, &self.group_parameter) + mu;
            y = multiply(mu, &r, &self.group_parameter) + y;
        }

        // In case the proof is shorter than the full proof, we need to compute the remaining powers.
        let expected = x.repeated_doubling(t);
        if y != expected {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Replace t with (t+1) >> 1 and return true iff the input was odd.
fn check_parity_and_iterate(t: &mut u64) -> bool {
    let parity = t.is_odd();
    if parity {
        t.add_assign(1);
    }
    t.shr_assign(1);
    parity
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::Parameter;
    use crate::vdf::pietrzak::PietrzaksVDF;
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
}
