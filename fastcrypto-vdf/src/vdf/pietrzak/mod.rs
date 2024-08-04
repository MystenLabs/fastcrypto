use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::parameterized_group::{Parameter, ParameterizedGroupElement};
use crate::vdf::pietrzak::fiat_shamir::{DefaultFiatShamir, FiatShamir};
use crate::vdf::VDF;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use fastcrypto::groups::Doubling;
use num_bigint::BigInt;
use num_integer::Integer;
use num_prime::BitTest;
use num_traits::{One, Zero};
use serde::Serialize;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Shr, ShrAssign};

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
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> Self {
        Self {
            group_parameter,
            iterations,
        }
    }
}

fn repeated_doubling<G: Doubling + Clone>(input: &G, doublings: u64) -> G {
    let mut output = input.clone();
    for _ in 0..doublings {
        output = output.double();
    }
    output
}

fn multiply<G: ParameterizedGroupElement<ScalarType = BigInt>>(
    element: &G,
    scalar: &BigInt,
    zero: G,
) -> G {
    let mut result = zero;
    for i in (0..scalar.bits()).rev() {
        result = result.double();
        if scalar.bit(i) {
            result = result + element;
        }
    }
    result
}

#[test]
fn test_multiply() {
    let discriminant = Discriminant::from_seed(&[1, 2, 3], 512).unwrap();
    let input = QuadraticForm::generator(&discriminant);

    let exponent = 13;
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

        let tau = self.iterations.bits() as u64;

        let mut x_i = input.clone();
        let mut y_i = output.clone();
        let mut t_i = self.iterations;

        let proof = (0..tau - 1)
            .map(|i| {
                let odd = t_i.is_odd();
                t_i >>= 1;

                // TODO: Precompute
                let mu_i = repeated_doubling(&x_i, t_i);

                let r = DefaultFiatShamir::compute_challenge(&x_i, &y_i, t_i, &mu_i);
                x_i = multiply(&x_i, &r, G::zero(&self.group_parameter)) + &mu_i;
                y_i = multiply::<G>(&mu_i, &r, G::zero(&self.group_parameter)) + &y_i;

                if odd {
                    y_i = y_i.double();
                }

                mu_i
            })
            .collect();

        assert_eq!(t_i, 1);

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &Vec<G>) -> FastCryptoResult<()> {
        let mut x_i = input.clone();
        let mut y_i = output.clone();
        let mut t_i = self.iterations;

        for mu_i in proof {
            t_i >>= 1;
            let r = DefaultFiatShamir::compute_challenge(&x_i, &y_i, t_i, &mu_i);
            x_i = multiply(&x_i, &r, G::zero(&self.group_parameter)) + mu_i;
            y_i = y_i.add(&multiply::<G>(&mu_i, &r, G::zero(&self.group_parameter)));
        }

        if y_i != x_i.double() {
            return Err(InvalidProof);
        }
        Ok(())
    }
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
        let iterations = 64u64;
        let discriminant = Discriminant::from_seed(&[0, 1, 2], 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = PietrzaksVDF::<QuadraticForm>::new(discriminant.clone(), iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        let other_input = input.clone() + &input;
        assert!(vdf.verify(&other_input, &output, &proof).is_err())
    }
}
