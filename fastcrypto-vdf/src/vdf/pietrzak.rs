// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::parameterized_group::{multiply, ParameterizedGroupElement};
use crate::vdf::VDF;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::{HashFunction, Keccak256};
use num_bigint::BigUint;
use num_integer::Integer;
use serde::Serialize;
use std::{iter, mem};

/// Default size in bytes of the Fiat-Shamir challenge used in proving and verification.
///
/// This is based on Pietrzak (2018), "Simple Verifiable Delay Functions" (https://eprint.iacr.org/2018/627.pdf)
/// which states that the challenge should be 2^l bits (see section 6), where l is the security
/// parameter. Soundness is proven in section 6.3 in this paper.
pub const DEFAULT_CHALLENGE_SIZE_IN_BYTES: usize = 16;

/// This implements Pietrzak's VDF construction from https://eprint.iacr.org/2018/627.pdf.
///
/// The VDF is, as in [crate::vdf::wesolowski::WesolowskisVDF], based on the repeated squaring of an
/// element in a group of unknown order. However, in this construction, proofs are larger and
/// verification is slower than in Wesolowski's construction, but the output of a VDF is unique,
/// assuming that the used group have no small subgroups, and proving is faster for the same number
/// of iterations.
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

    /// Compute the Fiat-Shamir challenge used in Pietrzak's VDF construction.
    fn compute_challenge(&self, input: &G, output: &G, mu: &G) -> BigUint {
        let seed = bcs::to_bytes(&(input, output, mu, self.iterations, &self.group_parameter))
            .expect("Failed to serialize Fiat-Shamir input.");
        let hash = Keccak256::digest(seed);
        BigUint::from_bytes_be(&hash.digest[..DEFAULT_CHALLENGE_SIZE_IN_BYTES])
    }
}

impl<G: ParameterizedGroupElement + Serialize> VDF for PietrzaksVDF<G>
where
    G::ParameterType: Serialize,
{
    type InputType = G;
    type OutputType = G;
    type ProofType = Vec<G>;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, Vec<G>)> {
        // Proof generation works but is not optimised.

        if !input.is_in_group(&self.group_parameter) || self.iterations == 0 {
            return Err(InvalidInput);
        }

        // Compute output = 2^iterations * input
        let output = input.clone().repeated_doubling(self.iterations);

        let mut x = input.clone();
        let mut y = output.clone();

        let mut proof = Vec::new();

        let t = iter::successors(Some(self.iterations), |t| Some((*t + 1) >> 1))
            .skip(1)
            .take_while(|t| *t > 1);

        if self.iterations.is_odd() {
            y = y.double();
        }

        // Compute the full proof. This loop may stop at any time which will give a shorter proof
        // that is computationally harder to verify.
        for t_i in t {
            // TODO: Precompute some of the mu's to speed up the proof generation.
            let mu = x.clone().repeated_doubling(t_i);

            let r = self.compute_challenge(&x, &y, &mu);
            x = multiply(&x, &r, &self.group_parameter) + &mu;
            y = multiply(&mu, &r, &self.group_parameter) + &y;

            if t_i.is_odd() {
                y = y.double();
            }

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

            let r = self.compute_challenge(&x, &y, mu);
            x = multiply(&x, &r, &self.group_parameter) + mu;
            y = multiply(mu, &r, &self.group_parameter) + &y;
        }

        // In case the proof is shorter than the full proof, we need to compute the remaining powers.
        x = x.repeated_doubling(t);
        if x != y {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Replace t with (t+1) >> 1 and return true iff the input was odd.
#[inline]
fn check_parity_and_iterate(t: &mut u64) -> bool {
    mem::replace(t, (*t >> 1) + (*t & 1)).is_odd()
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::rsa_group::modulus::test::{AMAZON_MODULUS_2048_REF, GOOGLE_MODULUS_4096_REF};
    use crate::rsa_group::RSAGroupElement;
    use crate::vdf::pietrzak::PietrzaksVDF;
    use crate::vdf::VDF;
    use num_bigint::{BigInt, BigUint};
    use std::str::FromStr;

    #[test]
    fn test_vdf() {
        let iterations = 136u64;
        let discriminant = Discriminant::from_seed(&[0, 1, 2], 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = PietrzaksVDF::<QuadraticForm>::new(discriminant.clone(), iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        // Regression tests
        let expected = QuadraticForm::from_a_b_and_discriminant(
            BigInt::from_str(
                "13206998000609712751440666523761252432358037295085948932090770003917198208994",
            )
            .unwrap(),
            BigInt::from_str(
                "-7219543762309344565443896781132785043370346972592093790721340651476391057433",
            )
            .unwrap(),
            &discriminant,
        )
        .unwrap();
        assert_eq!(output, expected);

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        let other_input = input.clone() + &input;
        assert!(vdf.verify(&other_input, &output, &proof).is_err())
    }

    #[test]
    fn test_vdf_edge_cases() {
        let discriminant = Discriminant::from_seed(&[0, 1, 2], 512).unwrap();
        let input = QuadraticForm::generator(&discriminant);

        assert!(PietrzaksVDF::<QuadraticForm>::new(discriminant.clone(), 1)
            .evaluate(&input)
            .is_ok());
        assert!(PietrzaksVDF::<QuadraticForm>::new(discriminant.clone(), 0)
            .evaluate(&input)
            .is_err());
    }

    #[test]
    fn test_vdf_rsa() {
        let iterations = 136u64;
        let input = RSAGroupElement::new(7u32.into(), &AMAZON_MODULUS_2048_REF);

        let vdf = PietrzaksVDF::<RSAGroupElement>::new(&AMAZON_MODULUS_2048_REF, iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        // Regression tests
        assert_eq!(output.value(), &BigUint::from_str("2916729428333236907384003242184677361436177746028521829074262794270450030614249791656280719383240637347810313226096694498769545443206627336734040174799816874893648275347170568080246298018251459166394606111665076144473956288322218549726358786461312990585124805408517840980926720744474390941814421387920163335970657049749743256686182627881823961603323280107182060168658389127157273203349284277273772693040421354262168429489840004941529927120543842810077679137948568146407590629247965765706139158405798203267187654092671067863393874252018466867363677473729172248315453692024494782080164026070367013679213682978612826272").unwrap());

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        let other_input = input.clone() + &input;
        assert!(vdf.verify(&other_input, &output, &proof).is_err())
    }
}
