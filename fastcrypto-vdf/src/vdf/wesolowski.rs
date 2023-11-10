// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::Discriminant;
use crate::vdf::VDF;
use crate::{
    bigint_utils, Parameter, ParameterizedGroupElement, ToBytes, UnknownOrderGroupElement,
};
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use num_bigint::{BigInt};
use num_integer::Integer;
use std::marker::PhantomData;
use std::ops::Neg;
use crate::bigint_utils::{DefaultPrimalityCheck, PrimalityCheck};

/// An implementation of the Wesolowski VDF construction (https://eprint.iacr.org/2018/623) over a
/// group of unknown order.
pub struct WesolowskiVDF<G: ParameterizedGroupElement + UnknownOrderGroupElement, F> {
    group_parameter: G::ParameterType,
    iterations: u64,
    _fiat_shamir: PhantomData<F>,
}

impl<G: ParameterizedGroupElement + UnknownOrderGroupElement, F> WesolowskiVDF<G, F> {
    /// Create a new VDF using the group defined by the given group parameter. Evaluating this VDF
    /// will require computing `2^iterations * input` which requires `iterations` group operations.
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> Self {
        Self {
            group_parameter,
            iterations,
            _fiat_shamir: PhantomData::<F>,
        }
    }
}

impl<
        G: ParameterizedGroupElement<ScalarType = BigInt> + UnknownOrderGroupElement,
        F: FiatShamir<G>,
    > VDF for WesolowskiVDF<G, F>
{
    type InputType = G;
    type OutputType = G;
    type ProofType = G;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, G)> {
        if self.iterations == 0 {
            return Ok((input.clone(), G::zero(&self.group_parameter)));
        }

        // Compute output = 2^iterations * input
        let mut output = input.clone();
        for _ in 0..self.iterations {
            output = output.double();
        }

        let challenge = F::compute_challenge(self, input, &output);

        // Algorithm from page 3 on https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
        let two = BigInt::from(2);
        let mut quotient_remainder = two.div_mod_floor(&challenge);
        let mut proof = input.mul(&quotient_remainder.0);
        for _ in 1..self.iterations {
            quotient_remainder = (&quotient_remainder.1 * &two).div_mod_floor(&challenge);
            proof = proof.double() + &input.mul(&quotient_remainder.0);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &G) -> FastCryptoResult<()> {
        if !input.same_group(output) || !input.same_group(proof) {
            return Err(InvalidInput);
        }

        let challenge = F::compute_challenge(self, input, output);

        let f1 = proof.mul(&challenge);

        let r = BigInt::modpow(&BigInt::from(2), &BigInt::from(self.iterations), &challenge);
        let f2 = input.mul(&r);

        if f1 + &f2 != *output {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Implementation of Wesolowski's VDF construction over a group of unknown order using a strong
/// Fiat-Shamir implementation.
pub type StrongVDF<G> = WesolowskiVDF<G, StrongFiatShamir<G, CHALLENGE_SIZE, DefaultPrimalityCheck>>;

/// Implementation of Wesolowski's VDF construction over a group of unknown order using the Fiat-Shamir
/// construction from chiavdf (https://github.com/Chia-Network/chiavdf).
pub type WeakVDF<G> = WesolowskiVDF<G, WeakFiatShamir<G, CHALLENGE_SIZE, DefaultPrimalityCheck>>;

impl<G: ParameterizedGroupElement + UnknownOrderGroupElement, F> WesolowskiVDF<G, F> {
    /// Create a new VDF over an group of unknown where the discriminant has a given size and
    /// is generated based on a seed. The `iterations` parameters specifies the number of group
    /// operations the evaluation function requires.
    pub fn from_seed(seed: &[u8], size_in_bits: usize, iterations: u64) -> FastCryptoResult<Self> {
        Ok(Self::new(
            G::ParameterType::from_seed(seed, size_in_bits)?,
            iterations,
        ))
    }
}

pub trait FiatShamir<G: ParameterizedGroupElement + UnknownOrderGroupElement> {
    /// Compute the prime modulus used in proving and verification. This is a Fiat-Shamir construction
    /// to make the Wesolowski VDF non-interactive.
    fn compute_challenge<F>(vdf: &WesolowskiVDF<G, F>, input: &G, output: &G) -> G::ScalarType;
}

/// Size of the challenge used in proving and verification.
pub const CHALLENGE_SIZE: usize = 264;

/// Implementation of the Fiat-Shamir challenge generation compatible with chiavdf.
/// Note that this implementation is weak, meaning that not all public parameters are used in the
/// challenge generation. This is not secure if an adversary can influence the public parameters.
/// See https://eprint.iacr.org/2023/691.
pub struct WeakFiatShamir<G, const CHALLENGE_SIZE: usize, P> {
    _group: PhantomData<G>,
    _primality_check: PhantomData<P>,
}

impl<
        G: ParameterizedGroupElement<ScalarType = BigInt> + UnknownOrderGroupElement,
        const CHALLENGE_SIZE: usize,
        P: PrimalityCheck,
    > FiatShamir<G> for WeakFiatShamir<G, CHALLENGE_SIZE, P>
{
    fn compute_challenge<F>(_vdf: &WesolowskiVDF<G, F>, input: &G, output: &G) -> BigInt {
        let mut seed = vec![];
        seed.extend_from_slice(&input.as_bytes());
        seed.extend_from_slice(&output.as_bytes());
        bigint_utils::hash_prime::<P>(&seed, CHALLENGE_SIZE, &[CHALLENGE_SIZE - 1])
            .expect("The length should be a multiple of 8")
    }
}

/// Implementation of the Fiat-Shamir challenge generation for usage with Wesolowski's VDF construction.
/// The implementation is strong, meaning that all public parameters are used in the challenge generation.
/// See https://eprint.iacr.org/2023/691.
pub struct StrongFiatShamir<G, const CHALLENGE_SIZE: usize, P> {
    _group: PhantomData<G>,
    _primality_check: PhantomData<P>
}

impl<
        G: ParameterizedGroupElement<ScalarType = BigInt> + UnknownOrderGroupElement,
        const CHALLENGE_SIZE: usize,
        P: PrimalityCheck,
    > FiatShamir<G> for StrongFiatShamir<G, CHALLENGE_SIZE, P>
{
    fn compute_challenge<F>(vdf: &WesolowskiVDF<G, F>, input: &G, output: &G) -> BigInt {
        let mut seed = vec![];

        seed.extend_from_slice(&(input.as_bytes().len() as u64).to_be_bytes());
        seed.extend_from_slice(&input.as_bytes());
        seed.extend_from_slice(&(output.as_bytes().len() as u64).to_be_bytes());
        seed.extend_from_slice(&output.as_bytes());
        seed.extend_from_slice(&(vdf.iterations).to_be_bytes());
        seed.extend_from_slice(&vdf.group_parameter.to_bytes());

        bigint_utils::hash_prime::<P>(&seed, CHALLENGE_SIZE, &[CHALLENGE_SIZE - 1])
            .expect("The length should be a multiple of 8")
    }
}

impl Parameter for Discriminant {
    /// Compute a valid discriminant (aka a negative prime equal to 3 mod 4) based on the given seed.
    fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Discriminant> {
        Self::try_from(
            bigint_utils::hash_prime_default(seed, size_in_bits, &[0, 1, 2, size_in_bits - 1])?
                .neg(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::class_group::{Discriminant, QuadraticForm};
    use crate::vdf::wesolowski::{StrongVDF, WeakVDF};
    use crate::vdf::VDF;
    use crate::{Parameter, ParameterizedGroupElement};
    use num_bigint::BigInt;

    #[test]
    fn test_prove_and_verify() {
        let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
        let iterations = 1000u64;
        let discriminant = Discriminant::from_seed(&challenge, 1024).unwrap();

        let g = QuadraticForm::generator(&discriminant);

        let vdf = StrongVDF::<QuadraticForm>::new(discriminant, iterations);
        let (output, proof) = vdf.evaluate(&g).unwrap();
        assert!(vdf.verify(&g, &output, &proof).is_ok());

        // A modified output or proof fails to verify
        let modified_output = output.mul(&BigInt::from(2));
        let modified_proof = proof.mul(&BigInt::from(2));
        assert!(vdf.verify(&g, &modified_output, &proof).is_err());
        assert!(vdf.verify(&g, &output, &modified_proof).is_err());
    }

    #[test]
    fn test_verify_from_chain() {
        // Test vector from challenge_chain_sp_vdf in block 0 on chiavdf (https://chia.tt/info/block/0xd780d22c7a87c9e01d98b49a0910f6701c3b95015741316b3fda042e5d7b81d2)
        let challenge_hex = "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb";
        let iterations = 4194304u64;
        let result_hex = "0300445cbcaa176166d9a50b9699e9394be46766c8f6494a1a9afd95bb5dc652ee42101278ad7358baf4ae727e4f5a6f732e3a8c26d9d11365081275a6d4b36dda63a905baffdaebab3311d8d6e2f356edf3bb1cf90e5654e688869d66d1c60676440100";
        let proof_hex = "030040c178e0d3470733621c74dde8614c0421d03ad2ce3bb7cad3616646e3762b35568fbae23139119f7affdc7201f45ee284cc76be6e341c795ccb5779cf102305a31bae2f870ea52c87fb0803a4493a2eb1a2cbbce7e467938cb73447edde2d1b0100";

        let challenge = hex::decode(challenge_hex).unwrap();
        let discriminant = Discriminant::from_seed(&challenge, 1024).unwrap();

        let result_bytes = hex::decode(result_hex).unwrap();
        let result = QuadraticForm::from_bytes(&result_bytes, &discriminant).unwrap();

        let proof_bytes = hex::decode(proof_hex).unwrap();
        let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = WeakVDF::<QuadraticForm>::from_seed(&challenge, 1024, iterations).unwrap();
        assert!(vdf.verify(&input, &result, &proof).is_ok());
    }

    #[test]
    fn test_verify_1024() {
        let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
        let iterations = 1000u64;
        let result_hex = "030039c78c39cff6c29052bfc1453616ec7a47251509b9dbc33d1036bebd4d12e6711a51deb327120310f96be04c90fd4c3b1dab9617c3133132b827abe7bb2348707da8164b964e1b95cd6a8eaf36ffb80bab1f750410e793daec8228b222bd00370100";
        let proof_hex = "0100eb1e1b0b58bca2ceca30344321d77e6c6f995e7c9db878d63aa71348db3577634e309be81ed71cba185a0d3c6bba2945c7002cc757c29a612afec8bf95581c008d2fe1c77e5171f8b85706e5f823cd233d847117f25b53d45cb30fb036b5b0030100";

        let discriminant = Discriminant::from_seed(&challenge, 1024).unwrap();

        let result_bytes = hex::decode(result_hex).unwrap();
        let result = QuadraticForm::from_bytes(&result_bytes, &discriminant).unwrap();

        let proof_bytes = hex::decode(proof_hex).unwrap();
        let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = StrongVDF::<QuadraticForm>::new(discriminant, iterations);

        assert!(vdf.verify(&input, &result, &proof).is_ok());
    }
}
