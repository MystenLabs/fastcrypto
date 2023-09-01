// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError::{InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::class_group::{Discriminant, QuadraticForm};
use crate::groups::{ParameterizedGroupElement, UnknownOrderGroupElement};
use crate::hash::{HashFunction, Sha256};
use crate::vdf::VDF;
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_prime::nt_funcs::is_prime;
use std::cmp::min;
use std::marker::PhantomData;
use std::ops::Neg;

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

/// Implementation of Wesolowski's VDF construction over imaginary class groups using a strong
/// Fiat-Shamir implementation.
pub type ClassGroupVDF = WesolowskiVDF<QuadraticForm, StrongFiatShamir<B_BITS>>;

/// Implementation of Wesolowski's VDF construction over imaginary class groups compatible with chiavdf
/// (https://github.com/Chia-Network/chiavdf).
///
/// Note that the evaluation phase is slower than chia's implementations, so estimates on how long it
/// takes to evaluate the VDF should currently be used with caution.
pub type ChiaClassGroupVDF = WesolowskiVDF<QuadraticForm, ChiaFiatShamir>;

impl<F> WesolowskiVDF<QuadraticForm, F> {
    /// Create a new VDF over an imaginary class group where the discriminant has a given size and
    /// is generated based on a seed. The `iterations` parameters specifies the number of group
    /// operations the evaluation function requires.
    pub fn from_seed(
        seed: &[u8],
        discriminant_size_in_bits: usize,
        iterations: u64,
    ) -> FastCryptoResult<Self> {
        Ok(Self::new(
            Discriminant::from_seed(seed, discriminant_size_in_bits)?,
            iterations,
        ))
    }
}

pub trait FiatShamir<G: ParameterizedGroupElement + UnknownOrderGroupElement> {
    /// Compute the prime modulus used in proving and verification. This is a Fiat-Shamir construction
    /// to make the Wesolowski VDF non-interactive.
    fn compute_challenge<F>(vdf: &WesolowskiVDF<G, F>, input: &G, output: &G) -> G::ScalarType;
}

/// Size of the random prime modulus B used in proving and verification.
const B_BITS: usize = 264;

/// Implementation of the Fiat-Shamir challenge generation compatible with chiavdf.
/// Note that this implementation is weak, meaning that not all public parameters are used in the
/// challenge generation. This is not secure if an adversary can influence the public parameters.
/// See https://eprint.iacr.org/2023/691.
pub struct ChiaFiatShamir;

impl FiatShamir<QuadraticForm> for ChiaFiatShamir {
    fn compute_challenge<F>(
        _vdf: &WesolowskiVDF<QuadraticForm, F>,
        input: &QuadraticForm,
        output: &QuadraticForm,
    ) -> BigInt {
        let mut seed = vec![];
        seed.extend_from_slice(&input.as_bytes());
        seed.extend_from_slice(&output.as_bytes());
        hash_prime(&seed, B_BITS, &[B_BITS - 1]).expect("The length should be a multiple of 8")
    }
}

/// Implementation of the Fiat-Shamir challenge generation for usage with Wesolowski's VDF construction.
/// The implementation is strong, meaning that all public parameters are used in the challenge generation.
/// See https://eprint.iacr.org/2023/691.
pub struct StrongFiatShamir<const CHALLENGE_SIZE: usize>;

impl<const CHALLENGE_SIZE: usize> FiatShamir<QuadraticForm> for StrongFiatShamir<CHALLENGE_SIZE> {
    fn compute_challenge<F>(
        vdf: &WesolowskiVDF<QuadraticForm, F>,
        input: &QuadraticForm,
        output: &QuadraticForm,
    ) -> BigInt {
        let mut seed = vec![];
        seed.extend_from_slice(&input.as_bytes());
        seed.extend_from_slice(&output.as_bytes());
        seed.extend_from_slice(&vdf.group_parameter.to_bytes());
        seed.extend_from_slice(&vdf.iterations.to_be_bytes());
        hash_prime(&seed, CHALLENGE_SIZE, &[CHALLENGE_SIZE - 1])
            .expect("The length should be a multiple of 8")
    }
}

/// Implementation of HashPrime from chiavdf (https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43):
/// Generates a random pseudo-prime using the hash and check method:
/// Randomly chooses x with bit-length `length`, then applies a mask
///   (for b in bitmask) { x |= (1 << b) }.
/// Then return x if it is a pseudo-prime, otherwise repeat.
///
/// The length must be a multiple of 8, otherwise `FastCryptoError::InvalidInput` is returned.
fn hash_prime(seed: &[u8], length: usize, bitmask: &[usize]) -> FastCryptoResult<BigInt> {
    if length % 8 != 0 {
        return Err(InvalidInput);
    }

    let mut sprout: Vec<u8> = vec![];
    sprout.extend_from_slice(seed);

    loop {
        let mut blob = vec![];
        while blob.len() * 8 < length {
            for i in (0..sprout.len()).rev() {
                sprout[i] = sprout[i].wrapping_add(1);
                if sprout[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&sprout).digest;
            blob.extend_from_slice(&hash[..min(hash.len(), length / 8 - blob.len())]);
        }
        let mut x = BigInt::from_bytes_be(Sign::Plus, &blob);
        for b in bitmask {
            x.set_bit(*b as u64, true);
        }

        // The implementations of the primality test used below might be slightly different from the
        // one used by chiavdf, but since the risk of a false positive is very small (4^{-100}) this
        // is not an issue.
        if is_prime(&x.to_biguint().unwrap(), None).probably() {
            return Ok(x);
        }
    }
}

impl Discriminant {
    /// Compute a valid discriminant (aka a negative prime equal to 3 mod 4) based on the given seed.
    pub fn from_seed(seed: &[u8], length: usize) -> FastCryptoResult<Self> {
        Self::try_from(hash_prime(seed, length, &[0, 1, 2, length - 1])?.neg())
    }
}

#[test]
fn test_prove_and_verify() {
    let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
    let iterations = 1000u64;
    let discriminant = Discriminant::from_seed(&challenge, 1024).unwrap();

    let g = QuadraticForm::generator(&discriminant);

    let vdf = ClassGroupVDF::new(discriminant, iterations);
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

    let vdf = ChiaClassGroupVDF::from_seed(&challenge, 1024, iterations).unwrap();
    assert!(vdf.verify(&input, &result, &proof).is_ok());
}

#[test]
fn test_verify_1024() {
    let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
    let iterations = 1000u64;
    let result_hex = "030039c78c39cff6c29052bfc1453616ec7a47251509b9dbc33d1036bebd4d12e6711a51deb327120310f96be04c90fd4c3b1dab9617c3133132b827abe7bb2348707da8164b964e1b95cd6a8eaf36ffb80bab1f750410e793daec8228b222bd00370100";
    let proof_hex = "000075d043db5f619f5cb4e8ef7729c7cac154434c33d6e52dd086b90a52c7b1231890eda9d1365100e88993e332f0a99bb7763f215de2fb6b632445beeeff22b657dc90d4e110ed03eac10ec445117d211208c79dd4933ba58b8e17b4c54ef1824c0100";

    let discriminant = Discriminant::from_seed(&challenge, 1024).unwrap();

    let result_bytes = hex::decode(result_hex).unwrap();
    let result = QuadraticForm::from_bytes(&result_bytes, &discriminant).unwrap();

    let proof_bytes = hex::decode(proof_hex).unwrap();
    let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();

    let input = QuadraticForm::generator(&discriminant);

    let vdf = ClassGroupVDF::new(discriminant, iterations);
    assert!(vdf.verify(&input, &result, &proof).is_ok());
}

#[test]
fn test_verify_2048() {
    let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
    let iterations = 1000u64;
    let result_hex = "02001222c470df6df6e1321aa1c28279d0c64663c7f066888ff6cd854dcd5deb71f63dfe0b867675180fada390e0d7b1ff735b55fea2b88123a32d1e1239126b275578ea26a4a89e5ef290e2b7b8d072ab819d5b9422770339dc87fd4dc4ebf6add3e391067a557be4be5436355ab11035609d5a3dc71e95cf2a0dcbb228b85d9750a1dc670ac51822d7eff49b5cacd4a8cc485e53bbf7e44f95e7fd5ec55fca44eb91c4831b1e839d8b4c8453dce8be69698bc5cb8fa45120d201057e4d72a6746b0100";
    let proof_hex = "03008b91b20ab570b701d394aa095d8c670d95a8a3b26af966e979a27acf417421360ea54014668a121139ab11fe92cc0a8d192a8a675f244f3016ed23a7a82d9dd70de089d5bcb5bb0c9535923b2656b19c8cf0cc6e0e4c800c44fc17e16a1b96572f6e0e0967709af259b854a51bec270e5cf73cc4efa93791ac6a84dc2ab77f02d0234ac60b2a04740644ac845204c67f9063ab139e9a0eb25c4417c892ca52299202d3854243d7eb58cc46a837745a1eb92699eb89138eec89467f7226380b040600";

    let discriminant = Discriminant::from_seed(&challenge, 2048).unwrap();

    let result_bytes = hex::decode(result_hex).unwrap();
    let result = QuadraticForm::from_bytes(&result_bytes, &discriminant).unwrap();

    let proof_bytes = hex::decode(proof_hex).unwrap();
    let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();

    let input = QuadraticForm::generator(&discriminant);

    let vdf = ClassGroupVDF::new(discriminant, iterations);
    assert!(vdf.verify(&input, &result, &proof).is_ok());
}
