// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;
use std::ops::Neg;

use class_group::pari_init;
use curv::arithmetic::{BitManipulation, Converter, Modulo, Primes};
use curv::BigInt;

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::classgroup;
use crate::groups::classgroup::CompressedQuadraticForm;
use crate::hash::HashFunction;
use crate::hash::Sha256;

/// Size of the random prime modulus B used in proving and verification.
const B_BITS: usize = 264;

/// This represents a Verifiable Delay Function (VDF) construction over a given group.
pub trait VDF {
    type GroupElement;

    /// Evaluate this VDF and return the output and proof of correctness.
    fn prove(
        &self,
        input: Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<VDFOutput<Self::GroupElement>>;

    /// Verify the output and proof from a VDF.
    fn verify(
        &self,
        input: Self::GroupElement,
        output: &Self::GroupElement,
        proof: &Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<bool>;
}

pub struct VDFOutput<T> {
    output: T,
    proof: T,
}

/// An implementation of the Wesolowski VDF construction over ideal class groups. The implementation
/// is compatible with chiavdf.
pub struct ClassgroupVDF {
    discriminant: BigInt,
}

impl ClassgroupVDF {
    pub fn new(discriminant: BigInt) -> Self {
        unsafe {
            pari_init(1000000000, 2);
        }
        Self { discriminant }
    }

    pub fn from_challenge(challenge: &[u8], discriminant_size_in_bits: usize) -> Self {
        Self::new(get_discriminant(challenge, discriminant_size_in_bits))
    }
}

impl VDF for ClassgroupVDF {
    type GroupElement = CompressedQuadraticForm;

    fn prove(
        &self,
        input: Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<VDFOutput<Self::GroupElement>> {
        todo!()
    }

    fn verify(
        &self,
        input: Self::GroupElement,
        output: &Self::GroupElement,
        proof: &Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<bool> {
        if input.discriminant() != &self.discriminant
            || output.discriminant() != &self.discriminant
            || proof.discriminant() != &self.discriminant
        {
            return Err(FastCryptoError::InvalidInput);
        }

        let input_bytes = input.serialize()?;
        let input_uncompressed = input.decompress()?;

        let output_bytes = output.serialize()?;
        let output_decompressed = output.decompress()?;

        let proof_decompressed = proof.decompress()?;

        let b = get_b(&input_bytes, &output_bytes);
        let f1 = proof_decompressed * &b;
        let r = BigInt::mod_pow(&BigInt::from(2), &BigInt::from(iterations), &b);
        let f2 = input_uncompressed * &r;

        Ok(f1 + &f2 == output_decompressed)
    }
}

/// Compute the prime modulus used in proving and verification. This is a Fiat-Shamir construction to make
/// the Wesolowski VDF non-interactive.
fn get_b(x: &[u8], y: &[u8]) -> BigInt {
    let mut seed = vec![];
    seed.extend_from_slice(x);
    seed.extend_from_slice(y);
    hash_prime(&seed, B_BITS, &[B_BITS - 1])
}

/// Implementation of HashPrime from chiavdf (https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43):
/// Generates a random pseudo-prime using the hash and check method:
/// Randomly chooses x with bit-length `length`, then applies a mask
///   (for b in bitmask) { x |= (1 << b) }.
/// Then return x if it is a psuedoprime, otherwise repeat.
fn hash_prime(seed: &[u8], length: usize, bitmask: &[usize]) -> BigInt {
    assert_eq!(length % 8, 0);

    let mut sprout: Vec<u8> = vec![];
    sprout.extend_from_slice(seed);

    loop {
        let mut blob = vec![];
        while (blob.len() * 8) < length {
            for i in (0..sprout.len()).rev() {
                sprout[i] = sprout[i].wrapping_add(1);
                if sprout[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&sprout).digest;
            blob.extend_from_slice(&hash[..min(hash.len(), length / 8 - blob.len())]);
        }

        assert_eq!(blob.len() * 8, length);
        let mut x = BigInt::from_bytes(&blob);
        for b in bitmask {
            x.set_bit(*b, true);
        }
        // Note that the implementation used here is very similar to the one used in chiavdf, but it
        // could theoretically return something different.
        if x.is_probable_prime(100) {
            return x;
        }
    }
}

/// Compute a discriminant (aka a negative prime equal to 3 mod 4) based on the given seed.
fn get_discriminant(seed: &[u8], length: usize) -> BigInt {
    hash_prime(seed, length, &[0, 1, 2, length - 1]).neg()
}

#[test]
fn test_verify_chia_vdf_proof() {
    // Test vector from chiavdf (https://github.com/Chia-Network/chiavdf/blob/main/tests/test_verifier.py)
    let discriminant_hex = "d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf";
    let difficulty = 100000u64;
    let challenge_hex = "dd4d3fe6791fffb1b335";
    let result_hex = "010083b82ff747c385b0e2ff91ef1bea77d3d70b74322db1cd405e457aefece6ff23961c1243f1ed69e15efd232397e467200100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let proof_hex = "0200222889d197dbfddc011bba8725c753b3caf8cb85b2a03b4f8d92cf5606e81208d717f068b8476ffe1f9c2e0443fc55030605000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let discriminant = BigInt::from_hex(discriminant_hex).unwrap().neg();
    let challenge = hex::decode(challenge_hex).unwrap();
    assert_eq!(discriminant, get_discriminant(&challenge, 512));

    let result_bytes = hex::decode(result_hex).unwrap();
    let result_compressed =
        CompressedQuadraticForm::deserialize(&result_bytes, &discriminant).unwrap();

    let proof_bytes = hex::decode(proof_hex).unwrap();
    let proof_compressed =
        CompressedQuadraticForm::deserialize(&proof_bytes, &discriminant).unwrap();

    let vdf = ClassgroupVDF::new(discriminant.clone());
    assert!(vdf
        .verify(
            CompressedQuadraticForm::Generator(discriminant),
            &result_compressed,
            &proof_compressed,
            difficulty
        )
        .unwrap());
}

#[test]
fn test_bigint_import() {
    let x = BigInt::from_hex("d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf").unwrap();
    let bytes = classgroup::bigint_export(&x);
    let reconstructed = classgroup::bigint_import(&bytes);
    assert_eq!(x, reconstructed);
}
