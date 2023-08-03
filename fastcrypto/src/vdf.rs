// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a implementation of a verifiable delay function (VDF), using Wesolowski's
//! construction with ideal class groups.

use std::cmp::min;
use std::ops::Neg;

use class_group::pari_init;
use curv::arithmetic::{BitManipulation, Converter, Integer, Modulo, One, Primes};
use curv::BigInt;

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::classgroup::QuadraticForm;
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
        input: &Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<(Self::GroupElement, Self::GroupElement)>;

    /// Verify the output and proof from a VDF.
    fn verify(
        &self,
        input: &Self::GroupElement,
        output: &Self::GroupElement,
        proof: &Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<bool>;
}

/// An implementation of the Wesolowski VDF construction over ideal class groups. The implementation
/// is compatible with chiavdf.
///
/// Note that the evaluation phase is currently significantly slower than other implementations, so
/// estimates on how long it takes to evaluate a VDF should currently be used cautiously.
pub struct ClassgroupVDF {
    discriminant: BigInt,
}

impl ClassgroupVDF {
    /// Create a new Wesolowski VDF construction using a class group with the given discriminant.
    /// Ideally, the discriminant should be a negative prime equal to 1 mod 4.
    pub fn new(discriminant: BigInt) -> Self {
        unsafe {
            // The parameters here are the number of bytes allocated to the pari stack + initial list of precomputed primes
            pari_init(100_000_000_000, 0);
        }
        Self { discriminant }
    }

    /// Create a new Wesolowski VDF construction with a random discriminant of the given size sampled
    /// from a seed.
    pub fn from_seed(seed: &[u8], discriminant_size_in_bits: usize) -> FastCryptoResult<Self> {
        Ok(Self::new(get_discriminant(
            seed,
            discriminant_size_in_bits,
        )?))
    }
}

impl VDF for ClassgroupVDF {
    type GroupElement = QuadraticForm;

    fn prove(
        &self,
        input: &Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<(Self::GroupElement, Self::GroupElement)> {
        let mut output = input.clone();
        for _ in 0..iterations {
            output = output.double();
        }

        let input_bytes = &input.serialize()?;
        let output_bytes = &output.serialize()?;
        let b = get_b(input_bytes, output_bytes);

        let mut quotient_remainder = (BigInt::one(), BigInt::one());
        let mut proof = QuadraticForm::identity(&self.discriminant);
        let two = BigInt::from(2);

        // Algorithm from page 3 on https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
        for _ in 0..iterations {
            quotient_remainder = (&quotient_remainder.1 * &two).div_mod_floor(&b);
            proof = &proof.double() + &(input * &quotient_remainder.0);
        }

        Ok((output, proof))
    }

    fn verify(
        &self,
        input: &Self::GroupElement,
        output: &Self::GroupElement,
        proof: &Self::GroupElement,
        iterations: u64,
    ) -> FastCryptoResult<bool> {
        if input.discriminant() != self.discriminant
            || output.discriminant() != self.discriminant
            || proof.discriminant() != self.discriminant
        {
            return Err(FastCryptoError::InvalidInput);
        }

        let input_bytes = input.serialize()?;
        let output_bytes = output.serialize()?;
        let b = get_b(&input_bytes, &output_bytes);
        let f1 = proof * &b;

        let r = BigInt::mod_pow(&BigInt::from(2), &BigInt::from(iterations), &b);
        let f2 = input * &r;

        Ok(&f1 + &f2 == *output)
    }
}

/// Compute the prime modulus used in proving and verification. This is a Fiat-Shamir construction to make
/// the Wesolowski VDF non-interactive.
fn get_b(x: &[u8], y: &[u8]) -> BigInt {
    let mut seed = vec![];
    seed.extend_from_slice(x);
    seed.extend_from_slice(y);
    hash_prime(&seed, B_BITS, &[B_BITS - 1]).expect("The length should be a multiple of 8")
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
        return Err(FastCryptoError::InvalidInput);
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
        let mut x = BigInt::from_bytes(&blob);
        for b in bitmask {
            x.set_bit(*b, true);
        }
        // Note that the implementation used here is very similar to the one used in chiavdf, but it
        // could theoretically return something different.
        if x.is_probable_prime(100) {
            return Ok(x);
        }
    }
}

/// Compute a discriminant (aka a negative prime equal to 3 mod 4) based on the given seed.
fn get_discriminant(seed: &[u8], length: usize) -> FastCryptoResult<BigInt> {
    Ok(hash_prime(seed, length, &[0, 1, 2, length - 1])?.neg())
}

#[test]
fn test_verify_chia_vdf_proof() {
    // Test vector from chiavdf (https://github.com/Chia-Network/chiavdf/blob/main/tests/test_verifier.py)
    let challenge_hex = "efa94dee46bd9404fb48";
    let difficulty = 1000000u64;
    let discriminant_hex = "a110cf23134d6a4f3439c087ce79fcd53f23b460106d7e2789aeb846dee5e8518f59b1fd3fe9f4c42da8f5936f917d4cc122fda673c6ca784e9de561c8a6a12f";
    let result_hex = "030043791356fc0d3c31cdcc1909371085313f00a43c260aabfd379b67f1d9a8790c07989723e37f6dcd900c3bfe732e661a0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let proof_hex = "0300e500d6c3f2e7e2109a261d762c460cf9c2138d47338060e6936771eabb35a9122724318e2b28258882cb453f2f4bf00d0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let challenge = hex::decode(challenge_hex).unwrap();
    let discriminant = get_discriminant(&challenge, 512).unwrap();
    assert_eq!(
        discriminant,
        BigInt::from_hex(discriminant_hex).unwrap().neg()
    );

    let result_bytes = hex::decode(result_hex).unwrap();
    let result = QuadraticForm::deserialize(&result_bytes, &discriminant).unwrap();

    let proof_bytes = hex::decode(proof_hex).unwrap();
    let proof = QuadraticForm::deserialize(&proof_bytes, &discriminant).unwrap();

    let vdf = ClassgroupVDF::new(discriminant.clone());
    assert!(vdf
        .verify(
            &QuadraticForm::generator(&discriminant),
            &result,
            &proof,
            difficulty
        )
        .unwrap());
}

#[test]
fn test_prove_and_verify() {
    let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
    let discriminant = get_discriminant(&challenge, 512).unwrap();
    let difficulty = 1000u64;
    let vdf = ClassgroupVDF::new(discriminant.clone());

    let g = QuadraticForm::generator(&discriminant);
    let (output, proof) = vdf.prove(&g, difficulty).unwrap();

    assert!(vdf.verify(&g, &output, &proof, difficulty).unwrap());

    // Check that output is the same as chiavdf.
    assert_eq!(output.serialize().unwrap().to_vec(), hex::decode("00000f15c12a8df103ea8fac88eb3e5d956a0a6c7126671d5ca2613e2c11cfbc7f12f6a38a3e70c9faf569c596f7820c18140200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());
}
