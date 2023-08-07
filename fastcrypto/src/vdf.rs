// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a implementation of a verifiable delay function (VDF), using Wesolowski's
//! construction with ideal class groups.

#[cfg(test)]
use class_group::pari_init;
use std::cmp::min;
use std::ops::Neg;

use curv::arithmetic::{BitManipulation, Converter, Integer, Modulo, Primes};
use curv::BigInt;

use crate::error::FastCryptoError::{InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::classgroup::{Discriminant, QuadraticForm};
use crate::groups::{ParameterizedGroupElement, UnknownOrderGroupElement};
use crate::hash::HashFunction;
use crate::hash::Sha256;

/// Size of the random prime modulus B used in proving and verification.
const B_BITS: usize = 264;

/// This represents a Verifiable Delay Function (VDF) construction.
pub trait VDF {
    /// The type of the input to the VDF.
    type InputType;

    /// The type of the output from the VDF.
    type OutputType;

    /// The type of the proof of correctness for this VDF.
    type ProofType;

    /// Evaluate this VDF and return the output and a proof of correctness.
    fn eval(
        &self,
        input: &Self::InputType,
        iterations: u64,
    ) -> FastCryptoResult<(Self::OutputType, Self::ProofType)>;

    /// Verify the output and proof from a VDF.
    fn verify(
        &self,
        input: &Self::InputType,
        output: &Self::OutputType,
        proof: &Self::ProofType,
        iterations: u64,
    ) -> FastCryptoResult<()>;
}

/// An implementation of the Wesolowski VDF construction (https://eprint.iacr.org/2018/623) over a group of
/// unknown order. The implementation is compatible with chiavdf (https://github.com/Chia-Network/chiavdf).
///
/// Note that the evaluation phase is currently significantly slower than other implementations, so
/// estimates on how long it takes to evaluate a VDF should currently be used with caution.
pub struct WesolowskiVDF<G: ParameterizedGroupElement + UnknownOrderGroupElement> {
    group_parameter: G::ParameterType,
}

impl<G: ParameterizedGroupElement + UnknownOrderGroupElement> WesolowskiVDF<G> {
    /// Create a new VDF using group
    fn from_group_parameter(group_parameter: G::ParameterType) -> Self {
        Self { group_parameter }
    }
}

impl<G: ParameterizedGroupElement<ScalarType = BigInt> + UnknownOrderGroupElement> VDF
    for WesolowskiVDF<G>
{
    type InputType = G;
    type OutputType = G;
    type ProofType = G;

    fn eval(&self, input: &G, iterations: u64) -> FastCryptoResult<(G, G)> {
        if input.get_group_parameter() != self.group_parameter {
            return Err(InvalidInput);
        }

        if iterations == 0 {
            return Ok((input.clone(), G::zero(&self.group_parameter)));
        }

        let mut output = input.double();
        for _ in 1..iterations {
            output = output.double();
        }

        let b = get_b(&input.as_bytes(), &output.as_bytes());

        // Algorithm from page 3 on https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
        let two = BigInt::from(2);
        let mut quotient_remainder = two.div_mod_floor(&b);
        let mut proof = input.mul(&quotient_remainder.0);
        for _ in 1..iterations {
            quotient_remainder = (&quotient_remainder.1 * &two).div_mod_floor(&b);
            proof = proof.double() + input.mul(&quotient_remainder.0);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &G, iterations: u64) -> FastCryptoResult<()> {
        if input.get_group_parameter() != self.group_parameter
            || output.get_group_parameter() != self.group_parameter
            || proof.get_group_parameter() != self.group_parameter
        {
            return Err(InvalidInput);
        }

        let b = get_b(&input.as_bytes(), &output.as_bytes());
        let f1 = proof.mul(&b);

        let r = BigInt::mod_pow(&BigInt::from(2), &BigInt::from(iterations), &b);
        let f2 = input.mul(&r);

        if f1 + f2 != *output {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Implementation of Wesolowski's VDF construction over imaginary class groups.
pub type ClassGroupVDF = WesolowskiVDF<QuadraticForm>;

impl WesolowskiVDF<QuadraticForm> {
    /// Create a new VDF over an imaginary class group where the discriminant is generated based on a seed.
    pub fn from_seed(seed: &[u8], discriminant_size_in_bits: usize) -> FastCryptoResult<Self> {
        Ok(Self::from_group_parameter(Discriminant::from_seed(
            seed,
            discriminant_size_in_bits,
        )?))
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
        let mut x = BigInt::from_bytes(&blob);
        for b in bitmask {
            x.set_bit(*b, true);
        }

        // The implementations of the primality test used below might be slightly different from the
        // one used by chiavdf, but since the risk of a false positive is very small (4^{-100}) this
        // is not an issue.
        if x.is_probable_prime(100) {
            return Ok(x);
        }
    }
}

impl Discriminant {
    /// Compute a valid discriminant (aka a negative prime equal to 3 mod 4) based on the given seed.
    fn from_seed(seed: &[u8], length: usize) -> FastCryptoResult<Self> {
        Self::try_from(hash_prime(seed, length, &[0, 1, 2, length - 1])?.neg())
    }
}

#[test]
fn test_verify_chia_vdf_proof() {
    unsafe {
        pari_init(100_000_000_000, 0);
    }

    // Test vector from chiavdf (https://github.com/Chia-Network/chiavdf/blob/main/tests/test_verifier.py)
    let challenge_hex = "efa94dee46bd9404fb48";
    let difficulty = 1000000u64;
    let result_hex = "030043791356fc0d3c31cdcc1909371085313f00a43c260aabfd379b67f1d9a8790c07989723e37f6dcd900c3bfe732e661a0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let proof_hex = "0300e500d6c3f2e7e2109a261d762c460cf9c2138d47338060e6936771eabb35a9122724318e2b28258882cb453f2f4bf00d0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let challenge = hex::decode(challenge_hex).unwrap();
    let discriminant = Discriminant::from_seed(&challenge, 512).unwrap();

    let result_bytes = hex::decode(result_hex).unwrap();
    let result = QuadraticForm::from_bytes(&result_bytes, &discriminant).unwrap();

    let proof_bytes = hex::decode(proof_hex).unwrap();
    let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();

    let input = QuadraticForm::generator(&discriminant);

    let vdf = ClassGroupVDF::from_group_parameter(discriminant);
    assert!(vdf.verify(&input, &result, &proof, difficulty).is_ok());
}

#[test]
fn test_prove_and_verify() {
    unsafe {
        pari_init(100_000_000_000, 0);
    }

    let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
    let difficulty = 1000u64;
    let discriminant = Discriminant::from_seed(&challenge, 512).unwrap();

    let g = QuadraticForm::generator(&discriminant);

    let vdf = ClassGroupVDF::from_group_parameter(discriminant);
    let (output, proof) = vdf.eval(&g, difficulty).unwrap();
    assert!(vdf.verify(&g, &output, &proof, difficulty).is_ok());

    // Check that output is the same as chiavdf.
    assert_eq!(output.as_bytes(), hex::decode("00000f15c12a8df103ea8fac88eb3e5d956a0a6c7126671d5ca2613e2c11cfbc7f12f6a38a3e70c9faf569c596f7820c18140200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap());
}
