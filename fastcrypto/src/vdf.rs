// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;
use std::ops::{Add, Mul, Neg};
use std::time::Instant;

use bincode::Options;
use class_group::{ABDeltaTriple, BinaryQF, BinaryQFCompressed, bn_to_gen, pari_init};
use class_group::primitives::hash_to_prime;
use class_group::primitives::vdf::VDF as ExternalVDF;
use curv::arithmetic::{BitManipulation, Converter, Integer, Modulo, One, Primes, Roots, Zero};
use curv::BigInt;

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::vdf::CompressedQuadraticForm::Nontrivial;

pub const COMPRESSED_SIZE: usize = 100;
pub const B_BITS: usize = 264;

pub trait VDF {
    type Output;

    fn evaluate(&self, input: &[u8], difficulty: u64) -> FastCryptoResult<Self::Output>;
    fn verify(&self, input: &[u8], output: &Self::Output, difficulty: u64) -> FastCryptoResult<bool>;
}

pub struct WesolowskiVDF {
    discriminant_size_in_bits: usize,
}

impl WesolowskiVDF {
    pub fn new(discriminant_size_in_bits: usize) -> Self {
        Self {
            discriminant_size_in_bits,
        }
    }
}

impl VDF for WesolowskiVDF {
    type Output = ExternalVDF;

    fn evaluate(&self, input: &[u8], difficulty: u64) -> FastCryptoResult<Self::Output> {
        let x = BigInt::from_bytes(input);
        let ab_triple = ExternalVDF::setup(self.discriminant_size_in_bits, &x);
        let t = BigInt::from(difficulty);

        Ok(ExternalVDF::eval(&ab_triple, &x, &t))
    }

    fn verify(&self, input: &[u8], output: &ExternalVDF, difficulty: u64) -> FastCryptoResult<bool> {
        if BigInt::from_bytes(input) != output.x || BigInt::from(difficulty) != output.t {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(output.verify().is_ok())
    }
}

#[test]
fn test_wesolowski_vdf() {
    let vdf = WesolowskiVDF::new(512);
    let input = b"hello world";
    let difficulty = 1000;
    let start = Instant::now();
    let output = vdf.evaluate(input, difficulty).unwrap();
    let duration1 = start.elapsed();
    let start = Instant::now();
    let verified = vdf.verify(input, &output, difficulty).unwrap();
    let duration2 = start.elapsed();
    assert!(verified);
    println!("WesolowskiVDF: evaluate: {:?}, verify: {:?}", duration1, duration2);
}

/// ====
/// chiavdf compatability
/// ====

/// Export a big integer to a byte array of the given size. If the number is too large, an error is returned.
fn export_to_size(number: &BigInt, target_size: usize) -> FastCryptoResult<Vec<u8>> {
    let mut bytes = number.to_bytes();
    if bytes.len() > target_size {
        return Err(FastCryptoError::InputTooLong(bytes.len()));
    } else if bytes.len() < target_size {
        let mut new_bytes = vec![0u8; target_size - bytes.len()];
        new_bytes.append(&mut bytes);
        bytes = new_bytes;
    }
    Ok(bytes)
}

#[derive(PartialEq, Eq, Debug)]
pub struct QuadraticForm(pub BinaryQF);

pub enum CompressedQuadraticForm {
    Identity(BigInt),
    Generator(BigInt),
    Nontrivial(CompressedFormat),
}

#[derive(Clone, Debug)]
pub struct CompressedFormat {
    a_prime: BigInt,
    t_prime: BigInt,
    g: BigInt,
    b0: BigInt,
    b_sign: bool,
    delta: BigInt,
}

impl Mul<&BigInt> for QuadraticForm {
    type Output = Self;

    fn mul(self, rhs: &BigInt) -> Self::Output {
        Self(self.0.exp(rhs))
    }
}

impl Add<&QuadraticForm> for QuadraticForm {
    type Output = Self;

    fn add(self, rhs: &QuadraticForm) -> Self::Output {
        Self(self.0.compose(&rhs.0).reduce())
    }
}

impl QuadraticForm {
    fn from_a_b_delta(a: BigInt, b: BigInt, delta: &BigInt) -> Self {
        let c = ((&b * &b) - delta) / (BigInt::from(4) * &a);
        Self(BinaryQF { a, b, c })
    }

    fn discriminant(&self) -> BigInt {
        self.0.discriminant()
    }

    /// Return the identity element in a class group with a given discriminant, eg. (1, 1, X) where
    /// X is determined from the discriminant.
    fn zero(discriminant: &BigInt) -> Self {
        Self::from_a_b_delta(
            BigInt::one(),
            BigInt::one(),
            discriminant,
        )
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class group
    /// with a given discriminant. We use the element (2, 1, X) where X is determined from the discriminant.
    fn generator(discriminant: &BigInt) -> Self {
        Self::from_a_b_delta(
            BigInt::from(2),
            BigInt::one(),
            discriminant,
        )
    }

    fn from_compressed(compressed: &CompressedQuadraticForm) -> FastCryptoResult<Self> {
        match compressed {
            CompressedQuadraticForm::Identity(delta) => Ok(Self::zero(delta)),
            CompressedQuadraticForm::Generator(delta) => Ok(Self::generator(&delta)),
            Nontrivial(form) => {
                let CompressedFormat {
                    a_prime,
                    t_prime,
                    g,
                    b0,
                    b_sign,
                    delta,
                } = form.clone();

                // 3. if t = 0 then return (a,a)
                if t_prime.is_zero() {
                    return Ok(Self::from_a_b_delta(
                        a_prime.clone(),
                        a_prime,
                        &delta,
                    ));
                }

                let mut t = t_prime;
                if t < BigInt::zero() {
                    t += &a_prime;
                }

                if a_prime.is_zero() {
                    return Err(FastCryptoError::InvalidInput);
                }

                let mut t_inv = BigInt::mod_inv(&t, &a_prime).ok_or(FastCryptoError::InvalidInput)?;
                if t_inv < BigInt::zero() {
                    t_inv += &a_prime;
                }

                let d = delta.modulus(&a_prime);
                let tmp_debug = (&t * &t * &d).modulus(&a_prime);
                let tmp = tmp_debug.sqrt();
                assert_eq!(&tmp * &tmp, tmp_debug); // This fails, meaning that a_prime and/or t are wrong at this point

                let mut out_a = a_prime.clone();
                if g != BigInt::one() {
                    out_a = &a_prime * &g;
                }

                let mut out_b = (tmp * t_inv).mod_floor(&a_prime);
                if b0 > BigInt::zero() {
                    out_b += &a_prime * b0;
                }

                if b_sign {
                    out_b = -out_b;
                }

                // 10. return (a,b)
                let out = Self::from_a_b_delta(
                    out_a,
                    out_b,
                    &delta,
                );
                println!("Decompr discr: {}", out.discriminant());
                Ok(out)
            }
        }
    }
}

impl CompressedQuadraticForm {
    /// Serialize a compressed binary form according to the format defined in the chiavdf library.
    fn serialize(&self) -> FastCryptoResult<[u8; COMPRESSED_SIZE]> {
        match self {
            CompressedQuadraticForm::Identity(delta) => todo!(),
            CompressedQuadraticForm::Generator(delta) => todo!(),
            Nontrivial(form) => {
                let d_bits = (form.delta.bit_length() + 31) & !31;

                let mut bytes = vec![];
                bytes.push(form.b_sign as u8);
                bytes[0] |= ((form.t_prime < BigInt::zero()) as u8) << 1;

                let g_size = (form.g.bit_length() + 7) / 8 - 1;
                bytes.push(g_size as u8);

                let length = d_bits / 16 - g_size;
                bytes.extend_from_slice(&export_to_size(&form.a_prime, length)?);
                let length = d_bits / 32 - g_size;
                bytes.extend_from_slice(&export_to_size(&form.t_prime, length)?);
                let length = g_size + 1;
                bytes.extend_from_slice(&export_to_size(&form.g, length)?);
                let length = g_size + 1;
                bytes.extend_from_slice(&export_to_size(&form.b0, length)?);

                bytes.extend_from_slice(&vec![0u8; COMPRESSED_SIZE - bytes.len()]);

                bytes.try_into().map_err(|_| FastCryptoError::InvalidInput)
            }
        }
    }

    fn deserialize(bytes: &[u8], delta: &BigInt) -> FastCryptoResult<Self> {
        if bytes.len() != COMPRESSED_SIZE {
            return Err(FastCryptoError::InputLengthWrong(COMPRESSED_SIZE));
        }

        /*
         * Serialization format for compressed quadratic forms:
         *
         * Size (bytes)            Description
         * 1                       Sign bits and flags for special forms:
         *                         bit0 - b sign; bit1 - t sign;
         *                         bit2 - is identity form; bit3 - is generator form
         *
         * 1                       Size of 'g' in bytes minus 1 (g_size)
         *
         * d_bits / 16 - g_size    a' = a / g
         * d_bits / 32 - g_size    t' = t / g, where t satisfies (a*x + b*t < sqrt(a))
         * g_size + 1              g = gcd(a, t)
         * g_size + 1              b0 = b / a' (truncating division)
         *
         * Notes: 'd_bits' is the bit length of the discriminant, which is rounded up
         * to the next multiple of 32. Serialization of special forms (identity or
         * generator) takes only 1 byte.
         */

        let is_identity = bytes[0] & 0x04 != 0;
        let is_generator = bytes[0] & 0x08 != 0;

        if is_identity {
            return Ok(CompressedQuadraticForm::Identity(delta.clone()));
        } else if is_generator {
            return Ok(CompressedQuadraticForm::Generator(delta.clone()));
        }

        let d_bits = (delta.bit_length() + 31) & !31;
        let g_size = bytes[1] as usize;
        if g_size >= d_bits / 32 {
            return Err(FastCryptoError::InvalidInput);
        }

        let b_sign = bytes[0] & 0x01 != 0;
        let t_sign = bytes[0] & 0x02 != 0;

        let mut offset = 2;
        let length = d_bits / 16 - g_size;
        let a_prime = bigint_import(&bytes[offset..offset + length]);
        offset += length;
        let length = d_bits / 32 - g_size;
        let mut t_prime = bigint_import(&bytes[offset..offset + length]);
        if t_sign {
            t_prime = -t_prime;
        }
        offset += length;
        let length = g_size + 1;
        let g = bigint_import(&bytes[offset..offset + length]);
        offset += length;
        let length = g_size + 1;
        let b0 = bigint_import(&bytes[offset..offset + length]);

        return Ok(Nontrivial(CompressedFormat {
            a_prime,
            t_prime,
            g,
            b0,
            b_sign,
            delta: delta.clone(),
        }));
    }
}

fn bigint_import(bytes: &[u8]) -> BigInt {
    let mut result = BigInt::zero();
    let mut exponent = BigInt::one();
    for chunk in bytes.chunks(8) {
        let mut bytes = vec![];
        bytes.extend_from_slice(chunk);
        for i in 0..(8 - bytes.len()) {
            bytes.push(0);
        }
        let word: [u8; 8] = bytes.try_into().unwrap();
        result += BigInt::from(u64::from_le_bytes(word)) * &exponent;
        exponent = &exponent * BigInt::from_hex("10000000000000000").unwrap();
    }
    result
}

fn get_b(x: &[u8], y: &[u8]) -> BigInt {
    let mut seed = vec![];
    seed.extend_from_slice(x);
    seed.extend_from_slice(y);
    println!("{}", hex::encode(&seed));
    hash_prime(&seed, B_BITS, &[B_BITS - 1])
}

/// Implementation of HashPrime from chiavdf (https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43):
/// Generates a random psuedoprime using the hash and check method:
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
        if x.is_probable_prime(100) {
            return x;
        }
    }
}

fn verify(output: &CompressedQuadraticForm, proof: &CompressedQuadraticForm, delta: &BigInt, iterations: u64) -> FastCryptoResult<bool> {

    //    //algorithm 2 from https://eprint.iacr.org/2018/623.pdf
    //     pub fn verify(&self) -> Result<(), ErrorReason> {
    //         unsafe {
    //             pari_init(1000000000, 2);
    //         }
    //
    //         let g = BinaryQF::binary_quadratic_form_disc(&self.a_b_delta).reduce();
    //
    //         // test that g,y are elements of the class : https://eprint.iacr.org/2018/712.pdf 2.1 line 0
    //         if g.discriminant() != self.a_b_delta.delta
    //             || self.y.discriminant() != self.a_b_delta.delta
    //             || self.pi.discriminant() != self.a_b_delta.delta
    //         {
    //             return Err(ErrorReason::VDFVerifyError);
    //         }
    //         let l = hash_to_prime(&g, &self.y);
    //
    //         let r = BigInt::mod_pow(&BigInt::from(2), &self.t, &l);
    //         let pi_l_g_r = self.pi.exp(&l).compose(&g.exp(&r)).reduce();
    //
    //         match pi_l_g_r == self.y {
    //             true => Ok(()),
    //             false => Err(ErrorReason::VDFVerifyError),
    //         }
    //     }
    todo!()
}

fn get_discriminant(challenge: &[u8], length: usize) -> BigInt {
    hash_prime(challenge, length, &[0, 1, 2, length - 1]).neg()
}

#[test]
fn test_verify_chia_vdf_proof() {

    // Test vector from chiavdf (https://github.com/Chia-Network/chiavdf/blob/main/tests/test_verifier.py)
    let delta = BigInt::from_hex("d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf").unwrap().neg();

    let challenge = hex::decode("dd4d3fe6791fffb1b335").unwrap();
    assert_eq!(delta, get_discriminant(&challenge, 512));

    let difficulty = 100000u64;

    let result_hex = "010083b82ff747c385b0e2ff91ef1bea77d3d70b74322db1cd405e457aefece6ff23961c1243f1ed69e15efd232397e467200100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let result_bytes = hex::decode(result_hex).unwrap();
    let result_compressed = CompressedQuadraticForm::deserialize(&result_bytes, &delta).unwrap();
    let result = QuadraticForm::from_compressed(&result_compressed).unwrap();

    let proof_hex = "0200222889d197dbfddc011bba8725c753b3caf8cb85b2a03b4f8d92cf5606e81208d717f068b8476ffe1f9c2e0443fc55030605000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let proof_bytes = hex::decode(proof_hex).unwrap();
    let proof_compressed = CompressedQuadraticForm::deserialize(&proof_bytes, &delta).unwrap();
    let proof = QuadraticForm::from_compressed(&proof_compressed).unwrap();

    unsafe {
        pari_init(1000000000, 2);
    }

    // Serialized generator
    let x_bytes = hex::decode("08000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let b = get_b(&x_bytes, &result_bytes);

    let f1 = proof * &b;
    // proof and output have wrong discriminants!
    let r = BigInt::mod_pow(&BigInt::from(2), &BigInt::from(difficulty), &b);
    let f2 = QuadraticForm::generator(&delta) * &r;

    assert_eq!(f1 + &f2, result);
}
