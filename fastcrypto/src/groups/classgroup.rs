// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::classgroup::CompressedQuadraticForm::{Generator, Identity, Nontrivial};
use class_group::BinaryQF;
use curv::arithmetic::{BasicOps, BitManipulation, Converter, Integer, Modulo, One, Roots, Zero};
use curv::BigInt;
use std::cmp::Ordering;
use std::mem::swap;
use std::ops::{Add, Mul};

/// The size of a compressed quadratic form in bytes.
// TODO: It is not clear if this size is used only by the tests in chiavdf or if it's more widely used. The size should depend on the discriminant size, so it's perhaps chosen as an upper limit for commonly used discriminant sizes.
pub const COMPRESSED_SIZE: usize = 100;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QuadraticForm(BinaryQF);

impl Mul<&BigInt> for QuadraticForm {
    type Output = Self;

    // TODO: The current BigInt implementations is curv's wrapper of num-biginteger, but it should be wrapped or replaced with a more widely used BigInt implementation.
    fn mul(self, rhs: &BigInt) -> Self::Output {
        Self(self.0.exp(rhs))
    }
}

impl Mul<&BigInt> for &QuadraticForm {
    type Output = QuadraticForm;

    fn mul(self, rhs: &BigInt) -> Self::Output {
        QuadraticForm(self.0.exp(rhs))
    }
}

impl Add<&QuadraticForm> for &QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: &QuadraticForm) -> Self::Output {
        QuadraticForm(self.0.compose(&rhs.0).reduce())
    }
}

impl QuadraticForm {
    /// Compute self + self.
    pub fn double(&self) -> Self {
        self * &BigInt::from(2)
    }

    /// Create a new quadratic form with the given coordinates.
    pub fn from_a_b_c(a: BigInt, b: BigInt, c: BigInt) -> Self {
        Self(BinaryQF { a, b, c })
    }

    /// Create a new quadratic form given only the a and b coordinate and the discriminant.
    pub fn from_a_b_discriminant(a: BigInt, b: BigInt, discriminant: &BigInt) -> Self {
        let c = ((&b * &b) - discriminant) / (BigInt::from(4) * &a);
        Self(BinaryQF { a, b, c })
    }

    /// Return the identity element in a class group with a given discriminant, eg. (1, 1, X) where
    /// X is determined from the discriminant.
    pub fn identity(discriminant: &BigInt) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class group
    /// with a given discriminant. We use the element `(2, 1, x)` where `x` is determined from the discriminant.
    pub fn generator(discriminant: &BigInt) -> Self {
        Self::from_a_b_discriminant(BigInt::from(2), BigInt::one(), discriminant)
    }

    /// Serialize this quadratic form. The format follows that of chiavdf and is COMPACT_SIZE bytes long.
    pub fn serialize(&self) -> FastCryptoResult<[u8; COMPRESSED_SIZE]> {
        self.compress().serialize()
    }

    /// Deserialize bytes into a quadratic form. The format follows that of chiavdf and the bytes array
    /// should be COMPACT_SIZE bytes long.
    pub fn deserialize(bytes: &[u8], discriminant: &BigInt) -> FastCryptoResult<Self> {
        CompressedQuadraticForm::deserialize(bytes, discriminant)?.decompress()
    }

    /// Compute the discriminant `b^2 - 4ac` for this quadratic form.
    pub fn discriminant(&self) -> BigInt {
        self.0.discriminant()
    }

    /// Return a compressed representation of this quadratic form. See See https://eprint.iacr.org/2020/196.pdf.
    fn compress(&self) -> CompressedQuadraticForm {
        if self.0.a == BigInt::one() && self.0.b == BigInt::one() {
            return Identity(self.discriminant());
        } else if self.0.a == BigInt::from(2) && self.0.b == BigInt::one() {
            return Generator(self.discriminant());
        }

        let BinaryQF { a, b, c: _ } = self.0.clone();

        if a == b {
            return Nontrivial(CompressedFormat {
                a_prime: BigInt::zero(),
                t_prime: BigInt::zero(),
                g: BigInt::zero(),
                b0: BigInt::zero(),
                b_sign: false,
                discriminant: self.discriminant(),
            });
        }

        let b_sign = b < BigInt::zero();
        let b_abs = b.abs();

        let (_, _, mut t_prime) = partial_xgcd(&a, &b_abs);
        let g = a.gcd(&t_prime);

        let mut a_prime = a;
        let mut b0: BigInt;

        if g.is_one() {
            b0 = BigInt::zero();
        } else {
            a_prime /= &g;
            t_prime /= &g;

            // Compute b / a_prime with truncation towards zero similar to mpz_tdiv_q from the GMP library.
            b0 = b_abs.div_floor(&a_prime);
            if b_sign {
                b0 = -b0;
            }
        }

        Nontrivial(CompressedFormat {
            a_prime,
            t_prime,
            g,
            b0,
            b_sign,
            discriminant: self.discriminant(),
        })
    }
}

/// A quadratic form in compressed representation. See https://eprint.iacr.org/2020/196.pdf.
#[derive(PartialEq, Eq, Debug)]
enum CompressedQuadraticForm {
    Identity(BigInt),
    Generator(BigInt),
    Nontrivial(CompressedFormat),
}

#[derive(PartialEq, Eq, Debug)]
struct CompressedFormat {
    a_prime: BigInt,
    t_prime: BigInt,
    g: BigInt,
    b0: BigInt,
    b_sign: bool,
    discriminant: BigInt,
}

impl CompressedQuadraticForm {
    /// Return this as a QuadraticForm.
    fn decompress(&self) -> FastCryptoResult<QuadraticForm> {
        match self {
            Identity(discriminant) => Ok(QuadraticForm::identity(discriminant)),
            Generator(discriminant) => Ok(QuadraticForm::generator(discriminant)),
            Nontrivial(form) => {
                let CompressedFormat {
                    a_prime,
                    t_prime,
                    g,
                    b0,
                    b_sign,
                    discriminant,
                } = form;

                if t_prime.is_zero() {
                    return Ok(QuadraticForm::from_a_b_discriminant(
                        a_prime.clone(),
                        a_prime.clone(),
                        discriminant,
                    ));
                }

                if a_prime.is_zero() {
                    return Err(FastCryptoError::InvalidInput);
                }

                let mut t = t_prime.clone();
                if t < BigInt::zero() {
                    t += a_prime;
                }

                let t_inv = BigInt::mod_inv(&t, a_prime).ok_or(FastCryptoError::InvalidInput)?;
                let d_mod_a = discriminant.modulus(a_prime);
                let sqrt_input = (&t.pow(2) * &d_mod_a).modulus(a_prime);
                let sqrt = sqrt_input.sqrt();
                if &sqrt * &sqrt != sqrt_input {
                    return Err(FastCryptoError::InvalidInput);
                }

                let mut out_a = a_prime.clone();
                if !g.is_one() {
                    out_a = a_prime * g;
                }

                let mut out_b = (sqrt * t_inv).modulus(a_prime);
                if b0 > &BigInt::zero() {
                    out_b += a_prime * b0;
                }
                if *b_sign {
                    out_b = -out_b;
                }

                Ok(QuadraticForm::from_a_b_discriminant(
                    out_a,
                    out_b,
                    discriminant,
                ))
            }
        }
    }

    /// Serialize a compressed binary form according to the format defined in the chiavdf library.
    fn serialize(&self) -> FastCryptoResult<[u8; COMPRESSED_SIZE]> {
        match self {
            Identity(_) => {
                let mut bytes = [0u8; COMPRESSED_SIZE];
                bytes[0] = 0x04;
                Ok(bytes)
            }
            Generator(_) => {
                let mut bytes = [0u8; COMPRESSED_SIZE];
                bytes[0] = 0x08;
                Ok(bytes)
            }
            Nontrivial(form) => {
                let mut bytes = vec![];
                bytes.push(form.b_sign as u8);
                bytes[0] |= ((form.t_prime < BigInt::zero()) as u8) << 1;

                // The bit length of the discriminant, which is rounded up to the next multiple of 32.
                // Serialization of special forms (identity or generator) takes only 1 byte.
                let d_bits = (form.discriminant.bit_length() + 31) & !31;

                // Size of g in bytes minus 1 (g_size)
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

    /// Deserialize a compressed binary form according to the format defined in the chiavdf library.
    fn deserialize(bytes: &[u8], discriminant: &BigInt) -> FastCryptoResult<Self> {
        if bytes.len() != COMPRESSED_SIZE {
            return Err(FastCryptoError::InputLengthWrong(COMPRESSED_SIZE));
        }

        let is_identity = bytes[0] & 0x04 != 0;
        if is_identity {
            return Ok(Identity(discriminant.clone()));
        }

        let is_generator = bytes[0] & 0x08 != 0;
        if is_generator {
            return Ok(Generator(discriminant.clone()));
        }

        // The bit length of the discriminant, which is rounded up to the next multiple of 32.
        // Serialization of special forms (identity or generator) takes only 1 byte.
        let d_bits = (discriminant.bit_length() + 31) & !31;

        // Size of g in bytes minus 1 (g_size)
        let g_size = bytes[1] as usize;
        if g_size >= d_bits / 32 {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut offset = 2;
        let length = d_bits / 16 - g_size;

        // a' = a / g
        let a_prime = bigint_import(&bytes[offset..offset + length]);
        offset += length;
        let length = d_bits / 32 - g_size;

        // t' = t / g, where t satisfies (a*x + b*t < sqrt(a))
        let mut t_prime = bigint_import(&bytes[offset..offset + length]);
        let t_sign = bytes[0] & 0x02 != 0;
        if t_sign {
            t_prime = -t_prime;
        }
        offset += length;
        let length = g_size + 1;

        // g = gcd(a, t)
        let g = bigint_import(&bytes[offset..offset + length]);
        offset += length;
        let length = g_size + 1;

        // b0 = b / a'
        let b0 = bigint_import(&bytes[offset..offset + length]);
        let b_sign = bytes[0] & 0x01 != 0;

        Ok(Nontrivial(CompressedFormat {
            a_prime,
            t_prime,
            g,
            b0,
            b_sign,
            discriminant: discriminant.clone(),
        }))
    }
}

/// Import function for curv::BigInt aligned with chiavdf.
fn bigint_import(bytes: &[u8]) -> BigInt {
    // TODO: The copying done in to_vec is not needed
    let mut reversed = bytes.to_vec();
    reversed.reverse();
    BigInt::from_bytes(&reversed)
}

/// Export function for curv::BigInt aligned with chiavdf.
fn bigint_export(n: &BigInt) -> Vec<u8> {
    let mut bytes = n.to_bytes();
    bytes.reverse();
    bytes
}

/// Export a curv::BigInt to a byte array of the given size. Zeroes are padded to the end if the number
/// serializes to fewer bits than `target_size`. If the serialization is too large, an error is returned.
fn export_to_size(number: &BigInt, target_size: usize) -> FastCryptoResult<Vec<u8>> {
    let mut bytes = bigint_export(number);
    match bytes.len().cmp(&target_size) {
        Ordering::Less => {
            bytes.append(&mut vec![0u8; target_size - bytes.len()]);
            Ok(bytes)
        }
        Ordering::Equal => Ok(bytes),
        Ordering::Greater => Err(FastCryptoError::InputTooLong(bytes.len())),
    }
}

/// Takes `a`and `b`  with `a > b > 0` and returns `(r, s, t)` such that `r = s a + t b` with `|r|, |t| < sqrt(a)`.
fn partial_xgcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut r = (a.clone(), b.clone());
    let mut s = (BigInt::one(), BigInt::zero());
    let mut t = (BigInt::zero(), BigInt::one());

    let a_sqrt = a.sqrt();
    while r.1 > a_sqrt {
        let q = &r.0 / &r.1;
        let r1 = &r.0 - &q * &r.1;
        let s1 = &s.0 - &q * &s.1;
        let t1 = &t.0 - &q * &t.1;

        swap(&mut r.0, &mut r.1);
        r.1 = r1;
        swap(&mut s.0, &mut s.1);
        s.1 = s1;
        swap(&mut t.0, &mut t.1);
        t.1 = t1;
    }

    (r.1, s.1, t.1)
}

#[test]
fn test_bigint_import() {
    let x = BigInt::from_hex("d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf").unwrap();
    let bytes = bigint_export(&x);
    let reconstructed = bigint_import(&bytes);
    assert_eq!(x, reconstructed);
}

#[test]
fn test_compression() {
    let discriminant_hex = "d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf";
    let discriminant = -BigInt::from_hex(discriminant_hex).unwrap();
    let compressed_hex = "0200222889d197dbfddc011bba8725c753b3caf8cb85b2a03b4f8d92cf5606e81208d717f068b8476ffe1f9c2e0443fc55030605000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let compressed =
        CompressedQuadraticForm::deserialize(&hex::decode(compressed_hex).unwrap(), &discriminant)
            .unwrap();
    let decompressed = compressed.decompress().unwrap();
    let recompressed = decompressed.compress();
    assert_eq!(compressed, recompressed);
}

#[test]
fn test_serialize_deserialize() {
    let discriminant_hex = "d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf";
    let discriminant = -BigInt::from_hex(discriminant_hex).unwrap();
    let compressed_hex = "010083b82ff747c385b0e2ff91ef1bea77d3d70b74322db1cd405e457aefece6ff23961c1243f1ed69e15efd232397e467200100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let compressed_bytes = hex::decode(compressed_hex).unwrap();
    let compressed =
        CompressedQuadraticForm::deserialize(&compressed_bytes, &discriminant).unwrap();
    let serialized = compressed.serialize().unwrap();
    assert_eq!(serialized.to_vec(), compressed_bytes);

    let mut generator_serialized = [0u8; COMPRESSED_SIZE];
    generator_serialized[0] = 0x08;
    assert_eq!(
        QuadraticForm::generator(&discriminant)
            .compress()
            .serialize()
            .unwrap(),
        generator_serialized
    );
    assert_eq!(
        QuadraticForm::generator(&discriminant),
        CompressedQuadraticForm::deserialize(&generator_serialized, &discriminant)
            .unwrap()
            .decompress()
            .unwrap()
    );

    let mut identity_serialized = [0u8; COMPRESSED_SIZE];
    identity_serialized[0] = 0x04;
    assert_eq!(
        QuadraticForm::identity(&discriminant)
            .compress()
            .serialize()
            .unwrap(),
        identity_serialized
    );
    assert_eq!(
        QuadraticForm::identity(&discriminant),
        CompressedQuadraticForm::deserialize(&identity_serialized, &discriminant)
            .unwrap()
            .decompress()
            .unwrap()
    );
}
