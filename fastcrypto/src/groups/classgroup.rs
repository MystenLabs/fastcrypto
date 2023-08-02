// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::classgroup::CompressedQuadraticForm::{Generator, Identity, Nontrivial};
use ark_ff::{One, Zero};
use class_group::BinaryQF;
use curv::arithmetic::{BitManipulation, Converter, Integer, Modulo, Roots};
use curv::BigInt;
use std::ops::{Add, Mul};

/// The size of a compressed quadratic form in bytes.
pub const COMPRESSED_SIZE: usize = 100;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
///
/// Quadratic forms with the same discriminant (b^2 - 4ac) form a group which is a representation of
/// the ideal class group for an imaginary number field. See e.g. Henri Cohen (2010), "A Course in
/// Computational Algebraic Number Theory" for more details.
#[derive(PartialEq, Eq, Debug)]
pub struct QuadraticForm(BinaryQF);

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
    /// Create a new quadratic form given only the a and b coordinate and the discriminant.
    pub fn from_a_b_discriminant(a: BigInt, b: BigInt, discriminant: &BigInt) -> Self {
        let c = ((&b * &b) - discriminant) / (BigInt::from(4) * &a);
        Self(BinaryQF { a, b, c })
    }

    /// Return the identity element in a class group with a given discriminant, eg. (1, 1, X) where
    /// X is determined from the discriminant.
    pub fn zero(discriminant: &BigInt) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class group
    /// with a given discriminant. We use the element (2, 1, X) where X is determined from the discriminant.
    pub fn generator(discriminant: &BigInt) -> Self {
        Self::from_a_b_discriminant(BigInt::from(2), BigInt::one(), discriminant)
    }
}

/// A quadratic form in compressed representation. See https://eprint.iacr.org/2020/196.pdf.
pub enum CompressedQuadraticForm {
    Identity(BigInt),
    Generator(BigInt),
    Nontrivial(CompressedFormat),
}

#[derive(Debug)]
pub struct CompressedFormat {
    a_prime: BigInt,
    t_prime: BigInt,
    g: BigInt,
    b0: BigInt,
    b_sign: bool,
    discriminant: BigInt,
}

impl CompressedQuadraticForm {
    /// Return the discriminant of this form.
    pub fn discriminant(&self) -> &BigInt {
        match self {
            Identity(discriminant) => discriminant,
            Generator(discriminant) => discriminant,
            Nontrivial(form) => &form.discriminant,
        }
    }

    /// Return this as a QuadraticForm.
    pub fn decompress(&self) -> FastCryptoResult<QuadraticForm> {
        match self {
            Identity(discriminant) => Ok(QuadraticForm::zero(&discriminant)),
            Generator(discriminant) => Ok(QuadraticForm::generator(&discriminant)),
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
                        &discriminant,
                    ));
                }

                let mut t = t_prime.clone();
                if t < BigInt::zero() {
                    t += a_prime;
                }

                if a_prime.is_zero() {
                    return Err(FastCryptoError::InvalidInput);
                }

                let mut t_inv =
                    BigInt::mod_inv(&t, a_prime).ok_or(FastCryptoError::InvalidInput)?;
                if t_inv < BigInt::zero() {
                    t_inv += a_prime;
                }

                let d = discriminant.modulus(a_prime);
                let tmp_debug = (&t * &t * &d).modulus(a_prime);
                let tmp = tmp_debug.sqrt();
                assert_eq!(&tmp * &tmp, tmp_debug); // This fails, meaning that a_prime and/or t are wrong at this point

                let mut out_a = a_prime.clone();
                if *g != BigInt::one() {
                    out_a = a_prime * g;
                }

                let mut out_b = (tmp * t_inv).mod_floor(a_prime);
                if b0 > &BigInt::zero() {
                    out_b += a_prime * b0;
                }

                if *b_sign {
                    out_b = -out_b;
                }

                Ok(QuadraticForm::from_a_b_discriminant(
                    out_a,
                    out_b,
                    &discriminant,
                ))
            }
        }
    }

    /// Serialize a compressed binary form according to the format defined in the chiavdf library.
    pub fn serialize(&self) -> FastCryptoResult<[u8; COMPRESSED_SIZE]> {
        match self {
            Identity(_) => todo!(),
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
    pub(crate) fn deserialize(bytes: &[u8], discriminant: &BigInt) -> FastCryptoResult<Self> {
        if bytes.len() != COMPRESSED_SIZE {
            return Err(FastCryptoError::InputLengthWrong(COMPRESSED_SIZE));
        }

        let is_identity = bytes[0] & 0x04 != 0;
        let is_generator = bytes[0] & 0x08 != 0;

        if is_identity {
            return Ok(Identity(discriminant.clone()));
        } else if is_generator {
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

        return Ok(Nontrivial(CompressedFormat {
            a_prime,
            t_prime,
            g,
            b0,
            b_sign,
            discriminant: discriminant.clone(),
        }));
    }
}

/// Import function for curv::BigInt aligned with chiavdf.
pub(crate) fn bigint_import(bytes: &[u8]) -> BigInt {
    // TODO: The copying done in to_vec is not really needed
    let mut reversed = bytes.to_vec();
    reversed.reverse();
    BigInt::from_bytes(&reversed)
}

/// Export function for curv::BigInt aligned with chiavdf.
pub(crate) fn bigint_export(n: &BigInt) -> Vec<u8> {
    let mut bytes = n.to_bytes();
    bytes.reverse();
    bytes
}

/// Export a curv::BigInt to a byte array of the given size. If the number is too large, an error is returned.
fn export_to_size(number: &BigInt, target_size: usize) -> FastCryptoResult<Vec<u8>> {
    let mut bytes = bigint_export(&number);
    if bytes.len() > target_size {
        return Err(FastCryptoError::InputTooLong(bytes.len()));
    } else if bytes.len() < target_size {
        let mut new_bytes = vec![0u8; target_size - bytes.len()];
        new_bytes.append(&mut bytes);
        bytes = new_bytes;
    }
    Ok(bytes)
}
