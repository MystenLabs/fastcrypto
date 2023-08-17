// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Functionality to compress/decompress and serialize/deserialize quadratic forms.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::class_group::compressed::CompressedQuadraticForm::{
    Generator, Nontrivial, Zero,
};
use crate::groups::class_group::{Discriminant, QuadraticForm, QUADRATIC_FORM_SIZE_IN_BYTES};
use crate::groups::ParameterizedGroupElement;
use num_bigint::{BigInt, Sign};
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Signed, Zero as OtherZero};
use std::cmp::Ordering;
use std::ops::Mul;

/// A quadratic form in compressed representation. See https://eprint.iacr.org/2020/196.pdf.
#[derive(PartialEq, Eq, Debug)]
enum CompressedQuadraticForm {
    Zero(Discriminant),
    Generator(Discriminant),
    Nontrivial(CompressedFormat),
}

#[derive(PartialEq, Eq, Debug)]
struct CompressedFormat {
    a_prime: BigInt,
    t_prime: BigInt,
    g: BigInt,
    b0: BigInt,
    b_sign: bool,
    discriminant: Discriminant,
}

impl QuadraticForm {
    /// Serialize a quadratic form. The format follows that of chiavdf (see https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/bqfc.c#L222-L245)
    /// and the result will be exactly [`QUADRATIC_FORM_SIZE_IN_BYTES`] bytes long.
    pub(super) fn serialize(&self) -> [u8; QUADRATIC_FORM_SIZE_IN_BYTES] {
        self.compress().serialize()
    }

    /// Deserialize bytes into a quadratic form. The format follows that of chiavdf (see https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/bqfc.c#L258-L287)
    /// and the bytes array must be exactly [`QUADRATIC_FORM_SIZE_IN_BYTES`] bytes long.
    pub fn from_bytes(bytes: &[u8], discriminant: &Discriminant) -> FastCryptoResult<Self> {
        CompressedQuadraticForm::deserialize(bytes, discriminant)?.decompress()
    }

    /// Return a compressed representation of this quadratic form. See https://eprint.iacr.org/2020/196.pdf for a definition of the compression.
    fn compress(&self) -> CompressedQuadraticForm {
        // This implementation follows https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/bqfc.c#L6-L50.

        let Self {
            a,
            b,
            c: _,
            partial_gcd_limit: _,
        } = &self;

        if a == &BigInt::one() && b == &BigInt::one() {
            return Zero(self.discriminant());
        } else if a == &BigInt::from(2) && b == &BigInt::one() {
            return Generator(self.discriminant());
        }

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

        let b_sign = b < &BigInt::zero();
        let b_abs = b.abs();

        let (_, mut t_prime) = partial_xgcd(a, &b_abs).expect("a must be positive and b non-zero");
        let g = a.gcd(&t_prime);

        let mut b0: BigInt;
        let a_prime;

        if g.is_one() {
            b0 = BigInt::zero();
            a_prime = a.clone();
        } else {
            a_prime = a / &g;
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

impl CompressedQuadraticForm {
    /// Return this as an uncompressed QuadraticForm. See https://eprint.iacr.org/2020/196.pdf for a definition of the compression.
    fn decompress(&self) -> FastCryptoResult<QuadraticForm> {
        // This implementation follows https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/bqfc.c#L52-L116.
        match self {
            Zero(discriminant) => Ok(QuadraticForm::zero(discriminant)),
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

                let t = if t_prime < &BigInt::zero() {
                    t_prime + a_prime
                } else {
                    t_prime.clone()
                };

                let d_mod_a = discriminant.0.mod_floor(a_prime);
                let sqrt_input = t
                    .modpow(&BigInt::from(2), a_prime)
                    .mul(&d_mod_a)
                    .mod_floor(a_prime);
                let sqrt = sqrt_input.sqrt();

                // Ensure square root is exact
                if sqrt.pow(2) != sqrt_input {
                    return Err(FastCryptoError::InvalidInput);
                }

                let out_a = if !g.is_one() {
                    a_prime * g
                } else {
                    a_prime.clone()
                };

                let t_inv = mod_inverse(&t, a_prime)?;
                let mut out_b = sqrt.mul(&t_inv).mod_floor(a_prime);
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
    fn serialize(&self) -> [u8; QUADRATIC_FORM_SIZE_IN_BYTES] {
        // This implementation follows https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/bqfc.c#L222-L245.
        match self {
            Zero(_) => {
                let mut bytes = [0u8; QUADRATIC_FORM_SIZE_IN_BYTES];
                bytes[0] = 0x04;
                bytes
            }
            Generator(_) => {
                let mut bytes = [0u8; QUADRATIC_FORM_SIZE_IN_BYTES];
                bytes[0] = 0x08;
                bytes
            }
            Nontrivial(form) => {
                let mut bytes = vec![];
                bytes.push(form.b_sign as u8);
                bytes[0] |= ((form.t_prime < BigInt::zero()) as u8) << 1;

                // The bit length of the discriminant, which is rounded up to the next multiple of 32.
                // Serialization of special forms (identity or generator) takes only 1 byte.
                let d_bits = (form.discriminant.0.bits() as usize + 31) & !31;

                // Size of g in bytes minus 1 (g_size)
                let g_size = (form.g.bits() as usize + 7) / 8 - 1;
                bytes.push(g_size as u8);

                let a_prime_length = d_bits / 16 - g_size;
                let t_prime_length = d_bits / 32 - g_size;
                let g_length = g_size + 1;
                let b0_length = g_size + 1;

                bytes.extend_from_slice(
                    &export_to_size(&form.a_prime, a_prime_length)
                        .expect("The size bound on the discriminant ensures that this is true"),
                );
                bytes.extend_from_slice(
                    &export_to_size(&form.t_prime, t_prime_length)
                        .expect("The size bound on the discriminant ensures that this is true"),
                );
                bytes.extend_from_slice(
                    &export_to_size(&form.g, g_length)
                        .expect("The size bound on the discriminant ensures that this is true"),
                );
                bytes.extend_from_slice(
                    &export_to_size(&form.b0, b0_length)
                        .expect("The size bound on the discriminant ensures that this is true"),
                );
                bytes.extend_from_slice(&vec![0u8; QUADRATIC_FORM_SIZE_IN_BYTES - bytes.len()]);

                bytes
                    .try_into()
                    .expect("The size bound on the discriminant ensures that this is true")
            }
        }
    }

    /// Deserialize a compressed binary form according to the format defined in the chiavdf library.
    fn deserialize(bytes: &[u8], discriminant: &Discriminant) -> FastCryptoResult<Self> {
        // This implementation follows https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/bqfc.c#L258-L287.
        if bytes.len() != QUADRATIC_FORM_SIZE_IN_BYTES {
            return Err(FastCryptoError::InputLengthWrong(
                QUADRATIC_FORM_SIZE_IN_BYTES,
            ));
        }

        let is_identity = bytes[0] & 0x04 != 0;
        if is_identity {
            return Ok(Zero(discriminant.clone()));
        }

        let is_generator = bytes[0] & 0x08 != 0;
        if is_generator {
            return Ok(Generator(discriminant.clone()));
        }

        // The bit length of the discriminant, which is rounded up to the next multiple of 32.
        // Serialization of special forms (identity or generator) takes only 1 byte.
        let d_bits = (discriminant.0.bits() as usize + 31) & !31;

        // Size of g in bytes minus 1 (g_size)
        let g_size = bytes[1] as usize;
        if g_size >= d_bits / 32 {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut offset = 2;
        let a_prime_length = d_bits / 16 - g_size;
        let t_prime_length = d_bits / 32 - g_size;
        let g_length = g_size + 1;
        let b0_length = g_size + 1;

        // a' = a / g
        let a_prime = bigint_from_bytes(&bytes[offset..offset + a_prime_length]);
        offset += a_prime_length;

        // t' = t / g, where t satisfies (a*x + b*t < sqrt(a))
        let mut t_prime = bigint_from_bytes(&bytes[offset..offset + t_prime_length]);
        let t_sign = bytes[0] & 0x02 != 0;
        if t_sign {
            t_prime = -t_prime;
        }
        offset += t_prime_length;

        // g = gcd(a, t)
        let g = bigint_from_bytes(&bytes[offset..offset + g_length]);
        offset += g_length;

        // b0 = b / a'
        let b0 = bigint_from_bytes(&bytes[offset..offset + b0_length]);
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

/// Return the modular inverse of a modulo m or an error if a is not invertible modulo m.
fn mod_inverse(a: &BigInt, m: &BigInt) -> FastCryptoResult<BigInt> {
    if m <= &BigInt::one() || a.is_zero() {
        return Err(FastCryptoError::InvalidInput);
    }

    let ExtendedGcd::<BigInt> { gcd, x, y: _ } = a.extended_gcd(m);

    if !gcd.is_one() {
        return Err(FastCryptoError::InvalidInput);
    }
    Ok(x.mod_floor(m))
}

/// Import function for BigInts using little-endian representation.
fn bigint_from_bytes(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, bytes)
}

/// Export function for BigInts using little-endian representation.
fn bigint_to_bytes(n: &BigInt) -> Vec<u8> {
    let (_, bytes) = n.to_bytes_le();
    bytes
}

/// Export a curv::BigInt to a byte array of the given size. Zeroes are padded to the end if the number
/// serializes to fewer bits than `target_size`. If the serialization is too large, an error is returned.
fn export_to_size(number: &BigInt, target_size: usize) -> FastCryptoResult<Vec<u8>> {
    let mut bytes = bigint_to_bytes(number);
    match bytes.len().cmp(&target_size) {
        Ordering::Less => {
            bytes.append(&mut vec![0u8; target_size - bytes.len()]);
            Ok(bytes)
        }
        Ordering::Equal => Ok(bytes),
        Ordering::Greater => Err(FastCryptoError::InputTooLong(bytes.len())),
    }
}

/// Takes `a`and `b` and returns `(s, t)` such that `s = b t (mod a)` with `0 <= s < sqrt(a) and |t|
/// <= sqrt(a)`. This is algorithm 1 from https://arxiv.org/pdf/2211.16128.pdf.
fn partial_xgcd(a: &BigInt, b: &BigInt) -> FastCryptoResult<(BigInt, BigInt)> {
    if a <= b {
        let (s, t) = partial_xgcd(b, a)?;
        return Ok((t, s));
    }

    if b <= &BigInt::zero() {
        return Err(FastCryptoError::InvalidInput);
    }

    let mut s = (b.clone(), a.clone());
    let mut t = (BigInt::one(), BigInt::zero());

    while s.0 >= a.sqrt() {
        let q = s.1.div_floor(&s.0);

        let s_tmp = &s.1 - &q * &s.0;
        s.1 = s.0;
        s.0 = s_tmp;

        let t_tmp = &t.1 - &q * &t.0;
        t.1 = t.0;
        t.0 = t_tmp;
    }

    Ok((s.0, t.0))
}

#[cfg(test)]
mod tests {
    use crate::groups::class_group::compressed::{
        bigint_from_bytes, bigint_to_bytes, CompressedQuadraticForm,
    };
    use crate::groups::class_group::{Discriminant, QuadraticForm, QUADRATIC_FORM_SIZE_IN_BYTES};
    use crate::groups::ParameterizedGroupElement;
    use num_bigint::BigInt;
    use num_traits::Num;

    #[test]
    fn test_bigint_import() {
        let bytes = hex::decode("0102").unwrap();
        let bigint = bigint_from_bytes(&bytes);

        // We expect little endian, e.g. 0x02 * 256 + 0x01 = 513.
        let expected = BigInt::from_str_radix("513", 10).unwrap();
        assert_eq!(bigint, expected);

        let reconstructed = bigint_to_bytes(&bigint);
        assert_eq!(bytes, reconstructed);
    }

    #[test]
    fn test_compression() {
        let discriminant_hex = "d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf";
        let discriminant =
            Discriminant::try_from(-BigInt::from_str_radix(discriminant_hex, 16).unwrap()).unwrap();
        let compressed_hex = "0200222889d197dbfddc011bba8725c753b3caf8cb85b2a03b4f8d92cf5606e81208d717f068b8476ffe1f9c2e0443fc55030605000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let compressed = CompressedQuadraticForm::deserialize(
            &hex::decode(compressed_hex).unwrap(),
            &discriminant,
        )
        .unwrap();
        let decompressed = compressed.decompress().unwrap();
        let recompressed = decompressed.compress();
        assert_eq!(compressed, recompressed);
    }

    #[test]
    fn test_serialize_deserialize() {
        let discriminant_hex = "d2b4bc45525b1c2b59e1ad7f81a1003f2f0efdcbc734bf711ebf5599a73577a282af5e8959ffcf3ec8601b601bcd2fa54915823d73130e90cb90fe1c6c7c10bf";
        let discriminant =
            Discriminant::try_from(-BigInt::from_str_radix(discriminant_hex, 16).unwrap()).unwrap();
        let compressed_hex = "010083b82ff747c385b0e2ff91ef1bea77d3d70b74322db1cd405e457aefece6ff23961c1243f1ed69e15efd232397e467200100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let compressed_bytes = hex::decode(compressed_hex).unwrap();
        let compressed =
            CompressedQuadraticForm::deserialize(&compressed_bytes, &discriminant).unwrap();
        let serialized = compressed.serialize();
        assert_eq!(serialized.to_vec(), compressed_bytes);

        let mut generator_serialized = [0u8; QUADRATIC_FORM_SIZE_IN_BYTES];
        generator_serialized[0] = 0x08;
        assert_eq!(
            QuadraticForm::generator(&discriminant)
                .compress()
                .serialize(),
            generator_serialized
        );
        assert_eq!(
            QuadraticForm::generator(&discriminant),
            CompressedQuadraticForm::deserialize(&generator_serialized, &discriminant)
                .unwrap()
                .decompress()
                .unwrap()
        );

        let mut identity_serialized = [0u8; QUADRATIC_FORM_SIZE_IN_BYTES];
        identity_serialized[0] = 0x04;
        assert_eq!(
            QuadraticForm::zero(&discriminant).compress().serialize(),
            identity_serialized
        );
        assert_eq!(
            QuadraticForm::zero(&discriminant),
            CompressedQuadraticForm::deserialize(&identity_serialized, &discriminant)
                .unwrap()
                .decompress()
                .unwrap()
        );
    }
}
