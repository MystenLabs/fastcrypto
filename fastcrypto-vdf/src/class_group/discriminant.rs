// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::bigint_serde;
use crate::math::hash_prime;
use crate::math::hash_prime::is_probable_prime;
use crate::math::parameterized_group::Parameter;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use num_bigint::{BigInt, ToBigInt};
use num_integer::Integer;
use num_traits::Signed;
use serde::{Deserialize, Serialize};
use std::ops::Neg;

/// A discriminant for an imaginary class group. The discriminant is a negative integer congruent to
/// 1 mod 8.
#[derive(PartialEq, Eq, Debug, Clone, Serialize)]
pub struct Discriminant(#[serde(with = "crate::class_group::bigint_serde")] pub(crate) BigInt);

impl<'de> Deserialize<'de> for Discriminant {
    fn deserialize<D>(deserializer: D) -> Result<Discriminant, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Discriminant::try_from(bigint_serde::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    /// A valid discriminant should be a negative prime congruent to 1 mod 8. For large discriminants,
    /// this is very slow.
    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if !value.is_negative()
            || value.mod_floor(&BigInt::from(8)) != BigInt::from(1)
            || !is_probable_prime(value.abs().magnitude())
        {
            return Err(InvalidInput);
        }
        Ok(Self(value))
    }
}

impl Discriminant {
    /// Return the number of bits needed to represent this discriminant, not including the sign bit.
    pub fn bits(&self) -> u64 {
        self.0.bits()
    }

    /// Borrow a reference to the underlying big integer.
    pub(crate) fn as_bigint(&self) -> &BigInt {
        &self.0
    }

    /// Create a discriminant from the given bytes. The bytes must be an BCS encoding of the
    /// twos-complement big-endian encoding of the discriminant. Returns an error if the encoding is
    /// invalid.
    ///
    /// It is assumed that the discriminant is a negative prime which is 1 mod 8. If this is not the
    /// case, some functions may panic.
    ///
    /// To validate the input, use deserialization or `try_from` instead.
    pub fn from_trusted_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        let discriminant_bytes: Vec<u8> = bcs::from_bytes(bytes).map_err(|_| InvalidInput)?;
        Ok(Self(BigInt::from_signed_bytes_be(&discriminant_bytes)))
    }

    /// Create a discriminant from the given value. It is assumed that the discriminant is a negative
    /// prime which is 1 mod 8. If this is not the case, some functions may panic.
    ///
    /// To validate the input, use deserialization or `try_from` instead.
    pub fn from_trusted_bigint(value: BigInt) -> Self {
        Self(value)
    }
}

impl Parameter for Discriminant {
    /// Compute a valid discriminant (aka a negative prime equal to 1 mod 8) based on the given seed.
    /// The size_in_bits must be divisible by 8.
    fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Discriminant> {
        if size_in_bits % 8 != 0 {
            return Err(InvalidInput);
        }
        // Set the lower three bits to ensure that the prime is 7 mod 8 which makes the discriminant 1 mod 8.
        Ok(Self(
            hash_prime::hash_prime(seed, size_in_bits / 8, &[0, 1, 2, size_in_bits - 1])
                .to_bigint()
                .expect("Never fails")
                .neg(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminant() {
        let discriminant = Discriminant(-BigInt::from(223));
        assert_eq!(discriminant.bits(), 8);
        assert_eq!(discriminant.as_bigint(), &-BigInt::from(223));

        // Invalid modulus
        let candidate = BigInt::from(-29);
        assert!(candidate.is_negative());
        assert!(Discriminant::try_from(candidate).is_err());

        // Invalid sign
        let candidate = BigInt::from(17);
        assert_eq!(candidate.mod_floor(&BigInt::from(8)), BigInt::from(1));
        assert!(Discriminant::try_from(candidate).is_err());

        // Not prime
        let candidate = BigInt::from(-231);
        assert!(Discriminant::try_from(candidate).is_err());
    }

    #[test]
    fn test_discriminant_from_seed() {
        let seed = hex::decode("d911a54e3bf6f52b4111").unwrap();
        let target_size = 1024;
        let discriminant = Discriminant::from_seed(&seed, target_size).unwrap();
        assert_eq!(discriminant.bits() as usize, target_size);

        // Test vector from chiavdf computed using https://github.com/Chia-Network/chiavdf/blob/2844974ff81274060778a56dfefd2515bc567b90/tests/test_verifier.py.
        assert_eq!(discriminant.as_bigint().to_str_radix(16), "-95a0b0523b6c516e813d745e7e58b3c7223d511f6008a0ff2757c9a0f15cba8841293cc903af3a40654670c9dee17ec14da1457360aafe40a93831d90c3dd59738d8a24e415b6e33780224fa24171de1d4a1ca5fe4c877bf44361e7ba869126ac12367714eb4246a5e310515508ad35e170aee19cae371069d6d92e94c21d63f");
    }

    #[test]
    fn test_discriminant_to_from_bytes() {
        let discriminant = Discriminant(BigInt::from(-223));
        let bytes = bcs::to_bytes(&discriminant).unwrap();
        let discriminant2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, discriminant2);

        let discriminant = Discriminant::from_seed(&[0x01, 0x02, 0x03], 512).unwrap();
        let bytes = bcs::to_bytes(&discriminant).unwrap();
        let discriminant2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, discriminant2);

        // Test serde on invalid discriminants
        let invalid_discriminant_bytes =
            bcs::to_bytes(&BigInt::from(-221).to_signed_bytes_be()).unwrap();
        assert!(bcs::from_bytes::<Discriminant>(&invalid_discriminant_bytes).is_err());
        assert!(Discriminant::from_trusted_bytes(&invalid_discriminant_bytes).is_ok());

        let invalid_discriminant_bytes =
            bcs::to_bytes(&BigInt::from(17).to_signed_bytes_be()).unwrap();
        assert!(bcs::from_bytes::<Discriminant>(&invalid_discriminant_bytes).is_err());
        assert!(Discriminant::from_trusted_bytes(&invalid_discriminant_bytes).is_ok());
    }
}
