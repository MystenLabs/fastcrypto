// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::hash_prime;
use crate::math::parameterized_group::Parameter;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use num_bigint::{BigInt, ToBigInt};
use num_integer::Integer;
use num_traits::Signed;
use serde::Deserializer;
use serde::{Deserialize, Serialize};
use std::ops::Neg;

/// A discriminant for an imaginary class group. The discriminant is a negative integer congruent to
/// 1 mod 8.
#[derive(PartialEq, Eq, Debug, Clone, Serialize)]
pub struct Discriminant(#[serde(with = "crate::class_group::bigint_serde")] BigInt);

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    /// A valid discriminant should be a negative prime congruent to 1 mod 8. The primality is _not_
    /// checked.
    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if !value.is_negative() || value.mod_floor(&BigInt::from(8)) != BigInt::from(1) {
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
}

impl Parameter for Discriminant {
    /// Compute a valid discriminant (aka a negative prime equal to 1 mod 8) based on the given seed.
    /// The size_in_bits must be divisible by 8.
    fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Discriminant> {
        if size_in_bits % 8 != 0 {
            return Err(InvalidInput);
        }
        // Set the lower three bits to ensure that the prime is 7 mod 8 which makes the discriminant 1 mod 8.
        Self::try_from(
            hash_prime::hash_prime_default(seed, size_in_bits / 8, &[0, 1, 2, size_in_bits - 1])
                .to_bigint()
                .expect("Never fails")
                .neg(),
        )
    }
}

impl<'de> Deserialize<'de> for Discriminant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(crate::class_group::bigint_serde::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminant() {
        let discriminant = Discriminant::try_from(-BigInt::from(223)).unwrap();
        assert_eq!(discriminant.bits(), 8);
        assert_eq!(discriminant.as_bigint(), &-BigInt::from(223));

        // Invalid modulus
        let candidate = BigInt::from(-29);
        assert!(candidate.is_negative());
        assert!(Discriminant::try_from(candidate).is_err());

        // Invalid sign
        let candidate = BigInt::from(17);
        assert!(candidate.mod_floor(&BigInt::from(8)) == BigInt::from(1));
        assert!(Discriminant::try_from(candidate).is_err());
    }

    #[test]
    fn test_discriminant_from_seed() {
        let seed = [1, 2, 3];
        let target_size = 512;
        let discriminant = Discriminant::from_seed(&seed, target_size).unwrap();
        assert_eq!(discriminant.bits() as usize, target_size);
    }

    #[test]
    fn test_discriminant_to_from_bytes() {
        let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
        let bytes = bcs::to_bytes(&discriminant).unwrap();
        let discriminant2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, discriminant2);

        let discriminant = Discriminant::from_seed(&[0x01, 0x02, 0x03], 512).unwrap();
        let bytes = bcs::to_bytes(&discriminant).unwrap();
        let discriminant2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, discriminant2);
    }
}
