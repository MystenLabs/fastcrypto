// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{math::hash_prime, Parameter};
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
#[serde(transparent)]
pub struct Discriminant(BigInt);

fn validate(discriminant: &BigInt) -> FastCryptoResult<()> {
    if !discriminant.is_negative() || discriminant.mod_floor(&BigInt::from(8)) != BigInt::from(1) {
        return Err(InvalidInput);
    }
    Ok(())
}

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        validate(&value)?;
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
        let value = BigInt::deserialize(deserializer)?;
        validate(&value).map_err(serde::de::Error::custom)?;
        Ok(Discriminant(value))
    }
}
