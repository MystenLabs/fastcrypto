// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{math::hash_prime, Parameter, ToBytes};
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use num_bigint::{BigInt, Sign, ToBigInt};
use num_integer::Integer;
use num_traits::Signed;
use std::ops::Neg;

/// A discriminant for an imaginary class group. The discriminant is a negative integer which is
/// equal to 1 mod 8.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Discriminant(BigInt);

impl ToBytes for Discriminant {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_be().1
    }
}

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if !value.is_negative() || value.mod_floor(&BigInt::from(8)) != BigInt::from(1) {
            return Err(InvalidInput);
        }
        Ok(Self(value))
    }
}

impl Discriminant {
    /// Return the number of bits needed to represent this discriminant, not including the sign bit.
    pub fn bits(&self) -> usize {
        self.0.bits() as usize
    }

    /// Try to create a discriminant from a big-endian byte representation of the absolute value.
    /// Fails if the discriminant is not equal to 1 mod 8.
    pub fn try_from_be_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        let discriminant = BigInt::from_bytes_be(Sign::Minus, bytes);
        Self::try_from(discriminant)
    }

    /// Borrow a reference to the underlying big integer.
    pub fn as_bigint(&self) -> &BigInt {
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
