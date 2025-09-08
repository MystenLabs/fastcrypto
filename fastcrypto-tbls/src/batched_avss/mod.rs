// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1::MultiRecipientEncryption;
use crate::polynomial::Poly;
use fastcrypto::error::FastCryptoError::{InputTooLong, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;

#[cfg(test)]
mod tests;

pub mod avss;
pub mod dkg;

#[derive(Clone, Debug)]
pub struct Nonces<T: Clone>(Vec<T>);

impl<T: Scalar> Nonces<T> {
    fn len(&self) -> u16 {
        self.0.len() as u16
    }

    /// Create nonces from given vector.
    fn given(nonces: Vec<T>) -> FastCryptoResult<Self> {
        if nonces.len() > u16::MAX as usize {
            return Err(InputTooLong(u16::MAX as usize));
        }
        Ok(Nonces(nonces))
    }

    /// Sample n random nonces.
    fn random(n: u16, rng: &mut impl AllowedRng) -> Self {
        Nonces((0..n).map(|_| T::rand(rng)).collect())
    }

    fn polynomials(&self, degree: u16, rng: &mut impl AllowedRng) -> Vec<Poly<T>> {
        self.0
            .iter()
            .map(|c0| Poly::rand_fixed_c0(degree, *c0, rng))
            .collect()
    }
}
