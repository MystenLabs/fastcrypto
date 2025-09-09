// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::Poly;
use fastcrypto::error::FastCryptoError::InputTooLong;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Scalar;
use fastcrypto::traits::AllowedRng;

pub mod avss;
pub mod dkg;

#[derive(Clone, Debug)]
pub struct Nonces<T: Clone>(Vec<T>);

impl<T: Scalar> Nonces<T> {
    /// Create nonces from given vector.
    pub fn given(nonces: Vec<T>) -> FastCryptoResult<Self> {
        if nonces.len() > u16::MAX as usize {
            return Err(InputTooLong(u16::MAX as usize));
        }
        Ok(Nonces(nonces))
    }

    /// Sample n random nonces.
    pub fn random(n: u16, rng: &mut impl AllowedRng) -> Self {
        Nonces((0..n).map(|_| T::rand(rng)).collect())
    }

    pub(crate) fn polynomials(&self, degree: u16, rng: &mut impl AllowedRng) -> Vec<Poly<T>> {
        self.0
            .iter()
            .map(|c0| Poly::rand_fixed_c0(degree, *c0, rng))
            .collect()
    }
}
