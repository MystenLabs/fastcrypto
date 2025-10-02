// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use crate::threshold_schnorr::S;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use itertools::Itertools;

/// Decoder for Reed-Solomon codes.
/// This can correct up to (d-1)/2 errors, where d is the distance of the code.
/// The code is defined by the evaluation points `a` and the message length `k`.
/// The distance is given by `n - k + 1`, where `n` is the length of `a`.
///
/// The implementation follows the Gao decoding algorithm (see https://www.math.clemson.edu/~sgao/papers/RS.pdf).
pub struct RSDecoder {
    g0: Poly<S>,
    a: Vec<ShareIndex>,
    k: usize,
}

impl RSDecoder {
    /// Create a new Gao decoder with the given evaluation points `a` and message length `k`.
    pub fn new(a: Vec<ShareIndex>, k: usize) -> Self {
        assert!(k < a.len(), "Message length must be less than block length");
        let g0 = a
            .iter()
            .map(|ai| S::from(ai.get() as u128))
            .fold(Poly::one(), |acc, ai| {
                &acc * &Poly::from(vec![-ai, S::generator()])
            });
        Self { g0, a, k }
    }

    /// The length of the code words.
    fn block_length(&self) -> usize {
        self.a.len()
    }

    /// The length of the messages.
    fn message_length(&self) -> usize {
        self.k
    }

    /// The distance of the code.
    fn distance(&self) -> usize {
        self.block_length() - self.message_length() + 1
    }

    /// Compute the message polynomial.
    /// Returns an error if the input length is wrong or if there are too many errors to correct.
    pub fn compute_message_polynomial(&self, code_word: &[S]) -> FastCryptoResult<Poly<S>> {
        // The implementation follows Algorithm 1 in Gao's paper.

        if code_word.len() != self.block_length() {
            return Err(FastCryptoError::InputLengthWrong(self.block_length()));
        }

        // Step 1: Interpolation
        let g1 = Poly::interpolate(
            &self
                .a
                .iter()
                .zip(code_word)
                .map(|(index, value)| Eval {
                    index: *index,
                    value: *value,
                })
                .collect_vec(),
        )?;

        // Step 2: Partial GCD
        let (g, _, v) = Poly::partial_extended_gcd(
            &self.g0,
            &g1,
            (self.message_length() + self.block_length()) / 2,
        )?;

        // Step 3: Long division
        let (f1, r) = g.div_rem(&v)?;
        if !r.is_zero() || f1.degree() >= self.k {
            return Err(FastCryptoError::TooManyErrors((self.distance() - 1) / 2));
        }
        Ok(f1)
    }

    /// Encode the message using the Reed-Solomon code defined by the evaluation points `a`.
    /// Returns an error if the message length is wrong.
    #[cfg(test)]
    fn encode(&self, message: Vec<S>) -> FastCryptoResult<Vec<S>> {
        if message.len() != self.message_length() {
            return Err(FastCryptoError::InputLengthWrong(self.message_length()));
        }
        let f = Poly::from(message);
        Ok(self.a.iter().map(|ai| f.eval(*ai).value).collect_vec())
    }

    /// Try to correct the input and return the decoded message.
    /// Returns an error if the input length is wrong or if there are too many errors to correct.
    pub fn decode(&self, input: &[S]) -> FastCryptoResult<Vec<S>> {
        let mut f1 = self.compute_message_polynomial(input)?.as_vec().clone();
        f1.resize(self.k, S::zero());
        Ok(f1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gao_decoder() {
        let a = (1..=7).map(|i| ShareIndex::new(i).unwrap()).collect_vec();
        let k = 3;
        let decoder = RSDecoder::new(a.clone(), k);

        let message = vec![S::from(11u128), S::from(22u128), S::from(33u128)];
        let code_word = decoder.encode(message.clone()).unwrap();

        // Introduce errors
        let mut received = code_word.clone();
        received[4] = S::from(20u128); // Error at position 4
        received[2] = S::from(200u128); // Error at position 2

        let decoded_message = decoder.decode(&received).unwrap();
        assert_eq!(decoded_message, message);

        // Test with too many errors
        let mut received = code_word.clone();
        received[4] = S::from(20u128); // Error at position 4
        received[3] = S::from(2000u128); // Error at position 3
        received[2] = S::from(200u128); // Error at position 2
        assert!(decoder.decode(&received).is_err());
    }
}
