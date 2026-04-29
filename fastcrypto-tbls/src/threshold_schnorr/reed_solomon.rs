// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, MonicLinear, Poly};
use crate::threshold_schnorr::S;
use crate::types::{to_scalar, ShareIndex};
use fastcrypto::error::FastCryptoError::{InputLengthWrong, InvalidInput, TooManyErrors};
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;
use reed_solomon_erasure::galois_8::ReedSolomon;

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
        let mut g0 = Poly::one();
        for ai in &a {
            g0 *= MonicLinear(-to_scalar::<S>(ai));
        }
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
            return Err(InputLengthWrong(self.block_length()));
        }

        // Step 1: Interpolation
        let g1 = Poly::interpolate(
            &self
                .a
                .iter()
                .zip(code_word)
                .map(|(&index, &value)| Eval { index, value })
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
            return Err(TooManyErrors((self.distance() - 1) / 2));
        }
        Ok(f1)
    }

    /// Encode the message using the Reed-Solomon code defined by the evaluation points `a`.
    /// Returns an error if the message length is wrong.
    pub fn encode(&self, message: Vec<S>) -> FastCryptoResult<Vec<S>> {
        if message.len() != self.message_length() {
            return Err(InputLengthWrong(self.message_length()));
        }
        let f = Poly::from(message);
        Ok(self.a.iter().map(|&ai| f.eval(ai).value).collect_vec())
    }

    /// Try to correct the input and return the decoded message.
    /// Returns an error if the input length is wrong or if there are too many errors to correct.
    pub fn decode(&self, input: &[S]) -> FastCryptoResult<Vec<S>> {
        let mut f1 = self.compute_message_polynomial(input)?.to_vec();
        f1.truncate(self.k);
        Ok(f1)
    }

    /// Create a new decoder that can correct the given erasures.
    /// Returns an InvalidInput error if the given erasures are not unique or not a subset of self.a.
    pub fn with_erasures(&self, erasures: &[ShareIndex]) -> FastCryptoResult<RSDecoder> {
        // This follows section 4 in Gao's paper
        let erasures = erasures.iter().sorted().collect_vec();
        let a = self
            .a
            .iter()
            .filter(|ai| erasures.binary_search(ai).is_err())
            .cloned()
            .collect_vec();

        // Check if the erasures is a subset of a, e.g., that we have removed one a_i per erasure.
        if a.len() + erasures.len() != self.block_length() {
            return Err(InvalidInput);
        }

        let g0 = erasures.iter().fold(self.g0.clone(), |g0, ai| {
            &g0 / MonicLinear(-to_scalar::<S>(*ai))
        });

        Ok(RSDecoder { g0, a, k: self.k })
    }
}

/// A wrapper struct for the Reed-Solomon erasure coding library.
pub struct RSErasure(ReedSolomon);

impl RSErasure {
    /// Create a new Reed-Solomon erasure encoder/decoder.
    ///
    /// # Parameters
    /// - `k`: Number of **data** shards (sometimes called the message length).
    /// - `n`: Total number of shards, i.e. `k + (n-k)` where `n-k` are parity shards.
    ///
    /// # Errors
    /// Returns [`FastCryptoError::InvalidInput`] if `k == 0`, `n <= k` or `n > 256`.
    pub fn new(k: usize, n: usize) -> FastCryptoResult<Self> {
        // `reed_solomon_erasure::galois_8` only supports up to 256 total shards.
        if k == 0 || n <= k || n > 256 {
            return Err(InvalidInput);
        }
        ReedSolomon::new(k, n - k)
            .map_err(|_| InvalidInput)
            .map(Self)
    }

    /// Encode data shards into a full set of `n` shards (data + parity).
    ///
    /// The input must contain exactly `k` data shards. This function will append `n-k`
    /// parity shards and return the full vector.
    ///
    /// All shards must have the same length (as required by `reed_solomon_erasure`).
    ///
    /// Returns [`FastCryptoError::InvalidInput`] if encoding fails (for example if shard
    /// sizes are inconsistent).
    pub fn encode(&self, data: Vec<Vec<u8>>) -> FastCryptoResult<Vec<Vec<u8>>> {
        if data.len() != self.0.data_shard_count() {
            return Err(InputLengthWrong(self.0.data_shard_count()));
        }

        // `reed_solomon_erasure` requires all shards to have the same size, including parity.
        let shard_len = data.first().map(|s| s.len()).unwrap_or(0);
        if !data.iter().all(|s| s.len() == shard_len) {
            return Err(InvalidInput);
        }

        let mut shards = data;
        shards.resize(self.0.total_shard_count(), vec![0u8; shard_len]);
        self.0.encode(&mut shards).map_err(|_| InvalidInput)?;
        Ok(shards)
    }

    /// Reconstruct missing shards from a mix of present and absent shards.
    ///
    /// The input is a vector of length `n` where each entry is either `Some(shard)` if that
    /// shard is available, or `None` if it is missing. If enough shards are present (at least
    /// `k`), the missing shards will be reconstructed.
    ///
    /// The returned value contains all shards (data + parity) in index order.
    ///
    /// # Errors
    /// - Returns [`FastCryptoError::InvalidInput`] if reconstruction fails (inconsistent shard sizes, wrong number of shards).
    /// - Returns [`FastCryptoError::TooManyErrors`] if reconstruction succeeds, but the reconstructed set does not verify.
    pub fn reconstruct(&self, shards: Vec<Option<Vec<u8>>>) -> FastCryptoResult<Vec<Vec<u8>>> {
        let mut shards = shards;
        self.0.reconstruct(&mut shards).map_err(|_| InvalidInput)?;

        // `reconstruct` should have filled in every missing shard. If any are still absent,
        // treat it as an invalid reconstruction.
        let shards = shards
            .into_iter()
            .map(|s| s.ok_or(InvalidInput))
            .collect::<FastCryptoResult<Vec<_>>>()?;

        // Ensure the reconstructed shards are consistent.
        let verified = self.0.verify(&shards).map_err(|_| InvalidInput)?;
        if !verified {
            return Err(TooManyErrors(self.0.parity_shard_count()));
        }

        Ok(shards)
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

        // But with erasure coding, it works!
        let mut received = code_word.clone();
        let erasures = vec![a[3], a[2], a[4]];
        received.remove(4);
        received.remove(3);
        received.remove(2);
        let decoded_message = decoder
            .with_erasures(&erasures)
            .unwrap()
            .decode(&received)
            .unwrap();
        assert_eq!(decoded_message, message);
    }

    #[test]
    fn test_rs_erasure_encode_reconstruct_roundtrip() {
        let k = 3;
        let n = 5;
        let rs = RSErasure::new(k, n).unwrap();

        // All shards must have the same length.
        let data = vec![b"hello".to_vec(), b"world".to_vec(), b"!!!!!".to_vec()];
        let encoded = rs.encode(data.clone()).unwrap();
        assert_eq!(encoded.len(), n);

        // Drop up to `n-k` shards and reconstruct.
        let mut shards: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
        shards[1] = None;
        shards[4] = None;

        let reconstructed = rs.reconstruct(shards).unwrap();
        assert_eq!(reconstructed.len(), n);

        // First `k` shards are the data shards.
        assert_eq!(&reconstructed[..k], &data[..]);
    }

    #[test]
    fn test_rs_erasure_reconstruct_too_few_shards() {
        let k = 3;
        let n = 5;
        let rs = RSErasure::new(k, n).unwrap();

        let data = vec![b"aaaaa".to_vec(), b"bbbbb".to_vec(), b"ccccc".to_vec()];
        let encoded = rs.encode(data).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();

        // Leave only 2 shards present (< k).
        shards[0] = None;
        shards[1] = None;
        shards[2] = None;

        assert!(matches!(rs.reconstruct(shards), Err(InvalidInput)));
    }

    #[test]
    fn test_rs_erasure_new_invalid_params() {
        // Invalid because n <= k.
        assert!(matches!(RSErasure::new(3, 3), Err(InvalidInput)));
        assert!(matches!(RSErasure::new(3, 2), Err(InvalidInput)));
        // Invalid because k == 0.
        assert!(matches!(RSErasure::new(0, 1), Err(InvalidInput)));
        // Invalid because n > 256.
        assert!(matches!(RSErasure::new(1, 257), Err(InvalidInput)));
    }
}
