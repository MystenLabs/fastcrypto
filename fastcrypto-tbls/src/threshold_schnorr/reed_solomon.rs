// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, MonicLinear, Poly};
use crate::threshold_schnorr::S;
use crate::types::{to_scalar, ShareIndex};
use fastcrypto::error::FastCryptoError::{InputLengthWrong, InvalidInput, TooManyErrors};
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;
use reed_solomon_erasure::galois_16::ReedSolomon;
use serde::{Deserialize, Serialize};

/// Decoder for Reed-Solomon codes.
/// This can correct up to (d-1)/2 errors, where d is the distance of the code.
/// The code is defined by the evaluation points `a` and the message length `k`.
/// The distance is given by `n - k + 1`, where `n` is the length of `a`.
///
/// The implementation follows the Gao decoding algorithm
/// (see https://www.math.clemson.edu/~sgao/papers/RS.pdf).
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
    /// Returns an InvalidInput error if the given erasures are not unique or not a subset of
    /// self.a.
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
pub struct ErasureCoder(ReedSolomon);

/// An element of `GF(2^16)` as represented by the underlying coder.
type Element = [u8; ELEMENT_SIZE_IN_BYTES];

/// Size in bytes of one `GF(2^16)` element.
const ELEMENT_SIZE_IN_BYTES: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Shard(pub(crate) Vec<u8>);

impl ErasureCoder {
    /// Create a new erasure encoder/decoder.
    ///
    /// # Parameters
    /// - `n`: Total number of shards.
    /// - `k`: Number of data shards.
    ///
    /// # Errors
    /// Returns [`FastCryptoError::InvalidInput`] if `k == 0`, `n <= k` or `n > 65536`.
    pub fn new(n: usize, k: usize) -> FastCryptoResult<Self> {
        // The code is defined over GF(2^16), which has 2^16 = 65536 elements; n cannot exceed
        // that or the evaluation points would collide.
        if k == 0 || n <= k || n > 65536 {
            return Err(InvalidInput);
        }
        ReedSolomon::new(k, n - k)
            .map_err(|_| InvalidInput)
            .map(Self)
    }

    pub fn check_parameters(n: usize, k: usize) -> FastCryptoResult<()> {
        if k == 0 || n <= k || n > 65536 {
            return Err(InvalidInput);
        }
        Ok(())
    }

    /// Encode `data` into `n` shards of equal size, the first `k` of which hold the (zero-padded)
    /// data and the remaining `n - k` parity. Any `k` shards suffice to reconstruct the data.
    pub fn encode(&self, data: &[u8]) -> FastCryptoResult<Vec<Shard>> {
        if data.is_empty() {
            return Err(InvalidInput);
        }
        let len = u32::try_from(data.len()).map_err(|_| InvalidInput)?;
        let framed_len = std::mem::size_of::<u32>() + data.len();
        let shard_size = framed_len.div_ceil(ELEMENT_SIZE_IN_BYTES * self.0.data_shard_count());
        let bytes_per_shard = ELEMENT_SIZE_IN_BYTES * shard_size;
        let mut framed = Vec::with_capacity(bytes_per_shard * self.0.total_shard_count());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(data);
        framed.resize(bytes_per_shard * self.0.total_shard_count(), 0);
        let mut shards: Vec<Vec<Element>> = framed
            .chunks_exact(bytes_per_shard)
            .map(bytes_to_elements)
            .collect::<FastCryptoResult<_>>()?;
        self.0.encode(&mut shards).map_err(|_| InvalidInput)?;
        Ok(shards.into_iter().map(|s| Shard(s.concat())).collect_vec())
    }

    /// Reconstruct the original data from `n` (possibly missing) shards. Fails if more than
    /// `n - k` shards are missing, if the present shards are inconsistent with any single
    /// codeword, or if the recovered length prefix doesn't fit the recovered bytes.
    pub fn decode(&self, shards: Vec<Option<Shard>>) -> FastCryptoResult<Vec<u8>> {
        if shards.len() != self.0.total_shard_count() {
            return Err(InputLengthWrong(self.0.total_shard_count()));
        }

        let mut shards: Vec<Option<Vec<Element>>> = shards
            .into_iter()
            .map(|opt| {
                opt.map(|Shard(bytes)| bytes_to_elements(&bytes))
                    .transpose()
            })
            .collect::<FastCryptoResult<_>>()?;
        self.0.reconstruct(&mut shards).map_err(|_| InvalidInput)?;
        let shards = shards
            .into_iter()
            .map(|s| s.ok_or(InvalidInput))
            .collect::<FastCryptoResult<Vec<_>>>()?;

        // Ensure the reconstructed shards are consistent
        if !self.0.verify(&shards).map_err(|_| InvalidInput)? {
            return Err(TooManyErrors(0)); // This is just an erasure code, so we can't correct errors.
        }

        let framed: Vec<u8> = shards
            .into_iter()
            .take(self.0.data_shard_count())
            .flatten()
            .flatten()
            .collect();
        if framed.len() < std::mem::size_of::<u32>() {
            return Err(InvalidInput);
        }
        let len =
            u32::from_le_bytes(framed[..std::mem::size_of::<u32>()].try_into().unwrap()) as usize;
        let end = std::mem::size_of::<u32>()
            .checked_add(len)
            .ok_or(InvalidInput)?;
        if end > framed.len() {
            return Err(InvalidInput);
        }
        Ok(framed[std::mem::size_of::<u32>()..end].to_vec())
    }
}

/// Reinterpret `bytes` as a sequence of [Element]s. Fails with [`InvalidInput`] if the input
/// length is not a multiple of [`ELEMENT_SIZE_IN_BYTES`].
fn bytes_to_elements(bytes: &[u8]) -> FastCryptoResult<Vec<Element>> {
    if !bytes.len().is_multiple_of(ELEMENT_SIZE_IN_BYTES) {
        return Err(InvalidInput);
    }
    Ok(bytes
        .chunks_exact(ELEMENT_SIZE_IN_BYTES)
        .map(|p| p.try_into().expect("chunk has ELEMENT_SIZE_IN_BYTES bytes"))
        .collect())
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
    fn test_erasure_coder_new_rejects_invalid_parameters() {
        assert!(matches!(ErasureCoder::new(10, 0), Err(InvalidInput)));
        assert!(matches!(ErasureCoder::new(10, 10), Err(InvalidInput)));
        assert!(matches!(ErasureCoder::new(9, 10), Err(InvalidInput)));
        assert!(matches!(ErasureCoder::new(65537, 1), Err(InvalidInput)));
    }

    #[test]
    fn test_erasure_coder_roundtrip() {
        let n = 10;
        let k = 6;
        let coder = ErasureCoder::new(n, k).unwrap();

        for len in [1usize, 2, 3, 7, 8, 31, 32, 33, 100, 255] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
                .collect();
            let shards = coder.encode(&data).unwrap();
            assert_eq!(shards.len(), n);

            // Remove up to `parity` shards (erasures) and reconstruct.
            let mut opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
            for shard in opt_shards.iter_mut().take(n - k) {
                *shard = None;
            }

            let coder = ErasureCoder::new(n, k).unwrap();
            let recovered = coder.decode(opt_shards).unwrap();
            assert_eq!(recovered, data);
        }
    }

    #[test]
    fn test_erasure_coder_decode_rejects_too_many_missing_shards() {
        let n = 9;
        let k = 5;
        let coder = ErasureCoder::new(n, k).unwrap();
        let data: Vec<u8> = (0..123).map(|i| i as u8).collect();
        let shards = coder.encode(&data).unwrap();

        // Parity is `n - k` -- remove more shards than that.
        let mut opt_shards: Vec<Option<Shard>> = shards.into_iter().map(Some).collect();
        for shard in opt_shards.iter_mut().take(n - k + 1) {
            *shard = None;
        }

        assert!(matches!(coder.decode(opt_shards), Err(InvalidInput)));
    }

    #[test]
    fn test_erasure_coder_detects_corrupted_shard() {
        let n = 8;
        let k = 5;
        let coder = ErasureCoder::new(n, k).unwrap();
        let data: Vec<u8> = (0..200).map(|i| (i as u8) ^ 0xAA).collect();
        let mut shards = coder.encode(&data).unwrap();

        // Corrupt one shard (without declaring it missing). Reconstruction will succeed,
        // but verification should fail.
        shards[0].0[0] ^= 1;
        let opt_shards = shards.into_iter().map(Some).collect_vec();

        assert!(matches!(coder.decode(opt_shards), Err(TooManyErrors(_))));
    }

    #[test]
    fn test_erasure_coder_encode_shard_lengths() {
        // Each GF(2^16) element is 2 bytes; the framed payload is `u32_len || data` so the
        // pre-padding length is `4 + data_len`. Shards are sized to a whole number of pairs with
        // pair count ⌈(4 + data_len) / (2 · k)⌉.
        for &(n, k, data_len, expected_shard_bytes) in &[
            (10, 6, 1, 2),       // ⌈  5 /  12⌉ = 1 pair
            (10, 6, 8, 2),       // ⌈ 12 /  12⌉ = 1 pair
            (10, 6, 9, 4),       // ⌈ 13 /  12⌉ = 2 pairs
            (10, 6, 12, 4),      // ⌈ 16 /  12⌉ = 2 pairs
            (10, 6, 100, 18),    // ⌈104 /  12⌉ = 9 pairs
            (800, 268, 2028, 8), // ⌈2032 / 536⌉ = 4 pairs
        ] {
            let coder = ErasureCoder::new(n, k).unwrap();
            let data: Vec<u8> = (0..data_len).map(|i| i as u8).collect();
            let shards = coder.encode(&data).unwrap();
            assert_eq!(shards.len(), n, "shard count");
            for shard in &shards {
                assert_eq!(
                    shard.0.len(),
                    expected_shard_bytes,
                    "shard byte length for n={n}, k={k}, data_len={data_len}"
                );
            }
        }
    }
}
