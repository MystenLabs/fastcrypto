// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, MonicLinear, Poly};
use crate::threshold_schnorr::S;
use crate::types::{get_uniform_value, to_scalar, ShareIndex};
use fastcrypto::error::FastCryptoError::{InputLengthWrong, InvalidInput, TooManyErrors};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::GroupElement;
use itertools::Itertools;
use reed_solomon_erasure::galois_16::ReedSolomon;
use serde::{Deserialize, Serialize};

/// Decoder for Reed-Solomon codes.
/// This can correct up to (d-1)/2 errors, where d is the distance of the code.
/// The code is defined by the evaluation points `a` and the message length `k`.
/// The distance is given by `n - k + 1`, where `n` is the length of `a`.
///
/// The implementation follows the Gao decoding algorithm
/// (see <https://www.math.clemson.edu/~sgao/papers/RS.pdf>).
pub struct RSDecoder {
    g0: Poly<S>,
    a: Vec<ShareIndex>,
    k: usize,
}

impl RSDecoder {
    /// Create a new Gao decoder with the given evaluation points `a` and message length `k`.
    /// Returns an [InvalidInput] error if `k` is not smaller than the number of evaluation points.
    pub fn new(a: Vec<ShareIndex>, k: usize) -> FastCryptoResult<Self> {
        if k >= a.len() {
            return Err(InvalidInput);
        }
        let mut g0 = Poly::one();
        for ai in &a {
            g0 *= MonicLinear(-to_scalar::<S>(ai));
        }
        Ok(Self { g0, a, k })
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

    /// Decode the code word.
    /// Returns an error if the input length is wrong or if there are too many errors to correct.
    pub fn decode(&self, code_word: &[S]) -> FastCryptoResult<Decoding> {
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
        Ok(Decoding {
            message: f1,
            error_locator: v,
        })
    }
}

/// The result of decoding a code word.
pub struct Decoding {
    message: Poly<S>,
    error_locator: Poly<S>,
}

impl Decoding {
    /// The constant term of the message polynomial.
    pub fn constant_term(&self) -> S {
        self.message.c0()
    }

    /// Whether the code word had an error here.
    pub fn is_error(&self, index: ShareIndex) -> bool {
        // Gao remarks after Algorithm 1 that `v(x)` is the error locator polynomial, which the
        // paper defines as the product over exactly the error positions. It has lower degree than
        // the message polynomial, so this is the cheaper check.
        self.error_locator.eval(index).value == S::zero()
    }
}

/// A wrapper struct for the Reed-Solomon erasure coding library.
pub struct ErasureCoder(ReedSolomon);

/// An element of `GF(2^16)` as represented by the underlying coder.
type Element = [u8; ELEMENT_SIZE_IN_BYTES];

/// Size in bytes of one `GF(2^16)` element.
const ELEMENT_SIZE_IN_BYTES: usize = 2;

/// Size in bytes of a `u32`, the width of the length prefix framing an encoded payload.
const U32_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Shard(pub(crate) Vec<u8>);

pub type Shards = Vec<Shard>;

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
        Self::check_parameters(n, k)?;
        ReedSolomon::new(k, n - k)
            .map_err(|_| InvalidInput)
            .map(Self)
    }

    fn check_parameters(n: usize, k: usize) -> FastCryptoResult<()> {
        if k == 0 || n <= k || n > 65536 {
            return Err(InvalidInput);
        }
        Ok(())
    }

    /// Encode `data` into `n` shards of equal size, the first `k` of which hold the (zero-padded)
    /// data and the remaining `n - k` parity. Any `k` shards suffice to reconstruct the data.
    pub fn encode(&self, data: &[u8]) -> FastCryptoResult<Shards> {
        if data.is_empty() {
            return Err(InvalidInput);
        }
        let mut shards = self.bytes_to_element_shards(data)?;
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

        self.element_shards_to_bytes(shards)
    }

    /// An injective mapping from arbitrary binary `data` to `Vec<Vec<Element>>`, inverted by
    /// [`Self::element_shards_to_bytes`]. Returns [`InvalidInput`] if `data.len()` does not fit in a
    /// `u32`.
    fn bytes_to_element_shards(&self, data: &[u8]) -> FastCryptoResult<Vec<Vec<Element>>> {
        // Data format: a little-endian u32 length prefix followed by `data`, then zero padding to
        // fill a whole number of `Element`s across all shards.
        let len = u32::try_from(data.len()).map_err(|_| InvalidInput)?;
        let framed_len = U32_SIZE + data.len();
        let shard_size = framed_len.div_ceil(ELEMENT_SIZE_IN_BYTES * self.0.data_shard_count());
        let total = ELEMENT_SIZE_IN_BYTES * shard_size * self.0.total_shard_count();
        Ok(len
            .to_le_bytes()
            .into_iter()
            .chain(data.iter().copied())
            .chain(std::iter::repeat(0))
            .take(total)
            // Each `Element` is two bytes.
            .tuples::<(u8, u8)>()
            .map(|(a, b)| [a, b])
            .chunks(shard_size)
            .into_iter()
            .map(|shard| shard.collect_vec())
            .collect())
    }

    /// Recover the data from the reconstructed `shards`. Returns [`InvalidInput`] if the encoding
    /// is invalid.
    fn element_shards_to_bytes(&self, shards: Vec<Vec<Element>>) -> FastCryptoResult<Vec<u8>> {
        // A valid codeword has exactly `total_shard_count` shards, all of the same element length.
        if shards.len() != self.0.total_shard_count()
            || get_uniform_value(shards.iter().map(Vec::len)).is_none()
        {
            return Err(InvalidInput);
        }
        let framed: Vec<u8> = shards
            .into_iter()
            .take(self.0.data_shard_count())
            .flatten()
            .flatten()
            .collect();
        let prefix = framed.get(..U32_SIZE).ok_or(InvalidInput)?;
        let len = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
        let end = U32_SIZE.checked_add(len).ok_or(InvalidInput)?;
        if framed
            .get(end..)
            .ok_or(InvalidInput)?
            .iter()
            .any(|&b| b != 0)
        {
            return Err(InvalidInput);
        }
        Ok(framed[U32_SIZE..end].to_vec())
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
        let decoder = RSDecoder::new(a.clone(), k).unwrap();

        let message = Poly::from(vec![S::from(11u128), S::from(22u128), S::from(33u128)]);
        let code_word = a.iter().map(|&i| message.eval(i).value).collect_vec();

        // Introduce errors
        let mut received = code_word.clone();
        received[4] = S::from(20u128); // Error at position 4
        received[2] = S::from(200u128); // Error at position 2

        let decoding = decoder.decode(&received).unwrap();
        assert_eq!(decoding.constant_term(), message.c0());
        let errors = a.iter().filter(|&&i| decoding.is_error(i)).collect_vec();
        assert_eq!(errors, vec![&a[2], &a[4]]);

        // Test with too many errors
        let mut received = code_word.clone();
        received[4] = S::from(20u128); // Error at position 4
        received[3] = S::from(2000u128); // Error at position 3
        received[2] = S::from(200u128); // Error at position 2
        assert!(decoder.decode(&received).is_err());
    }

    #[test]
    fn test_decoding_can_exclude_an_honest_index() {
        // Corrupt parties evaluate `g`, which shares its constant term with the honest `f`. The
        // two agree only at zero, so every honest point is an error relative to `g`.
        let f = Poly::from(vec![S::from(10u128), S::from(3u128), S::from(2u128)]);
        let g = Poly::from(vec![S::from(10u128), S::from(5u128), S::from(7u128)]);
        let corrupt = [1u16, 2, 3, 4];
        let point = |i: u16| ShareIndex::new(i).unwrap();
        let word = |points: &[ShareIndex]| -> Vec<S> {
            points
                .iter()
                .map(|&i| {
                    if corrupt.contains(&i.get()) {
                        g.eval(i).value
                    } else {
                        f.eval(i).value
                    }
                })
                .collect_vec()
        };

        // Five points: the four corrupt ones outnumber the honest one, so the decoding settles on
        // `g`. The constant term still comes out right, but the honest index is named as the error.
        let few = (1..=5).map(point).collect_vec();
        let decoding = RSDecoder::new(few.clone(), 3)
            .unwrap()
            .decode(&word(&few))
            .unwrap();
        assert_eq!(decoding.constant_term(), f.c0());
        assert!(decoding.is_error(point(5)));
        assert!(corrupt.iter().all(|&i| !decoding.is_error(point(i))));

        // In between it decodes to neither: with `c` corrupt and message length `k` it settles on
        // `g` up to `n = 2c - k`, finds `f` from `n = 2c + k`, and fails over the `2k` in between.
        let between = (1..=8).map(point).collect_vec();
        assert!(RSDecoder::new(between.clone(), 3)
            .unwrap()
            .decode(&word(&between))
            .is_err());

        // Eleven points: the same four are within the correction radius, so the decoding finds `f`
        // and the locator names them instead.
        let many = (1..=11).map(point).collect_vec();
        let decoding = RSDecoder::new(many.clone(), 3)
            .unwrap()
            .decode(&word(&many))
            .unwrap();
        assert_eq!(decoding.constant_term(), f.c0());
        assert!(corrupt.iter().all(|&i| decoding.is_error(point(i))));
        assert!(!decoding.is_error(point(5)));
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

    #[test]
    fn test_element_shards_to_bytes_validation() {
        let coder = ErasureCoder::new(10, 6).unwrap();

        // One `Element` per shard so all shards have the same length. Flattening the first
        // `k = 6` shards yields `u32_le(1) || data_byte || pad || zero padding`.
        let data_byte = 0xABu8;
        let make_shards = |pad: u8| -> Vec<Vec<Element>> {
            let mut shards: Vec<Vec<Element>> =
                vec![vec![[1, 0]], vec![[0, 0]], vec![[data_byte, pad]]];
            shards.resize(coder.0.total_shard_count(), vec![[0, 0]]);
            shards
        };

        // Well-formed with zero padding decodes; non-zero padding is rejected.
        assert_eq!(
            coder.element_shards_to_bytes(make_shards(0)).unwrap(),
            vec![data_byte]
        );
        assert!(matches!(
            coder.element_shards_to_bytes(make_shards(1)),
            Err(InvalidInput)
        ));

        // Wrong shard count is rejected.
        let mut too_few = make_shards(0);
        too_few.pop();
        assert!(matches!(
            coder.element_shards_to_bytes(too_few),
            Err(InvalidInput)
        ));

        // Shards of differing lengths are rejected.
        let mut ragged = make_shards(0);
        ragged[0].push([0, 0]);
        assert!(matches!(
            coder.element_shards_to_bytes(ragged),
            Err(InvalidInput)
        ));
    }
}
