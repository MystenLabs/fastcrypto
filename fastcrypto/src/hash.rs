// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a selection of cryptographic hash functions implementing a common [HashFunction] trait.
//!
//! # Example
//! ```
//! # use fastcrypto::hash::*;
//! let digest1 = Sha256::digest(b"Hello, world!");
//!
//! let mut hash_function = Sha256::default();
//! hash_function.update(b"Hello, ");
//! hash_function.update(b"world!");
//! let digest2 = hash_function.finalize();
//!
//! assert_eq!(digest1, digest2);
//! ```

use core::fmt::Debug;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use digest::OutputSizeUser;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{fmt, marker::PhantomData};

use crate::encoding::{Base64, Encoding};

/// Represents a digest of `DIGEST_LEN` bytes.
#[serde_as]
#[derive(Hash, PartialEq, Eq, Clone, Serialize, Deserialize, Ord, PartialOrd, Copy)]
pub struct Digest<const DIGEST_LEN: usize> {
    #[serde_as(as = "[_; DIGEST_LEN]")]
    pub digest: [u8; DIGEST_LEN],
}

impl<const DIGEST_LEN: usize> Digest<DIGEST_LEN> {
    /// Create a new digest containing the given bytes
    pub fn new(digest: [u8; DIGEST_LEN]) -> Self {
        Digest { digest }
    }

    /// Copy the digest into a new vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.digest.to_vec()
    }

    /// The size of this digest in bytes.
    pub fn size(&self) -> usize {
        DIGEST_LEN
    }
}

impl<const DIGEST_LEN: usize> fmt::Debug for Digest<DIGEST_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.digest))
    }
}

impl<const DIGEST_LEN: usize> fmt::Display for Digest<DIGEST_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            Base64::encode(self.digest).get(0..DIGEST_LEN).unwrap()
        )
    }
}

impl<const DIGEST_LEN: usize> AsRef<[u8]> for Digest<DIGEST_LEN> {
    fn as_ref(&self) -> &[u8] {
        self.digest.as_ref()
    }
}

impl<const DIGEST_LEN: usize> From<Digest<DIGEST_LEN>> for [u8; DIGEST_LEN] {
    fn from(digest: Digest<DIGEST_LEN>) -> Self {
        digest.digest
    }
}

/// Trait implemented by hash functions providing a output of fixed length
pub trait HashFunction<const DIGEST_LENGTH: usize>: Default {
    /// The length of this hash functions digests in bytes.
    const OUTPUT_SIZE: usize = DIGEST_LENGTH;

    /// Create a new hash function of the given type
    fn new() -> Self {
        Self::default()
    }

    /// Process the given data, and update the internal of the hash function.
    fn update<Data: AsRef<[u8]>>(&mut self, data: Data);

    /// Retrieve result and consume hash function.
    fn finalize(self) -> Digest<DIGEST_LENGTH>;

    /// Compute the digest of the given data and consume the hash function.
    fn digest<Data: AsRef<[u8]>>(data: Data) -> Digest<DIGEST_LENGTH> {
        let mut h = Self::default();
        h.update(data);
        h.finalize()
    }

    /// Compute a single digest from all slices in the iterator in order and consume the hash function.
    fn digest_iterator<K: AsRef<[u8]>, I: Iterator<Item = K>>(iter: I) -> Digest<DIGEST_LENGTH> {
        let mut h = Self::default();
        iter.into_iter().for_each(|chunk| h.update(chunk.as_ref()));
        h.finalize()
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash<const DIGEST_LEN: usize> {
    /// The type of the digest when this is hashed.
    type TypedDigest: Into<Digest<DIGEST_LEN>> + Eq + std::hash::Hash + Copy + fmt::Debug;

    fn digest(&self) -> Self::TypedDigest;
}

/// This wraps a [digest::Digest] as a [HashFunction].
#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static, const DIGEST_LEN: usize>(Variant);

/// This trait allows using a [HashFunctionWrapper] where a [digest::Digest] was expected.
pub trait ReverseWrapper {
    type Variant: digest::Digest + 'static + digest::core_api::CoreProxy + OutputSizeUser;
}

impl<
        Variant: digest::Digest + 'static + digest::core_api::CoreProxy + OutputSizeUser,
        const DIGEST_LEN: usize,
    > ReverseWrapper for HashFunctionWrapper<Variant, DIGEST_LEN>
{
    type Variant = Variant;
}

impl<Variant: digest::Digest + 'static + Default, const DIGEST_LEN: usize> HashFunction<DIGEST_LEN>
    for HashFunctionWrapper<Variant, DIGEST_LEN>
{
    fn update<Data: AsRef<[u8]>>(&mut self, data: Data) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest<DIGEST_LEN> {
        Digest {
            digest: self.0.finalize().as_slice().try_into().unwrap(),
        }
    }
}

// Impl std::io::Write for HashFunctionWrapper. Needed for compatability in Sui.
impl<Variant: digest::Digest + 'static + Default, const DIGEST_LEN: usize> std::io::Write
    for HashFunctionWrapper<Variant, DIGEST_LEN>
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The [SHA-2](https://en.wikipedia.org/wiki/SHA-2) hash function with 256 bit digests.
pub type Sha256 = HashFunctionWrapper<sha2::Sha256, 32>;

/// The [SHA-3](https://en.wikipedia.org/wiki/SHA-3) hash function with 256 bit digests.
pub type Sha3_256 = HashFunctionWrapper<sha3::Sha3_256, 32>;

/// The [SHA-512](https://en.wikipedia.org/wiki/SHA-2) hash function with 512 bit digests.
pub type Sha512 = HashFunctionWrapper<sha2::Sha512, 64>;

/// The [KECCAK](https://keccak.team/files/Keccak-reference-3.0.pdf) hash function with 256 bit digests.
pub type Keccak256 = HashFunctionWrapper<sha3::Keccak256, 32>;

/// The [BLAKE2-256](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) hash function with 256 bit digests.
pub type Blake2b256 = HashFunctionWrapper<blake2::Blake2b<typenum::U32>, 32>;

/// The [BLAKE3](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3) hash function with 256 bit digests.
#[derive(Default)]
pub struct Blake3 {
    instance: blake3::Hasher,
}

impl HashFunction<32> for Blake3 {
    fn update<Data: AsRef<[u8]>>(&mut self, data: Data) {
        self.instance.update(data.as_ref());
    }

    fn finalize(self) -> Digest<32> {
        Digest {
            digest: self.instance.finalize().into(),
        }
    }
}

/// A Multiset Hash is a homomorphic hash function, which hashes arbitrary multisets of objects such
/// that the hash of the union of two multisets is easy to compute from the hashes of the two multisets.
///
/// The hash may be computed incrementally, adding items one at a time, and the order does not affect the
/// result. The hash of two multisets can be compared by using the Eq trait impl'd for the given hash function,
/// and the hash function should be collision resistant.
///
/// See ["Incremental Multiset Hash Functions and Their Application to Memory Integrity Checking" by D. Clarke
/// et al.](https://link.springer.com/chapter/10.1007/978-3-540-40061-5_12) for a discussion of this type of hash
/// functions.
///
/// # Example
/// ```
/// use fastcrypto::hash::{EllipticCurveMultisetHash, MultisetHash};
///
/// let mut hash1 = EllipticCurveMultisetHash::default();
/// hash1.insert(b"Hello");
/// hash1.insert(b"World");
///
/// let mut hash2 = EllipticCurveMultisetHash::default();
/// hash2.insert(b"World");
/// hash2.insert(b"Hello");
///
/// assert_eq!(hash1, hash2);
/// ```
pub trait MultisetHash<I>: Eq {
    /// Insert an item into this hash function.
    fn insert(&mut self, item: &I);

    /// Insert multiple items into this hash function.
    fn insert_all<'a, It>(&'a mut self, items: It)
    where
        It: 'a + IntoIterator<Item = &'a I>,
        I: 'a;

    /// Add all the elements of another hash function into this hash function.
    fn union(&mut self, other: &Self);
}

/// `EllipticCurveMultisetHash` (ECMH) is a homomorphic multiset hash function. Concretely, each element is mapped
/// to a point on an elliptic curve on which the DL problem is hard (the Ristretto group in Curve25519),
/// and the hash is the sum of all such points.
///
/// For more information about the construction of ECMH and its security, see ["Elliptic Curve Multiset Hash" by J.
/// Maitin-Shepard et al.](https://arxiv.org/abs/1601.06502).
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct EllipticCurveMultisetHash<I: MultisetItem> {
    accumulator: RistrettoPoint,
    item_type: PhantomData<I>,
}

impl<I: MultisetItem> PartialEq for EllipticCurveMultisetHash<I> {
    fn eq(&self, other: &Self) -> bool {
        self.accumulator == other.accumulator
    }
}

impl<I: MultisetItem> Eq for EllipticCurveMultisetHash<I> {}

impl<I: MultisetItem> MultisetHash<I> for EllipticCurveMultisetHash<I> {
    fn insert(&mut self, item: &I) {
        let mut hash_function = Sha512::default();
        item.as_bytes(|data: &[u8]| hash_function.update(data));
        let hash = hash_function.finalize().digest;
        let point: RistrettoPoint = RistrettoPoint::from_uniform_bytes(&hash);
        self.accumulator += point;
    }

    fn insert_all<'a, It>(&'a mut self, items: It)
    where
        It: 'a + IntoIterator<Item = &'a I>,
        I: 'a,
    {
        for i in items {
            self.insert(i);
        }
    }

    fn union(&mut self, other: &EllipticCurveMultisetHash<I>) {
        self.accumulator += other.accumulator;
    }
}

impl<I: MultisetItem> Debug for EllipticCurveMultisetHash<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accumulator").finish()
    }
}

/// Impl'd by items that can be be represented uniquely in binary form. This form is used when an item is
/// inserted into a multiset mash function.
pub trait MultisetItem {
    /// Gives a unique binary representation of this accumulateble object to the given consumer.
    fn as_bytes<F: FnOnce(&[u8])>(&self, consumer: F);
}

impl MultisetItem for [u8] {
    fn as_bytes<F: FnOnce(&[u8])>(&self, consumer: F) {
        consumer(self);
    }
}

impl<const N: usize> MultisetItem for [u8; N] {
    fn as_bytes<F: FnOnce(&[u8])>(&self, consumer: F) {
        consumer(self.as_slice());
    }
}

impl MultisetItem for Vec<u8> {
    fn as_bytes<F: FnOnce(&[u8])>(&self, consumer: F) {
        consumer(self.as_slice())
    }
}
