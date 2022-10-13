// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;

/// Represents a digest of `DIGEST_LEN`bytes.
#[serde_with::serde_as]
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
        write!(f, "{}", Base64::encode_string(&self.digest))
    }
}

impl<const DIGEST_LEN: usize> fmt::Display for Digest<DIGEST_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            Base64::encode_string(&self.digest)
                .get(0..DIGEST_LEN)
                .unwrap()
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
    type TypedDigest: Into<Digest<DIGEST_LEN>> + Eq + std::hash::Hash + Copy;

    fn digest(&self) -> Self::TypedDigest;
}

/// This wraps a `digest::Digest` as a `fastcrypto::hash::HashFunction`.
#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static, const DIGEST_LEN: usize>(Variant);

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

/// SHA-2
pub type Sha256 = HashFunctionWrapper<sha2::Sha256, 32>;

/// SHA-3
pub type Sha3_256 = HashFunctionWrapper<sha3::Sha3_256, 32>;

/// SHA-512
pub type Sha512 = HashFunctionWrapper<sha2::Sha512, 64>;

/// KECCAK
pub type Keccak256 = HashFunctionWrapper<sha3::Keccak256, 32>;

/// BLAKE2-256
pub type Blake2b256 = HashFunctionWrapper<blake2::Blake2b<typenum::U32>, 32>;

/// BLAKE3
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
