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

use digest::OutputSizeUser;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;

use crate::encoding::{Base64, Encoding};

/// Represents a digest of `DIGEST_LEN` bytes.
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
        write!(f, "{}", Base64::encode(&self.digest))
    }
}

impl<const DIGEST_LEN: usize> fmt::Display for Digest<DIGEST_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            Base64::encode(&self.digest).get(0..DIGEST_LEN).unwrap()
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
