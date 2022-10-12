// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The length of a digest.
pub const DIGEST_LEN: usize = 32;

/// Represents a 32 bytes digest.
#[derive(Hash, PartialEq, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd, Copy)]
pub struct Digest(pub [u8; DIGEST_LEN]);

impl Digest {
    /// Create a new digest containing the given bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    /// Copy the digest into a new vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// The size of this digest in bytes.
    pub fn size(&self) -> usize {
        DIGEST_LEN
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            Base64::encode_string(&self.0).get(0..DIGEST_LEN).unwrap()
        )
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Digest> for [u8; 32] {
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

/// Trait implemented by hash functions providing a output of fixed length
pub trait HashFunction: Default {
    /// Create a new hash function of the given type
    fn new() -> Self {
        Self::default()
    }

    /// Process the given data, and update the internal of the hash function.
    fn update<Data: AsRef<[u8]>>(&mut self, data: Data);

    /// Retrieve result and consume hash function.
    fn finalize(self) -> Digest;

    /// Compute the digest of the given data and consume the hash function.
    fn digest<Data: AsRef<[u8]>>(data: Data) -> Digest {
        let mut h = Self::default();
        h.update(data);
        h.finalize()
    }

    /// Compute a single digest from all slices in the iterator in order and consume the hash function.
    fn digest_iterator<K: AsRef<[u8]>, I: Iterator<Item = K>>(iter: I) -> Digest {
        let mut h = Self::default();
        iter.into_iter().for_each(|chunk| h.update(chunk.as_ref()));
        h.finalize()
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    // Since associated type defaults are still unstable, we cannot define the digesttype from the Hasher or vice versa.
    type TypedDigest: Into<Digest> + Eq + std::hash::Hash + Copy;

    fn digest(&self) -> Self::TypedDigest;
}

#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static>(Variant);

impl<Variant: digest::Digest<OutputSize = typenum::U32> + 'static + Default> HashFunction
    for HashFunctionWrapper<Variant>
{
    fn update<Data: AsRef<[u8]>>(&mut self, data: Data) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

/// SHA-2
pub type Sha256 = HashFunctionWrapper<sha2::Sha256>;

/// SHA-3
pub type Sha3_256 = HashFunctionWrapper<sha3::Sha3_256>;

/// KECCAK
pub type Keccak256 = HashFunctionWrapper<sha3::Keccak256>;

/// BLAKE2-256
pub type Blake2b256 = HashFunctionWrapper<blake2::Blake2b<typenum::U32>>;

/// BLAKE3
#[derive(Default)]
pub struct Blake3 {
    instance: blake3::Hasher,
}

impl HashFunction for Blake3 {
    fn update<Data: AsRef<[u8]>>(&mut self, data: Data) {
        self.instance.update(data.as_ref());
    }

    fn finalize(self) -> Digest {
        Digest(self.instance.finalize().into())
    }
}
