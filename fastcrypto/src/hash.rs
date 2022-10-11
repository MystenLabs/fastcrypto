// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use digest::OutputSizeUser;
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use std::fmt;

pub type DefaultHashFunction = Blake2b<typenum::U32>;

/// Represents a hash digest of `DigestLength` bytes.
#[derive(Hash, PartialEq, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest<DigestLength: ArrayLength<u8> + 'static>(pub GenericArray<u8, DigestLength>);

impl<DigestLength: ArrayLength<u8> + 'static> OutputSizeUser for Digest<DigestLength> {
    type OutputSize = DigestLength;
}

impl<DigestLength: ArrayLength<u8> + 'static> Digest<DigestLength> {
    /// Copy the digest into a new vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// The size of this digest in bytes.
    pub fn size(&self) -> usize {
        DigestLength::USIZE
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> fmt::Debug for Digest<DigestLength> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(&self.0))
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> fmt::Display for Digest<DigestLength> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            Base64::encode_string(&self.0)
                .get(0..DigestLength::USIZE)
                .unwrap()
        )
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> AsRef<[u8]> for Digest<DigestLength> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Trait implemented by hash functions providing a output of fixed length
pub trait HashFunction: Default {
    // Output type of this hash function
    type DigestType: Sized + OutputSizeUser;

    /// Process the given data, and update the internal of the hash function.
    fn update(&mut self, data: &[u8]);

    /// Retrieve result and consume hash function.
    fn finalize(self) -> Self::DigestType;

    fn digest(data: &[u8]) -> Self::DigestType {
        let mut h = Self::default();
        h.update(data);
        h.finalize()
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hashable {
    type Hasher: HashFunction;

    fn digest(self) -> <<Self as Hashable>::Hasher as HashFunction>::DigestType;
}

#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static>(Variant);

impl<Variant: digest::Digest + 'static> OutputSizeUser for HashFunctionWrapper<Variant> {
    type OutputSize = Variant::OutputSize;
}

impl<Variant: digest::Digest + 'static + Default> HashFunction for HashFunctionWrapper<Variant> {
    type DigestType = Digest<Variant::OutputSize>;

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest<Variant::OutputSize> {
        Digest(self.0.finalize())
    }
}

/// SHA-2
pub type Sha256 = HashFunctionWrapper<sha2::Sha256>;

/// SHA-3
pub type Sha3_256 = HashFunctionWrapper<sha3::Sha3_256>;

/// KECCAK
pub type Keccak256 = HashFunctionWrapper<sha3::Keccak256>;

/// BLAKE2
pub type Blake2b<DigestLength> = HashFunctionWrapper<blake2::Blake2b<DigestLength>>;

/// BLAKE3
#[derive(Default)]
pub struct Blake3 {
    instance: blake3::Hasher,
}

impl OutputSizeUser for Blake3 {
    type OutputSize = typenum::U32;
}

impl HashFunction for Blake3 {
    type DigestType = Digest<typenum::U32>;

    fn update(&mut self, data: &[u8]) {
        self.instance.update(data);
    }

    fn finalize(self) -> Digest<typenum::U32> {
        let hash: [u8; 32] = self.instance.finalize().into();
        Digest(hash.into())
    }
}
