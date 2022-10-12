// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A generic trait impl'd by all hashfunction outputs.
pub trait GenericDigest: Sized + Eq + Clone + core::hash::Hash + Copy {}

/// Represents a concrete digest of `DigestLength` bytes.
#[derive(Hash, PartialEq, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd, Copy)]
pub struct Digest<DigestLength: ArrayLength<u8> + 'static + Copy>(
    pub GenericArray<u8, DigestLength>,
)
where
    DigestLength::ArrayType: Copy;

impl<DigestLength: ArrayLength<u8> + 'static + Copy + std::hash::Hash + std::cmp::Eq> GenericDigest
    for Digest<DigestLength>
where
    DigestLength::ArrayType: Copy,
{
}

/// A digest consisting of 512 bits = 64 bytes.
pub type Digest512 = Digest<typenum::U64>;

/// A digest consisting of 256 bits = 32 bytes.
pub type Digest256 = Digest<typenum::U32>;

/// A digest consisting of 128 bits = 16 bytes.
pub type Digest128 = Digest<typenum::U16>;

impl<DigestLength: ArrayLength<u8> + 'static> Digest<DigestLength>
where
    DigestLength::ArrayType: Copy,
{
    /// Copy the digest into a new vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// The size of this digest in bytes.
    pub fn size(&self) -> usize {
        DigestLength::USIZE
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> fmt::Debug for Digest<DigestLength>
where
    DigestLength::ArrayType: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(&self.0))
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> fmt::Display for Digest<DigestLength>
where
    DigestLength::ArrayType: Copy,
{
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

impl<DigestLength: ArrayLength<u8> + 'static> AsRef<[u8]> for Digest<DigestLength>
where
    DigestLength::ArrayType: Copy,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Trait implemented by hash functions providing a output of fixed length
pub trait HashFunction: Default {
    // Output type of this hash function
    type DigestType: GenericDigest;

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
    //type DigestType: HashFunction::DigestType;

    fn digest(&self) -> <<Self as Hashable>::Hasher as HashFunction>::DigestType;
}

#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static>(Variant);

impl<Variant: digest::Digest + 'static + Default> HashFunction for HashFunctionWrapper<Variant>
where
    Variant::OutputSize: Eq + core::hash::Hash,
    <Variant::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
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

/// BLAKE2-256
pub type Blake2b256 = Blake2b<typenum::U32>;

/// BLAKE3
#[derive(Default)]
pub struct Blake3 {
    instance: blake3::Hasher,
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
