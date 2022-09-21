// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Encoding};
use blake2::digest::{Update, VariableOutput};
use digest::OutputSizeUser;
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use std::{fmt, marker::PhantomData};

/// Represents a hash digest of `DigestLength` bytes.
#[derive(Hash, PartialEq, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest<DigestLength: ArrayLength<u8> + 'static>(GenericArray<u8, DigestLength>);

impl<DigestLength: ArrayLength<u8> + 'static> Digest<DigestLength> {

    /// Clone the given slice into a new `Digest`.
    pub fn from_bytes(val: &[u8]) -> Self {
        Digest(GenericArray::<u8, DigestLength>::clone_from_slice(val))
    }

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

/// This trait is implemented by all messages that can be hashed.
pub trait Hashable<DigestLength: ArrayLength<u8> + 'static> {
    fn digest<H: HashFunction<DigestLength>>(self) -> Digest<DigestLength>;
}

impl<DigestLength: ArrayLength<u8> + 'static> Hashable<DigestLength> for &[u8] {
    /// Hash this data using the given hash function.
    fn digest<H: HashFunction<DigestLength>>(self) -> Digest<DigestLength> {
        H::digest(self)
    }
}

/// Trait implemented by hash functions providing a output of fixed length
pub trait HashFunction<DigestLength: ArrayLength<u8>>: OutputSizeUser + Sized + Default {

    /// Process the given data, and update the internal of the hash function.
    fn update(&mut self, data: &[u8]);

    /// Retrieve result and consume hash function.
    fn finalize(self) -> Digest<DigestLength>;

    fn digest(data: &[u8]) -> Digest<DigestLength> {
        let mut h = Self::default();
        h.update(data);
        h.finalize()
    }
}

#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static>(Variant);

impl<Variant: digest::Digest + 'static> OutputSizeUser for HashFunctionWrapper<Variant> {
    type OutputSize = Variant::OutputSize;
}

impl<Variant: digest::Digest + 'static + Default> HashFunction<Variant::OutputSize>
    for HashFunctionWrapper<Variant>
{
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest<Variant::OutputSize> {
        Digest(self.0.finalize())
    }
}

// SHA-2
pub type Sha256 = HashFunctionWrapper<sha2::Sha256>;

// SHA-3
pub type Sha3_256 = HashFunctionWrapper<sha3::Sha3_256>;

// KECCAK
pub type Keccak256 = HashFunctionWrapper<sha3::Keccak256>;