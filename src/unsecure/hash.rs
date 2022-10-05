// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::hash::Hasher;

use digest::OutputSizeUser;
use generic_array::GenericArray;
use twox_hash::xxh3::HasherExt;

use crate::hash::{Digest, HashFunction};

/// XXH3 hash function.
///
/// Warning: This is NOT a cryptographic hash function and should NOT be used in production.
#[cfg(feature = "unsecure_schemes")]
#[derive(Default)]
pub struct XXH3Unsecure {
    instance: twox_hash::xxh3::Hash64,
}

impl OutputSizeUser for XXH3Unsecure {
    type OutputSize = typenum::U8;
}

impl HashFunction<typenum::U8> for XXH3Unsecure {
    fn update(&mut self, data: &[u8]) {
        self.instance.write(data);
    }

    fn finalize(self) -> Digest<typenum::U8> {
        let hash: [u8; 8] = self.instance.finish().to_le_bytes();
        Digest(hash.into())
    }
}

/// XXH128 hash function.
///
/// Warning: This is NOT a cryptographic hash function and should NOT be used in production.
#[cfg(feature = "unsecure_schemes")]
#[derive(Default)]
pub struct XXH128Unsecure {
    instance: twox_hash::xxh3::Hash128,
}

impl OutputSizeUser for XXH128Unsecure {
    type OutputSize = typenum::U16;
}

impl HashFunction<typenum::U16> for XXH128Unsecure {
    fn update(&mut self, data: &[u8]) {
        self.instance.write(data);
    }

    fn finalize(self) -> Digest<typenum::U16> {
        let hash: [u8; 16] = self.instance.finish_ext().to_be_bytes();
        Digest(hash.into())
    }
}

/// A fast 256 bit hash function based on xxHash3. The digest consists of two copies of a
/// Xxh128 digest of the data.
///
/// Warning: This is NOT a cryptographic hash function and should NOT be used in production.
#[cfg(feature = "unsecure_schemes")]
#[derive(Default)]
pub struct Fast256HashUnsecure {
    instance: twox_hash::xxh3::Hash128,
}

impl OutputSizeUser for Fast256HashUnsecure {
    type OutputSize = typenum::U32;
}

impl HashFunction<typenum::U32> for Fast256HashUnsecure {
    fn update(&mut self, data: &[u8]) {
        self.instance.write(data);
    }

    fn finalize(self) -> Digest<typenum::U32> {
        // Create a 32 byte digest consisting of two copies of a Xxh128 digest.
        let short_digest: [u8; 16] = self.instance.finish_ext().to_be_bytes();
        let mut digest = GenericArray::<u8, typenum::U32>::default();
        digest[..16].copy_from_slice(&short_digest);
        digest[16..32].copy_from_slice(&short_digest);
        Digest(digest)
    }
}
