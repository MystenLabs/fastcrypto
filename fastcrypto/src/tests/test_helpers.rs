// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::{HashFunction, Sha256};
use crate::traits::KeyPair;
use rand::prelude::StdRng;
use rand::SeedableRng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Check that:
/// 1. The object can be serialized and deserialized to the same object
/// 2. Serialization is deterministic
/// 3. The serialized object is the same as the expected bytes
/// 4. Deserialization results in a different object if we change 1 byte in the serialized object
pub fn verify_serialization<T>(obj: &T, expected: Option<&[u8]>)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let bytes1 = bincode::serialize(obj).unwrap();
    let obj2: T = bincode::deserialize(&bytes1).unwrap();
    let bytes2 = bincode::serialize(&obj2).unwrap();
    if let Some(exp) = expected {
        assert_eq!(bytes1, exp);
    }
    assert_eq!(*obj, obj2);
    assert_eq!(bytes1, bytes2);
    // Test that bincode and bcs produce the same results (to make sure we can safely switch if
    // needed).
    assert_eq!(bytes1, bcs::to_bytes(obj).unwrap());
    assert_eq!(obj2, bcs::from_bytes::<T>(&bytes1).unwrap());
    // Test a failed deserialization
    let mut bytes3 = bytes1;
    bytes3[0] = if bytes3[0] > 100 {
        bytes3[0] - 1
    } else {
        bytes3[0] + 1
    };
    let obj3 = bincode::deserialize::<T>(&bytes3);
    assert!(obj3.is_err() || obj3.ok().unwrap() != *obj);
}

/// Generate `n` random key pairs.
pub fn keys<KP: KeyPair>(n: usize) -> Vec<KP> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..n).map(|_| KeyPair::generate(&mut rng)).collect()
}

pub struct DifferentMsgsSignatures<KP: KeyPair> {
    pub digests: Vec<Vec<u8>>,
    pub pubkeys: Vec<KP::PubKey>,
    pub signatures: Vec<KP::Sig>,
}

/// Generate a tuple of vectors containing messages, public keys and the corresponding signatures to be used in tests.
pub fn signature_test_inputs_different_msg<KP: KeyPair>() -> DifferentMsgsSignatures<KP> {
    // Make signatures.
    let digests: Vec<Vec<u8>> = [b"Hello", b"world", b"!!!!!"]
        .iter()
        .map(|msg| Sha256::digest(*msg).to_vec())
        .collect();
    let (pubkeys, signatures): (Vec<_>, Vec<_>) = keys::<KP>(3)
        .into_iter()
        .take(3)
        .zip(&digests)
        .map(|(kp, digest)| {
            let sig = kp.sign(digest.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();
    DifferentMsgsSignatures {
        digests,
        pubkeys,
        signatures,
    }
}

/// Runs the destructor of `value` in place and returns the bytes it leaves behind in each
/// `(offset, len)` range of its storage. Offsets are relative to the start of `T`; use
/// [`field_offset`] to compute them.
///
/// This lets zeroization tests inspect what `Drop` leaves in memory without reading freed
/// memory: `value` is moved into a [`std::mem::ManuallyDrop`], whose storage stays allocated
/// after the destructor runs. Only ask for ranges that hold initialized bytes after the drop,
/// such as byte arrays that the destructor zeroizes.
pub fn bytes_after_drop<T>(value: T, ranges: &[(usize, usize)]) -> Vec<Vec<u8>> {
    for &(offset, len) in ranges {
        assert!(
            offset + len <= std::mem::size_of::<T>(),
            "range is outside of the value"
        );
    }
    let mut value = std::mem::ManuallyDrop::new(value);
    // SAFETY: `value` is not used as a `T` after being dropped; only raw bytes are read below.
    unsafe { std::mem::ManuallyDrop::drop(&mut value) };
    let base = std::ptr::addr_of!(value).cast::<u8>();
    ranges
        .iter()
        .map(|&(offset, len)| {
            // SAFETY: the range lies within `value`'s storage, which is still allocated, and the
            // caller guarantees these bytes are initialized after the drop.
            unsafe { std::slice::from_raw_parts(base.add(offset), len) }.to_vec()
        })
        .collect()
}

/// Returns the offset in bytes of `field`, which must lie inside `base`, from the start of `base`.
pub fn field_offset<T, U: ?Sized>(base: &T, field: &U) -> usize {
    let start = base as *const T as usize;
    let field = field as *const U as *const u8 as usize;
    assert!(
        field >= start && field < start + std::mem::size_of::<T>(),
        "field is not inside base"
    );
    field - start
}
