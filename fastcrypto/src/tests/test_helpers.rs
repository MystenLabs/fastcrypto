// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::{HashFunction, Sha256};
use crate::traits::KeyPair;
use aes::cipher::crypto_common::rand_core::SeedableRng;
use rand::prelude::StdRng;
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
    if expected.is_some() {
        assert_eq!(bytes1, expected.unwrap());
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
