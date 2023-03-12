// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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
