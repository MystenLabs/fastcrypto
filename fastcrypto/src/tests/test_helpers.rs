// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

pub fn verify_serialization<T>(obj: &T, expected: &[u8])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let bytes1 = bincode::serialize(obj).unwrap();
    let obj2: T = bincode::deserialize(&bytes1).unwrap();
    let bytes2 = bincode::serialize(&obj2).unwrap();
    assert_eq!(bytes1, *expected);
    assert_eq!(*obj, obj2);
    assert_eq!(bytes1, bytes2);
    // Test a failed deserialization
    let mut bytes3 = bytes1;
    bytes3[0] = if bytes3[0] > 100 {
        bytes3[0] + 1
    } else {
        bytes3[0] - 1
    };
    let obj3 = bincode::deserialize::<T>(&bytes3);
    assert!(obj3.is_err() || obj3.ok().unwrap() != *obj);
}
