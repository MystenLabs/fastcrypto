// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::HashFunction;
use crate::unsecure::hash::{Fast256HashUnsecure, XXH128Unsecure, XXH3Unsecure};

#[test]
fn test_xxh3() {
    let data1 = b"my message";
    let data2 = b"other message";

    // Digests should be 8 bytes long
    let digest1 = XXH3Unsecure::digest(data1);
    assert_eq!(8, digest1.size());

    // Different messages should have different digests
    let digest2 = XXH3Unsecure::digest(data2);
    assert_ne!(digest1, digest2);

    // Digests of the same message should be equal
    let digest3 = XXH3Unsecure::digest(data1);
    assert_eq!(digest1, digest3);
}

#[test]
fn test_xxh128() {
    let data1 = b"my message";
    let data2 = b"other message";

    // Digests should be 16 bytes long
    let digest1 = XXH128Unsecure::digest(data1);
    assert_eq!(16, digest1.size());

    // Different messages should have different digests
    let digest2 = XXH128Unsecure::digest(data2);
    assert_ne!(digest1, digest2);

    // Digests of the same message should be equal
    let digest3 = XXH128Unsecure::digest(data1);
    assert_eq!(digest1, digest3);
}

#[test]
fn test_256bit_hash() {
    let data1 = b"my message";
    let data2 = b"other message";

    // Digests should be 32 bytes long
    let digest1 = Fast256HashUnsecure::digest(data1);
    assert_eq!(32, digest1.size());

    // Different messages should have different digests
    let digest2 = Fast256HashUnsecure::digest(data2);
    assert_ne!(digest1, digest2);

    // Digests of the same message should be equal
    let digest3 = Fast256HashUnsecure::digest(data1);
    assert_eq!(digest1, digest3);
}
