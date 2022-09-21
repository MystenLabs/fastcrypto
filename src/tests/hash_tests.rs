// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use generic_array::typenum::{U32, U64};

use crate::hash::{Blake2b, HashFunction, Keccak256, Sha256, Sha3_256};

#[test]
fn test_sha256() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Sha256::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("2196d60feda3cd3787885c10a905e11fae911c32a0eb67fd290ade5df7eab140").unwrap()
    );
}

#[test]
fn test_sha3_256() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Sha3_256::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("8fa965f6b63464045e1a8a80e3175fec4e5468d2904f6d7338cf83a65528a8f5").unwrap()
    );
}

#[test]
fn test_keccak_256() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Keccak256::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("efecd3c9e52abd231ce0ce9548f0f9083fe040b291de26a3baa698956a847156").unwrap()
    );
}

#[test]
fn test_blake2b_256() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Blake2b::<U32>::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("cc4e83cd4f030b0aabe27cf65a3ff92d0b5445f6466282e6b83a529b66094ebb").unwrap()
    );
}

#[test]
fn test_blake2b_512() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Blake2b::<U64>::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("c4cc8d6a3fc41e284afb3d8549daf98b1f4dbb5bf021fd92daa45cf37a0b9cb78cce45006fb23d5e18512eb9a324d02a81eb903d6dbdffb1fbe9f2d36845d460").unwrap()
    );
}
