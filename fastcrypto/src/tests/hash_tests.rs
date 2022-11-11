// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::{
    Accumulator, Blake2b256, Blake3, HashFunction, Keccak256, Sha256, Sha3_256, Sha512,
};

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
fn test_sha512() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Sha512::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("cbd83ff929e1b4a72e144b5533e59edba3a90f761e188bd809f994137d67ecd8b87e4c250d461f7f4c64c22f10e9f5c598849f2685f5b828b501e38d2b252d12").unwrap()
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
    let digest = Blake2b256::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("cc4e83cd4f030b0aabe27cf65a3ff92d0b5445f6466282e6b83a529b66094ebb").unwrap()
    );
}

#[test]
fn test_blake3() {
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Blake3::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("1b6d57a5017077b00cc9ce0641fb8ddcc136fbdb83325b31597fbe9441d9b269").unwrap()
    );
}

#[test]
fn test_accumulator() {
    let mut accumulator = Accumulator::default();

    // Two different multisets should give different hashes
    accumulator.insert(b"Hello");
    let check1 = accumulator.clone();
    accumulator.insert(b"World");
    assert_ne!(check1, accumulator);

    // Hashing the same elements should give the same hash
    let mut accumulator2 = Accumulator::default();
    accumulator2.insert_all([b"Hello", b"World"]);
    assert_eq!(accumulator, accumulator2);

    // The order doesn't matter
    let mut accumulator3 = Accumulator::default();
    accumulator3.insert_all([b"World", b"Hello"]);
    assert_eq!(accumulator, accumulator3);

    // The union of two accumulators should be equal to if all elements were inserted into a single accumulator
    let mut accumulator3 = Accumulator::default();
    accumulator3.insert(b"World");
    accumulator3.union(check1);
    assert_eq!(accumulator, accumulator3);
}
