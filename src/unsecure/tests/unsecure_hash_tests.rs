// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::HashFunction;

#[test]
fn test_xxh3() {
    use crate::unsecure::hash::XXH3Unsecure;
    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = XXH3Unsecure::digest(&data);
    assert_eq!(digest.as_ref(), hex::decode("A27C666A28F313B7").unwrap());
}

#[test]
fn test_xxh128() {
    use crate::unsecure::hash::XXH128Unsecure;

    let data =
        hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = XXH128Unsecure::digest(&data);
    assert_eq!(
        digest.as_ref(),
        hex::decode("15A52E2CC34B8AC7A906AF85B364E8CD").unwrap()
    );
}
