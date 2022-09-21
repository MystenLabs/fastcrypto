// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::{Sha256, HashFunction};

#[test]
fn test_sha256() {
    let data = hex::decode("301d56460954541aab6dd7ddc0dd08f8cb3ebd884784a0e797905107533cae62").unwrap();
    let digest = Sha256::digest(&data);
    assert_eq!(digest.as_ref(), hex::decode("2196d60feda3cd3787885c10a905e11fae911c32a0eb67fd290ade5df7eab140").unwrap());
}