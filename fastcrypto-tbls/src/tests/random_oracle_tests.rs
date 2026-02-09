// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::random_oracle::RandomOracle;

#[test]
fn test_random_oracle() {
    let ro1 = RandomOracle::new("abc");
    assert_eq!(ro1.evaluate(&"alice"), ro1.evaluate(&"alice"));
    assert_ne!(ro1.evaluate(&"alice"), ro1.evaluate(&"bob"));
    let ro2 = RandomOracle::new("def");
    assert_ne!(ro1.evaluate(&"alice"), ro2.evaluate(&"alice"));
    let ro3 = ro1.extend("def");
    assert_ne!(ro1.evaluate(&"alice"), ro3.evaluate(&"alice"));
}

#[test]
fn test_empty_strings() {
    let ro1 = RandomOracle::new("");
    let ro2 = RandomOracle::new("def");
    assert_ne!(ro1.evaluate(&"alice"), ro2.evaluate(&"alice"));

    let ro3 = ro2.extend("");
    assert_ne!(ro3.evaluate(&"alice"), ro2.evaluate(&"alice"));
}

#[test]
fn test_regression() {
    let ro1 = RandomOracle::new("abc");
    assert_eq!(
        ro1.evaluate(&"alice").to_vec(),
        hex::decode("f52f72aac5d40ebb30677b5531ccf7b42dbfaa2b6426c196af72237b96185e4d04412d872deacc64403bf06fd03b3925d3d3b0e7344b983c4189d19c7acce2f2").unwrap()
    );
}
