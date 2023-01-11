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
    let ro4 = RandomOracle::new("abc-def");
    assert_eq!(ro3.evaluate(&"alice"), ro4.evaluate(&"alice"));
}
