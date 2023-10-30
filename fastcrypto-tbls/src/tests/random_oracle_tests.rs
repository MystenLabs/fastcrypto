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
    // Regression
    assert_eq!(
        ro1.evaluate(&"alice").to_vec(),
        hex::decode("ea7857d7b4946f810e15e6fb1f95eb3a2c8117e78ab7f23f7d139444c67b415dcfb080f878d22cf5c5010660fee38722588d7f071972c67ab1affcaabfca76c3").unwrap()
    );
}
