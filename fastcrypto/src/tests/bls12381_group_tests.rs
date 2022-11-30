// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::bls12381::{BLS12381Scalar, G1Element};
use crate::groups::GroupElement;

#[test]
fn test_arithmetic() {
    // Test that different ways of computing [5]G gives the expected result
    let g = G1Element::generator();

    let p1 = g * BLS12381Scalar::from(5);

    let p2 = g + g + g + g + g + g - g;
    assert_eq!(p1, p2);

    let mut p3 = G1Element::zero();
    p3 += p2;
    assert_eq!(p1, p3);

    let mut p4 = g;
    p4 *= BLS12381Scalar::from(5);
    assert_eq!(p1, p4);

    let p5 = g * (BLS12381Scalar::from(7) - BLS12381Scalar::from(2));
    assert_eq!(p1, p5);
}
