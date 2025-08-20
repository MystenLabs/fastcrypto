// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::{Doubling, GroupElement};

use crate::groups::secp256k1::{ProjectivePoint, Scalar};
use crate::groups::{secp256k1, Scalar as ScalarTrait};
use crate::serde_helpers::ToFromByteArray;
use rand::thread_rng;

#[test]
fn test_to_from_byte_array() {
    let scalar = secp256k1::Scalar::rand(&mut thread_rng());
    let bytes = scalar.to_byte_array();
    let reconstructed = Scalar::from_byte_array(&bytes).unwrap();
    assert_eq!(scalar, reconstructed);
}

#[test]
fn test_arithmetic() {
    let p = ProjectivePoint::generator();
    let two_p = p + p;
    let s = Scalar::from(2);
    assert_eq!(two_p, p.double());
    assert_eq!(two_p, p * s);
    assert_eq!(p, two_p * (Scalar::generator() / s).unwrap());

    // Check that u128 is decoded correctly.
    let x: u128 = 2 << 66;
    let x_scalar = Scalar::from(x);
    let res = x_scalar / Scalar::from(8);
    assert_eq!(res.unwrap(), Scalar::from(2 << 63));
}

// TODO: add serde tests & regression
