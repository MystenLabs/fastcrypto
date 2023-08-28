// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::GroupElement;

use crate::groups::secp256r1::{ProjectivePoint, Scalar};
use crate::groups::{secp256r1, Scalar as ScalarTrait};
use crate::serde_helpers::ToFromByteArray;
use rand::thread_rng;

#[test]
fn test_to_from_byte_array() {
    let scalar = secp256r1::Scalar::rand(&mut thread_rng());
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
}

// TODO: add serde tests & regression
