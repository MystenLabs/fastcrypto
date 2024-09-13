// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigInt;

use crate::class_group::discriminant::{Discriminant, DISCRIMINANT_3072};
use crate::class_group::QuadraticForm;
use crate::math::parameterized_group::ParameterizedGroupElement;

#[test]
fn test_composition() {
    // The order of the class group (the class number) for -223 is 7 (see https://mathworld.wolfram.com/ClassNumber.html).
    let discriminant = Discriminant::from_trusted_bigint(BigInt::from(-223));
    let mut g = QuadraticForm::generator(&discriminant);

    for _ in 1..=6 {
        assert_ne!(QuadraticForm::zero(&discriminant), g);
        g = g.compose(&QuadraticForm::generator(&discriminant));
    }
    assert_eq!(QuadraticForm::zero(&discriminant), g);
}

#[test]
fn test_qf_to_from_bytes() {
    let discriminant = Discriminant::from_trusted_bigint(BigInt::from(-223));
    let expected = QuadraticForm::generator(&discriminant);
    let bytes = bcs::to_bytes(&expected).unwrap();
    let actual = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_large_qf_to_from_bytes() {
    assert_eq!(DISCRIMINANT_3072.bits(), 3072);

    let expected =
        QuadraticForm::hash_to_group_with_default_parameters(&[1, 2, 3], &DISCRIMINANT_3072)
            .unwrap();
    let bytes = bcs::to_bytes(&expected).unwrap();
    let actual = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(expected, actual);

    let a_bytes = bcs::to_bytes(&expected.a.to_signed_bytes_be()).unwrap();
    let b_bytes = bcs::to_bytes(&expected.b.to_signed_bytes_be()).unwrap();
    let c_bytes = bcs::to_bytes(&expected.c.to_signed_bytes_be()).unwrap();

    assert_eq!(bytes[..a_bytes.len()], a_bytes);
    assert_eq!(bytes[a_bytes.len()..a_bytes.len() + b_bytes.len()], b_bytes);
    assert_eq!(bytes[a_bytes.len() + b_bytes.len()..], c_bytes);
}
