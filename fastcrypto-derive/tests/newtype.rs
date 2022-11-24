// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use fastcrypto_derive::{
    AddAssignSelfRef, AddSelfRef, MulAssignSelfRef, MulSelfRef, NegSelf, SubAssignSelfRef,
    SubSelfRef, SumSelfRef,
};

#[derive(
    AddSelfRef,
    AddAssignSelfRef,
    SubSelfRef,
    SubAssignSelfRef,
    NegSelf,
    MulSelfRef,
    MulAssignSelfRef,
    SumSelfRef,
)]
#[ScalarType = "Bar"]
struct Foo(i64);

struct Bar(i64);

#[test]
fn test_add_self_ref() {
    let foo1 = Foo(1);
    let foo2 = Foo(2);
    let foo3 = Foo(3);

    assert_eq!(foo1.add(&foo2).0, 3);
    assert_eq!(foo3.add(foo2).0, 5);
}

#[test]
fn test_add_assign_self_ref() {
    let mut foo1 = Foo(1);
    let foo2 = Foo(2);
    let mut foo3 = Foo(3);

    foo1.add_assign(&foo2);
    assert_eq!(foo1.0, 3);
    foo3.add_assign(foo2);
    assert_eq!(foo3.0, 5);
}

#[test]
fn test_sub_self_ref() {
    let foo1 = Foo(3);
    let foo2 = Foo(2);
    let foo3 = Foo(5);

    assert_eq!(foo1.sub(&foo2).0, 1);
    assert_eq!(foo3.sub(foo2).0, 3);
}

#[test]
fn test_sub_assign_self_ref() {
    let mut foo1 = Foo(3);
    let foo2 = Foo(2);
    let mut foo3 = Foo(5);

    foo1.sub_assign(&foo2);
    assert_eq!(foo1.0, 1);
    foo3.sub_assign(foo2);
    assert_eq!(foo3.0, 3);
}

#[test]
fn test_neg_self() {
    let foo1 = Foo(3);

    assert_eq!((foo1.neg()).0, -3);
}

#[test]
fn test_mul_self_ref() {
    let foo1 = Foo(1);
    let foo2 = Bar(2);
    let foo3 = Foo(3);

    assert_eq!(foo1.mul(&foo2).0, 2);
    assert_eq!(foo3.mul(foo2).0, 6);
}

#[test]
fn test_mul_assign_self_ref() {
    let mut foo1 = Foo(3);
    let foo2 = Bar(2);
    let mut foo3 = Foo(5);

    foo1.mul_assign(&foo2);
    assert_eq!(foo1.0, 6);
    foo3.mul_assign(foo2);
    assert_eq!(foo3.0, 10);
}

#[test]
fn test_sum_self_ref() {
    let foo1 = Foo(1);
    let foo2 = Foo(2);
    let foo3 = Foo(3);

    assert_eq!(vec![foo1, foo2, foo3].iter().sum::<Foo>().0, 6);
}
