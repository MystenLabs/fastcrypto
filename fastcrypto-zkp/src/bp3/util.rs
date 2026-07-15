// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::GroupElement;
use itertools::Either::{Left, Right};
use itertools::Itertools;

/// Splits vector `v` into two vectors `v_even` and `v_odd` where `v_even` contains the elements at even indices and
/// `v_odd` contains the elements at odd indices.
pub fn reduce<T>(v: &[T]) -> (Vec<T>, Vec<T>)
where
    T: Copy,
{
    v.iter().enumerate().partition_map(|(index, value)| {
        if index % 2 == 0 {
            Left(value)
        } else {
            Right(value)
        }
    })
}

/// Computes the inner product of two vectors `v` and `w`, i.e., `result = sum_i (v_i * w_i)`.
/// Panics if `v` and `w` have different lengths.
pub fn inner_product<T: GroupElement>(v: &[T], w: &[T::ScalarType]) -> T {
    T::sum(v.iter().zip_eq(w).map(|(vi, wi)| *vi * wi))
}

/// Computes the weighted inner product of two vectors `v` and `w` with a given `weight`, i.e., `result = sum_i (v_i * w_i * weight^i)`.
/// Panics if `v` and `w` have different lengths.
pub fn weighted_inner_product<T: GroupElement>(
    v: &[T],
    w: &[T::ScalarType],
    weight: &T::ScalarType,
) -> T {
    T::sum(
        v.iter()
            .zip_eq(w)
            .zip(itertools::iterate(*weight, |x| *x * weight))
            .map(|((v_val, w_val), exp)| *v_val * w_val * exp),
    )
}

/// Scales each element of vector `v` by a given `scalar`, i.e., `result[i] = v[i] * scalar`.
pub fn scale<T: GroupElement>(v: &[T], scalar: T::ScalarType) -> Vec<T> {
    v.iter().map(|x| *x * scalar).collect()
}

/// Adds two vectors `v` and `w` element-wise, i.e., `result[i] = v[i] + w[i]`.
/// Panics if `v` and `w` have different lengths.
pub fn add<T: GroupElement>(v: &[T], w: &[T]) -> Vec<T> {
    v.iter()
        .zip_eq(w)
        .map(|(v_val, w_val)| *v_val + w_val)
        .collect()
}
