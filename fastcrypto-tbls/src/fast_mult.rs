// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::Scalar;
use std::borrow::Borrow;

/// Multiply x.1 with y using u128s if possible, otherwise convert x.1 to the group element and multiply.
/// Invariant: If res = fast_mult(x1, x2, y) then x.0 * x.1 * y = res.0 * res.1.
pub(crate) fn fast_mult<C: Scalar>(x: (C, u128), y: u128) -> (C, u128) {
    if x.1.leading_zeros() >= (128 - y.leading_zeros()) {
        (x.0, x.1 * y)
    } else {
        (x.0 * C::from(x.1), y)
    }
}

/// Compute initial * \prod factors.
pub(crate) fn fast_product<C: Scalar>(initial: C, factors: impl Iterator<Item = u128>) -> C {
    let (result, remaining) = factors.fold((initial, 1), |acc, factor| {
        debug_assert_ne!(factor, 0);
        fast_mult(acc, factor)
    });
    debug_assert_ne!(remaining, 0);
    result * C::ScalarType::from(remaining)
}

/// Compute initial * (terms_0 - base) * (terms_1 - base)...
pub(crate) fn fast_product_of_differences<C: Scalar>(
    initial: C,
    base: u128,
    terms: impl Iterator<Item = impl Borrow<u128>>,
) -> C {
    let mut negative = false;
    let mut result = fast_product(
        initial,
        terms.map(|term| {
            let term = term.borrow();
            if base > *term {
                negative = !negative;
                base - term
            } else {
                term - base
            }
        }),
    );
    if negative {
        result = -result;
    };
    result
}
