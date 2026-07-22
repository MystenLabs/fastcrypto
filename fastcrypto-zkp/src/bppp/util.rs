// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Scalar-vector helpers shared by the BP++ modules.

use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::groups::{GroupElement, Scalar};

/// The scalar 1. `GroupElement::generator` is the multiplicative identity
/// for fastcrypto's scalar types; this name says what it means here.
pub(crate) fn one() -> RistrettoScalar {
    RistrettoScalar::generator()
}

/// Inner product `<a, b> = sum_i a_i * b_i`.
pub(crate) fn inner_product(a: &[RistrettoScalar], b: &[RistrettoScalar]) -> RistrettoScalar {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .fold(RistrettoScalar::zero(), |acc, (x, y)| acc + *x * y)
}

/// Weighted inner product `<a, b>_mu = sum_i a_i * b_i * mu^{i+1}`.
pub(crate) fn weighted_inner_product(
    a: &[RistrettoScalar],
    b: &[RistrettoScalar],
    mu: RistrettoScalar,
) -> RistrettoScalar {
    debug_assert_eq!(a.len(), b.len());
    let mut weight = mu;
    let mut result = RistrettoScalar::zero();
    for (x, y) in a.iter().zip(b) {
        result += *x * y * weight;
        weight *= mu;
    }
    result
}

/// Weighted norm `|n|^2_mu = <n, n>_mu`.
pub(crate) fn weighted_norm(n: &[RistrettoScalar], mu: RistrettoScalar) -> RistrettoScalar {
    weighted_inner_product(n, n, mu)
}

/// Power vector `(1, x, x^2, ..., x^{n-1})`.
pub(crate) fn power_vector(x: RistrettoScalar, n: usize) -> Vec<RistrettoScalar> {
    let mut v = Vec::with_capacity(n);
    let mut cur = one();
    for _ in 0..n {
        v.push(cur);
        cur *= x;
    }
    v
}

/// Even-indexed elements `(v_0, v_2, v_4, ...)`.
pub(crate) fn even_elements<T: Copy>(v: &[T]) -> Vec<T> {
    v.iter().step_by(2).copied().collect()
}

/// Odd-indexed elements `(v_1, v_3, v_5, ...)`.
pub(crate) fn odd_elements<T: Copy>(v: &[T]) -> Vec<T> {
    v.iter().skip(1).step_by(2).copied().collect()
}

/// Component-wise sum `a + b`.
pub(crate) fn vec_add(a: &[RistrettoScalar], b: &[RistrettoScalar]) -> Vec<RistrettoScalar> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| *x + y).collect()
}

/// Scalar multiple `s * a`.
pub(crate) fn vec_scalar_mul(s: RistrettoScalar, a: &[RistrettoScalar]) -> Vec<RistrettoScalar> {
    a.iter().map(|x| s * x).collect()
}

/// Component-wise (Hadamard) product `a ∘ b`.
pub(crate) fn hadamard(a: &[RistrettoScalar], b: &[RistrettoScalar]) -> Vec<RistrettoScalar> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| *x * y).collect()
}

/// `v` padded to length `n` with zeros on the right.
pub(crate) fn pad_to(v: &[RistrettoScalar], n: usize) -> Vec<RistrettoScalar> {
    debug_assert!(v.len() <= n);
    let mut out = v.to_vec();
    out.resize(n, RistrettoScalar::zero());
    out
}

/// Batch inversion by Montgomery's trick: compute the prefix products
/// `p_i = x_0 * ... * x_{i-1}`, invert only the total product `p_n`, and then
/// recover each inverse on a backward pass via
/// `x_i^{-1} = p_i * (x_i * ... * x_{n-1})^{-1}`, where the suffix-product
/// inverse is maintained by multiplying `x_i` back in at each step. Costs one
/// inversion plus ~3n multiplications instead of n inversions. Errors with
/// `InvalidInput` if any input is zero.
pub(crate) fn batch_invert(inputs: &[RistrettoScalar]) -> FastCryptoResult<Vec<RistrettoScalar>> {
    // prefix[i] = inputs[0] * ... * inputs[i-1]
    let mut prefix = Vec::with_capacity(inputs.len());
    let mut acc = one();
    for x in inputs {
        prefix.push(acc);
        acc *= x;
    }
    // A single zero input makes the total product zero, so this errors.
    let mut suffix_inv = acc.inverse()?;
    // suffix_inv = (inputs[i] * ... * inputs[n-1])^{-1} going backwards.
    let mut out = vec![RistrettoScalar::zero(); inputs.len()];
    for i in (0..inputs.len()).rev() {
        out[i] = suffix_inv * prefix[i];
        suffix_inv *= inputs[i];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: u64) -> RistrettoScalar {
        RistrettoScalar::from(x)
    }

    #[test]
    fn test_inner_products() {
        let a = vec![s(1), s(2), s(3)];
        let b = vec![s(4), s(5), s(6)];
        assert_eq!(inner_product(&a, &b), s(32));

        // <a, b>_mu with mu = 2: 4*2 + 10*4 + 18*8 = 192
        let mu = s(2);
        assert_eq!(weighted_inner_product(&a, &b, mu), s(192));
        assert_eq!(weighted_norm(&a, mu), s(2 + 4 * 4 + 9 * 8));

        // Pre-weighting identity used throughout the protocol:
        // <a, b>_mu = <a ∘ bar_mu, b> with bar_mu = (mu, mu^2, ...).
        let bar_mu = vec_scalar_mul(mu, &power_vector(mu, a.len()));
        assert_eq!(
            weighted_inner_product(&a, &b, mu),
            inner_product(&hadamard(&a, &bar_mu), &b)
        );
    }

    #[test]
    fn test_power_vector() {
        assert_eq!(power_vector(s(3), 4), vec![s(1), s(3), s(9), s(27)]);
        assert!(power_vector(s(3), 0).is_empty());
    }

    #[test]
    fn test_even_odd_split() {
        let v = vec![s(0), s(1), s(2), s(3), s(4)];
        assert_eq!(even_elements(&v), vec![s(0), s(2), s(4)]);
        assert_eq!(odd_elements(&v), vec![s(1), s(3)]);
    }

    #[test]
    fn test_batch_invert() {
        let mut rng = rand::thread_rng();
        let inputs: Vec<RistrettoScalar> =
            (0..17).map(|_| RistrettoScalar::rand(&mut rng)).collect();
        let inverses = batch_invert(&inputs).unwrap();
        for (x, xi) in inputs.iter().zip(&inverses) {
            assert_eq!(*x * xi, one());
        }
        assert!(batch_invert(&[]).unwrap().is_empty());

        let with_zero = vec![s(1), s(0), s(2)];
        assert!(batch_invert(&with_zero).is_err());
    }
}
