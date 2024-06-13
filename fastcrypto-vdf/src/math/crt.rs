// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::extended_gcd::extended_euclidean_algorithm;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed};

/// Maximum number of inputs allowed for the CRT solver.
const MAX_ALLOWED_INPUTS: usize = 64;

/// Find the unique x such that x = a mod p and x = b mod q for relatively prime p and q and 0 <= x
/// < pq.
pub(crate) fn solve_simple_congruence_equation_system(
    a: &BigInt,
    p: &BigInt,
    b: &BigInt,
    q: &BigInt,
) -> FastCryptoResult<BigInt> {
    if !p.is_positive() || !q.is_positive() {
        return Err(InvalidInput);
    }

    // The moduli must be relatively prime
    let output = extended_euclidean_algorithm(p, q, true);
    if !output.gcd.is_one() {
        return Err(InvalidInput);
    }

    let a = a.mod_floor(p);
    let b = b.mod_floor(q);

    let result = a * output.y * q + b * output.x.unwrap() * p;

    if result.is_negative() {
        Ok(result + &(p * q))
    } else {
        Ok(result)
    }
}

/// Find the unique x such that x = a_i mod p_i for relatively prime p_i and 0 <= x < Prod p_i.
pub(crate) fn solve_congruence_equation_system(
    a: &[BigInt],
    p: &[BigInt],
) -> FastCryptoResult<BigInt> {
    assert_eq!(a.len(), p.len());

    // Avoid filling the stack with recursive calls
    if a.len() > MAX_ALLOWED_INPUTS {
        return Err(InvalidInput);
    }

    match a.len() {
        0 => Err(InvalidInput),
        1 => Ok(a[0].clone()),
        2 => solve_simple_congruence_equation_system(&a[0], &p[0], &a[1], &p[1]),
        _ => {
            let x = solve_simple_congruence_equation_system(&a[0], &p[0], &a[1], &p[1])?;
            let y = solve_congruence_equation_system(&a[2..], &p[2..])?;
            solve_simple_congruence_equation_system(
                &x,
                &(&p[0] * &p[1]),
                &y,
                &p[2..].iter().product(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    #[test]
    fn test_simple_crt() {
        let a = BigInt::from(3);
        let p = BigInt::from(5);
        let b = BigInt::from(4);
        let q = BigInt::from(7);

        let x = super::solve_simple_congruence_equation_system(&a, &p, &b, &q).unwrap();
        assert_eq!(x, BigInt::from(18));
    }

    #[test]
    fn test_crt() {
        let a: Vec<BigInt> = vec![0, 3, 4].into_iter().map(BigInt::from).collect();
        let p: Vec<BigInt> = vec![3, 4, 5].into_iter().map(BigInt::from).collect();
        let x = super::solve_congruence_equation_system(&a, &p).unwrap();
        assert_eq!(x, BigInt::from(39));
    }

    #[test]
    fn test_large_crt_fails() {
        let a: Vec<BigInt> = vec![0; 65].into_iter().map(BigInt::from).collect();
        let p: Vec<BigInt> = vec![3; 65].into_iter().map(BigInt::from).collect();
        assert!(super::solve_congruence_equation_system(&a, &p).is_err());
    }
}
