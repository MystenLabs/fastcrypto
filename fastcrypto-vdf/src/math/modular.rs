// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::jacobi;
use crate::math::jacobi::jacobi;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Signed, ToPrimitive, Zero};

/// Compute a modular square root of a modulo p with p prime if this exists. This function does not
/// check that p is prime and if it is not, the result is undefined. If check_legendre is set to
/// true, the function verifies that a is a quadratic residue modulo p and returns None otherwise.
/// If check_legendre is set to false, the function assumes that a is a quadratic residue modulo p
/// and if this is not the case, the result is undefined.
pub fn modular_square_root(a: &BigInt, p: &BigInt, check_legendre: bool) -> Option<BigInt> {
    // Algorithm 2.3.8 in Crandall & Pomerance, "Prime Numbers: A Computational Perspective"

    // Handle special cases
    if !p.is_positive() || !p.is_odd() {
        return None;
    }

    if a.is_zero() {
        return Some(BigInt::zero());
    }

    // Check that a is a quadratic residue modulo p
    if check_legendre && jacobi(a, p).unwrap() != 1 {
        return None;
    }

    let a = a.mod_floor(p);
    match mod8(p) {
        3 | 7 => Some(a.modpow(&((p + 1) >> 2), p)),
        5 => {
            let mut x = a.modpow(&((p + 3) >> 3), p);
            let c = x.modpow(&2.into(), p);
            if c != a {
                x = x * BigInt::from(2).modpow(&((p - 1) >> 2), p) % p;
            }
            Some(x)
        }
        1 => {
            let mut d: BigInt = 2.into();
            while jacobi::jacobi(&d, p).expect("p is positive and odd") != -1 {
                d += 1;
                if &d >= p {
                    return None;
                }
            }
            let p_minus_1: BigInt = p - 1;
            let s = p_minus_1.trailing_zeros().expect("p > 1");
            let t = &p_minus_1 >> s;

            let a_t = a.modpow(&t, p);
            let d_t = d.modpow(&t, p);
            let mut m = 0.into();

            for i in 0..s {
                let lhs = (&a_t * d_t.modpow(&m, p)).modpow(&(1 << (s - 1 - i)).into(), p);
                if lhs == p_minus_1 {
                    m += 1 << i;
                }
            }
            let x = a.modpow(&((t + 1) >> 1), p) * d_t.modpow(&(m >> 1), p) % p;
            Some(x)
        }
        _ => None,
    }
}

/// Compute a mod 8.
pub fn mod8(a: &BigInt) -> u8 {
    (a & &7.into()).to_u8().expect("Is smaller than 8")
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    #[test]
    fn test_sqrt() {
        let a = BigInt::from(58);
        let p = BigInt::from(101);
        let x = super::modular_square_root(&a, &p, true).unwrap();
        assert_eq!(x.modpow(&BigInt::from(2), &p), a);
        assert!(x == BigInt::from(19) || x == BigInt::from(82));

        let a = BigInt::from(111);
        let p = BigInt::from(113);
        let x = super::modular_square_root(&a, &p, true).unwrap();
        assert_eq!(x.modpow(&BigInt::from(2), &p), a);
        assert!(x == BigInt::from(26) || x == BigInt::from(87));
    }
}
