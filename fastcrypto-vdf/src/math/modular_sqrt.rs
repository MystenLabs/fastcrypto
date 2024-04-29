// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::jacobi;
use crate::math::jacobi::jacobi;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};

/// Compute a modular square root of a modulo p with p prime if this exists. This function does not
/// check that p is prime and if it is not, the result is undefined. If check_legendre is set to
/// true, the function verifies that a is a quadratic residue modulo p and returns None otherwise.
/// If check_legendre is set to false, the function assumes that a is a quadratic residue modulo p
/// and if this is not the case, the result is undefined.
pub(crate) fn modular_square_root(
    a: &BigInt,
    p: &BigInt,
    check_legendre: bool,
) -> FastCryptoResult<BigInt> {
    // Algorithm 2.3.8 in Crandall & Pomerance, "Prime Numbers: A Computational Perspective"

    // Handle special cases
    if !p.is_positive() || !p.is_odd() || p.is_one() {
        return Err(InvalidInput);
    }

    if a.is_zero() {
        return Ok(BigInt::zero());
    }

    // Check that a is a quadratic residue modulo p
    if check_legendre && jacobi(a, p).unwrap() != 1 {
        return Err(InvalidInput);
    }

    let two = BigInt::from(2);

    let a = a.mod_floor(p);
    match mod8(p) {
        3 | 7 => Ok(a.modpow(&((p + 1) >> 2), p)),
        5 => {
            let mut x = a.modpow(&((p + 3) >> 3), p);
            let c = x.modpow(&two, p);
            if c != a {
                x *= two.modpow(&((p - 1) >> 2), p) % p;
            }
            Ok(x)
        }
        1 => {
            let mut d: BigInt = two.clone();
            while jacobi::jacobi(&d, p).expect("p is positive and odd") != -1 {
                d += 1;
                if &d >= p {
                    return Err(InvalidInput);
                }
            }
            let p_minus_1: BigInt = p - 1;
            let s = p_minus_1.trailing_zeros().expect("p is verified to be > 1");
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
            Ok(x)
        }
        _ => Err(InvalidInput),
    }
}

/// Compute a mod 8.
fn mod8(a: &BigInt) -> u8 {
    (a & &7.into()).to_u8().expect("Is smaller than 8")
}

#[cfg(test)]
mod tests {
    use crate::math::modular_sqrt::jacobi;
    use num_bigint::BigInt;

    #[test]
    fn test_sqrt() {
        // 1, 3, 5, 7 mod 8
        let moduli: [usize; 4] = [257, 163, 197, 127];
        for p in moduli.iter() {
            for a in 2..*p {
                let p = BigInt::from(*p);
                let a = BigInt::from(a);
                match super::modular_square_root(&a, &p, true) {
                    Ok(x) => {
                        assert_eq!(jacobi(&a, &p).unwrap(), 1);
                        assert_eq!(x.modpow(&BigInt::from(2), &p), a);
                    }
                    Err(_) => assert_eq!(jacobi(&a, &p).unwrap(), -1),
                }
            }
        }
    }
}
