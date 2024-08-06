// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::mem::swap;
use std::ops::{RemAssign, ShrAssign};

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;

/// Compute the Jacobi symbol (a/m) for odd m. If m is prime, this is the same as the Legendre symbol.
/// m must be odd and positive.
pub fn jacobi(a: &BigInt, m: &BigInt) -> FastCryptoResult<i8> {
    if !m.is_positive() || m.is_even() {
        return Err(InvalidInput);
    }

    // After the reduction, we know that both a and m are positive
    let mut a = a.mod_floor(m).into_parts().1;
    let mut m = m.magnitude().clone();

    // The output
    let mut t = true;

    let mut m_1 = m.bit(1);

    while !a.is_zero() {
        // Remove all trailing zeros from a and adjust t accordingly
        let trailing_zeros = a.trailing_zeros().expect("a is not zero");
        if !trailing_zeros.is_zero() {
            a.shr_assign(trailing_zeros);
        }

        let a_1 = a.bit(1);
        if (trailing_zeros.is_odd() && (m_1 ^ m.bit(2))) ^ (m_1 && a_1) {
            t = !t;
        }

        // Swap a and m
        m_1 = a_1;
        swap(&mut a, &mut m);
        a.rem_assign(&m);
    }

    if m.is_one() {
        return Ok(if t { 1 } else { -1 });
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    fn test_jacobi_single(a: &str, m: &str, expected: i8) {
        let a = BigInt::parse_bytes(a.as_bytes(), 10).unwrap();
        let m = BigInt::parse_bytes(m.as_bytes(), 10).unwrap();
        assert_eq!(super::jacobi(&a, &m).unwrap(), expected);
    }

    #[test]
    fn test_jacobi() {
        test_jacobi_single("1", "3", 1);
        test_jacobi_single("2", "3", -1);
        test_jacobi_single("30", "59", -1);
        test_jacobi_single("89", "59", -1);
        test_jacobi_single("-19", "59", -1);
        test_jacobi_single("1001", "9907", -1);
        test_jacobi_single("2", "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389647960126939249806625440700685819469589938384356951833568218188663", 1);
        test_jacobi_single("3", "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389647960126939249806625440700685819469589938384356951833568218188663", -1);
    }
}
