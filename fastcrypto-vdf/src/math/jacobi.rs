use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::mem::swap;
use std::ops::{RemAssign, ShrAssign};

/// Compute the Jacobi symbol (a/m) for odd m. If m is prime, this is the same as the Legendre symbol.
pub fn jacobi(a: &BigInt, m: &BigInt) -> i8 {
    assert!(m.is_positive());
    assert!(m.is_odd());

    // After the reduction, we know that both a and m are positive
    let mut a = a.mod_floor(m).into_parts().1;
    let mut m = m.magnitude().clone();

    // The output
    let mut t = true;

    // The second bit of m
    let mut m_2nd_bit = m.bit(1);

    while !a.is_zero() {
        // Shift a to the right until odd and let s be the number of shifts
        let s_odd = into_odd_part(&mut a) & 1 != 0;

        // To check if m is 3 or 5 mod 8 we check that only one of the second and third bits are set
        if s_odd && (m_2nd_bit ^ m.bit(2)) {
            t = !t;
        }

        swap(&mut a, &mut m);

        // a and m have been swapped
        let a_2nd_bit = m_2nd_bit;
        m_2nd_bit = m.bit(1);

        // Check if both a and m are 3 mod 4
        if a_2nd_bit && m_2nd_bit {
            t = !t;
        }
        a.rem_assign(&m);
    }

    if m.is_one() {
        return if t { 1 } else { -1 };
    }
    0
}

/// Given an integer a, find the largest power of two s such that a = 2^s * b for some odd b. Set
/// a = b and return s.
fn into_odd_part(a: &mut BigUint) -> u8 {
    let mut s = 0;
    while a.is_even() {
        a.shr_assign(1);
        s += 1;
    }
    s
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    fn test_jacobi_single(a: &str, m: &str, expected: i8) {
        let a = BigInt::parse_bytes(a.as_bytes(), 10).unwrap();
        let m = BigInt::parse_bytes(m.as_bytes(), 10).unwrap();
        assert_eq!(super::jacobi(&a, &m), expected);
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
