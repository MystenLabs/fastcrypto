use crate::math::extended_gcd::extended_euclidean_algorithm;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed};

/// Find the unique x such that x = a mod p and x = b mod q for relatively prime p and q and 0 <= x
/// < pq.
pub fn solve_simple_equation(a: &BigInt, p: &BigInt, b: &BigInt, q: &BigInt) -> Option<BigInt> {
    if !p.is_positive() || !q.is_positive() {
        return None;
    }

    // The moduli must be relatively prime
    let output = extended_euclidean_algorithm(p, q);
    if !output.gcd.is_one() {
        return None;
    }

    let a = a.mod_floor(p);
    let b = b.mod_floor(q);

    let result = a * output.y * q + b * output.x * p;

    if result.is_negative() {
        Some(result + &(p * q))
    } else {
        Some(result)
    }
}

/// Find the unique x such that x = a_i mod p_i for relatively prime p_i and 0 <= x < Prod p_i.
pub fn solve_equation(a: &Vec<BigInt>, p: &Vec<BigInt>) -> Option<BigInt> {
    assert_eq!(a.len(), p.len());
    match a.len() {
        0 => None,
        1 => Some(a[0].clone()),
        2 => solve_simple_equation(&a[0], &p[0], &a[1], &p[1]),
        _ => {
            let x = solve_simple_equation(&a[0], &p[0], &a[1], &p[1])?;
            let y = solve_equation(&a[2..].to_vec(), &p[2..].to_vec())?;
            solve_simple_equation(&x, &(&p[0] * &p[1]), &y, &p[2..].iter().product())
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

        let x = super::solve_simple_equation(&a, &p, &b, &q).unwrap();
        assert_eq!(x, BigInt::from(18));
    }

    #[test]
    fn test_crt() {
        let a = vec![0, 3, 4].into_iter().map(BigInt::from).collect();
        let p = vec![3, 4, 5].into_iter().map(BigInt::from).collect();
        let x = super::solve_equation(&a, &p).unwrap();
        assert_eq!(x, BigInt::from(39));
    }
}
