use crate::class_group::{Discriminant, QuadraticForm};
use crate::hash_prime::{DefaultPrimalityCheck, PrimalityCheck};
use crate::math::crt::solve_equation;
use crate::math::jacobi;
use crate::math::modular::modular_square_root;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;
use num_bigint::{BigInt, UniformBigInt};
use num_integer::Integer;
use num_traits::Signed;
use rand::distributions::uniform::UniformSampler;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::{AddAssign, ShlAssign, Shr};

pub trait SampleModulus {
    /// Generate (a,b) deterministically from a seed such that a < sqrt(|discriminant|)/2 and b is
    /// the square root of the discriminant modulo a.
    fn sample_modulus(discriminant: &Discriminant, seed: &[u8]) -> (BigInt, BigInt);
}

impl QuadraticForm {
    /// Generate a random quadratic form from a seed with the given discriminant. This method is
    /// deterministic and has a large co-domain, meaning that it is unfeasible for an adversary to
    /// guess the output and that it is collision resistant. It is, however, not a random function
    /// since only a small subset of the output space is reachable, namely the numbers whose a coordinate
    /// is smaller than sqrt(|discriminant|)/2 and is the product of K primes all smaller than
    /// (sqrt(|discriminant|)/2)^{1/k}, and the function output is not uniform among these.
    pub fn from_seed(seed: &[u8], discriminant: &Discriminant, k: u16) -> Self {
        // Sample a and b such that a < sqrt(|discriminant|)/2 and b' is the square root of the
        // discriminant modulo a.
        let (a, mut b) = sample_modulus(discriminant, seed, k);

        // b must be odd
        if b.is_even() {
            b -= &a;
        }

        QuadraticForm::from_a_b_discriminant(a, b, discriminant)
            .expect("a and b are constructed such that this never fails")
    }
}

/// Sample a product of K primes and return this along with the square root of the discriminant modulo a.
fn sample_modulus(discriminant: &Discriminant, seed: &[u8], k: u16) -> (BigInt, BigInt) {
    // If a is smaller than this bound and |b| < a, the form is guaranteed to be reduced.
    let mut bound: BigInt = discriminant.0.abs().sqrt().shr(1);
    if k > 1 {
        bound = bound.nth_root(k as u32);
    }

    if bound < 8 * BigInt::from(k) * bound.bits() {
        panic!(
            "The bound, {}, is too small to sample {} distinct primes",
            bound, k
        );
    }

    // Seed a rng with the hash of the seed
    let mut rng = ChaCha8Rng::from_seed(Sha256::digest(seed).digest);
    let mut factors = Vec::with_capacity(k as usize);
    let mut square_roots = Vec::with_capacity(k as usize);

    for _ in 0..k {
        let mut factor;
        loop {
            factor = sample_odd(&bound, &mut rng);
            if !factors.contains(&factor)
                && jacobi::jacobi(&discriminant.0, &factor) == 1
                && DefaultPrimalityCheck::is_probable_prime(factor.magnitude())
            {
                // Found a valid factor
                break;
            }
        }
        let square_root = modular_square_root(&discriminant.0, &factor, false)
            .expect("Legendre symbol checked above");
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root =
        solve_equation(&square_roots, &factors).expect("The factors are distinct primes");

    (result, square_root)
}

/// Sample a random odd number in [1, bound)
fn sample_odd<R: Rng>(bound: &BigInt, rng: &mut R) -> BigInt {
    let mut a = UniformBigInt::new(BigInt::from(1), bound.clone().shr(1)).sample(rng);
    a.shl_assign(1);
    a.add_assign(1);
    a
}

#[cfg(test)]
mod tests {
    use crate::class_group::{Discriminant, QuadraticForm};
    use crate::Parameter;

    #[test]
    fn test_qf_from_seed() {
        let mut seed = [0u8; 32];
        let discriminant = Discriminant::from_seed(&seed, 512).unwrap();

        for _ in 0..10 {
            let qf = QuadraticForm::from_seed(&seed, &discriminant, 1);
            assert!(qf.is_reduced());
            assert_eq!(qf.discriminant(), discriminant);
            seed[0] += 1;
        }

        for _ in 0..10 {
            let qf = QuadraticForm::from_seed(&seed, &discriminant, 4);
            assert!(qf.is_reduced());
            assert_eq!(qf.discriminant(), discriminant);
            seed[0] += 1;
        }
    }
}
