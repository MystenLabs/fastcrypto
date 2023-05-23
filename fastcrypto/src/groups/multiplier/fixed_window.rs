use crate::groups::multiplier::{integer_utils, DefaultMultiplier, ScalarMultiplier};
use crate::groups::{Doubling, GroupElement};
use crate::serde_helpers::ToFromByteArray;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem::size_of;

/// Performs scalar multiplication using a fixed window method. If the addition and doubling operations for
/// `G` are constant time, the `mul`  is also constant time. The `CACHE_SIZE` should ideally be a power of
/// two. The `SCALAR_SIZE` is the number of bytes in the byte representation of the scalar type `S`, and we
/// assume that the `S::from_bytes` method returns the scalar in little-endian format.
pub struct FixedWindowMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element, B, up to (2^WINDOW_WIDTH - 1) * B.
    cache: [G; CACHE_SIZE],
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > FixedWindowMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    /// The number of bits in the window. This is equal to the floor of the log2 of the cache size.
    const WINDOW_WIDTH: usize = 8 * size_of::<usize>() - CACHE_SIZE.leading_zeros() as usize - 1;

    /// Get the multiple `s * base_element` for a scalar `s` with `0 <= s < 2^Self::WINDOW_WIDTH`.
    /// If `s` is not in this range the method will panic.
    fn get_precomputed_multiple(&self, s: usize) -> G {
        self.cache[s]
    }
}

impl<
        G: GroupElement<ScalarType = S> + Doubling,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for FixedWindowMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        // Compute cache [0, base_element, 2 * base_element, ..., (2^WINDOW_WIDTH - 1) * base_element]
        let mut cache = [G::zero(); CACHE_SIZE];
        for i in 1..CACHE_SIZE {
            cache[i] = cache[i - 1] + base_element;
        }
        Self { cache }
    }

    fn mul(&self, scalar: &S) -> G {
        let scalar_bytes = scalar.to_byte_array();

        let limbs = integer_utils::compute_base_2w_expansion::<SCALAR_SIZE>(
            &scalar_bytes,
            Self::WINDOW_WIDTH,
        );

        // Number of digits in the base 2^window_size representation of the scalar
        let mut r: G = self.get_precomputed_multiple(limbs[limbs.len() - 1]);

        for i in (0..=(limbs.len() - 2)).rev() {
            for _ in 1..=Self::WINDOW_WIDTH {
                r = r.double();
            }
            r += self.get_precomputed_multiple(limbs[i]);
        }
        r
    }
}

trait SmallScalarMultiplier<G: GroupElement> {
    fn new(base_element: G) -> Self;
    fn mul(&self, scalar: usize) -> G;
}

/// NOT constant time
struct LazySmallMultiplier<G: GroupElement + Doubling> {
    cache: HashMap<usize, G>,
}

impl<G: GroupElement + Doubling> SmallScalarMultiplier<G> for LazySmallMultiplier<G> {
    fn new(base_element: G) -> Self {
        let mut multiplier = Self {
            cache: HashMap::new(),
        };
        multiplier.cache.insert(1, base_element);
        multiplier
    }

    fn mul(&self, scalar: usize) -> G {
        if scalar == 0 {
            return G::zero();
        }
        if self.cache.contains_key(&scalar) {
            return *self.cache.get(&scalar).unwrap();
        }
        let mut result = self.mul(scalar >> 1).double();
        if scalar % 2 == 1 {
            result += *self.cache.get(&1).unwrap();
        }
        result
    }
}

pub trait DoubleScalarMultiplier<G: GroupElement> {
    fn new(base_element: G) -> Self;
    fn mul(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G;
}

pub struct WrappingDoubleMultiplier<G: GroupElement, M: ScalarMultiplier<G>>(PhantomData<G>, M);

impl<G: GroupElement, M: ScalarMultiplier<G>> DoubleScalarMultiplier<G>
    for WrappingDoubleMultiplier<G, M>
{
    fn new(base_element: G) -> Self {
        Self(PhantomData::default(), M::new(base_element))
    }

    fn mul(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G {
        self.1.mul(base_scalar) + *other_element * other_scalar
    }
}

pub type DefaultDoubleMultiplier<G> = WrappingDoubleMultiplier<G, DefaultMultiplier<G>>;

/// NOT constant time
pub struct MyDoubleMultiplier<
    G: GroupElement<ScalarType = S> + Doubling,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
> {
    cache: FixedWindowMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>,
}

impl<
        G: GroupElement<ScalarType = S> + Doubling,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > DoubleScalarMultiplier<G> for MyDoubleMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        Self {
            cache: FixedWindowMultiplier::new(base_element),
        }
    }

    fn mul(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G {
        let scalar_bytes = base_scalar.to_byte_array();
        let other_scalar_bytes = other_scalar.to_byte_array();

        let window_width = 8 * size_of::<usize>() - CACHE_SIZE.leading_zeros() as usize - 1;

        let limbs =
            integer_utils::compute_base_2w_expansion::<SCALAR_SIZE>(&scalar_bytes, window_width);
        let other_limbs = integer_utils::compute_base_2w_expansion::<SCALAR_SIZE>(
            &other_scalar_bytes,
            window_width,
        );

        let lazy_multiplier = LazySmallMultiplier::new(*other_element);
        let mut r: G = self.cache.get_precomputed_multiple(limbs[limbs.len() - 1])
            + lazy_multiplier.mul(other_limbs[other_limbs.len() - 1]);

        for i in (0..=(limbs.len() - 2)).rev() {
            for _ in 1..=window_width {
                r = r.double();
            }
            r += self.cache.get_precomputed_multiple(limbs[i]);
            r += lazy_multiplier.mul(other_limbs[i]);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::secp256r1::{ProjectivePoint, Scalar};

    #[test]
    fn test_scalar_multiplication_ristretto() {
        let multiplier = FixedWindowMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32>::new(
            RistrettoPoint::generator(),
        );
        let scalar = RistrettoScalar::from(123456789);
        let expected = RistrettoPoint::generator() * scalar;
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_scalar_multiplication_secp256r1() {
        let scalar = Scalar::from(123456789);
        let expected = ProjectivePoint::generator() * scalar;

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 15, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 16, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 17, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 32, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 64, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 512, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_double_mul() {
        let multiplier = MyDoubleMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32>::new(
            RistrettoPoint::generator(),
        );

        let other_point = RistrettoPoint::generator() * RistrettoScalar::from(3);

        let a = RistrettoScalar::from(2345);
        let b = RistrettoScalar::from(6789);
        let expected = RistrettoPoint::generator() * a + other_point * b;
        let actual = multiplier.mul(&a, &other_point, &b);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_small_multiplier() {
        let multiplier = LazySmallMultiplier::<RistrettoPoint>::new(RistrettoPoint::generator());
        let expected = RistrettoPoint::generator() * RistrettoScalar::from(7);
        let actual = multiplier.mul(7);
        assert_eq!(expected, actual);
    }
}
