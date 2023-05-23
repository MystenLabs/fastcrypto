use crate::groups::multiplier::integer_utils::div_ceil;
use crate::groups::multiplier::{integer_utils, ScalarMultiplier};
use crate::groups::{Doubling, GroupElement};
use crate::serde_helpers::ToFromByteArray;
use std::mem::size_of;

/// Performs scalar multiplication using a comb method. We must have HEIGHT >= ceil(SCALAR_SIZE * 8 / ceil(log2(WIDTH))
/// and the precomputation tables will be of size WIDTH x HEIGHT. Once precomputation has been done,
/// a scalar multiplication requires HEIGHT additions.
pub struct CombMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const WIDTH: usize,
    const HEIGHT: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element, B, up to WIDTH x HEIGHT - 1.
    cache: [[G; WIDTH]; HEIGHT],
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const WIDTH: usize,
        const HEIGHT: usize,
        const SCALAR_SIZE: usize,
    > CombMultiplier<G, S, WIDTH, HEIGHT, SCALAR_SIZE>
{
    /// The number of bits in the window. This is equal to the floor of the log2 of the `WIDTH`.
    const WINDOW_WIDTH: usize = 8 * size_of::<usize>() - WIDTH.leading_zeros() as usize - 1;

    /// Get 2^column * row * base_point.
    fn get_precomputed_multiple(&self, row: usize, column: usize) -> G {
        self.cache[row][column]
    }
}

impl<
        G: GroupElement<ScalarType = S> + Doubling,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const WIDTH: usize,
        const HEIGHT: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for CombMultiplier<G, S, WIDTH, HEIGHT, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        // Verify cache parameters
        let lower_limit = div_ceil(SCALAR_SIZE * 8, Self::WINDOW_WIDTH);
        if HEIGHT < lower_limit {
            panic!("Invalid parameters. HEIGHT needs to be at least {} with the given WIDTH and SCALAR_SIZE.", lower_limit);
        }

        let mut cache = [[G::zero(); WIDTH]; HEIGHT];

        // Compute cache [0, base_element, 2 * base_element, ..., (2^WINDOW_WIDTH - 1) * base_element]
        for j in 1..WIDTH {
            cache[0][j] = cache[0][j - 1] + base_element;
        }

        // Compute cache[i][j] = 2^i * j * base_element
        for i in 1..HEIGHT {
            for j in 0..WIDTH {
                cache[i][j] = cache[i - 1][j];
                for _ in 0..Self::WINDOW_WIDTH {
                    cache[i][j] = cache[i][j].double();
                }
            }
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
        let mut r: G = self.get_precomputed_multiple(0, limbs[0]);

        for i in 1..limbs.len() {
            r += self.get_precomputed_multiple(i, limbs[i]);
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
        let multiplier = CombMultiplier::<RistrettoPoint, RistrettoScalar, 16, 64, 32>::new(
            RistrettoPoint::generator(),
        );
        let scalar = RistrettoScalar::from(12345423);
        let expected = RistrettoPoint::generator() * scalar;
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_scalar_multiplication_secp256r1() {
        let scalar = Scalar::from(123456789);
        let expected = ProjectivePoint::generator() * scalar;

        let multiplier = CombMultiplier::<ProjectivePoint, Scalar, 16, 64, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = CombMultiplier::<ProjectivePoint, Scalar, 32, 52, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = CombMultiplier::<ProjectivePoint, Scalar, 64, 43, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        // Assert a panic due to setting the HEIGHT too small
        assert!(std::panic::catch_unwind(|| {
            CombMultiplier::<ProjectivePoint, Scalar, 16, 63, 32>::new(ProjectivePoint::generator())
        })
        .is_err());
    }
}
