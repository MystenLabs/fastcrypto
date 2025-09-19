// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::GroupElement;
use itertools::Itertools;

/// Lazy evaluation of Pascal matrix-vector multiplication, returning one element at a time.
/// Computing the next element takes O(h) group additions, where h is the height of the input column.
/// The construction is from https://eprint.iacr.org/2023/1175.pdf.
pub struct LazyPascalVectorMultiplier<C> {
    height: usize,
    buffer: Vec<C>,
    counter: usize,
}

impl<C: GroupElement> LazyPascalVectorMultiplier<C> {
    /// Create a new lazy Pascal vector iterator that will yield `height` elements.
    /// Panics if the input vector is shorter than `height` or if `height` is zero.
    pub fn new(height: usize, vector: Vec<C>) -> Self {
        assert!(height <= vector.len() && height > 0);
        Self {
            height,
            buffer: vector,
            counter: 0,
        }
    }

    /// The remaining number of elements this iterator will yield.
    fn remaining(&self) -> usize {
        self.height - self.counter
    }
}

impl<C: GroupElement> Iterator for LazyPascalVectorMultiplier<C> {
    type Item = C;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter >= self.height {
            return None;
        }
        for j in (0..self.buffer.len()).rev().skip(1) {
            let term = self.buffer[j + 1];
            *self.buffer.get_mut(j).unwrap() += term;
        }
        self.counter += 1;
        Some(self.buffer[0])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.height - self.counter;
        (remaining, Some(remaining))
    }
}

impl<C: GroupElement> ExactSizeIterator for LazyPascalVectorMultiplier<C> {}

/// Lazy evaluation of Pascal matrix multiplication, returning one element at a time.
/// Computing the next element takes O(h) group additions, where h is the height of the given columns.
/// The construction is from https://eprint.iacr.org/2023/1175.pdf.
pub struct LazyPascalMatrixMultiplier<C> {
    height: usize,
    buffers: Vec<Vec<C>>,
    current_vector: LazyPascalVectorMultiplier<C>,
}

impl<C: GroupElement> LazyPascalMatrixMultiplier<C> {
    /// Create a new lazy Pascal matrix iterator that will yield `height * columns.len()` elements.
    /// Panics if
    /// * `columns` is empty,
    /// * if the columns are not all of the same length which is at least `height`,
    /// * if `height` is zero.
    pub fn new(height: usize, columns: Vec<Vec<C>>) -> Self {
        assert!(!columns.is_empty());
        assert!(columns.iter().map(|c| c.len()).all_equal());

        let width = columns[0].len();
        assert!(height <= width && height > 0);

        let mut buffers = columns;
        Self {
            height,
            current_vector: LazyPascalVectorMultiplier::new(height, buffers.pop().unwrap()),
            buffers,
        }
    }

    fn remaining(&self) -> usize {
        self.current_vector.remaining() + self.buffers.len() * self.height
    }
}

impl<C: GroupElement> Iterator for LazyPascalMatrixMultiplier<C> {
    type Item = C;

    fn next(&mut self) -> Option<Self::Item> {
        match self.current_vector.next() {
            Some(v) => Some(v),
            None => {
                if self.buffers.is_empty() {
                    None
                } else {
                    self.current_vector =
                        LazyPascalVectorMultiplier::new(self.height, self.buffers.pop().unwrap());
                    self.current_vector.next()
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl<C: GroupElement> ExactSizeIterator for LazyPascalMatrixMultiplier<C> {}

#[test]
fn test_small_lazy_pascal_vector() {
    use fastcrypto::groups::bls12381::Scalar;

    let expected = [
        vec![1, 1, 1, 1],
        vec![1, 2, 3, 4],
        vec![1, 3, 6, 10],
        vec![1, 4, 10, 20],
        vec![1, 5, 15, 35],
    ];

    for i in 0..5 {
        let mut x = vec![Scalar::from(0u128); 5];
        x[i] = Scalar::from(1u128);
        let y = LazyPascalVectorMultiplier::new(4, x).collect::<Vec<_>>();
        assert_eq!(
            y,
            expected[i]
                .iter()
                .map(|&v| Scalar::from(v))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_small_lazy_pascal_matrix() {
    use fastcrypto::groups::bls12381::Scalar;

    let expected = [vec![1, 3, 6, 10], vec![1, 2, 3, 4], vec![1, 1, 1, 1]];

    let columns = (0..3)
        .map(|i| {
            let mut x = vec![Scalar::from(0u128); 7];
            x[i] = Scalar::from(1u128);
            x
        })
        .collect::<Vec<_>>();

    let y = LazyPascalMatrixMultiplier::new(4, columns);

    assert_eq!(y.len(), 12);

    let expected_flat: Vec<Scalar> = expected
        .iter()
        .flatten()
        .map(|&v| Scalar::from(v))
        .collect();
    assert_eq!(y.collect_vec(), expected_flat);
}

#[test]
fn test_large_lazy_pascal_matrix() {
    use fastcrypto::groups::bls12381::Scalar;

    let expected = [
        vec![1, 7, 28, 84, 210, 462, 924],
        vec![1, 6, 21, 56, 126, 252, 462],
        vec![1, 5, 15, 35, 70, 126, 210],
        vec![1, 4, 10, 20, 35, 56, 84],
        vec![1, 3, 6, 10, 15, 21, 28],
        vec![1, 2, 3, 4, 5, 6, 7],
        vec![1, 1, 1, 1, 1, 1, 1],
    ];

    let columns = (0..7)
        .map(|i| {
            let mut x = vec![Scalar::from(0u128); 7];
            x[i] = Scalar::from(1u128);
            x
        })
        .collect::<Vec<_>>();

    let y = LazyPascalMatrixMultiplier::new(7, columns);

    assert_eq!(y.len(), 49);

    let expected_flat: Vec<Scalar> = expected
        .iter()
        .flatten()
        .map(|&v| Scalar::from(v))
        .collect();
    assert_eq!(y.collect_vec(), expected_flat);
}

#[test]
fn random_test_vector() {
    use fastcrypto::groups::bls12381::Scalar;
    use fastcrypto::groups::Scalar as _;

    // Full 7x7 Pascal matrix for comparison.
    let p7 = [
        vec![1, 1, 1, 1, 1, 1, 1],
        vec![1, 2, 3, 4, 5, 6, 7],
        vec![1, 3, 6, 10, 15, 21, 28],
        vec![1, 4, 10, 20, 35, 56, 84],
        vec![1, 5, 15, 35, 70, 126, 210],
        vec![1, 6, 21, 56, 126, 252, 462],
        vec![1, 7, 28, 84, 210, 462, 924],
    ];

    let mut rng = rand::thread_rng();
    let v = (0..7).map(|_| Scalar::rand(&mut rng)).collect_vec();

    // Compute expected result using naive matrix-vector multiplication.
    let expected = p7
        .iter()
        .map(|row| {
            row.iter()
                .zip(&v)
                .map(|(&a, b)| Scalar::from(a) * b)
                .reduce(|a, b| a + b)
                .unwrap()
        })
        .collect_vec();

    let actual = LazyPascalVectorMultiplier::new(7, v).collect_vec();

    assert_eq!(actual, expected);
}
