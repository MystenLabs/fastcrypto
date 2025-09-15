use fastcrypto::groups::GroupElement;

/// Construction from https://eprint.iacr.org/2023/1175.pdf
pub struct PascalMatrix {
    m: usize,
    n: usize,
}

impl PascalMatrix {
    pub fn new(m: usize, n: usize) -> Self {
        assert!(m <= n && m > 0);
        Self { m, n }
    }

    pub fn vector_mul<C: GroupElement>(&self, x: &[C]) -> Vec<C> {
        assert_eq!(x.len(), self.m);

        let mut buffer = x.to_vec();
        (0..self.m)
            .map(|_| {
                for j in (0..(self.n - 1)).rev() {
                    let (buffer, tail) = buffer.split_at_mut(j + 1);
                    buffer[j] += tail[0];
                }
                buffer[0]
            })
            .collect()
    }
}

pub struct UTPascalMatrix {
    m: usize,
    n: usize,
}

impl UTPascalMatrix {
    pub fn new(m: usize, n: usize) -> Self {
        assert!(m <= n && m > 0);
        Self { m, n }
    }

    pub fn vector_mul<C: GroupElement>(&self, x: &[C]) -> Vec<C> {
        assert_eq!(x.len(), self.m);

        let mut buffer = x.to_vec();
        (0..self.m)
            .map(|i| {
                for j in (i..(self.n - 1)).rev() {
                    let (buffer, tail) = buffer.split_at_mut(j + 1);
                    buffer[j] += tail[0];
                }
                buffer[i]
            })
            .collect()
    }
}

#[test]
fn test_small_pascal_matrix() {
    use fastcrypto::groups::bls12381::Scalar;

    let expected = [
        vec![1, 1, 1, 1],
        vec![1, 2, 3, 4],
        vec![1, 3, 6, 10],
        vec![1, 4, 10, 20],
    ];

    let pascal = PascalMatrix::new(4, 4);
    for i in 0..4 {
        let mut x = vec![Scalar::zero(); 4];
        x[i] = Scalar::generator();
        let y = pascal.vector_mul(&x);
        let y_expected = &expected[i]
            .iter()
            .map(|v| Scalar::from(*v as u128))
            .collect::<Vec<_>>();
        assert_eq!(&y, y_expected);
    }
}

#[test]
fn test_small_ut_pascal_matrix() {
    use fastcrypto::groups::bls12381::Scalar;

    // Returns transposed compared to paper, so lower triangular
    let expected = [
        vec![1, 0, 0, 0],
        vec![1, 1, 0, 0],
        vec![1, 2, 1, 0],
        vec![1, 3, 3, 1],
    ];

    let pascal = UTPascalMatrix::new(4, 4);
    for i in 0..4 {
        let mut x = vec![Scalar::zero(); 4];
        x[i] = Scalar::generator();
        let y = pascal.vector_mul(&x);
        let y_expected = &expected[i]
            .iter()
            .map(|v| Scalar::from(*v as u128))
            .collect::<Vec<_>>();
        assert_eq!(&y, y_expected);
    }

    let not_square = UTPascalMatrix::new(3, 4);
    let x = [Scalar::from(1), Scalar::from(2), Scalar::from(3)];
    let y = not_square.vector_mul(&x);
    // TODO: Construct actual test vectors
    let expected = [Scalar::from(6), Scalar::from(8), Scalar::from(3)];
    assert_eq!(y, expected);
}
