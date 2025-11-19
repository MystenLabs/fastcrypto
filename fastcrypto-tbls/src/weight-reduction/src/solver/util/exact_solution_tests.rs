#[rustfmt::skip]
macro_rules! tests {
  ($solve_func:path) => {
    use crate::types::Ratio;
    use test_case::test_case;

    struct TestCase<'a> {
      alpha: Ratio,
      beta: Ratio,
      weights: &'a [u64],
      expected: Vec<u64>,
    }

    #[test_case(
      TestCase {
        alpha: Ratio::new(1, 3),
        beta: Ratio::new(1, 2),
        weights: &[1, 1, 1, 1],
        expected: vec![1, 1, 1],
      };
      "basic"
    )]
    #[test_case(
      TestCase {
        alpha: Ratio::new(5, 11),
        beta: Ratio::new(21, 30),
        weights: &[3, 2, 2, 2, 2],
        expected: vec![1, 1, 1],
      };
      "different_weights"
    )]
    #[test_case(
      TestCase {
        alpha: Ratio::new(2, 9),
        beta: Ratio::new(21, 90),
        weights: &[2, 2, 2, 1, 1, 1],
        expected: vec![2, 2, 2, 1, 1, 1],
      };
      "different_weights_in_output"
    )]
    fn all(test_case: TestCase) {
      assert_eq!(
        test_case.expected,
        $solve_func(test_case.alpha, test_case.beta, test_case.weights)
      );
    }
  };
}

pub(crate) use tests;
