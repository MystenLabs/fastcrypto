use super::gcd_wr::solve;
use crate::types::Ratio;
use test_case::test_case;

struct TestCase<'a> {
  alpha: Ratio,
  beta: Ratio,
  weights: &'a [u64],
  expected: Vec<u64>,
}

#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[1],
    expected: vec![1],
  };
  "one_weight"
)]
#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[5],
    expected: vec![1],
  };
  "one_large_weight"
)]
#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[1000, 1],
    expected: vec![1],
  };
  "one_small_one_large_weight"
)]
#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[30, 10, 10, 10, 10, 10, 10, 5, 5],
    expected: vec![2, 1, 1, 1, 1, 1, 1],
  };
  "basic"
)]
fn all(test_case: &TestCase) {
  assert_eq!(
    test_case.expected,
    solve(test_case.alpha, test_case.beta, test_case.weights),
  );
}
