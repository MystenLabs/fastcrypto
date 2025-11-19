use super::deltas::generate;
use crate::types::Ratio;
use test_case::test_case;

struct TestCase<'a> {
  weights: &'a [u64],
  c: Ratio,
  expected: &'a [usize],
}

#[test_case(
  &TestCase {
    weights: &[9],
    c: 0.into(),
    expected: &[0, 0, 0],
  };
  "one_weight"
)]
#[test_case(
  &TestCase {
    weights: &[9, 2],
    c: 0.into(),
    expected: &[0, 0, 0, 0, 1, 0],
  };
  "two_weights"
)]
#[test_case(
  &TestCase {
    weights: &[9, 2],
    c: Ratio::new(1, 2),
    expected: &[0, 0, 1, 0],
  };
  "two_weights_c"
)]
#[test_case(
  &TestCase {
    weights: &[6, 6, 5, 3, 3, 3],
    c: 0.into(),
    expected: &[0, 1, 2, 0, 1, 3, 4, 5, 2, 0],
  };
  "index_ties"
)]
fn all(test_case: &TestCase) {
  let ret: Vec<_> = generate(test_case.weights, test_case.c)
    .take(test_case.expected.len())
    .collect();
  assert_eq!(test_case.expected, ret);
}
