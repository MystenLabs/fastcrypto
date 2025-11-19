use super::iter_any::find;
use crate::types::Ratio;
use test_case::test_case;

fn to_iter(
  ticket_assignments: &[Vec<u64>],
) -> impl Iterator<Item = Vec<u64>> + use<'_> {
  ticket_assignments.iter().cloned()
}

struct TestCase<'a> {
  alpha: Ratio,
  beta: Ratio,
  weights: &'a [u64],
  ticket_assignments: &'a [Vec<u64>],
  expected: Option<Vec<u64>>,
}

#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[],
    ticket_assignments: &[],
    expected: None,
  };
  "no_solution"
)]
#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[1, 1, 1, 1],
    ticket_assignments: &[vec![2, 2, 2, 2], vec![1, 1, 1, 1]],
    expected: Some(vec![2, 2, 2, 2]),
  };
  "basic"
)]
#[test_case(
  &TestCase {
    alpha: Ratio::new(1, 3),
    beta: Ratio::new(1, 2),
    weights: &[1, 1, 1, 1],
    ticket_assignments: &[vec![1, 1], vec![1, 1, 1]],
    expected: Some(vec![1, 1, 1]),
  };
  "beta_condition"
)]
fn all(test_case: &TestCase) {
  let ret = find(
    test_case.alpha,
    test_case.beta,
    test_case.weights,
    to_iter(test_case.ticket_assignments),
  );
  assert_eq!(test_case.expected, ret);
}
