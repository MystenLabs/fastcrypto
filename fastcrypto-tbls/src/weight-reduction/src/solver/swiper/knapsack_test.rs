use super::knapsack::is_valid;
use test_case::test_case;

struct TestCase<'a> {
  weights: &'a [u64],
  tickets: &'a [u64],
  max_weight: u64,
  expected_adv_num_tickets: u64,
}

#[test_case(
  &TestCase {
    weights: &[5, 4, 3],
    tickets: &[1, 1, 1],
    max_weight: 2,
    expected_adv_num_tickets: 0,
  };
  "selects_zero"
)]
#[test_case(
  &TestCase {
    weights: &[5, 4, 3],
    tickets: &[3, 2, 1],
    max_weight: 4,
    expected_adv_num_tickets: 2,
  };
  "selects_one"
)]
#[test_case(
  &TestCase {
    weights: &[5, 4, 3],
    tickets: &[3, 2, 1],
    max_weight: 8,
    expected_adv_num_tickets: 4,
  };
  "selects_two"
)]
#[test_case(
  &TestCase {
    weights: &[5, 4, 3],
    tickets: &[3, 2, 1],
    max_weight: 22,
    expected_adv_num_tickets: 6,
  };
  "selects_all"
)]
#[test_case(
  &TestCase {
    weights: &[],
    tickets: &[],
    max_weight: 9,
    expected_adv_num_tickets: 0,
  };
  "empty"
)]
#[test_case(
  &TestCase {
    weights: &[2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1],
    tickets: &[1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0],
    max_weight: 6,
    expected_adv_num_tickets: 3,
  };
  "ones_twos"
)]
fn all(test_case: &TestCase) {
  assert!(!is_valid(
    test_case.weights,
    test_case.tickets,
    test_case.max_weight,
    test_case.expected_adv_num_tickets,
  ));

  assert!(is_valid(
    test_case.weights,
    test_case.tickets,
    test_case.max_weight,
    test_case.expected_adv_num_tickets + 1,
  ));

  if test_case.expected_adv_num_tickets > 0 {
    assert!(!is_valid(
      test_case.weights,
      test_case.tickets,
      test_case.max_weight,
      test_case.expected_adv_num_tickets - 1,
    ));
  }
}
