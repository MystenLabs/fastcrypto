use super::sorted::*;
use test_case::test_case;

struct TestCase<'a> {
  n: u64,
  total_num_tickets: u64,
  expected: &'a [Vec<u64>],
}

#[test_case(
  &TestCase {
    n: 9,
    total_num_tickets: 0,
    expected: &[vec![]],
  };
  "zero_tickets"
)]
#[test_case(
  &TestCase {
    n: 9,
    total_num_tickets: 1,
    expected: &[vec![1]],
  };
  "one_ticket"
)]
#[test_case(
  &TestCase {
    n: 9,
    total_num_tickets: 2,
    expected: &[vec![1, 1], vec![2]],
  };
  "two_tickets"
)]
#[test_case(
  &TestCase {
    n: 9,
    total_num_tickets: 3,
    expected: &[vec![1, 1, 1], vec![2, 1], vec![3]],
  };
  "three_tickets"
)]
#[test_case(
  &TestCase {
    n: 9,
    total_num_tickets: 4,
    expected: &[vec![1, 1, 1, 1], vec![2, 1, 1], vec![2, 2], vec![3, 1], vec![4]],
  };
  "four_tickets"
)]
#[test_case(
  &TestCase {
    n: 2,
    total_num_tickets: 4,
    expected: &[vec![2, 2], vec![3, 1], vec![4]],
  };
  "four_tickets_small_n"
)]
#[test_case(
  &TestCase {
    n: 3,
    total_num_tickets: 5,
    expected: &[vec![2, 2, 1], vec![3, 1, 1], vec![3, 2], vec![4, 1], vec![5]],
  };
  "five_tickets_small_n"
)]
fn enumerate_all(test_case: &TestCase) {
  let ret: Vec<_> =
    enumerate(test_case.n, test_case.total_num_tickets).collect();
  assert_eq!(test_case.expected, ret);
}

#[test]
fn enumerate_infinite_basic() {
  let mut it = enumerate_infinite(4);
  assert_eq!(Some(vec![]), it.next());
  assert_eq!(Some(vec![1]), it.next());
  assert_eq!(Some(vec![1, 1]), it.next());
  assert_eq!(Some(vec![2]), it.next());
  assert_eq!(Some(vec![1, 1, 1]), it.next());
  assert_eq!(Some(vec![2, 1]), it.next());
  assert_eq!(Some(vec![3]), it.next());
}
