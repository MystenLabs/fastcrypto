use super::compact_display::CompactDisplay;
use test_case::test_case;

struct TestCase<'a> {
  tickets: &'a [u64],
  expected: &'a str,
}

#[test_case(
  &TestCase {
    tickets: &[],
    expected: "[]",
  };
  "empty"
)]
#[test_case(
  &TestCase {
    tickets: &[0],
    expected: "[[0; 1]]",
  };
  "one"
)]
#[test_case(
  &TestCase {
    tickets: &[2, 2, 2, 3, 3],
    expected: "[[2; 3], [3; 2]]",
  };
  "basic"
)]
#[test_case(
  &TestCase {
    tickets: &[3, 3, 2, 2, 2],
    expected: "[[3; 2], [2; 3]]",
  };
  "basic_rev"
)]
fn all(test_case: &TestCase) {
  assert_eq!(
    test_case.expected,
    CompactDisplay(test_case.tickets).to_string()
  );
}
