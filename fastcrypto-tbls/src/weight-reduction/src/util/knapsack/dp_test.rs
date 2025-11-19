use super::dp::DP;

#[test]
fn new_zero_target() {
  assert!(DP::new(1, 0).is_none());
}

#[test]
fn new_basic() {
  assert!(DP::new(1, 1).is_some());
}

#[test]
fn make_copy_zero_target() {
  let dp = DP::new(1, 1).unwrap();
  assert!(dp.make_copy(0).is_none());
}

#[test]
fn make_copy_basic() {
  let mut dp = DP::new(2, 9).unwrap();
  dp = dp.apply(1, 5).unwrap();
  assert!(dp.make_copy(4).is_none());
  assert!(dp.make_copy(5).is_none());
  {
    let dp = dp.make_copy(6).unwrap();
    assert!(dp.apply(1, 1).is_none());
  }
  {
    let dp = dp.make_copy(8).unwrap();
    assert!(dp.make_copy(8).unwrap().apply(1, 2).is_some());
    assert!(dp.apply(1, 3).is_none());
  }
}

#[test]
fn apply_adversarial_tickets_basic() {
  let mut dp = DP::new(50, 9).unwrap();
  assert_eq!(0, dp.adversarial_tickets());
  dp = dp.apply(20, 3).unwrap();
  assert_eq!(3, dp.adversarial_tickets());
  dp = dp.apply(30, 4).unwrap();
  assert_eq!(7, dp.adversarial_tickets());
  dp = dp.apply(10, 2).unwrap();
  assert_eq!(7, dp.adversarial_tickets());
  dp = dp.apply(10, 2).unwrap();
  assert_eq!(8, dp.adversarial_tickets());
  assert!(dp.make_copy(9).unwrap().apply(10, 2).is_none());
  assert!(dp.apply(10, 3).is_none());
}

#[test]
fn apply_adversarial_tickets_large_weight() {
  let mut dp = DP::new(50, 9).unwrap();
  dp = dp.apply(51, 1).unwrap();
  assert_eq!(0, dp.adversarial_tickets());
  dp = dp.apply(3, 2).unwrap();
  assert_eq!(2, dp.adversarial_tickets());
  dp = dp.apply(51, 1).unwrap();
  assert_eq!(2, dp.adversarial_tickets());
}

#[test]
fn apply_adversarial_tickets_zero_tickets() {
  let mut dp = DP::new(50, 9).unwrap();
  dp = dp.apply(1, 0).unwrap();
  assert_eq!(0, dp.adversarial_tickets());
  dp = dp.apply(3, 2).unwrap();
  assert_eq!(2, dp.adversarial_tickets());
  dp = dp.apply(1, 0).unwrap();
  assert_eq!(2, dp.adversarial_tickets());
}

#[test]
fn apply_adversarial_tickets_large_ticket() {
  let dp = DP::new(50, 9).unwrap();
  assert!(dp.make_copy(9).unwrap().apply(1, 9).is_none());
  assert!(dp.apply(1, 10).is_none());
}

#[test]
fn adv_tickets_target_test() {
  let dp = DP::new(50, 9).unwrap();
  assert_eq!(9, dp.adv_tickets_target());
}
