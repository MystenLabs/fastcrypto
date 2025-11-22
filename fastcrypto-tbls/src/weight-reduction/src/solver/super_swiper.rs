use std::collections::BTreeSet;

use super::util::swiper_common::{Tickets, generate_deltas};
use crate::util::knapsack::DP;

// Type alias for rational numbers used in weight reduction
pub type Ratio = num_rational::Ratio<u64>;

// Helper functions for weight reduction calculations
fn calc_max_adv_weight(alpha: Ratio, total_weight: u64) -> u64 {
  (alpha * total_weight).to_integer()
}

fn calc_max_adv_weight_from_weights(alpha: Ratio, weights: &[u64]) -> u64 {
  calc_max_adv_weight(alpha, weights.iter().sum::<u64>())
}

fn calc_adv_tickets_target(beta: Ratio, total_num_tickets: u64) -> u64 {
  (beta * total_num_tickets).ceil().to_integer()
}

// Calculates the head indices for the current batch.
fn calc_indices_head(tickets_len: usize, deltas: &[usize]) -> Vec<usize> {
  let mut indices_tail = deltas.to_vec();
  indices_tail.sort_unstable_by(|a, b| b.cmp(a));
  indices_tail.dedup();

  let mut indices_head: Vec<_> = (0..tickets_len).collect();
  for &index in &indices_tail {
    if index < indices_head.len() {
      indices_head.swap_remove(index);
    }
  }

  indices_head
}

// Calculates the DP data structure with indices applied that are not in `delta`s.
// Returns None iff the DP head cannot be constructed which means
// that the current batch should be skipped.
fn calc_dp_head(
  beta: Ratio,
  weights: &[u64],
  max_adv_weight: u64,
  deltas: &[usize],
  tickets: &Tickets,
) -> Option<DP> {
  let mut dp_head = DP::new(
    max_adv_weight,
    calc_adv_tickets_target(beta, tickets.total() + deltas.len() as u64),
  )
  .unwrap();

  let indices_head = calc_indices_head(tickets.data().len(), deltas);
  for index in indices_head {
    dp_head = dp_head.apply(weights[index], tickets.get(index))?;
  }

  Some(dp_head)
}

// Apply those indices to dp_head that are in `add_indices` but not in
// `exclude_indices`.
fn apply(
  weights: &[u64],
  dp_head: &DP,
  tickets: &Tickets,
  adv_tickets_target: u64,
  add_indices: &[usize],
  exclude_indices: &[usize],
) -> Option<DP> {
  let mut dp = dp_head.make_copy(adv_tickets_target)?;

  let exclude_indices =
    exclude_indices.iter().copied().collect::<BTreeSet<_>>();
  let add_indices = add_indices.iter().copied().collect::<BTreeSet<_>>();

  for index in add_indices {
    if !exclude_indices.contains(&index) {
      dp = dp.apply(weights[index], tickets.get(index))?;
    }
  }

  Some(dp)
}

fn update_tickets(deltas: &[usize], tickets: &mut Tickets) {
  for &index in deltas {
    tickets.update(index);
  }
}

// Apply `deltas` to provided `tickets`. If after applying 0 or more
// deltas, a valid ticket assignment is found, returns true with
// `tickets` containing the corresponding ticket assignment.
// Otherwise, returns false with `tickets` containing
// the new ticket assignment after applying all deltas.
// `dp_head` must have all indices applied except those in `deltas` with data
// in `tickets`.
fn process_batch_recursive(
  beta: Ratio,
  weights: &[u64],
  deltas: &[usize],
  dp_head: &DP,
  tickets: &mut Tickets,
) -> bool {
  if deltas.is_empty() {
    // All indices in `deltas` were successfully applied without the adversary
    // winning. We found a solution.
    // Sanity check: `dp_head` must have the right target.
    let adv_tickets_target = calc_adv_tickets_target(beta, tickets.total());
    assert!(dp_head.adv_tickets_target() == adv_tickets_target);
    return true;
  }

  // Number of tickets assignments in the left branch.
  let left_branch_size = deltas.len().div_ceil(2);

  {
    let (deltas_left, deltas_apply) = deltas.split_at(left_branch_size - 1);
    if let Some(dp) = apply(
      weights,
      dp_head,
      tickets,
      calc_adv_tickets_target(beta, tickets.total() + deltas_left.len() as u64),
      deltas_apply,
      deltas_left,
    ) {
      if process_batch_recursive(beta, weights, deltas_left, &dp, tickets) {
        return true;
      }
    } else {
      // Apply the left deltas before continuing.
      update_tickets(deltas_left, tickets);
    }
    tickets.update(deltas_apply[0]);
  }

  {
    let (deltas_apply, deltas_right) = deltas.split_at(left_branch_size);
    if let Some(dp) = apply(
      weights,
      dp_head,
      tickets,
      calc_adv_tickets_target(
        beta,
        tickets.total() + deltas_right.len() as u64,
      ),
      deltas_apply,
      deltas_right,
    ) {
      process_batch_recursive(beta, weights, deltas_right, &dp, tickets)
    } else {
      // Apply the rest of the deltas before exiting.
      update_tickets(deltas_right, tickets);
      false
    }
  }
}

// Apply `deltas` to provided `tickets`. If after applying 0 or more
// deltas a valid ticket assignment is found, returns true with
// `tickets` containing the corresponding ticket assignment.
// Otherwise, returns false with `tickets` containing
// the new ticket assignment after applying all deltas.
fn process_batch(
  beta: Ratio,
  weights: &[u64],
  max_adv_weight: u64,
  deltas: &[usize],
  tickets: &mut Tickets,
) -> bool {
  let Some(dp_head) =
    calc_dp_head(beta, weights, max_adv_weight, deltas, tickets)
  else {
    // We are exiting early. Apply all of the deltas before that.
    update_tickets(deltas, tickets);
    return false;
  };

  process_batch_recursive(beta, weights, deltas, &dp_head, tickets)
}

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
  debug_assert!(weights.is_sorted_by(|a, b| a >= b));

  let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);

  let mut tickets = Tickets::new();
  let mut g = generate_deltas(weights, alpha);

  let mut batch_size: usize = 1;
  loop {
    tickets.update(g.next().unwrap());
    let deltas: Vec<_> = (&mut g).take(batch_size - 1).collect();

    let ret =
      process_batch(beta, weights, max_adv_weight, &deltas, &mut tickets);
    if ret {
      return tickets.extract_data();
    }

    batch_size *= 2;
  }
}

#[cfg(test)]
mod calc_indices_head_tail_tests {
  use super::calc_indices_head;
  use test_case::test_case;

  struct TestCase<'a> {
    tickets_len: usize,
    deltas: &'a [usize],
    expected: Vec<usize>,
  }

  #[test_case(
    TestCase {
      tickets_len: 0,
      deltas: &[0, 1],
      expected: vec![],
    };
    "zero_tickets"
  )]
  #[test_case(
    TestCase {
      tickets_len: 5,
      deltas: &[1, 3],
      expected: vec![0, 2, 4],
    };
    "multiple_tickets"
  )]
  #[test_case(
    TestCase {
      tickets_len: 5,
      deltas: &[3, 3],
      expected: vec![0, 1, 2, 4],
    };
    "index_updated_multiple_times"
  )]
  #[test_case(
    TestCase {
      tickets_len: 5,
      deltas: &[0, 4],
      expected: vec![1, 2, 3],
    };
    "first_last_index_updated"
  )]
  fn all(mut test_case: TestCase) {
    let mut ret = calc_indices_head(test_case.tickets_len, test_case.deltas);
    test_case.expected.sort_unstable();
    ret.sort_unstable();
    assert_eq!(test_case.expected, ret);
  }
}

#[cfg(test)]
mod calc_dp_head_tests {
  use super::Ratio;
  use crate::util::knapsack::DP;

  fn calc_dp_head(
    beta: Ratio,
    weights: &[u64],
    max_adv_weight: u64,
    deltas: &[usize],
    tickets: &[u64],
  ) -> Option<DP> {
    let tickets =
      crate::solver::util::swiper_common::Tickets::from_vec(tickets.to_vec());

    super::calc_dp_head(beta, weights, max_adv_weight, deltas, &tickets)
  }

  #[test]
  fn zero_tickets() {
    let beta = Ratio::new(1, 2);
    let weights = &[20, 30];
    let max_adv_weight = 50;
    let deltas = &[0, 1];
    let tickets = &[];

    let dp =
      calc_dp_head(beta, weights, max_adv_weight, deltas, tickets).unwrap();

    assert_eq!(0, dp.adversarial_tickets());
  }

  #[test]
  fn many_adversarial_tickets() {
    let beta = Ratio::new(1, 2);
    let weights = &[20, 30];
    let max_adv_weight = 50;
    let deltas = &[1, 2];
    let tickets = &[3];

    assert!(
      calc_dp_head(beta, weights, max_adv_weight, deltas, tickets).is_none()
    );
  }

  #[test]
  fn basic() {
    let beta = Ratio::new(1, 2);
    let weights = &[20, 30, 10, 10];
    let max_adv_weight = 50;
    let deltas = &[2, 5];
    let tickets = &[2, 3, 9, 1];

    let dp =
      calc_dp_head(beta, weights, max_adv_weight, deltas, tickets).unwrap();

    assert_eq!(5, dp.adversarial_tickets());
  }
}
