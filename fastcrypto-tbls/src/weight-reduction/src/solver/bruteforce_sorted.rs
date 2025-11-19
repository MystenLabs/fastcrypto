use super::util::enumerate::sorted::{enumerate, enumerate_infinite};
use super::util::iter_any;
use crate::types::Ratio;

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
  debug_assert!(weights.is_sorted_by(|a, b| a >= b));

  let tickets_it = enumerate_infinite(weights.len() as u64);
  iter_any(alpha, beta, weights, tickets_it).unwrap()
}

pub fn solve_with_limit(
  alpha: Ratio,
  beta: Ratio,
  weights: &[u64],
  max_total_num_tickets: u64,
) -> Option<Vec<u64>> {
  debug_assert!(weights.is_sorted_by(|a, b| a >= b));

  for total_num_tickets in 1..=max_total_num_tickets {
    let tickets_it = enumerate(weights.len() as u64, total_num_tickets);
    let ret = iter_any(alpha, beta, weights, tickets_it);
    if ret.is_some() {
      return ret;
    }
  }

  None
}
