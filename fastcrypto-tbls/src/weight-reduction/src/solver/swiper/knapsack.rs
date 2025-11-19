use std::cmp::min;

// Returns the maximum number of adversarial tickets if it is strictly less than
// adv_tickets_target or None otherwise. All elements in weights must be positive.
pub fn is_valid(
  weights: &[u64],
  tickets: &[u64],
  max_weight: u64,
  adv_tickets_target: u64,
) -> bool {
  // Reimplementation of solver/knapsack.py _knapsack_impl() of the original
  // Swiper implementation.

  assert!(tickets.len() == weights.len());
  debug_assert!(weights.iter().all(|&w| w > 0));

  for (&w, &t) in weights.iter().zip(tickets) {
    if (w <= max_weight) && (t >= adv_tickets_target) {
      return false;
    }
  }

  let mut dp: Vec<u64> = Vec::with_capacity(adv_tickets_target as usize + 1);
  dp.push(0);
  for _ in 0..adv_tickets_target {
    dp.push(u64::MAX);
  }

  for (&w, &t) in weights.iter().zip(tickets).filter(|&(_, &t)| t > 0) {
    for i in (0..dp.len()).rev() {
      if t >= i as u64 {
        dp[i] = min(dp[i], w);
      } else if dp[i - t as usize] != u64::MAX {
        dp[i] = min(dp[i], dp[i - t as usize] + w);
      }
    }
  }

  *dp.last().unwrap() > max_weight
}
