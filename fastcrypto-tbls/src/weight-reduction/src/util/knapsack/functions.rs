use super::dp::DP;

fn make_dp(
  weights: &[u64],
  tickets: &[u64],
  max_weight: u64,
  adv_tickets_target: u64,
) -> Option<DP> {
  assert!(tickets.len() <= weights.len());
  debug_assert!(weights.iter().all(|&w| w > 0));
  debug_assert!(tickets.iter().all(|&t| t > 0));

  let mut dp = DP::new(max_weight, adv_tickets_target)?;

  for (&w, &t) in weights.iter().zip(tickets) {
    dp = dp.apply(w, t)?;
  }

  Some(dp)
}

// Returns the maximum number of adversarial tickets if it is strictly less than
// adv_tickets_target or None otherwise.
// All elements in weights and tickets must be positive.
pub fn adversarial_tickets(
  weights: &[u64],
  tickets: &[u64],
  max_weight: u64,
  adv_tickets_target: u64,
) -> Option<u64> {
  let dp = make_dp(weights, tickets, max_weight, adv_tickets_target)?;
  Some(dp.adversarial_tickets())
}

// Returns true iff the adversary cannot get adv_tickets_target tickets.
pub fn is_valid(
  weights: &[u64],
  tickets: &[u64],
  max_weight: u64,
  adv_tickets_target: u64,
) -> bool {
  make_dp(weights, tickets, max_weight, adv_tickets_target).is_some()
}
