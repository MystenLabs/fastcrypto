use crate::types::Ratio;
use crate::util::basic::{
  calc_adv_tickets_target, calc_max_adv_weight_from_weights,
};
use crate::util::knapsack::is_valid;

pub fn find<I: IntoIterator<Item = Vec<u64>>>(
  alpha: Ratio,
  beta: Ratio,
  weights: &[u64],
  ticket_assignments: I,
) -> Option<Vec<u64>> {
  let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);

  for tickets in ticket_assignments {
    let total_num_tickets: u64 = tickets.iter().sum();
    let valid = is_valid(
      weights,
      &tickets,
      max_adv_weight,
      calc_adv_tickets_target(beta, total_num_tickets),
    );
    if valid {
      return Some(tickets);
    }
  }

  None
}
