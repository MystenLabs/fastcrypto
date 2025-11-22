use crate::solver::super_swiper::Ratio;

pub fn calc_max_adv_weight(alpha: Ratio, total_weight: u64) -> u64 {
  (alpha * total_weight).to_integer()
}

pub fn calc_max_adv_weight_from_weights(alpha: Ratio, weights: &[u64]) -> u64 {
  calc_max_adv_weight(alpha, weights.iter().sum::<u64>())
}

pub fn calc_adv_tickets_target(beta: Ratio, total_num_tickets: u64) -> u64 {
  (beta * total_num_tickets).ceil().to_integer()
}
