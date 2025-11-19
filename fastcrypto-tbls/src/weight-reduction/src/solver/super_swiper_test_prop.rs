use super::util::proptest_util::input;
use super::util::swiper_common;
use crate::types::Ratio;
use crate::util::basic::{
  calc_adv_tickets_target, calc_max_adv_weight_from_weights,
};
use crate::util::knapsack::is_valid;
use proptest::prelude::*;

pub fn simple_extended_swiper(
  alpha: Ratio,
  beta: Ratio,
  weights: &[u64],
) -> Vec<u64> {
  let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);

  let mut tickets = swiper_common::Tickets::new();
  let mut g = swiper_common::generate_deltas(weights, alpha);

  while !is_valid(
    weights,
    tickets.data(),
    max_adv_weight,
    calc_adv_tickets_target(beta, tickets.total()),
  ) {
    let index = g.next().unwrap();
    tickets.update(index);
  }

  tickets.extract_data()
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(1000))]
  #[test]
  fn against_simple_extended_swiper(input in input()) {
    assert_eq!(
      simple_extended_swiper(input.alpha, input.beta, &input.weights),
      super::super_swiper::solve(input.alpha, input.beta, &input.weights),
    );
  }
}
