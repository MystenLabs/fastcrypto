use super::util::proptest_util::input;
use super::util::swiper_common;
use crate::types::Ratio;
use crate::util::basic::{
  calc_adv_tickets_target, calc_max_adv_weight_from_weights,
};
use crate::util::knapsack::is_valid;
use proptest::prelude::*;

fn simple_faster_swiper(
  alpha: Ratio,
  beta: Ratio,
  weights: &[u64],
) -> Vec<u64> {
  let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);
  let bound = swiper_common::bound(alpha, beta, weights.len() as u64);

  let mut tickets = swiper_common::Tickets::new();
  let mut deltas = Vec::new();
  let mut g = swiper_common::generate_deltas(weights, alpha);
  {
    let index = g.next().unwrap();
    tickets.update(index);
    deltas.push(index);
  }

  let mut l = 0u64;
  let mut r = 1u64;
  while !is_valid(
    weights,
    tickets.data(),
    max_adv_weight,
    calc_adv_tickets_target(beta, tickets.total()),
  ) {
    l = r;
    r *= 2;
    if r >= bound {
      r = bound;
    }
    for index in (&mut g).take((r - l) as usize) {
      tickets.update(index);
      deltas.push(index);
    }
  }

  // Here, l tickets are not sufficient but r tickets are.

  while r - l > 1 {
    let m = (l + r) / 2;

    tickets.clear();
    for &index in deltas.iter().take(m as usize) {
      tickets.update(index);
    }

    let valid = is_valid(
      weights,
      tickets.data(),
      max_adv_weight,
      calc_adv_tickets_target(beta, m),
    );
    if valid {
      r = m;
    } else {
      l = m;
    }
  }

  tickets.clear();
  for &index in deltas.iter().take(r as usize) {
    tickets.update(index);
  }

  tickets.extract_data()
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(1000))]
  #[test]
  fn against_swiper(input in input()) {
    assert_eq!(
      simple_faster_swiper(input.alpha, input.beta, &input.weights),
      super::faster_swiper::solve(input.alpha, input.beta, &input.weights),
    );
  }
}
