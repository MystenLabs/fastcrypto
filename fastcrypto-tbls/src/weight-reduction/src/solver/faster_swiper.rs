use super::util::swiper_common;
use crate::types::Ratio;
use crate::util::basic::{
  calc_adv_tickets_target, calc_max_adv_weight_from_weights,
};
use crate::util::knapsack::{DP, is_valid};
use std::collections::BTreeSet;

// Returns true iff the ticket assignment in tickets is valid.
// dp_head must have exactly those indices applied that are not in indices_tail.
// indices_tail must produce distinct indices.
pub fn check_candidate<'a, I: IntoIterator<Item = &'a usize>>(
  weights: &[u64],
  tickets: &[u64],
  dp_head: &DP,
  indices_tail: I,
  adv_tickets_target: u64,
) -> bool {
  let Some(mut dp) = dp_head.make_copy(adv_tickets_target) else {
    return false;
  };

  for &index in indices_tail {
    if index < tickets.len() {
      dp = match dp.apply(weights[index], tickets[index]) {
        Some(x) => x,
        None => return false,
      };
    }
  }

  true
}

fn update(
  weights: &[u64],
  new_tickets: &swiper_common::Tickets,
  new_deltas: &[usize],
  mut dp_head: DP,
  mut indices_tail: BTreeSet<usize>,
) -> (DP, BTreeSet<usize>) {
  let new_indices_tail: BTreeSet<_> = new_deltas.iter().copied().collect();

  for &index in &indices_tail {
    if !new_indices_tail.contains(&index) {
      dp_head = dp_head
        .apply(weights[index], new_tickets.get(index))
        .unwrap();
    }
  }

  indices_tail = new_indices_tail;

  (dp_head, indices_tail)
}

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
  debug_assert!(weights.is_sorted_by(|a, b| a >= b));

  let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);
  let bound = swiper_common::bound(alpha, beta, weights.len() as u64);

  let mut tickets_r = swiper_common::Tickets::new();
  let mut deltas = Vec::new();
  let mut g = swiper_common::generate_deltas(weights, alpha);
  {
    let index = g.next().unwrap();
    tickets_r.update(index);
    deltas.push(index);
  }

  let mut l = 0u64;
  let mut r = 1u64;
  while !is_valid(
    weights,
    tickets_r.data(),
    max_adv_weight,
    calc_adv_tickets_target(beta, tickets_r.total()),
  ) {
    l = r;
    r *= 2;
    if r >= bound {
      r = bound;
    }
    for index in (&mut g).take((r - l) as usize) {
      tickets_r.update(index);
      deltas.push(index);
    }
  }

  // Here, l tickets are not sufficient but r tickets are.

  let mut tickets_l = tickets_r;
  tickets_l.clear();
  for &index in deltas.iter().take(l as usize) {
    tickets_l.update(index);
  }

  let mut deltas = &deltas[l as usize..];

  let mut indices_tail: BTreeSet<_> = deltas.iter().copied().collect();

  let mut dp_head =
    DP::new(max_adv_weight, calc_adv_tickets_target(beta, r)).unwrap();
  for (index, &t) in tickets_l.data().iter().enumerate() {
    if !indices_tail.contains(&index) {
      dp_head = dp_head.apply(weights[index], t).unwrap();
    }
  }

  while r - l > 1 {
    let m = (l + r) / 2;
    let adv_tickets_target = calc_adv_tickets_target(beta, m);

    let mut tickets_m = tickets_l.clone();
    for &index in &deltas[..(m - l) as usize] {
      tickets_m.update(index);
    }

    let valid = check_candidate(
      weights,
      tickets_m.data(),
      &dp_head,
      &indices_tail,
      adv_tickets_target,
    );

    if valid {
      deltas = &deltas[..(m - l) as usize];

      (dp_head, indices_tail) =
        update(weights, &tickets_l, deltas, dp_head, indices_tail);

      r = m;
    } else {
      tickets_l = tickets_m;
      deltas = &deltas[(m - l) as usize..];

      (dp_head, indices_tail) =
        update(weights, &tickets_l, deltas, dp_head, indices_tail);

      l = m;
    }
  }

  assert!(indices_tail.len() == 1);
  for index in indices_tail {
    tickets_l.update(index);
  }
  tickets_l.extract_data()
}
