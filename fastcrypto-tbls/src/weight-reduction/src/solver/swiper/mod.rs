/// Reimplementation of the original Swiper implementation in Python.
mod knapsack;
#[cfg(test)]
mod knapsack_test;

use super::util::swiper_common;
use crate::solver::super_swiper::Ratio;
use crate::util::basic::{
  calc_adv_tickets_target, calc_max_adv_weight_from_weights,
};
use knapsack::is_valid;

type Ratio128 = num_rational::Ratio<u128>;

fn to_ratio_128(x: Ratio) -> Ratio128 {
  Ratio128::new(u128::from(*x.numer()), u128::from(*x.denom()))
}

fn average(a: Ratio, b: Ratio) -> Ratio128 {
  let a = to_ratio_128(a);
  let b = to_ratio_128(b);
  (a + b) / 2
}

fn map_fractional(w: u64, s: Ratio, c: Ratio) -> Ratio {
  s * w + c
}

fn map(w: u64, s: Ratio, c: Ratio) -> u64 {
  map_fractional(w, s, c).to_integer()
}

fn allocate(weights: &[u64], s: Ratio, c: Ratio) -> Vec<u64> {
  let mut res = Vec::with_capacity(weights.len());
  for &w in weights {
    res.push(map(w, s, c));
  }
  res
}

fn allocate128(weights: &[u64], s: Ratio128, c: Ratio) -> Vec<u64> {
  let c = to_ratio_128(c);

  let mut res = Vec::with_capacity(weights.len());
  for &w in weights {
    res.push((s * u128::from(w) + c).to_integer().try_into().unwrap());
  }
  res
}

fn round_down(weights: &[u64], tickets: &[u64], c: Ratio) -> Ratio {
  let f = |w, t| {
    let t = Ratio::from_integer(t);
    if t < c { Ratio::ZERO } else { (t - c) / w }
  };
  weights
    .iter()
    .zip(tickets)
    .map(|(&w, &t)| f(w, t))
    .max()
    .unwrap()
}

fn round_up(weights: &[u64], tickets: &[u64], c: Ratio) -> Ratio {
  weights
    .iter()
    .zip(tickets)
    .map(|(&w, &t)| (Ratio::from_integer(t + 1) - c) / w)
    .min()
    .unwrap()
}

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
  assert!(!weights.is_empty());
  debug_assert!(weights.is_sorted_by(|a, b| a >= b));

  let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);
  let bound = swiper_common::bound(alpha, beta, weights.len() as u64);

  let allocate = |s: Ratio| allocate(weights, s, alpha);
  let allocate128 = |s: Ratio128| allocate128(weights, s, alpha);
  let round_down = |tickets: &[u64]| round_down(weights, tickets, alpha);
  let round_up = |tickets: &[u64]| round_up(weights, tickets, alpha);
  let is_valid = |tickets: &[u64]| {
    is_valid(
      weights,
      tickets,
      max_adv_weight,
      calc_adv_tickets_target(beta, tickets.iter().sum()),
    )
  };

  let mut sl = Ratio::ZERO;
  let mut sr = Ratio::new(1, weights[0]);
  while allocate(sr).iter().copied().sum::<u64>() < bound {
    sl = sr;
    sr *= 2;
  }

  while sr != sl {
    let tickets = allocate128(average(sl, sr));

    if tickets.iter().sum::<u64>() >= bound {
      sr = round_down(&tickets);
      debug_assert!(is_valid(&allocate(sr)));
    } else {
      sl = round_up(&tickets);
    }
  }

  sl = Ratio::ZERO;
  while sr != sl {
    let tickets = allocate128(average(sl, sr));

    if is_valid(&tickets) {
      sr = round_down(&tickets);
      debug_assert!(is_valid(&allocate(sr)));
    } else {
      sl = round_up(&tickets);
    }
  }

  let mut border_set = Vec::new();
  let mut tickets_l = Vec::with_capacity(weights.len());
  for (i, &w) in weights.iter().enumerate() {
    let t = map(w, sr, alpha);
    let tt = if map_fractional(w, sr, alpha).is_integer() {
      border_set.push(i);
      t - 1
    } else {
      t
    };
    tickets_l.push(tt);
  }

  let mut kl = 0;
  let mut kr = {
    let total: u64 = tickets_l.iter().sum();
    assert!(total < bound);
    std::cmp::min(border_set.len(), (bound - total) as usize)
  };

  while kr - kl > 1 {
    let km = (kl + kr) / 2;

    let mut tickets = tickets_l.clone();
    for &i in border_set.iter().take(km) {
      tickets[i] += 1;
    }

    if is_valid(&tickets) {
      kr = km;
    } else {
      kl = km;
    }
  }

  let mut res = tickets_l;
  for &i in border_set.iter().take(kr) {
    res[i] += 1;
  }
  debug_assert!(res.iter().sum::<u64>() <= bound);
  debug_assert!(is_valid(&res));
  while *res.last().unwrap() == 0 {
    res.pop();
  }
  res
}
