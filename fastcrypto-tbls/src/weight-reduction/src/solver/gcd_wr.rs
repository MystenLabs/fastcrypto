use crate::types::Ratio;

fn adjusted_weight(w: u64, gcd: u64) -> u64 {
  let m = w % gcd;
  if m * 2 < gcd { w - m } else { w + gcd - m }
}

fn adjustment_distance(weights: &[u64], gcd: u64) -> u64 {
  weights
    .iter()
    .map(|&w| w.abs_diff(adjusted_weight(w, gcd)))
    .sum()
}

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
  debug_assert!(weights.is_sorted_by(|a, b| a >= b));
  assert!(!weights.is_empty());
  assert!(*weights.last().unwrap() > 0);

  let total_weight = weights.iter().sum::<u64>();
  let max_distance = ((beta - alpha) / (Ratio::from_integer(1) - beta)
    * total_weight)
    .ceil()
    .to_integer()
    - 1;

  let test = |gcd: u64| adjustment_distance(weights, gcd) <= max_distance;

  // Search for the largest gcd.

  // Initial value for gcd that must work.
  let mut l = std::cmp::max(2 * max_distance / (weights.len() as u64), 1);
  debug_assert!(test(l));
  let mut r = l * 2;

  while test(r) {
    l = r;
    r *= 2;
  }

  // Here, l is a gcd with good distance and r is a gcd with distance too large.

  while r - l > 1 {
    let m = (l + r) / 2;
    if test(m) {
      l = m;
    } else {
      r = m;
    }
  }

  let mut tickets = Vec::new();
  for &w in weights {
    let t = adjusted_weight(w, l) / l;
    if t == 0 {
      break;
    }
    tickets.push(t);
  }

  tickets
}
