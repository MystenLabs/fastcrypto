use crate::types::Ratio;

// Bound on the maximum total number of tickets that Swiper returns.
// n: number of parties
pub fn bound(alpha: Ratio, beta: Ratio, n: u64) -> u64 {
  (alpha * (Ratio::from_integer(1) - alpha) / (beta - alpha) * n).to_integer()
    + 1
}
