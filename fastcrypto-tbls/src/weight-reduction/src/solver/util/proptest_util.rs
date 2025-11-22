use crate::solver::super_swiper::Ratio;
use proptest::prelude::*;

prop_compose! {
  fn alpha_beta_denom()(beta_d in 2..=5u64)
    (alpha_d in (beta_d + 1)..=(beta_d + 4), beta_d in Just(beta_d)) -> (u64, u64)
  {
    (alpha_d, beta_d)
  }
}

prop_compose! {
  fn alpha_beta()((alpha_d, beta_d) in alpha_beta_denom()) -> (Ratio, Ratio) {
    (Ratio::new(1, alpha_d), Ratio::new(1, beta_d))
  }
}

prop_compose! {
  fn weights()(mut weights in proptest::collection::vec(1..(1u64<<20), 1..100))
  -> Vec<u64>
  {
    weights.sort_unstable_by(|a, b| b.cmp(a));
    weights
  }
}

#[derive(Debug)]
pub struct Input {
  pub alpha: Ratio,
  pub beta: Ratio,
  pub weights: Vec<u64>,
}

prop_compose! {
  pub fn input()((alpha, beta) in alpha_beta(), weights in weights()) -> Input {
    Input{alpha, beta, weights}
  }
}
