use super::util::proptest_util::input;
use proptest::prelude::*;

proptest! {
  #![proptest_config(ProptestConfig::with_cases(300))]
  #[test]
  fn no_crash(input in input()) {
    super::swiper::solve(input.alpha, input.beta, &input.weights);
  }
}
