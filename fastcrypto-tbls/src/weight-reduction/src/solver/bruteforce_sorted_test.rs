use crate::types::Ratio;

fn solve_with_large_limit(
  alpha: Ratio,
  beta: Ratio,
  weights: &[u64],
) -> Vec<u64> {
  super::bruteforce_sorted::solve_with_limit(alpha, beta, weights, 99).unwrap()
}

mod solve_test {
  crate::solver::util::exact_solution_tests!(
    crate::solver::bruteforce_sorted::solve
  );
}

mod solve_with_limit_test {
  crate::solver::util::exact_solution_tests!(super::solve_with_large_limit);

  #[test]
  fn none() {
    let ret = crate::solver::bruteforce_sorted::solve_with_limit(
      Ratio::new(1, 3),
      Ratio::new(1, 2),
      &[1, 1, 1, 1],
      2,
    );
    assert!(ret.is_none());
  }
}
