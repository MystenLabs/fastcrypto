#[cfg(test)]
mod exact_solution_tests;

pub(super) mod swiper_common;

#[cfg(test)]
pub(super) use exact_solution_tests::tests as exact_solution_tests;
