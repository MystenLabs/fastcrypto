mod iter_any;
#[cfg(test)]
mod iter_any_test;

#[cfg(test)]
mod exact_solution_tests;
#[cfg(test)]
pub mod proptest_util;

pub(super) mod enumerate;
pub(super) mod swiper_common;

#[cfg(test)]
pub(super) use exact_solution_tests::tests as exact_solution_tests;
pub(super) use iter_any::find as iter_any;
