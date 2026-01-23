// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The implementation of the algorithms presented in the paper
//! Weight reduction in distributed protocols: new algorithms and analysis
//! [paper](https://eprint.iacr.org/2025/1076).
//! Adapted from: https://github.com/tolikzinovyev/weight-reduction

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use itertools::Itertools;
use std::cmp::Ordering;
use std::collections::{BTreeSet, BinaryHeap};
use std::ops::Index;

pub mod weight_reduction_checks;

// Type alias for rational numbers used in weight reduction
pub type Ratio = num_rational::Ratio<u64>;

// Helper functions for weight reduction calculations
fn max_adv_weight(alpha: Ratio, total_weight: u64) -> u64 {
    (alpha * total_weight).to_integer()
}

fn max_adv_weight_from_weights(alpha: Ratio, weights: &[u64]) -> u64 {
    max_adv_weight(alpha, weights.iter().sum())
}

fn adv_tickets_target(beta: Ratio, total_num_tickets: u64) -> u64 {
    (beta * total_num_tickets).ceil().to_integer()
}

// Dynamic Programming data structure for knapsack calculations
#[derive(Debug)]
struct DP {
    max_weight: u64,
    adv_tickets_target: u64,
    dp: Vec<u64>,
}

impl DP {
    /// Create a knapsack dynamic programming data with configured max weight
    /// and adversarial tickets target. Returns None only when it's immediately
    /// clear we can achieve the adversarial tickets target -- if and only if
    /// adv_tickets_target = 0.
    fn new(max_weight: u64, adv_tickets_target: u64) -> Option<DP> {
        if adv_tickets_target == 0 {
            return None;
        }
        Some(DP {
            max_weight,
            adv_tickets_target,
            dp: vec![0],
        })
    }

    /// Create a copy of the data structure with a new configured adversarial
    /// tickets target. It must be less or equal to the previously configured
    /// adversarial tickets target. Returns None iff the new adversarial tickets
    /// target has already been achieved.
    fn make_copy(&self, adv_tickets_target: u64) -> Option<DP> {
        assert!(adv_tickets_target <= self.adv_tickets_target);

        if self.dp.len() > adv_tickets_target as usize {
            return None;
        }

        Some(DP {
            max_weight: self.max_weight,
            adv_tickets_target,
            dp: self.dp.clone(),
        })
    }

    /// Apply an element with weight w and t tickets. Returns None iff
    /// the configured adversarial tickets target is achieved.
    fn apply(mut self, w: u64, t: u64) -> Option<DP> {
        assert!(w > 0);

        if w > self.max_weight || t == 0 {
            return Some(self);
        }
        if t >= self.adv_tickets_target {
            return None;
        }

        for i in (1..self.dp.len()).rev() {
            if self.dp[i] != 0 {
                let accumulated_weight = self.dp[i] + w;
                let accumulated_tickets = i + t as usize;
                if accumulated_weight <= self.max_weight {
                    if accumulated_tickets >= self.adv_tickets_target as usize {
                        return None;
                    }
                    ensure_size(&mut self.dp, accumulated_tickets + 1);
                    if accumulated_weight < self.dp[accumulated_tickets]
                        || self.dp[accumulated_tickets] == 0
                    {
                        self.dp[accumulated_tickets] = accumulated_weight;
                    }
                }
            }
        }

        let t = t as usize;
        ensure_size(&mut self.dp, t + 1);
        if w < self.dp[t] || self.dp[t] == 0 {
            self.dp[t] = w;
        }

        Some(self)
    }

    /// Returns the maximum achievable adversarial number of tickets.
    #[cfg(test)]
    fn adversarial_tickets(&self) -> u64 {
        self.dp
            .iter()
            .rposition(|&w| w != 0)
            .map(|t| t as u64)
            .unwrap_or(0)
    }
}

// Tickets data structure for managing ticket assignments
#[derive(Debug, Clone)]
struct Tickets {
    tickets: Vec<u64>,
    total: u64,
}

impl Tickets {
    fn new() -> Self {
        Self {
            tickets: Vec::new(),
            total: 0,
        }
    }

    fn update(&mut self, index: usize) {
        ensure_size(&mut self.tickets, index + 1);
        self.tickets[index] += 1;
        self.total += 1;
    }

    fn into_vec(self) -> Vec<u64> {
        self.tickets
    }

    fn update_many(&mut self, indices: &[usize]) {
        for &index in indices {
            self.update(index);
        }
    }

    #[cfg(test)]
    fn from_vec(tickets: Vec<u64>) -> Self {
        let total = tickets.iter().sum();
        Self { tickets, total }
    }
}

impl Index<usize> for Tickets {
    type Output = u64;
    fn index(&self, index: usize) -> &u64 {
        self.tickets.get(index).unwrap_or(&0)
    }
}

// Helper types for generating deltas
#[derive(Eq, PartialEq)]
struct QueueElement {
    s: Ratio,
    i: usize,
}

impl Ord for QueueElement {
    fn cmp(&self, other: &Self) -> Ordering {
        other.s.cmp(&self.s).then(other.i.cmp(&self.i))
    }
}

impl PartialOrd for QueueElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct Generator<'a> {
    weights: &'a [u64],
    c: Ratio,
    r: usize,
    queue: BinaryHeap<QueueElement>,
}

impl<'a> Generator<'a> {
    fn new(weights: &'a [u64], c: Ratio) -> FastCryptoResult<Self> {
        debug_assert!(weights.windows(2).all(|w| w[0] >= w[1]));
        if weights.is_empty()
            || weights.last().copied().unwrap_or(0) == 0
            || c < 0.into()
            || c >= 1.into()
        {
            return Err(FastCryptoError::InvalidInput);
        }
        let queue = BinaryHeap::from([QueueElement {
            s: (Ratio::from_integer(1) - c) / Ratio::from_integer(*weights.first().unwrap()),
            i: 0,
        }]);

        Ok(Self {
            weights,
            c,
            r: 0,
            queue,
        })
    }
}

impl Iterator for Generator<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let QueueElement { s, i } = self.queue.pop()?;
        let new_value = (s * self.weights[i] + self.c).to_integer();

        self.queue.push(QueueElement {
            s: (Ratio::from_integer(new_value + 1) - self.c) / Ratio::from_integer(self.weights[i]),
            i,
        });
        if i == self.r && self.r + 1 < self.weights.len() {
            self.r += 1;
            self.queue.push(QueueElement {
                s: (Ratio::from_integer(1) - self.c) / Ratio::from_integer(self.weights[self.r]),
                i: self.r,
            });
        }

        Some(i)
    }
}

fn generate_deltas(weights: &[u64], c: Ratio) -> impl Iterator<Item = usize> + '_ {
    Generator::new(weights, c).expect("Invalid input to generate_deltas")
}

/// Calculates the head indices for the current batch.
fn indices_head(tickets_len: usize, deltas: &[usize]) -> impl Iterator<Item = usize> + '_ {
    set_minus(0..tickets_len, deltas.iter())
}

/// Calculates the DP data structure with indices applied that are not in `delta`s.
/// Returns None iff the DP head cannot be constructed which means
/// that the current batch should be skipped.
fn dp_head(
    beta: Ratio,
    weights: &[u64],
    max_adv_weight: u64,
    deltas: &[usize],
    tickets: &Tickets,
) -> Option<DP> {
    indices_head(tickets.tickets.len(), deltas)
        .into_iter()
        .try_fold(
            DP::new(
                max_adv_weight,
                adv_tickets_target(beta, tickets.total + deltas.len() as u64),
            )?,
            |dp, index| dp.apply(weights[index], tickets[index]),
        )
}

/// Apply those indices to dp_head that are in `add_indices` but not in
/// `exclude_indices`.
fn apply(
    weights: &[u64],
    dp_head: &DP,
    tickets: &Tickets,
    adv_tickets_target: u64,
    add_indices: &[usize],
    exclude_indices: &[usize],
) -> Option<DP> {
    set_minus(add_indices.iter().copied(), exclude_indices.iter())
        .try_fold(dp_head.make_copy(adv_tickets_target)?, |dp, i| {
            dp.apply(weights[i], tickets[i])
        })
}

/// Apply `deltas` to provided `tickets`. If after applying 0 or more
/// deltas, a valid ticket assignment is found, returns true with
/// `tickets` containing the corresponding ticket assignment.
/// Otherwise, returns false with `tickets` containing
/// the new ticket assignment after applying all deltas.
/// `dp_head` must have all indices applied except those in `deltas` with data
/// in `tickets`.
///
/// # Recursion Depth Bound
/// The recursion depth is bounded by O(log n) where n = `deltas.len()`, because:
/// - Each recursive call splits `deltas` roughly in half
/// - The base case is when `deltas.is_empty()`
/// - Maximum depth is approximately log₂(n) + 1
///
/// Since `deltas` comes from `batch_size - 1` in `solve()`, and `batch_size` grows
/// exponentially, the recursion depth grows logarithmically.
fn process_batch_recursive(
    beta: Ratio,
    weights: &[u64],
    deltas: &[usize],
    dp_head: &DP,
    tickets: &mut Tickets,
) -> bool {
    if deltas.is_empty() {
        // All indices in `deltas` were successfully applied without the adversary
        // winning. We found a solution.
        // Sanity check: `dp_head` must have the right target.
        assert_eq!(
            dp_head.adv_tickets_target,
            adv_tickets_target(beta, tickets.total)
        );
        return true;
    }

    // Number of tickets assignments in the left branch.
    let left_branch_size = (deltas.len() + 1) / 2;

    let deltas_left = &deltas[..left_branch_size - 1];
    if let Some(dp) = apply(
        weights,
        dp_head,
        tickets,
        adv_tickets_target(beta, tickets.total + deltas_left.len() as u64),
        deltas,
        deltas_left,
    ) {
        if process_batch_recursive(beta, weights, deltas_left, &dp, tickets) {
            return true;
        }
    } else {
        // Apply the left deltas before continuing.
        tickets.update_many(deltas_left);
    }
    tickets.update(deltas[left_branch_size - 1]);

    let deltas_right = &deltas[left_branch_size..];
    if let Some(dp) = apply(
        weights,
        dp_head,
        tickets,
        adv_tickets_target(beta, tickets.total + deltas_right.len() as u64),
        deltas,
        deltas_right,
    ) {
        process_batch_recursive(beta, weights, deltas_right, &dp, tickets)
    } else {
        // Apply the rest of the deltas before exiting.
        tickets.update_many(deltas_right);
        false
    }
}

/// Apply `deltas` to provided `tickets`. If after applying 0 or more
/// deltas a valid ticket assignment is found, returns true with
/// `tickets` containing the corresponding ticket assignment.
/// Otherwise, returns false with `tickets` containing
/// the new ticket assignment after applying all deltas.
fn process_batch(
    beta: Ratio,
    weights: &[u64],
    max_adv_weight: u64,
    deltas: &[usize],
    tickets: &mut Tickets,
) -> bool {
    let Some(dp_head) = dp_head(beta, weights, max_adv_weight, deltas, tickets) else {
        // We are exiting early. Apply all of the deltas before that.
        tickets.update_many(deltas);
        return false;
    };
    process_batch_recursive(beta, weights, deltas, &dp_head, tickets)
}

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
    debug_assert!(weights.windows(2).all(|w| w[0] >= w[1]));

    let max_adv_weight = max_adv_weight_from_weights(alpha, weights);

    let mut tickets = Tickets::new();
    let mut g = generate_deltas(weights, alpha);

    let mut batch_size: usize = 1;
    // This loop terminates because:
    // 1. The generator `g` is infinite (always produces deltas via the queue-based algorithm)
    // 2. We use exponential backoff: batch_size doubles each iteration (1, 2, 4, 8, ...)
    // 3. The algorithm is guaranteed to find a solution (by the paper's theoretical results)
    // 4. Once batch_size is large enough to include all deltas needed for a valid solution,
    //    `process_batch_recursive` will eventually return true when it successfully applies
    //    all deltas in the batch without the adversary winning (see the empty deltas base case)
    //
    // # Overflow Safety
    // The paper guarantees a solution with at most O(n) total tickets, where n = weights.len().
    // Since we need at most n indices (one per weight) to form a solution, `batch_size` will
    // never need to exceed n. We cap it at `weights.len()` to prevent overflow and ensure
    // termination even in edge cases.
    let max_batch_size = weights.len();
    loop {
        tickets.update(g.next().unwrap());
        let deltas = (&mut g).take(batch_size - 1).collect_vec();

        if process_batch(beta, weights, max_adv_weight, &deltas, &mut tickets) {
            return tickets.into_vec();
        }

        // Prevent overflow: cap batch_size at max_batch_size
        batch_size = (batch_size * 2).min(max_batch_size);
    }
}

/// If `vector` is smaller than `size`, append default values to match size.
/// Otherwise, do nothing.
fn ensure_size<T: Clone + Default>(vector: &mut Vec<T>, size: usize) {
    if vector.len() < size {
        vector.resize(size, T::default());
    }
}

/// Return all elements from `base` that is not in `to_exclude` in O(max(n log n, |base|)) time where `n = |to_exclude|`.
fn set_minus<'a, T: Ord + 'a>(
    base: impl Iterator<Item = T> + 'a,
    to_exclude: impl Iterator<Item = &'a T>,
) -> impl Iterator<Item = T> + 'a {
    let excluded = to_exclude.into_iter().collect::<BTreeSet<_>>();
    base.filter(move |i| !excluded.contains(i))
}

#[cfg(test)]
mod calc_indices_head_tail_tests {
    use super::indices_head;
    use itertools::Itertools;
    use test_case::test_case;

    struct TestCase<'a> {
        tickets_len: usize,
        deltas: &'a [usize],
        expected: Vec<usize>,
    }

    #[test_case(
    TestCase {
      tickets_len: 0,
      deltas: &[0, 1],
      expected: vec![],
    };
    "zero_tickets"
  )]
    #[test_case(
    TestCase {
      tickets_len: 5,
      deltas: &[1, 3],
      expected: vec![0, 2, 4],
    };
    "multiple_tickets"
  )]
    #[test_case(
    TestCase {
      tickets_len: 5,
      deltas: &[3, 3],
      expected: vec![0, 1, 2, 4],
    };
    "index_updated_multiple_times"
  )]
    #[test_case(
    TestCase {
      tickets_len: 5,
      deltas: &[0, 4],
      expected: vec![1, 2, 3],
    };
    "first_last_index_updated"
  )]
    fn all(mut test_case: TestCase<'_>) {
        let mut ret = indices_head(test_case.tickets_len, test_case.deltas).collect_vec();
        test_case.expected.sort_unstable();
        ret.sort_unstable();
        assert_eq!(test_case.expected, ret);
    }
}

#[cfg(test)]
mod calc_dp_head_tests {
    use super::{dp_head, solve, Ratio, Tickets, DP};

    fn calc_dp_head_helper(
        beta: Ratio,
        weights: &[u64],
        max_adv_weight: u64,
        deltas: &[usize],
        tickets: &[u64],
    ) -> Option<DP> {
        let tickets = Tickets::from_vec(tickets.to_vec());
        dp_head(beta, weights, max_adv_weight, deltas, &tickets)
    }

    #[test]
    fn zero_tickets() {
        let beta = Ratio::new(1, 2);
        let weights = &[20, 30];
        let max_adv_weight = 50;
        let deltas = &[0, 1];
        let tickets = &[];

        let dp = calc_dp_head_helper(beta, weights, max_adv_weight, deltas, tickets).unwrap();

        assert_eq!(0, dp.adversarial_tickets());
    }

    #[test]
    fn many_adversarial_tickets() {
        let beta = Ratio::new(1, 2);
        let weights = &[20, 30];
        let max_adv_weight = 50;
        let deltas = &[1, 2];
        let tickets = &[3];

        assert!(calc_dp_head_helper(beta, weights, max_adv_weight, deltas, tickets).is_none());
    }

    #[test]
    fn basic() {
        let beta = Ratio::new(1, 2);
        let weights = &[20, 30, 10, 10];
        let max_adv_weight = 50;
        let deltas = &[2, 5];
        let tickets = &[2, 3, 9, 1];

        let dp = calc_dp_head_helper(beta, weights, max_adv_weight, deltas, tickets).unwrap();

        assert_eq!(5, dp.adversarial_tickets());
    }

    #[test]
    fn test_reduction() {
        let alpha = Ratio::new(1, 3);
        let beta = Ratio::new(2, 5);
        let weights = &[
            391, 325, 286, 275, 255, 238, 235, 206, 206, 198, 193, 192, 192, 190, 188, 186, 186,
            185, 185, 185, 175, 169, 158, 158, 158, 158, 158, 151, 151, 146, 145, 144, 118, 110,
            98, 94, 89, 84, 76, 71, 71, 64, 63, 62, 62, 60, 59, 57, 57, 57, 54, 50, 50, 50, 49, 48,
            48, 48, 48, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 47, 45, 41, 40, 38, 38, 37,
            37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 36, 36, 36, 36, 36, 36, 36,
            36, 36, 36, 35, 35,
        ];
        let new_weights = solve(alpha, beta, weights);
        let expected = vec![
            7, 6, 5, 5, 5, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        assert_eq!(expected, new_weights);
    }
}
