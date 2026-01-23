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

pub mod weight_reduction_checks;

// Type alias for rational numbers used in weight reduction
pub type Ratio = num_rational::Ratio<u64>;

// Helper functions for weight reduction calculations
fn calc_max_adv_weight(alpha: Ratio, total_weight: u64) -> u64 {
    (alpha * total_weight).to_integer()
}

fn calc_max_adv_weight_from_weights(alpha: Ratio, weights: &[u64]) -> u64 {
    calc_max_adv_weight(alpha, weights.iter().sum())
}

fn calc_adv_tickets_target(beta: Ratio, total_num_tickets: u64) -> u64 {
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

        if adv_tickets_target < self.dp.len() as u64 {
            return None;
        }

        let dp = self
            .dp
            .iter()
            .take(adv_tickets_target as usize)
            .copied()
            .collect_vec();

        Some(DP {
            max_weight: self.max_weight,
            adv_tickets_target,
            dp,
        })
    }

    /// Apply an element with weight w and t tickets. Returns None iff
    /// the configured adversarial tickets target is achieved.
    fn apply(mut self, w: u64, t: u64) -> Option<DP> {
        assert!(w > 0);

        if (w > self.max_weight) || (t == 0) {
            return Some(self);
        }
        let adv_tickets_target = self.adv_tickets_target as usize;
        if t as usize >= adv_tickets_target {
            return None;
        }

        for i in (1..self.dp.len()).rev() {
            if self.dp[i] != 0 {
                let accumulated_weight = self.dp[i] + w;
                let accumulated_tickets = i + t as usize;
                if accumulated_weight <= self.max_weight {
                    if accumulated_tickets >= adv_tickets_target {
                        return None;
                    }
                    if self.dp.len() <= accumulated_tickets {
                        self.dp.resize(accumulated_tickets + 1, 0);
                    }
                    if (accumulated_weight < self.dp[accumulated_tickets])
                        || (self.dp[accumulated_tickets] == 0)
                    {
                        self.dp[accumulated_tickets] = accumulated_weight;
                    }
                }
            }
        }

        let t = t as usize;
        if self.dp.len() <= t {
            self.dp.resize(t + 1, 0);
        }
        if (w < self.dp[t]) || (self.dp[t] == 0) {
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
        if index >= self.tickets.len() {
            self.tickets.resize(index + 1, 0);
        }
        self.tickets[index] += 1;
        self.total += 1;
    }

    fn get(&self, index: usize) -> u64 {
        self.tickets.get(index).copied().unwrap_or(0)
    }

    fn as_slice(&self) -> &[u64] {
        &self.tickets
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
fn calc_indices_head(tickets_len: usize, deltas: &[usize]) -> Vec<usize> {
    let exclude_indices = BTreeSet::from_iter(deltas.iter().copied());
    (0..tickets_len)
        .filter(|i| !exclude_indices.contains(i))
        .collect()
}

/// Calculates the DP data structure with indices applied that are not in `delta`s.
/// Returns None iff the DP head cannot be constructed which means
/// that the current batch should be skipped.
fn calc_dp_head(
    beta: Ratio,
    weights: &[u64],
    max_adv_weight: u64,
    deltas: &[usize],
    tickets: &Tickets,
) -> Option<DP> {
    let dp_head = DP::new(
        max_adv_weight,
        calc_adv_tickets_target(beta, tickets.total + deltas.len() as u64),
    )
    .unwrap();

    let indices_head = calc_indices_head(tickets.as_slice().len(), deltas);
    let dp_head = indices_head.into_iter().try_fold(dp_head, |dp, index| {
        dp.apply(weights[index], tickets.get(index))
    })?;

    Some(dp_head)
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
    let dp = dp_head.make_copy(adv_tickets_target)?;

    let exclude_set = BTreeSet::from_iter(exclude_indices.iter().copied());

    let dp = add_indices
        .iter()
        .copied()
        .filter(|index| !exclude_set.contains(index))
        .try_fold(dp, |dp, index| dp.apply(weights[index], tickets.get(index)))?;

    Some(dp)
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
        let adv_tickets_target = calc_adv_tickets_target(beta, tickets.total);
        assert_eq!(dp_head.adv_tickets_target, adv_tickets_target);
        return true;
    }

    // Number of tickets assignments in the left branch.
    let left_branch_size = (deltas.len() + 1) / 2;

    let (deltas_left, deltas_apply) = deltas.split_at(left_branch_size - 1);
    if let Some(dp) = apply(
        weights,
        dp_head,
        tickets,
        calc_adv_tickets_target(beta, tickets.total + deltas_left.len() as u64),
        deltas_apply,
        deltas_left,
    ) {
        if process_batch_recursive(beta, weights, deltas_left, &dp, tickets) {
            return true;
        }
    } else {
        // Apply the left deltas before continuing.
        tickets.update_many(deltas_left);
    }
    tickets.update(deltas_apply[0]);

    let (deltas_apply, deltas_right) = deltas.split_at(left_branch_size);
    if let Some(dp) = apply(
        weights,
        dp_head,
        tickets,
        calc_adv_tickets_target(beta, tickets.total + deltas_right.len() as u64),
        deltas_apply,
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
    let Some(dp_head) = calc_dp_head(beta, weights, max_adv_weight, deltas, tickets) else {
        // We are exiting early. Apply all of the deltas before that.
        tickets.update_many(deltas);
        return false;
    };

    process_batch_recursive(beta, weights, deltas, &dp_head, tickets)
}

pub fn solve(alpha: Ratio, beta: Ratio, weights: &[u64]) -> Vec<u64> {
    debug_assert!(weights.windows(2).all(|w| w[0] >= w[1]));

    let max_adv_weight = calc_max_adv_weight_from_weights(alpha, weights);

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
        let deltas: Vec<_> = (&mut g).take(batch_size - 1).collect();

        let ret = process_batch(beta, weights, max_adv_weight, &deltas, &mut tickets);
        if ret {
            return tickets.into_vec();
        }

        // Prevent overflow: cap batch_size at max_batch_size
        if batch_size >= max_batch_size {
            // If we've reached the maximum, continue with the same batch size
            // This should not happen in practice due to the theoretical guarantees,
            // but provides a safety net.
            continue;
        }
        batch_size = (batch_size * 2).min(max_batch_size);
    }
}

#[cfg(test)]
mod calc_indices_head_tail_tests {
    use super::calc_indices_head;
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
        let mut ret = calc_indices_head(test_case.tickets_len, test_case.deltas);
        test_case.expected.sort_unstable();
        ret.sort_unstable();
        assert_eq!(test_case.expected, ret);
    }
}

#[cfg(test)]
mod calc_dp_head_tests {
    use super::{calc_dp_head, Ratio, Tickets, DP};

    fn calc_dp_head_helper(
        beta: Ratio,
        weights: &[u64],
        max_adv_weight: u64,
        deltas: &[usize],
        tickets: &[u64],
    ) -> Option<DP> {
        let tickets = Tickets::from_vec(tickets.to_vec());
        calc_dp_head(beta, weights, max_adv_weight, deltas, &tickets)
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
}
