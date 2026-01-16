// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;

/// Calculate the maximum delta across top, bottom, and random validity checks.
///
/// # Parameters
/// - `t_prime`: Threshold in reduced weights (beta * total_new_weights)
/// - `old_weights`: Original weights (in original order)
/// - `reduced_weights`: Reduced weights (in original order)
/// - `t`: Input threshold (alpha * old_weights_total)
/// - `n_random`: Number of random subsets to test
///
/// # Returns
/// The maximum delta value from all checks, or None if t_prime cannot be reached
///
/// # Delta Calculation
/// For each validity check (top, bottom, or random):
/// 1. Take the top reduced weights to reach t' = beta * total_new_weights
/// 2. Let w1 = sum of old weights corresponding to the subset
/// 3. Then delta = w1 - t, where t is the input threshold
pub fn get_delta(
    t_prime: u64,
    old_weights: &[u64],
    reduced_weights: &[u64],
    t: u64,
    n_random: usize,
) -> Option<u64> {
    if old_weights.len() != reduced_weights.len() {
        return None;
    }

    // Helper function to calculate delta for a given sorted order
    let calculate_delta_for_subset = |indexed: &[(usize, u64, u64)]| -> Option<u64> {
        // Take reduced weights to reach t_prime
        let mut reduced_sum = 0u64;
        let mut subset_indices = Vec::new();

        for (idx, _old_w, red_w) in indexed {
            if reduced_sum >= t_prime {
                break;
            }
            reduced_sum += red_w;
            subset_indices.push(*idx);
        }

        // If we couldn't reach t_prime, return None
        if reduced_sum < t_prime {
            return None;
        }

        // Calculate w1 = sum of old weights corresponding to the subset
        let w1: u64 = subset_indices.iter().map(|&idx| old_weights[idx]).sum();

        // Calculate delta = w1 - t
        // Skip if delta would be negative (w1 < t)
        if w1 < t {
            return None;
        }

        let delta = w1 - t;
        Some(delta)
    };

    // Check top weights (sorted by reduced weight descending)
    let mut indexed_top: Vec<(usize, u64, u64)> = old_weights
        .iter()
        .enumerate()
        .zip(reduced_weights.iter())
        .map(|((i, &old_w), &red_w)| (i, old_w, red_w))
        .collect();
    indexed_top.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by reduced weight descending
    let delta_top = calculate_delta_for_subset(&indexed_top);

    // Check bottom weights (sorted by reduced weight ascending)
    let mut indexed_bot: Vec<(usize, u64, u64)> = old_weights
        .iter()
        .enumerate()
        .zip(reduced_weights.iter())
        .map(|((i, &old_w), &red_w)| (i, old_w, red_w))
        .collect();
    indexed_bot.sort_by(|a, b| a.2.cmp(&b.2)); // Sort by reduced weight ascending
    let delta_bot = calculate_delta_for_subset(&indexed_bot);

    // Generate n random subsets
    let mut delta_random = Vec::new();
    let mut rng = rand::thread_rng();

    for _ in 0..n_random {
        // Create a random permutation of indices
        let mut indexed_random: Vec<(usize, u64, u64)> = old_weights
            .iter()
            .enumerate()
            .zip(reduced_weights.iter())
            .map(|((i, &old_w), &red_w)| (i, old_w, red_w))
            .collect();

        // Shuffle randomly
        for i in 0..indexed_random.len() {
            let j = rng.gen_range(i..indexed_random.len());
            indexed_random.swap(i, j);
        }

        // Calculate delta for this random ordering
        if let Some(delta) = calculate_delta_for_subset(&indexed_random) {
            delta_random.push(delta);
        }
    }

    // If any validity check resulted in a negative delta (None), skip this solution
    // Top and bottom checks must both pass
    let delta_top_value = match delta_top {
        Some(d) => d,
        None => return None, // Top check had negative delta, skip solution
    };
    let delta_bot_value = match delta_bot {
        Some(d) => d,
        None => return None, // Bottom check had negative delta, skip solution
    };

    // All random subsets must pass (no negative deltas)
    if delta_random.len() < n_random {
        // Some random subsets were skipped due to negative delta, skip solution
        return None;
    }

    // Collect all delta values (all should be valid at this point)
    let mut all_deltas = Vec::new();
    all_deltas.push(delta_top_value);
    all_deltas.push(delta_bot_value);
    all_deltas.extend(delta_random);

    // Return the maximum delta
    Some(all_deltas.iter().fold(0u64, |a, &b| a.max(b)))
}
