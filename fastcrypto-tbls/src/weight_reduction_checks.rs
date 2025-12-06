// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use rand::Rng;

/// Helper function to check top nodes property (returns Result instead of asserting)
/// 
/// Checks that the top nodes (by weight) satisfy the alpha/beta property:
/// 1. Takes original weights in sorted decreasing order
/// 2. Computes the subset from left to right such that the total of the subset
///    is < alpha * total_original, but adding the next element would result
///    in total >= alpha * total_original
/// 3. Takes the corresponding reduced weights subset
/// 4. Checks that total of the subset < beta * total_reduced
/// 5. Checks that adding the next element would result in total >= beta * total_reduced
pub fn check_top_nodes_internal(
    original_weights_sorted: &[u64],
    reduced_weights_sorted: &[u64],
    alpha: num_rational::Ratio<u64>,
    beta: num_rational::Ratio<u64>,
    total_original: u64,
    total_reduced: u64,
) -> FastCryptoResult<()> {
    if original_weights_sorted.len() != reduced_weights_sorted.len() {
        return Err(FastCryptoError::InvalidInput);
    }

    let alpha_threshold = (alpha * total_original).to_integer();
    let mut subset_sum = 0u64;
    let mut subset_size = 0usize;
    
    for (i, &weight) in original_weights_sorted.iter().enumerate() {
        let new_sum = subset_sum + weight;
        if new_sum >= alpha_threshold {
            break;
        }
        subset_sum = new_sum;
        subset_size = i + 1;
    }
    
    // If subset is empty, that's okay - it means all weights are >= alpha threshold
    if subset_size == 0 {
        return Ok(());
    }
    
    if subset_sum >= alpha_threshold {
        return Err(FastCryptoError::InvalidInput);
    }
    
    if subset_size < original_weights_sorted.len() {
        let next_sum = subset_sum + original_weights_sorted[subset_size];
        if next_sum < alpha_threshold {
            return Err(FastCryptoError::InvalidInput);
        }
    }
    
    let reduced_subset: &[u64] = &reduced_weights_sorted[..subset_size];
    let reduced_subset_sum: u64 = reduced_subset.iter().sum();
    let beta_threshold = (beta * total_reduced).to_integer();
    
    if reduced_subset_sum >= beta_threshold {
        return Err(FastCryptoError::InvalidInput);
    }
    
    if subset_size < reduced_weights_sorted.len() {
        let next_reduced_sum = reduced_subset_sum + reduced_weights_sorted[subset_size];
        if next_reduced_sum < beta_threshold {
            let threshold_95_percent = (beta_threshold * 95) / 100;
            if next_reduced_sum < threshold_95_percent {
                return Err(FastCryptoError::InvalidInput);
            }
        }
    }
    
    Ok(())
}

/// Helper function to check bottom nodes property (returns Result instead of asserting)
/// 
/// Checks that the bottom nodes (by weight) satisfy the alpha/beta property:
/// Similar to check_top_nodes_internal but considers weights from smallest to largest
pub fn check_bot_nodes_internal(
    original_weights_sorted: &[u64],
    reduced_weights_sorted: &[u64],
    alpha: num_rational::Ratio<u64>,
    beta: num_rational::Ratio<u64>,
    total_original: u64,
    total_reduced: u64,
) -> FastCryptoResult<()> {
    if original_weights_sorted.len() != reduced_weights_sorted.len() {
        return Err(FastCryptoError::InvalidInput);
    }

    let alpha_threshold = (alpha * total_original).to_integer();
    let mut subset_sum = 0u64;
    let mut subset_size = 0usize;
    
    for (i, &weight) in original_weights_sorted.iter().enumerate() {
        let new_sum = subset_sum + weight;
        if new_sum >= alpha_threshold {
            break;
        }
        subset_sum = new_sum;
        subset_size = i + 1;
    }
    
    // If subset is empty, that's okay - it means all weights are >= alpha threshold
    if subset_size == 0 {
        return Ok(());
    }
    
    if subset_sum >= alpha_threshold {
        return Err(FastCryptoError::InvalidInput);
    }
    
    if subset_size < original_weights_sorted.len() {
        let next_sum = subset_sum + original_weights_sorted[subset_size];
        if next_sum < alpha_threshold {
            return Err(FastCryptoError::InvalidInput);
        }
    }
    
    let reduced_subset: &[u64] = &reduced_weights_sorted[..subset_size];
    let reduced_subset_sum: u64 = reduced_subset.iter().sum();
    let beta_threshold = (beta * total_reduced).to_integer();
    
    if reduced_subset_sum >= beta_threshold {
        return Err(FastCryptoError::InvalidInput);
    }
    
    if subset_size < reduced_weights_sorted.len() {
        let next_reduced_sum = reduced_subset_sum + reduced_weights_sorted[subset_size];
        if next_reduced_sum < beta_threshold {
            let threshold_80_percent = (beta_threshold * 80) / 100;
            if next_reduced_sum < threshold_80_percent {
                return Err(FastCryptoError::InvalidInput);
            }
        }
    }
    
    Ok(())
}

/// Validates weight reduction by checking both top and bottom nodes properties.
/// 
/// This function prepares sorted weights and validates that both the top nodes
/// (largest weights) and bottom nodes (smallest weights) satisfy the alpha/beta property.
/// 
/// # Parameters
/// - `original_weights`: Original weights from nodes (unsorted)
/// - `reduced_weights`: Reduced weights from nodes (unsorted)
/// - `alpha`: Ratio representing the adversarial weight fraction
/// - `beta`: Ratio representing the ticket target fraction
/// - `total_original`: Total of original weights
/// - `total_reduced`: Total of reduced weights
/// 
/// # Returns
/// `Ok(())` if both checks pass, `Err(InvalidInput)` otherwise
pub fn validate_weight_reduction(
    original_weights: &[u64],
    reduced_weights: &[u64],
    alpha: num_rational::Ratio<u64>,
    beta: num_rational::Ratio<u64>,
    total_original: u64,
    total_reduced: u64,
) -> FastCryptoResult<()> {
    // Prepare sorted weights for checking (descending for top nodes)
    let mut original_weights_sorted_desc: Vec<u64> = original_weights.to_vec();
    original_weights_sorted_desc.sort_by(|a, b| b.cmp(a));
    let mut reduced_weights_sorted_desc: Vec<u64> = reduced_weights.to_vec();
    reduced_weights_sorted_desc.sort_by(|a, b| b.cmp(a));

    // Prepare sorted weights for checking (ascending for bottom nodes)
    let mut original_weights_sorted_asc: Vec<u64> = original_weights.to_vec();
    original_weights_sorted_asc.sort();
    let mut reduced_weights_sorted_asc: Vec<u64> = reduced_weights.to_vec();
    reduced_weights_sorted_asc.sort();

    // Check top nodes property
    check_top_nodes_internal(
        &original_weights_sorted_desc,
        &reduced_weights_sorted_desc,
        alpha,
        beta,
        total_original,
        total_reduced,
    )?;

    // Check bottom nodes property
    check_bot_nodes_internal(
        &original_weights_sorted_asc,
        &reduced_weights_sorted_asc,
        alpha,
        beta,
        total_original,
        total_reduced,
    )?;

    Ok(())
}

/// Calculate slack for a given threshold t.
/// 
/// Checks both top and bottom reduced weights to reach t, plus n random subsets,
/// then calculates: slack = (w1 - alpha*old_weights_total)/w1
/// where w1 is the sum of old weights corresponding to the subset.
/// Returns the maximum slack from all checks.
/// 
/// # Parameters
/// - `t`: Threshold value (target sum of reduced weights)
/// - `old_weights`: Original weights (in original node order)
/// - `reduced_weights`: Reduced weights (in original node order)
/// - `alpha`: Alpha ratio
/// - `old_weights_total`: Total of old weights
/// - `n_random`: Number of random subsets to test (default: 2)
/// 
/// # Returns
/// The maximum slack value from all checks, or None if t cannot be reached
pub fn get_slack(
    t: u64,
    old_weights: &[u64],
    reduced_weights: &[u64],
    alpha: num_rational::Ratio<u64>,
    old_weights_total: u64,
    n_random: usize,
) -> Option<f64> {
    if old_weights.len() != reduced_weights.len() {
        return None;
    }

    // Helper function to calculate slack for a given sorted order
    let calculate_slack_for_subset = |indexed: &[(usize, u64, u64)]| -> Option<f64> {
        // Take reduced weights to reach t
        let mut reduced_sum = 0u64;
        let mut subset_indices = Vec::new();
        
        for (idx, _old_w, red_w) in indexed {
            if reduced_sum >= t {
                break;
            }
            reduced_sum += red_w;
            subset_indices.push(*idx);
        }

        // If we couldn't reach t, return None
        if reduced_sum < t {
            return None;
        }

        // Calculate w1 = sum of old weights corresponding to the subset
        let w1: u64 = subset_indices.iter().map(|&idx| old_weights[idx]).sum();
        
        if w1 == 0 {
            return None;
        }

        // Calculate slack = (w1 - alpha*old_weights_total)/w1
        let alpha_times_total = (alpha * old_weights_total).to_integer();
        if w1 < alpha_times_total {
            // If w1 < alpha*old_weights_total, slack would be negative, skip this subset
            return None;
        }
        
        let slack = (w1 - alpha_times_total) as f64 / alpha_times_total as f64;
        Some(slack)
    };

    // Check top weights (sorted by reduced weight descending)
    let mut indexed_top: Vec<(usize, u64, u64)> = old_weights
        .iter()
        .enumerate()
        .zip(reduced_weights.iter())
        .map(|((i, &old_w), &red_w)| (i, old_w, red_w))
        .collect();
    indexed_top.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by reduced weight descending
    let slack_top = calculate_slack_for_subset(&indexed_top);

    // Check bottom weights (sorted by reduced weight ascending)
    let mut indexed_bot: Vec<(usize, u64, u64)> = old_weights
        .iter()
        .enumerate()
        .zip(reduced_weights.iter())
        .map(|((i, &old_w), &red_w)| (i, old_w, red_w))
        .collect();
    indexed_bot.sort_by(|a, b| a.2.cmp(&b.2)); // Sort by reduced weight ascending
    let slack_bot = calculate_slack_for_subset(&indexed_bot);

    // Generate n random subsets
    let mut slack_random = Vec::new();
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
        
        // Calculate slack for this random ordering
        if let Some(slack) = calculate_slack_for_subset(&indexed_random) {
            slack_random.push(slack);
        }
    }

    // Collect all slack values
    let mut all_slacks = Vec::new();
    if let Some(top) = slack_top {
        all_slacks.push(top);
    }
    if let Some(bot) = slack_bot {
        all_slacks.push(bot);
    }
    all_slacks.extend(slack_random);

    // Return the maximum slack, or None if no valid slack was found
    if all_slacks.is_empty() {
        None
    } else {
        Some(all_slacks.iter().fold(0.0, |a, &b| a.max(b)))
    }
}
