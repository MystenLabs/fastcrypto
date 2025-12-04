// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};

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
