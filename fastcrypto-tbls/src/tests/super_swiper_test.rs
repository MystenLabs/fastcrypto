// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Stand-alone test file for Nodes::new_super_swiper_reduced function
// Run with: clear && cargo test --package fastcrypto-tbls --lib test_reference_weights -- --nocapture

mod tests {
    use crate::ecies_v1;
    use crate::nodes::{Node, Nodes};
    use crate::weight_reduction_checks;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
    use num_rational::Ratio;
    use rand::thread_rng;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::fs::File;
    use std::io::Write;
    use zeroize::Zeroize;

    fn create_test_nodes<G>(weights: Vec<u16>) -> Vec<Node<G>>
    where
        G: GroupElement + Serialize + DeserializeOwned,
        G::ScalarType: FiatShamirChallenge + Zeroize,
    {
        let sk = ecies_v1::PrivateKey::<G>::new(&mut thread_rng());
        let pk = ecies_v1::PublicKey::<G>::from_private_key(&sk);
        weights
            .into_iter()
            .enumerate()
            .map(|(i, weight)| Node {
                id: i as u16,
                pk: pk.clone(),
                weight,
            })
            .collect()
    }

    // Helper function to load Sui validator weights from sui_real_all.dat
    fn load_sui_validator_weights() -> Vec<u64> {
        const WEIGHTS_DATA: &str = include_str!("../weight-reduction/data/sui_real_all.dat");
        WEIGHTS_DATA
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.parse::<u64>()
                    .unwrap_or_else(|_| panic!("Failed to parse weight: {}", line))
            })
            .collect()
    }

    fn scale_weights_to_u16(weights: &[u64]) -> Vec<u16> {
        if weights.is_empty() {
            return vec![];
        }
        // Calculate total weight first to ensure it fits in u16::MAX
        let total: u64 = weights.iter().sum();
        let max_weight = *weights.iter().max().unwrap();
        
        // Scale factor: we need to ensure both individual weights and total weight fit in u16
        let scale_for_max = if max_weight > u16::MAX as u64 {
            (max_weight as f64 / u16::MAX as f64).ceil() as u64
        } else {
            1
        };
        let scale_for_total = if total > u16::MAX as u64 {
            (total as f64 / u16::MAX as f64).ceil() as u64
        } else {
            1
        };
        let scale_factor = scale_for_max.max(scale_for_total);
        
        weights
            .iter()
            .map(|&w| {
                let scaled = (w / scale_factor.max(1)) as u16;
                // Ensure at least 1 if original was > 0
                scaled.max(1)
            })
            .collect()
    }

    /// Calculates the subset size for top nodes (for CSV generation purposes).
    /// 
    /// This function finds the subset size where:
    /// - Total < alpha * total_original
    /// - But adding next element would make total >= alpha * total_original
    /// 
    /// Returns the size of the subset (number of elements included)
    fn calculate_top_subset_size(
        original_weights_sorted: &[u64],
        alpha: Ratio<u64>,
        total_original: u64,
    ) -> usize {
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
        
        subset_size
    }

    #[test]
    fn test_reference_weights() {
        // Test with realistic validator weight distribution
        let sui_weights = load_sui_validator_weights();
        let scaled_weights = scale_weights_to_u16(&sui_weights);
        let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights);
        let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
        let original_total_weight = original_nodes.total_weight();
        let allowed_delta = 1000u16; // Not used but required for compatibility
        let total_weight_upper_bound = u16::MAX; // Use max value for this test

        let (reduced_nodes, new_t) = Nodes::new_super_swiper_reduced(
            nodes_vec,
            0, // t parameter is unused
            allowed_delta,
            total_weight_upper_bound,
        )
        .unwrap();

        // Print the reduced weights
        println!("\n=== Super Swiper Weight Reduction Results ===");
        println!("Original total weight: {}", original_total_weight);
        println!("Reduced total weight: {}", reduced_nodes.total_weight());
        println!("New threshold (new_t): {}", new_t);
        println!("Reduction ratio: {:.2}%", (reduced_nodes.total_weight() as f64 / original_total_weight as f64) * 100.0);
        println!("\nReduced weights by node:");
        for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            println!("  Node {}: {} -> {}", orig.id, orig.weight, red.weight);
        }
        println!("\nTotal new weight: {}", reduced_nodes.total_weight());
        println!("===================================\n");

        // Verify reduction occurred
        assert!(reduced_nodes.total_weight() < original_total_weight);
        assert!(reduced_nodes.total_weight() <= total_weight_upper_bound);

        // Verify threshold was adjusted correctly
        assert!(new_t > 0);
        // new_t should be approximately beta * total_reduced_weight (beta starts at 34/100)
        // Allow for rounding differences (within 1)
        let expected_t_min = ((34u32 * reduced_nodes.total_weight() as u32) / 100u32) as u16;
        let expected_t_max = ((41u32 * reduced_nodes.total_weight() as u32) / 100u32) as u16;
        assert!(
            new_t >= expected_t_min.saturating_sub(1) && new_t <= expected_t_max + 1,
            "new_t ({}) should be approximately beta * total_reduced_weight (expected range: {} - {})",
            new_t,
            expected_t_min,
            expected_t_max
        );

        // Verify all node IDs are preserved
        assert_eq!(original_nodes.num_nodes(), reduced_nodes.num_nodes());
        for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            assert_eq!(orig.id, red.id);
            assert_eq!(orig.pk, red.pk);
            assert!(red.weight <= orig.weight);
        }

        // Note: check_top_nodes and check_bot_nodes are now done internally by new_super_swiper_reduced
    }

    fn write_weights_csv(
        sui_weights: &[u64],
        scaled_weights: &[u16],
        reduced_weights: &[u16],
        alpha_numer: u64,
        alpha_denom: u64,
        beta_numer: u64,
        beta_denom: u64,
        subset_size: usize,
        filename: &str,
    ) -> std::io::Result<()> {
        let mut file = File::create(filename)?;
        
        // Write header with alpha and beta (using original values, not simplified)
        writeln!(file, "alpha,{}/{}", alpha_numer, alpha_denom)?;
        writeln!(file, "beta,{}/{}", beta_numer, beta_denom)?;
        writeln!(file)?;
        
        // Calculate totals for percentage calculations
        let scaled_total: u64 = scaled_weights.iter().map(|&w| w as u64).sum();
        let reduced_total: u64 = reduced_weights.iter().map(|&w| w as u64).sum();
        
        // Write CSV header
        writeln!(file, "Sui Validator Weight,Scaled Weight,Scaled Weight %,Reduced Weight,Reduced Weight %,In Top Scaled,In Top Reduced")?;
        
        // Create sorted indices to map back to original order
        let mut scaled_with_indices: Vec<(usize, u16)> = scaled_weights.iter().enumerate().map(|(i, &w)| (i, w)).collect();
        scaled_with_indices.sort_by(|a, b| b.1.cmp(&a.1));
        
        let mut reduced_with_indices: Vec<(usize, u16)> = reduced_weights.iter().enumerate().map(|(i, &w)| (i, w)).collect();
        reduced_with_indices.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Create sets of indices that are in the top subset
        let top_scaled_indices: std::collections::HashSet<usize> = scaled_with_indices[..subset_size]
            .iter()
            .map(|(idx, _)| *idx)
            .collect();
        let top_reduced_indices: std::collections::HashSet<usize> = reduced_with_indices[..subset_size]
            .iter()
            .map(|(idx, _)| *idx)
            .collect();
        
        // Write data rows (in original order)
        for i in 0..sui_weights.len() {
            let sui_weight = sui_weights[i];
            let scaled_weight = scaled_weights[i];
            let reduced_weight = reduced_weights[i];
            let scaled_weight_pct = if scaled_total > 0 {
                (scaled_weight as f64 / scaled_total as f64) * 100.0
            } else {
                0.0
            };
            let reduced_weight_pct = if reduced_total > 0 {
                (reduced_weight as f64 / reduced_total as f64) * 100.0
            } else {
                0.0
            };
            let in_top_scaled = if top_scaled_indices.contains(&i) { "Yes" } else { "No" };
            let in_top_reduced = if top_reduced_indices.contains(&i) { "Yes" } else { "No" };
            
            writeln!(
                file, 
                "{},{},{:.4},{},{:.4},{},{}", 
                sui_weight, 
                scaled_weight, 
                scaled_weight_pct,
                reduced_weight, 
                reduced_weight_pct,
                in_top_scaled, 
                in_top_reduced
            )?;
        }
        
        // Write totals
        writeln!(file)?;
        let sui_total: u64 = sui_weights.iter().sum();
        writeln!(file, "{},{},{:.4},{},{:.4},,", sui_total, scaled_total, 100.0, reduced_total, 100.0)?;
        
        Ok(())
    }

    #[test]
    fn test_more_weights() {
        // Test with realistic validator weight distribution
        let sui_weights = load_sui_validator_weights();
        let scaled_weights = scale_weights_to_u16(&sui_weights);
        let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights.clone());
        let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
        let original_total_weight = original_nodes.total_weight();
        
        let allowed_delta = 1000u16; // Not used but required for compatibility
        let total_weight_upper_bound = u16::MAX; // Use max value for this test

        let (reduced_nodes, new_t) = Nodes::new_super_swiper_reduced(
            nodes_vec,
            0, // t parameter is unused
            allowed_delta,
            total_weight_upper_bound,
        )
        .unwrap();

        // Print the reduced weights
        println!("\n=== Super Swiper Weight Reduction Results ===");
        println!("Original total weight: {}", original_total_weight);
        println!("Reduced total weight: {}", reduced_nodes.total_weight());
        println!("New threshold (new_t): {}", new_t);
        println!("Reduction ratio: {:.2}%", (reduced_nodes.total_weight() as f64 / original_total_weight as f64) * 100.0);
        println!("\nReduced weights by node:");
        for (_orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            // println!("  Node {}: {} -> {}", orig.id, orig.weight, red.weight);
            println!("{}", red.weight);
        }
        println!("\nTotal new weight: {}", reduced_nodes.total_weight());
        println!("===================================\n");

        // Verify reduction occurred
        assert!(reduced_nodes.total_weight() < original_total_weight);

        // Verify threshold was adjusted correctly
        assert!(new_t > 0);
        // new_t should be approximately beta * total_reduced_weight (beta starts at 34/100)
        // Allow for rounding differences (within 1)
        let expected_t_min = ((34u32 * reduced_nodes.total_weight() as u32) / 100u32) as u16;
        let expected_t_max = ((41u32 * reduced_nodes.total_weight() as u32) / 100u32) as u16;
        assert!(
            new_t >= expected_t_min.saturating_sub(1) && new_t <= expected_t_max + 1,
            "new_t ({}) should be approximately beta * total_reduced_weight (expected range: {} - {})",
            new_t,
            expected_t_min,
            expected_t_max
        );

        // Verify all node IDs are preserved
        assert_eq!(original_nodes.num_nodes(), reduced_nodes.num_nodes());
        for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            assert_eq!(orig.id, red.id);
            assert_eq!(orig.pk, red.pk);
            assert!(red.weight <= orig.weight);
        }

        // Note: check_top_nodes and check_bot_nodes are now done internally by new_super_swiper_reduced
    }

    #[test]
    fn test_new_super_swiper_reduced_with_upper_bound() {
        // Test the new function signature with total_weight_upper_bound = 1000
        let sui_weights = load_sui_validator_weights();
        let scaled_weights = scale_weights_to_u16(&sui_weights);
        let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights.clone());
        let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
        let original_total_weight = original_nodes.total_weight();
        
        let allowed_delta = 1000u16; // Not used but required for compatibility
        let total_weight_upper_bound = 1000u16;

        let result = Nodes::new_super_swiper_reduced(
            nodes_vec.clone(),
            0, // t parameter is unused
            allowed_delta,
            total_weight_upper_bound,
        );

        match result {
            Ok((reduced_nodes, new_t)) => {
                println!("\n=== New Super Swiper Weight Reduction Results (Upper Bound = {}) ===", total_weight_upper_bound);
                println!("Original total weight: {}", original_total_weight);
                println!("Reduced total weight: {}", reduced_nodes.total_weight());
                println!("New threshold (new_t): {}", new_t);
                println!("Reduction ratio: {:.2}%", (reduced_nodes.total_weight() as f64 / original_total_weight as f64) * 100.0);

                // Verify reduction occurred and meets upper bound
                assert!(reduced_nodes.total_weight() <= total_weight_upper_bound);
                assert!(reduced_nodes.total_weight() < original_total_weight);

                // Verify threshold was adjusted correctly
                assert!(new_t > 0);
                // new_t should be approximately beta * total_reduced_weight (beta starts at 34/100, may increase up to 41/100)
                // Allow for rounding differences (within 1)
                let expected_t_min = ((34u32 * reduced_nodes.total_weight() as u32) / 100u32) as u16;
                let expected_t_max = ((41u32 * reduced_nodes.total_weight() as u32) / 100u32) as u16;
                assert!(
                    new_t >= expected_t_min.saturating_sub(1) && new_t <= expected_t_max + 1,
                    "new_t ({}) should be approximately beta * total_reduced_weight (expected range: {} - {})",
                    new_t,
                    expected_t_min,
                    expected_t_max
                );

                // Verify all node IDs are preserved
                assert_eq!(original_nodes.num_nodes(), reduced_nodes.num_nodes());
                for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
                    assert_eq!(orig.id, red.id);
                    assert_eq!(orig.pk, red.pk);
                    assert!(red.weight <= orig.weight);
                }

                // Validate weight reduction using the validation function
                let alpha = Ratio::new(1u64, 3u64);
                let beta = Ratio::new(34u64, 100u64); // Initial beta, may have been increased
                let original_weights: Vec<u64> = original_nodes.iter().map(|n| n.weight as u64).collect();
                let reduced_weights: Vec<u64> = reduced_nodes.iter().map(|n| n.weight as u64).collect();
                
                // Validate using the weight_reduction_checks module
                weight_reduction_checks::validate_weight_reduction(
                    &original_weights,
                    &reduced_weights,
                    alpha,
                    beta,
                    original_total_weight as u64,
                    reduced_nodes.total_weight() as u64,
                ).expect("Weight reduction validation should pass");
                
                // Calculate subset size for CSV generation
                let mut original_weights_sorted_desc: Vec<u64> = original_weights.clone();
                original_weights_sorted_desc.sort_by(|a, b| b.cmp(a));
                let subset_size_top = calculate_top_subset_size(
                    &original_weights_sorted_desc,
                    alpha,
                    original_total_weight as u64,
                );

                // Write CSV file
                let reduced_weights_vec: Vec<u16> = reduced_nodes.iter().map(|n| n.weight).collect();
                let csv_path = "../weight_reduction_results_upper_bound.csv";
                match write_weights_csv(
                    &sui_weights,
                    &scaled_weights,
                    &reduced_weights_vec,
                    1u64, // alpha numerator
                    3u64, // alpha denominator
                    34u64, // beta numerator (may have been increased, but we use initial)
                    100u64, // beta denominator
                    subset_size_top,
                    csv_path,
                ) {
                    Ok(_) => println!("CSV file written to: {}", csv_path),
                    Err(e) => eprintln!("Failed to write CSV file: {}", e),
                }

                println!("Test passed: Weight reduction successful with upper bound {}", total_weight_upper_bound);
            }
            Err(e) => {
                panic!("Weight reduction failed: {:?}", e);
            }
        }
    }
}

