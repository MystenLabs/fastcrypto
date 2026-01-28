// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Stand-alone test file for Nodes::new_super_swiper_reduced function
// Run with: clear && cargo test --package fastcrypto-tbls --lib test_<> -- --nocapture

mod tests {
    use crate::ecies_v1;
    use crate::nodes::{Node, Nodes};
    use crate::weight_reduction::weight_reduction_checks::compute_precision_loss;

    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
    use num_rational::Ratio;
    use rand::thread_rng;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::fs::{self, File};
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

    // Helper function to load Sui validator voting power for a specific epoch
    fn load_sui_validator_voting_power_for_epoch(epoch: u64) -> Vec<u64> {
        let weights_data = match epoch {
            100 => include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_100.dat"),
            200 => include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_200.dat"),
            400 => include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_400.dat"),
            800 => include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_800.dat"),
            974 => include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_974.dat"),
            _ => panic!("Unsupported epoch: {}", epoch),
        };
        weights_data
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.parse::<u64>()
                    .unwrap_or_else(|_| panic!("Failed to parse voting power: {}", line))
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

    // Type alias for epoch comparison results: (epoch, new_reduced_total, super_swiper_total, delta, delta_pct)
    type EpochComparisonResult = (u64, Option<u16>, Option<u16>, Option<u64>, Option<f64>);

    #[test]
    fn test_all_epochs_comparison() {
        // Test both algorithms across all epochs and create a comparison chart
        let epochs = vec![100, 200, 400, 800, 974];
        let mut results: Vec<EpochComparisonResult> = Vec::new();

        println!("\n🔬 Testing weight reduction across multiple epochs...\n");

        for epoch in epochs {
            println!("📊 Processing epoch {}...", epoch);
            let sui_weights = load_sui_validator_voting_power_for_epoch(epoch);
            let scaled_weights = scale_weights_to_u16(&sui_weights);
            let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights.clone());
            let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
            let original_total_weight = original_nodes.total_weight();

            // Calculate t = alpha * total_old_weights, where alpha = 1/3
            let alpha = Ratio::new(1u64, 3u64);
            let t = (alpha * original_total_weight as u64).to_integer() as u16;
            let allowed_delta = (original_total_weight as f64 * 0.08) as u16;
            let total_weight_lower_bound = 1u16;

            // Original weights for delta calculation
            let original_weights: Vec<u64> = scaled_weights.iter().map(|&w| w as u64).collect();

            // Test new_reduced
            let new_reduced_result = Nodes::new_reduced(
                nodes_vec.clone(),
                t,
                allowed_delta,
                total_weight_lower_bound,
            );

            // Test new_super_swiper_reduced
            let super_swiper_result = Nodes::new_super_swiper_reduced(
                nodes_vec.clone(),
                t,
                allowed_delta,
                total_weight_lower_bound,
            );

            let new_reduced_total = new_reduced_result
                .ok()
                .map(|(reduced_nodes, _)| reduced_nodes.total_weight());

            let (super_swiper_total, delta_info) = match super_swiper_result {
                Ok((reduced_nodes, _, _beta)) => {
                    // Calculate delta for super_swiper
                    let reduced_weights: Vec<u64> = reduced_nodes
                        .iter()
                        .map(|node| node.weight as u64)
                        .collect();

                    // Compute delta = sum(max(original[i] - reduced[i] * d, 0))
                    // where d = total_original / total_reduced (exact ratio)
                    let (delta, _d) = compute_precision_loss(&original_weights, &reduced_weights);
                    let delta_int = delta.to_integer();
                    let delta_pct = (delta_int as f64 / original_total_weight as f64) * 100.0;

                    (
                        Some(reduced_nodes.total_weight()),
                        Some((delta_int, delta_pct)),
                    )
                }
                Err(_) => (None, None),
            };

            results.push((
                epoch,
                new_reduced_total,
                super_swiper_total,
                delta_info.map(|(d, _)| d),
                delta_info.map(|(_, p)| p),
            ));

            println!(
                "  ✅ Epoch {}: new_reduced={:?}, super_swiper={:?}",
                epoch, new_reduced_total, super_swiper_total
            );
        }

        // Print comparison chart
        let separator = "=".repeat(90);
        println!("\n{}", separator);
        println!("📈 WEIGHT REDUCTION COMPARISON CHART");
        println!("{}", separator);
        println!(
            "{:<12} | {:<20} | {:<20} | {:<15} | {:<15}",
            "Epoch", "new_reduced", "super_swiper", "Delta", "Delta %"
        );
        println!(
            "{}-+-{}-+-{}-+-{}-+-{}",
            "-".repeat(12),
            "-".repeat(20),
            "-".repeat(20),
            "-".repeat(15),
            "-".repeat(15)
        );
        for (epoch, new_reduced, super_swiper, delta, delta_pct) in &results {
            let new_reduced_str = new_reduced
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let super_swiper_str = super_swiper
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let delta_str = delta
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let delta_pct_str = delta_pct
                .map(|v| format!("{:.2}%", v))
                .unwrap_or_else(|| "N/A".to_string());
            println!(
                "{:<12} | {:<20} | {:<20} | {:<15} | {:<15}",
                epoch, new_reduced_str, super_swiper_str, delta_str, delta_pct_str
            );
        }
        println!("{}", separator);
        println!();

        // Verify all tests passed
        for (epoch, new_reduced, super_swiper, _, _) in &results {
            assert!(
                new_reduced.is_some(),
                "new_reduced failed for epoch {}",
                epoch
            );
            assert!(
                super_swiper.is_some(),
                "super_swiper failed for epoch {}",
                epoch
            );
        }

        println!("✅ All epochs processed successfully!");
    }

    #[test]
    fn test_generate_csv_per_epoch() {
        // Generate CSV files per epoch with validator index, original weight, and super swiper reduced weight
        let epochs = vec![100, 200, 400, 800, 974];

        // Create output directory if it doesn't exist
        let output_dir = "../weight_reduction/csv";
        fs::create_dir_all(output_dir).expect("Failed to create CSV output directory");

        println!("\n📝 Generating CSV files per epoch...\n");

        for epoch in epochs {
            println!("📊 Processing epoch {}...", epoch);
            let sui_weights = load_sui_validator_voting_power_for_epoch(epoch);
            let scaled_weights = scale_weights_to_u16(&sui_weights);
            let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights.clone());
            let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
            let original_total_weight = original_nodes.total_weight();

            // Calculate t = alpha * total_old_weights, where alpha = 1/3
            let alpha = Ratio::new(1u64, 3u64);
            let t = (alpha * original_total_weight as u64).to_integer() as u16;
            let allowed_delta = (original_total_weight as f64 * 0.08) as u16;
            let total_weight_lower_bound = 1u16;

            // Run super_swiper reduction
            let super_swiper_result = Nodes::new_super_swiper_reduced(
                nodes_vec.clone(),
                t,
                allowed_delta,
                total_weight_lower_bound,
            );

            match super_swiper_result {
                Ok((reduced_nodes, new_t, beta)) => {
                    // Create a map from validator ID to reduced weight for efficient lookup
                    let reduced_weights_map: HashMap<u16, u16> = reduced_nodes
                        .iter()
                        .map(|node| (node.id, node.weight))
                        .collect();

                    // Calculate actual delta - ensure weights are in the same order
                    let original_weights: Vec<u64> =
                        scaled_weights.iter().map(|&w| w as u64).collect();
                    let reduced_weights: Vec<u64> = scaled_weights
                        .iter()
                        .enumerate()
                        .map(|(idx, _)| {
                            reduced_weights_map.get(&(idx as u16)).copied().unwrap_or(0) as u64
                        })
                        .collect();
                    // Compute new delta: d = total_orig/total_red (exact ratio), delta = sum(max(orig - red*d, 0))
                    let (precision_delta, d) =
                        compute_precision_loss(&original_weights, &reduced_weights);

                    // Create CSV file
                    let csv_path = format!("{}/epoch_{}.csv", output_dir, epoch);
                    let mut file = File::create(&csv_path).expect("Failed to create CSV file");

                    // Write metadata row (first row): epoch, alpha, beta, allowed_delta, precision_delta, d,
                    // original_total_weight, reduced_total_weight, original_threshold, reduced_threshold
                    let alpha_str = format!("{}/{}", alpha.numer(), alpha.denom());
                    let beta_str = format!("{}/{}", beta.numer(), beta.denom());
                    let d_str = format!("{}/{}", d.numer(), d.denom());
                    let delta_str =
                        format!("{}/{}", precision_delta.numer(), precision_delta.denom());
                    writeln!(
                        file,
                        "{},{},{},{},{},{},{},{},{},{}",
                        epoch,
                        alpha_str,
                        beta_str,
                        allowed_delta,
                        delta_str,
                        d_str,
                        original_total_weight,
                        reduced_nodes.total_weight(),
                        t,
                        new_t
                    )
                    .expect("Failed to write CSV metadata row");

                    // Write header row (second row)
                    writeln!(
                        file,
                        "validator_index,original_weight,super_swiper_reduced_weight"
                    )
                    .expect("Failed to write CSV header");

                    // Write data rows - iterate in original order (by validator index)
                    for (index, original_weight) in scaled_weights.iter().enumerate() {
                        let reduced_weight = reduced_weights_map
                            .get(&(index as u16))
                            .copied()
                            .unwrap_or(0);

                        writeln!(file, "{},{},{}", index, original_weight, reduced_weight)
                            .expect("Failed to write CSV row");
                    }

                    println!("  ✅ Generated: {}", csv_path);
                }
                Err(e) => {
                    eprintln!("  ❌ Failed to reduce weights for epoch {}: {:?}", epoch, e);
                }
            }
        }

        println!("\n✅ CSV generation complete!");
    }
}
