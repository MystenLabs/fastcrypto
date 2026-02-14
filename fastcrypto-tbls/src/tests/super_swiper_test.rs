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

    fn ratio_to_decimal(r: &Ratio<u64>) -> String {
        format!("{:.6}", *r.numer() as f64 / *r.denom() as f64)
    }

    // Type alias for epoch comparison results: (epoch, W, t, f, W', t', f', delta, d)
    type EpochComparisonResult = (
        u64,
        Option<u16>,
        Option<u16>,
        Option<u64>,
        Option<u16>,
        Option<u16>,
        Option<u16>,
        Option<String>,
        Option<String>,
    );

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

            // Test new_reduced (not used in output, but kept for potential future use)
            let _new_reduced_result = Nodes::new_reduced(
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
                None,
            );

            // Calculate f = (W-t)/2
            let f = if original_total_weight >= t as u16 {
                Some((original_total_weight - t as u16) as u64 / 2)
            } else {
                None
            };

            let (w_prime, t_prime, f_prime, delta_str, d_str) = match super_swiper_result {
                Ok((reduced_nodes, new_t, f_p)) => {
                    let w_p = reduced_nodes.total_weight();
                    // Compute precision loss δ and divisor d for table
                    let original_weights: Vec<u64> =
                        scaled_weights.iter().map(|&w| w as u64).collect();
                    let reduced_weights: Vec<u64> =
                        reduced_nodes.iter().map(|n| n.weight as u64).collect();
                    let (precision_delta, d) =
                        compute_precision_loss(&original_weights, &reduced_weights);
                    let delta_val = Some(ratio_to_decimal(&precision_delta));
                    let d_val = Some(ratio_to_decimal(&d));
                    (Some(w_p), Some(new_t), Some(f_p), delta_val, d_val)
                }
                Err(_) => (None, None, None, None, None),
            };

            results.push((
                epoch,
                Some(original_total_weight),
                Some(t),
                f,
                w_prime,
                t_prime,
                f_prime,
                delta_str.clone(),
                d_str.clone(),
            ));

            println!(
                "  ✅ Epoch {}: W={}, t={}, f={:?}, W'={:?}, t'={:?}, f'={:?}, δ={:?}, d={:?}",
                epoch, original_total_weight, t, f, w_prime, t_prime, f_prime, delta_str, d_str
            );
        }

        // Print comparison chart
        let separator = "=".repeat(115);
        println!("\n{}", separator);
        println!("📈 WEIGHT REDUCTION COMPARISON CHART");
        println!("{}", separator);
        println!(
            "{:<8} | {:<6} | {:<6} | {:<8} | {:<8} | {:<8} | {:<8} | {:<10} | {:<10}",
            "Epoch", "W", "t", "f", "W'", "t'", "f'", "delta", "d"
        );
        println!(
            "{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}",
            "-".repeat(8),
            "-".repeat(6),
            "-".repeat(6),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(10),
            "-".repeat(10)
        );
        for (epoch, w, t_val, f_val, w_prime, t_prime, f_prime, delta, d) in &results {
            let w_str = w
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let t_str = t_val
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let f_str = f_val
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let w_prime_str = w_prime
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let t_prime_str = t_prime
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let f_prime_str = f_prime
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let delta_str = delta.clone().unwrap_or_else(|| "N/A".to_string());
            let d_str = d.clone().unwrap_or_else(|| "N/A".to_string());
            println!(
                "{:<8} | {:<6} | {:<6} | {:<8} | {:<8} | {:<8} | {:<8} | {:<10} | {:<10}",
                epoch, w_str, t_str, f_str, w_prime_str, t_prime_str, f_prime_str, delta_str, d_str
            );
        }
        println!("{}", separator);
        println!();

        // Verify all tests passed
        for (epoch, w, t_val, f_val, w_prime, t_prime, f_prime, delta, d) in &results {
            assert!(
                w.is_some() && t_val.is_some() && f_val.is_some(),
                "Failed to calculate W, t, f for epoch {}",
                epoch
            );
            assert!(
                w_prime.is_some()
                    && t_prime.is_some()
                    && f_prime.is_some()
                    && delta.is_some()
                    && d.is_some(),
                "super_swiper failed for epoch {}",
                epoch
            );
        }

        println!("✅ All epochs processed successfully!");
    }
}
