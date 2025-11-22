// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Stand-alone test file for Nodes::new_super_swiper_reduced function
// Run with: cargo +nightly test --features super-swiper test_reference_weights -- --nocapture
// Alt: clear && cargo +nightly test --package fastcrypto-tbls --lib --features super-swiper test_reference_weights -- --nocapture

#[cfg(feature = "super-swiper")]
mod tests {
    use crate::ecies_v1;
    use crate::nodes::{Node, Nodes};
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

    #[test]
    fn test_reference_weights() {
        // Test with realistic validator weight distribution
        let sui_weights = load_sui_validator_weights();
        let scaled_weights = scale_weights_to_u16(&sui_weights);
        let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights);
        let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
        let original_total_weight = original_nodes.total_weight();
        let t = ((original_total_weight as u32 * 5) / 16) as u16;

        let alpha = Ratio::new(5, 16); // 5/16 adversary
        let beta = Ratio::new(1, 3);  // 1/3 threshold
        let total_weight_lower_bound = 1;

        let (reduced_nodes, new_t) = Nodes::new_super_swiper_reduced(
            nodes_vec,
            alpha,
            beta,
        )
        .unwrap();

        // Print the reduced weights
        println!("\n=== Super Swiper Weight Reduction Results ===");
        println!("Original total weight: {}", original_total_weight);
        println!("Reduced total weight: {}", reduced_nodes.total_weight());
        println!("Original threshold (t): {}", t);
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
        assert!(reduced_nodes.total_weight() >= total_weight_lower_bound);

        // Verify threshold was adjusted correctly
        assert!(new_t <= t);
        assert!(new_t > 0);

        // Verify all node IDs are preserved
        assert_eq!(original_nodes.num_nodes(), reduced_nodes.num_nodes());
        for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            assert_eq!(orig.id, red.id);
            assert_eq!(orig.pk, red.pk);
            assert!(red.weight <= orig.weight);
        }
    }

    #[test]
    fn test_more_weights() {
        // Test with realistic validator weight distribution
        let sui_weights = load_sui_validator_weights();
        let scaled_weights = scale_weights_to_u16(&sui_weights);
        let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights);
        let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
        let original_total_weight = original_nodes.total_weight();
        
        let alpha_numerator = 1;
        let alpha_denominator = 3;
        let beta_numerator = 10;
        let beta_denominator = 29;
        let alpha = Ratio::new(alpha_numerator, alpha_denominator);
        let beta = Ratio::new(beta_numerator, beta_denominator);
        
        let t = (beta_numerator as u32 * original_total_weight as u32 / beta_denominator as u32) as u16;

        let (reduced_nodes, new_t) = Nodes::new_super_swiper_reduced(
            nodes_vec,
            alpha,
            beta,
        )
        .unwrap();

        // Print the reduced weights
        println!("\n=== Super Swiper Weight Reduction Results ===");
        println!("Original total weight: {}", original_total_weight);
        println!("Reduced total weight: {}", reduced_nodes.total_weight());
        println!("Original threshold (t): {}", t);
        println!("New threshold (new_t): {}", new_t);
        println!("Reduction ratio: {:.2}%", (reduced_nodes.total_weight() as f64 / original_total_weight as f64) * 100.0);
        println!("\nReduced weights by node:");
        for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            // println!("  Node {}: {} -> {}", orig.id, orig.weight, red.weight);
            println!("{}", red.weight);
        }
        println!("\nTotal new weight: {}", reduced_nodes.total_weight());
        println!("===================================\n");

        // Verify reduction occurred
        assert!(reduced_nodes.total_weight() < original_total_weight);

        // Verify threshold was adjusted correctly
        assert!(new_t <= t);
        assert!(new_t > 0);

        // Verify all node IDs are preserved
        assert_eq!(original_nodes.num_nodes(), reduced_nodes.num_nodes());
        for (orig, red) in original_nodes.iter().zip(reduced_nodes.iter()) {
            assert_eq!(orig.id, red.id);
            assert_eq!(orig.pk, red.pk);
            assert!(red.weight <= orig.weight);
        }
    }
}

