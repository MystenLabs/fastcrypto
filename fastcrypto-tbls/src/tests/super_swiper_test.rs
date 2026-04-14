// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Epoch comparison tests for `Nodes::new_super_swiper_reduced` and `Nodes::new_reduced`.
// Baseline: t=34%·W, L=75%·W, allowed_delta=8%·W. Alt: t=52%·W, L=80%·W, allowed_delta=8%·W.
// Run: cargo test -p fastcrypto-tbls --lib super_swiper_test::tests -- --nocapture

mod tests {
    use crate::ecies_v1;
    use crate::nodes::{Node, Nodes};
    use crate::weight_reduction::weight_reduction_checks::compute_precision_loss;
    use fastcrypto::error::FastCryptoResult;

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

    /// Largest `f` with `t + 2f <= w` and `t > f` (unsigned), or `None` if no such `f` exists.
    fn f_upper_bound(w: u64, t: u16) -> Option<u64> {
        let t_u = u64::from(t);
        if t_u == 0 || w < t_u {
            None
        } else {
            let cap_from_sum = (w - t_u) / 2;
            let cap_from_strict = t_u - 1;
            Some(cap_from_sum.min(cap_from_strict))
        }
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

    type ReduceRistretto = fn(
        Vec<Node<RistrettoPoint>>,
        u16,
        u16,
        u16,
    ) -> FastCryptoResult<(Nodes<RistrettoPoint>, u16)>;

    /// Threshold `t`, liveness `L`, and reducer `allowed_delta` as fractions of total weight `W`.
    struct EpochChartParams {
        /// `t = floor((t_alpha * W).to_integer())` with `t_alpha = t_numer / t_denom`.
        t_alpha: Ratio<u64>,
        /// `L = floor(liveness_pct * W)` as `u16`.
        liveness_pct: f64,
        /// `allowed_delta = floor(allowed_delta_pct * W)` as `u16`.
        allowed_delta_pct: f64,
    }

    impl EpochChartParams {
        fn baseline_34_75_8() -> Self {
            Self {
                t_alpha: Ratio::new(34u64, 100u64),
                liveness_pct: 0.75,
                allowed_delta_pct: 0.08,
            }
        }

        /// `t = 52% W`, `L = 80% W`, `allowed_delta = 8% W`.
        fn t52_l80_delta8() -> Self {
            Self {
                t_alpha: Ratio::new(52u64, 100u64),
                liveness_pct: 0.80,
                allowed_delta_pct: 0.08,
            }
        }
    }

    /// How `f_l` and scaled `f'_l` are derived from liveness `L`, threshold `t`, and precision loss.
    enum FFromLiveness {
        /// `f_l = L - t - 3δ`, `f'_l = (f_l + δ) / d` (super swiper convention).
        SuperSwiper,
        /// `f_l = L - t - δ`, `f'_l = f_l / d` (`new_reduced` convention).
        NewReduced,
    }

    fn value_with_pct_of_w_prime(opt: Option<u16>, w_prime: Option<u16>) -> String {
        match (opt, w_prime) {
            (Some(n), Some(wp)) if wp > 0 => {
                let p = 100.0 * f64::from(n) / f64::from(wp);
                format!("{n} ({p:.1}%)")
            }
            (Some(n), Some(_)) => format!("{n} (N/A)"),
            (Some(n), None) => n.to_string(),
            (None, _) => "N/A".to_string(),
        }
    }

    fn run_all_epochs_comparison_chart(
        reducer: ReduceRistretto,
        chart_title: &str,
        fail_label: &str,
        f_from_liveness: FFromLiveness,
        params: &EpochChartParams,
    ) {
        let epochs = vec![100, 200, 400, 800, 974];
        let mut results: Vec<EpochComparisonResult> = Vec::new();

        println!(
            "\n🔬 Testing weight reduction across multiple epochs ({})...\n  params: t = {}%·W, L = {}%·W, allowed_delta = {}%·W\n",
            chart_title,
            100.0 * (*params.t_alpha.numer() as f64) / (*params.t_alpha.denom() as f64),
            params.liveness_pct * 100.0,
            params.allowed_delta_pct * 100.0,
        );

        for epoch in epochs {
            println!("📊 Processing epoch {}...", epoch);
            let sui_weights = load_sui_validator_voting_power_for_epoch(epoch);
            let scaled_weights = scale_weights_to_u16(&sui_weights);
            let nodes_vec = create_test_nodes::<RistrettoPoint>(scaled_weights.clone());
            let original_nodes = Nodes::new(nodes_vec.clone()).unwrap();
            let original_total_weight = original_nodes.total_weight();

            let t = (params.t_alpha * original_total_weight as u64).to_integer() as u16;
            let allowed_delta = (original_total_weight as f64 * params.allowed_delta_pct) as u16;
            let total_weight_lower_bound = 1u16;

            let reduced_result = reducer(
                nodes_vec.clone(),
                t,
                allowed_delta,
                total_weight_lower_bound,
            );

            let liveness_weight = (original_total_weight as f64 * params.liveness_pct) as u16;
            let (w_prime, t_prime, f_prime, delta_str, d_str, f) = match reduced_result {
                Ok((reduced_nodes, new_t)) => {
                    let w_p = reduced_nodes.total_weight();
                    let original_weights: Vec<u64> =
                        scaled_weights.iter().map(|&w| w as u64).collect();
                    let reduced_weights: Vec<u64> =
                        reduced_nodes.iter().map(|n| n.weight as u64).collect();
                    let (precision_delta, d) =
                        compute_precision_loss(&original_weights, &reduced_weights);
                    let delta_int = precision_delta.to_integer();
                    let d_int = d.to_integer().max(1);

                    let w = u64::from(original_total_weight);
                    let f_l = match f_from_liveness {
                        FFromLiveness::SuperSwiper => {
                            u64::from(liveness_weight).saturating_sub(u64::from(t) + 3 * delta_int)
                        }
                        FFromLiveness::NewReduced => {
                            u64::from(liveness_weight).saturating_sub(u64::from(t) + delta_int)
                        }
                    };
                    let f_val = f_upper_bound(w, t).map(|cap| f_l.min(cap));

                    let f_prime_l = match f_from_liveness {
                        FFromLiveness::SuperSwiper => (f_l + delta_int) / d_int,
                        FFromLiveness::NewReduced => f_l / d_int,
                    };
                    let f_prime_val = f_upper_bound(u64::from(w_p), new_t)
                        .and_then(|cap| u16::try_from(f_prime_l.min(cap)).ok());

                    let delta_val = Some(ratio_to_decimal(&precision_delta));
                    let d_val = Some(ratio_to_decimal(&d));
                    (Some(w_p), Some(new_t), f_prime_val, delta_val, d_val, f_val)
                }
                Err(_) => (
                    None::<u16>,
                    None::<u16>,
                    None::<u16>,
                    None::<String>,
                    None::<String>,
                    None::<u64>,
                ),
            };

            let row: EpochComparisonResult = (
                epoch,
                Some(original_total_weight),
                Some(t),
                f,
                w_prime,
                t_prime,
                f_prime,
                delta_str.clone(),
                d_str.clone(),
            );
            results.push(row);

            println!(
                "  ✅ Epoch {}: W={}, t={}, f={:?}, W'={:?}, t'={:?}, f'={:?}, δ={:?}, d={:?}",
                epoch, original_total_weight, t, f, w_prime, t_prime, f_prime, delta_str, d_str
            );
        }

        let col_tpf = 20;
        let separator = "=".repeat(120);
        println!("\n{}", separator);
        println!(
            "📈 WEIGHT REDUCTION COMPARISON CHART — {} (t={}%·W, L={}%·W, δ_allow={}%·W)",
            chart_title,
            100.0 * (*params.t_alpha.numer() as f64) / (*params.t_alpha.denom() as f64),
            params.liveness_pct * 100.0,
            params.allowed_delta_pct * 100.0,
        );
        println!("{}", separator);
        println!(
            "{:<8} | {:<6} | {:<6} | {:<8} | {:<8} | {:<width$} | {:<width$} | {:<10} | {:<10}",
            "Epoch",
            "W",
            "t",
            "f",
            "W'",
            "t' (% W')",
            "f' (% W')",
            "delta",
            "d",
            width = col_tpf,
        );
        println!(
            "{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}",
            "-".repeat(8),
            "-".repeat(6),
            "-".repeat(6),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(col_tpf),
            "-".repeat(col_tpf),
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
            let t_prime_str = value_with_pct_of_w_prime(*t_prime, *w_prime);
            let f_prime_str = value_with_pct_of_w_prime(*f_prime, *w_prime);
            let delta_str = delta.clone().unwrap_or_else(|| "N/A".to_string());
            let d_str = d.clone().unwrap_or_else(|| "N/A".to_string());
            println!(
                "{:<8} | {:<6} | {:<6} | {:<8} | {:<8} | {:<width$} | {:<width$} | {:<10} | {:<10}",
                epoch,
                w_str,
                t_str,
                f_str,
                w_prime_str,
                t_prime_str,
                f_prime_str,
                delta_str,
                d_str,
                width = col_tpf,
            );
        }
        println!("{}", separator);
        println!();

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
                "{} failed for epoch {}",
                fail_label,
                epoch
            );
        }

        println!("✅ All epochs processed successfully ({})!", chart_title);
    }

    #[test]
    fn test_all_epochs_comparison() {
        let params = EpochChartParams::baseline_34_75_8();
        run_all_epochs_comparison_chart(
            Nodes::new_super_swiper_reduced,
            "new_super_swiper_reduced",
            "new_super_swiper_reduced",
            FFromLiveness::SuperSwiper,
            &params,
        );
    }

    #[test]
    fn test_all_epochs_comparison_new_reduced() {
        let params = EpochChartParams::baseline_34_75_8();
        run_all_epochs_comparison_chart(
            Nodes::new_reduced,
            "new_reduced",
            "new_reduced",
            FFromLiveness::NewReduced,
            &params,
        );
    }

    #[test]
    fn test_all_epochs_comparison_super_swiper_t52_l80_delta8() {
        let params = EpochChartParams::t52_l80_delta8();
        run_all_epochs_comparison_chart(
            Nodes::new_super_swiper_reduced,
            "new_super_swiper_reduced",
            "new_super_swiper_reduced",
            FFromLiveness::SuperSwiper,
            &params,
        );
    }

    #[test]
    fn test_all_epochs_comparison_new_reduced_t52_l80_delta8() {
        let params = EpochChartParams::t52_l80_delta8();
        run_all_epochs_comparison_chart(
            Nodes::new_reduced,
            "new_reduced",
            "new_reduced",
            FFromLiveness::NewReduced,
            &params,
        );
    }
}
