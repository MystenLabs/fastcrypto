// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::knapsack_weight_reduction::{reduce_weights, verify_reduction, ReducedWeights};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Exhaustively check the four security constraints from the module docs over
/// every subset, returning the first violation. Only usable for small n.
fn brute_force_violation(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    r: &ReducedWeights,
) -> Option<String> {
    let n = weights.len();
    assert!(n <= 16, "exhaustive check only for small n");
    for mask in 0u32..(1 << n) {
        let (mut w, mut wp) = (0u32, 0u32);
        for (i, (&orig, &red)) in weights.iter().zip(r.weights.iter()).enumerate() {
            if mask >> i & 1 == 1 {
                w += orig as u32;
                wp += red as u32;
            }
        }
        if w < t as u32 && wp >= r.t as u32 {
            return Some(format!("privacy: w(S)={} w'(S)={} t'={}", w, wp, r.t));
        }
        if w <= f as u32 && wp > r.f as u32 {
            return Some(format!("byzantine: w(S)={} w'(S)={} f'={}", w, wp, r.f));
        }
        if w >= t as u32 + delta as u32 && wp < r.t as u32 {
            return Some(format!("liveness-t: w(S)={} w'(S)={} t'={}", w, wp, r.t));
        }
        if w >= t as u32 + f as u32 + delta as u32 && wp < r.t as u32 + r.f as u32 {
            return Some(format!(
                "liveness-tf: w(S)={} w'(S)={} t'+f'={}",
                w,
                wp,
                r.t as u32 + r.f as u32
            ));
        }
    }
    None
}

#[test]
fn test_verify_reduction_matches_brute_force() {
    // The knapsack verifier must agree with the exhaustive subset checker on
    // arbitrary candidates, valid or not: verify on the algorithm's output
    // (which also confirms the output satisfies all four constraints), then
    // on random mutations of it.
    let mut rng = StdRng::seed_from_u64(13);
    for _ in 0..300 {
        let n = rng.gen_range(3..=12);
        let weights = (0..n)
            .map(|_| rng.gen_range(0..=200u16))
            .collect::<Vec<_>>();
        let w_total = weights.iter().map(|&w| w as u32).sum::<u32>();
        if w_total < 2 {
            continue;
        }
        // reduce_weights requires f < t, t + 2f <= W and t + f + delta <= W.
        let t = rng.gen_range(1..=w_total as u16);
        let f = rng.gen_range(0..=(t - 1).min((w_total as u16 - t) / 2));
        let delta = rng.gen_range(0..=(w_total as u16 - t - f));
        let r = reduce_weights(&weights, t, f, delta, 1).unwrap();
        assert!(r.t > r.f);
        assert!(verify_reduction(&weights, t, f, delta, &r).is_ok());
        for _ in 0..10 {
            let mut m = r.clone();
            match rng.gen_range(0..4) {
                0 => m.t = m.t.saturating_add(rng.gen_range(1..=2)),
                1 => m.t = (m.t.saturating_sub(1)).max(1),
                2 => m.f = m.f.saturating_sub(rng.gen_range(0..=2)),
                _ => {
                    let i = rng.gen_range(0..n);
                    m.weights[i] = if rng.gen_bool(0.5) {
                        m.weights[i].saturating_add(1)
                    } else {
                        m.weights[i].saturating_sub(1)
                    };
                }
            }
            // The verifier checks the four coalition predicates plus the
            // t' > f' sanity condition.
            assert_eq!(
                verify_reduction(&weights, t, f, delta, &m).is_ok(),
                brute_force_violation(&weights, t, f, delta, &m).is_none() && m.t > m.f,
            );
        }
    }
}

#[test]
fn test_verify_reduction_accepts_legacy_ceiling_reductions() {
    // Any divisor accepted by the legacy sum-of-remainders criterion (with the
    // ceiling thresholds) satisfies the four properties, so the verifier must
    // accept it at exactly that criterion's budget.
    let mut rng = StdRng::seed_from_u64(17);
    let mut checked = 0;
    for _ in 0..50 {
        let n = rng.gen_range(3..=30);
        let weights = (0..n)
            .map(|_| rng.gen_range(1..=200u16))
            .collect::<Vec<_>>();
        let w_total = weights.iter().map(|&w| w as u32).sum::<u32>() as u16;
        let f = rng.gen_range(0..=w_total / 3);
        let t = rng.gen_range(f + 1..=w_total);
        for d in [2u16, 3, 5, 7, 10, 17, 25, 33, 40] {
            // Skip divisors where the ceilings collide (t' == f'): the four
            // coalition predicates still hold there, but the verifier's t' > f'
            // sanity check rejects such candidates.
            if t.div_ceil(d) == f.div_ceil(d) {
                continue;
            }
            let delta =
                weights.iter().map(|&w| w % d).sum::<u16>() + (d - t % d) % d + (d - f % d) % d;
            // The verifier requires t + 2f <= W and t + f + delta <= W.
            if (t as u32) + 2 * (f as u32) > w_total as u32
                || (t as u32) + (f as u32) + (delta as u32) > w_total as u32
            {
                continue;
            }
            let r = ReducedWeights {
                weights: weights.iter().map(|&w| w / d).collect(),
                t: t.div_ceil(d),
                f: f.div_ceil(d),
            };

            assert!(verify_reduction(&weights, t, f, delta, &r).is_ok());
            checked += 1;
        }
    }
    assert!(checked > 0);
}

#[test]
fn test_reduce_weights_is_deterministic() {
    let weights = (0..100u16).map(|i| i % 37 + 1).collect::<Vec<_>>();
    let a = reduce_weights(&weights, 700, 350, 300, 1).unwrap();
    let b = reduce_weights(&weights, 700, 350, 300, 1).unwrap();
    assert_eq!(a, b);
}

#[test]
fn test_reduce_weights_input_validation() {
    assert!(reduce_weights(&[], 1, 0, 0, 1).is_err());
    assert!(reduce_weights(&[0, 0], 1, 0, 0, 1).is_err());
    // t == 0 or t > W
    assert!(reduce_weights(&[5, 5], 0, 0, 0, 1).is_err());
    assert!(reduce_weights(&[5, 5], 11, 0, 0, 1).is_err());
    // t + f + delta > W (liveness hypotheses unsatisfiable)
    assert!(reduce_weights(&[5, 5], 5, 0, 6, 1).is_err());
    assert!(reduce_weights(&[5, 5], 5, 3, 3, 1).is_err());
    // t + 2f > W (structural feasibility violated)
    assert!(reduce_weights(&[5, 5], 5, 4, 0, 1).is_err());
    // valid: t + 2f <= W and t + f + delta <= W
    assert!(reduce_weights(&[5, 5], 5, 2, 2, 1).is_ok());
    // f >= t
    assert!(reduce_weights(&[5, 5], 5, 11, 0, 1).is_err());
    // f >= t
    assert!(reduce_weights(&[5, 5], 3, 3, 0, 1).is_err());
    assert!(reduce_weights(&[5, 5], 3, 4, 0, 1).is_err());
    // individual weight above MAX_WEIGHT
    assert!(reduce_weights(&[10_001, 5], 5, 0, 0, 1).is_err());
    // bad lower bound
    assert!(reduce_weights(&[5, 5], 5, 0, 0, 0).is_err());
    assert!(reduce_weights(&[5, 5], 5, 0, 0, 11).is_err());
}

#[test]
fn test_reduce_weights_respects_lower_bound() {
    let weights = vec![100u16; 50];
    let unrestricted = reduce_weights(&weights, 1700, 1400, 500, 1).unwrap();
    let bounded = reduce_weights(&weights, 1700, 1400, 500, 2000).unwrap();
    let total = |r: &ReducedWeights| r.weights.iter().map(|&w| w as u32).sum::<u32>();
    assert!(total(&unrestricted) < total(&bounded));
    assert!(total(&bounded) >= 2000);
}

const SUI_EPOCH_DATA: &[(&str, &str)] = &[
    (
        "100",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_100_details.txt"),
    ),
    (
        "200",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_200_details.txt"),
    ),
    (
        "400",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_400_details.txt"),
    ),
    (
        "800",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_800_details.txt"),
    ),
    (
        "974",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_974_details.txt"),
    ),
    (
        "1000",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_1000_details.txt"),
    ),
    (
        "1100",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_1100_details.txt"),
    ),
    (
        "1200",
        include_str!("../weight_reduction/data/sui_real_all_voting_power_epoch_1200_details.txt"),
    ),
];

fn parse_sui_epoch(contents: &str) -> Vec<u16> {
    contents
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let weight = line.rsplit(',').next().expect("non-empty CSV line").trim();
            weight.parse::<u16>().expect("u16 voting power")
        })
        .collect()
}

#[test]
fn test_reduce_weights_on_sui_epochs() {
    // Expected totals from the analysis prototype (delta = 800); each is 30-50%
    // below Nodes::prop_reduce on the same inputs.
    let expected: &[(&str, u16, u16, u32)] = &[
        ("100", 3400, 2900, 469),
        ("100", 5200, 2000, 252),
        ("200", 3400, 2900, 277),
        ("200", 5200, 2000, 273),
        ("400", 3400, 2900, 438),
        ("400", 5200, 2000, 267),
        ("800", 3400, 2900, 447),
        ("800", 5200, 2000, 442),
        ("974", 3400, 2900, 479),
        ("974", 5200, 2000, 461),
        ("1000", 3400, 2900, 485),
        ("1000", 5200, 2000, 453),
        ("1100", 3400, 2900, 485),
        ("1100", 5200, 2000, 443),
        ("1200", 3400, 2900, 485),
        ("1200", 5200, 2000, 439),
    ];
    for &(epoch, t, f, expected_total) in expected {
        let weights = parse_sui_epoch(
            SUI_EPOCH_DATA
                .iter()
                .find(|(e, _)| *e == epoch)
                .expect("known epoch")
                .1,
        );
        assert_eq!(weights.iter().map(|&w| w as u32).sum::<u32>(), 10000);
        let r = reduce_weights(&weights, t, f, 800, 1).unwrap();
        let total = r.weights.iter().map(|&w| w as u32).sum::<u32>();
        assert_eq!(
            total, expected_total,
            "epoch {} (t={}, f={}): W'={} expected {}",
            epoch, t, f, total, expected_total
        );
        assert!(r.t < t && r.f <= f);
        assert!(r.t > r.f);
        // Full-size exact verification of the four properties (the brute-force
        // checker cannot handle n > 16; the knapsack verifier can).
        assert!(verify_reduction(&weights, t, f, 800, &r).is_ok());
        // t' is tight: lowering it must violate privacy.
        let mut bad = r.clone();
        bad.t -= 1;
        assert!(verify_reduction(&weights, t, f, 800, &bad).is_err());
    }
}

#[test]
fn test_reduce_weights_sui_benchmark() {
    // reduce_weights on real Sui parameters should run in the order of 10 ms.
    let mut worst = std::time::Duration::ZERO;
    let mut total = std::time::Duration::ZERO;
    let mut cases = 0u32;
    for (epoch, contents) in SUI_EPOCH_DATA {
        let weights = parse_sui_epoch(contents);
        for (t, f) in [(3400u16, 2900u16), (5200, 2000)] {
            let start = std::time::Instant::now();
            let r = reduce_weights(&weights, t, f, 800, 1).unwrap();
            let elapsed = start.elapsed();
            worst = worst.max(elapsed);
            total += elapsed;
            cases += 1;
            println!(
                "epoch {} t={} f={}: W'={} in {:?}",
                epoch,
                t,
                f,
                r.weights.iter().map(|&w| w as u32).sum::<u32>(),
                elapsed
            );
        }
    }
    println!("worst {:?}, avg {:?}", worst, total / cases);
    // Timing assertions are only meaningful in optimized builds. Locally the
    // worst case is ~20ms; the bound leaves headroom for slower CI machines.
    if !cfg!(debug_assertions) {
        assert!(
            worst < std::time::Duration::from_millis(50),
            "worst {:?}",
            worst
        );
    }
}

#[test]
fn test_reduce_weights_hashi_parameters() {
    // The Hashi parametrization: t and delta fixed in bps, f structural:
    // f = floor((W - t) / 2), so t + 2f = W up to a rounding unit.
    let (t, delta) = (3334u16, 800u16);
    for (epoch, contents) in SUI_EPOCH_DATA {
        let weights = parse_sui_epoch(contents);
        let w_total = weights.iter().map(|&w| w as u32).sum::<u32>() as u16;
        let f = (w_total - t) / 2;
        let r = reduce_weights(&weights, t, f, delta, 1).unwrap();
        assert!(verify_reduction(&weights, t, f, delta, &r).is_ok());
        let total = r.weights.iter().map(|&w| w as u32).sum::<u32>();
        // A real reduction must be found, with consistent thresholds.
        assert!(total < w_total as u32, "epoch {}: no reduction", epoch);
        assert!(r.t > r.f);
        println!("epoch {}: W'={} t'={} f'={}", epoch, total, r.t, r.f);
    }
}
