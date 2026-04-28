// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::nodes::{derive_reduced_params, Node, Nodes};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::num::NonZeroU16;
use zeroize::Zeroize;

fn get_nodes<G>(n: u16) -> Vec<Node<G>>
where
    G: GroupElement + Serialize + DeserializeOwned,
    G::ScalarType: FiatShamirChallenge + Zeroize,
{
    let sk = ecies_v1::PrivateKey::<G>::new(&mut thread_rng());
    let pk = ecies_v1::PublicKey::<G>::from_private_key(&sk);
    (0..n)
        .map(|i| Node {
            id: i,
            pk: pk.clone(),
            weight: if i > 10 { 10 + i % 10 } else { 1 + i },
        })
        .collect()
}

#[test]
fn test_new_failures() {
    // empty
    let nodes_vec = get_nodes::<G2Element>(0);
    assert!(Nodes::new(nodes_vec).is_err());
    // missing id
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec.remove(7);
    assert!(Nodes::new(nodes_vec).is_err());
    // start id is not 0
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec.remove(0);
    assert!(Nodes::new(nodes_vec).is_err());
    // duplicate id
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec[19].id = 1;
    assert!(Nodes::new(nodes_vec).is_err());
    // too many nodes
    let nodes_vec = get_nodes::<G2Element>(20000);
    assert!(Nodes::new(nodes_vec).is_err());
    // too little
    let nodes_vec: Vec<Node<G2Element>> = Vec::new();
    assert!(Nodes::new(nodes_vec).is_err());
    // too large total weight
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec[19].weight = u16::MAX - 5;
    assert!(Nodes::new(nodes_vec).is_err());
    // zero total weight
    let mut nodes_vec = get_nodes::<G2Element>(2);
    nodes_vec[0].weight = 0;
    nodes_vec[1].weight = 0;
    assert!(Nodes::new(nodes_vec).is_err());
}

#[test]
fn test_new_order() {
    // order should not matter
    let mut nodes_vec = get_nodes::<G2Element>(100);
    nodes_vec.shuffle(&mut thread_rng());
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    nodes_vec.shuffle(&mut thread_rng());
    let nodes2 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(nodes1, nodes2);
    assert_eq!(nodes1.hash(), nodes2.hash());
}

#[test]
fn test_zero_weight() {
    // The basic case
    let nodes_vec = get_nodes::<G2Element>(10);
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU16::new(1).unwrap())
            .unwrap()
            .id,
        0
    );
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU16::new(2).unwrap())
            .unwrap()
            .id,
        1
    );
    assert_eq!(
        nodes1.share_ids_of(0).unwrap(),
        vec![NonZeroU16::new(1).unwrap()]
    );

    // first node's weight is 0
    let mut nodes_vec = get_nodes::<G2Element>(10);
    nodes_vec[0].weight = 0;
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU16::new(1).unwrap())
            .unwrap()
            .id,
        1
    );
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU16::new(2).unwrap())
            .unwrap()
            .id,
        1
    );
    assert_eq!(nodes1.share_ids_of(0).unwrap(), vec![]);

    // last node's weight is 0
    let mut nodes_vec = get_nodes::<G2Element>(10);
    nodes_vec[9].weight = 0;
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU16::new(nodes1.total_weight()).unwrap())
            .unwrap()
            .id,
        8
    );
    assert_eq!(nodes1.share_ids_of(9).unwrap(), vec![]);

    // third node's weight is 0
    let mut nodes_vec = get_nodes::<G2Element>(10);
    nodes_vec[2].weight = 0;
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU16::new(4).unwrap())
            .unwrap()
            .id,
        3
    );
    assert_eq!(nodes1.share_ids_of(2).unwrap(), vec![]);
}

#[test]
fn test_interfaces() {
    let nodes_vec = get_nodes::<G2Element>(100);
    let nodes = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(nodes.total_weight(), 1361);
    assert_eq!(nodes.num_nodes(), 100);
    assert!(nodes
        .share_ids_iter()
        .zip(1u16..=5050)
        .all(|(a, b)| a.get() == b));

    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU16::new(1).unwrap())
            .unwrap(),
        &nodes_vec[0]
    );
    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU16::new(3).unwrap())
            .unwrap(),
        &nodes_vec[1]
    );
    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU16::new(4).unwrap())
            .unwrap(),
        &nodes_vec[2]
    );
    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU16::new(1361).unwrap())
            .unwrap(),
        &nodes_vec[99]
    );
    assert!(nodes
        .share_id_to_node(&NonZeroU16::new(1362).unwrap())
        .is_err());
    assert!(nodes
        .share_id_to_node(&NonZeroU16::new(15051).unwrap())
        .is_err());

    assert_eq!(nodes.node_id_to_node(1).unwrap(), &nodes_vec[1]);
    assert!(nodes.node_id_to_node(100).is_err());

    assert_eq!(
        nodes.share_ids_of(1).unwrap(),
        vec![NonZeroU16::new(2).unwrap(), NonZeroU16::new(3).unwrap()]
    );
    assert!(nodes.share_ids_of(123).is_err());
}

#[test]
fn test_reduce() {
    for number_of_nodes in [10, 50, 100, 150, 200, 250, 300, 350, 400] {
        let node_vec = get_nodes::<RistrettoPoint>(number_of_nodes);
        let nodes = Nodes::new(node_vec.clone()).unwrap();
        let t = nodes.total_weight() / 3;

        // No extra gap, should return the inputs
        let (new_nodes, new_t) = Nodes::new_reduced(node_vec.clone(), t, 1, 1).unwrap();
        assert_eq!(nodes, new_nodes);
        assert_eq!(t, new_t);

        // 10% gap
        let (new_nodes, _new_t) =
            Nodes::new_reduced(node_vec, t, nodes.total_weight() / 10, 1).unwrap();
        // Estimate the real factor d
        let d = nodes.iter().last().unwrap().weight / new_nodes.iter().last().unwrap().weight;
        // The loss per node is on average (d - 1) / 2
        // We use 9 instead of 10 to compensate wrong value of d
        assert!((d - 1) / 2 * number_of_nodes < (nodes.total_weight() / 9));
    }
}

/// Sui mainnet voting-power snapshots embedded at compile time. Each file is a CSV
/// `Validator Name,Voting Power` with a single header line and basis-point weights
/// summing to 10000.
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

fn build_sui_nodes(weights: &[u16]) -> Vec<Node<RistrettoPoint>> {
    let sk = ecies_v1::PrivateKey::<RistrettoPoint>::new(&mut thread_rng());
    let pk = ecies_v1::PublicKey::<RistrettoPoint>::from_private_key(&sk);
    weights
        .iter()
        .enumerate()
        .map(|(i, &w)| Node {
            id: i as u16,
            pk: pk.clone(),
            weight: w,
        })
        .collect()
}

/// Single shared scenario for the Sui-epoch tests below.
const SUI_T: u16 = 4000;
const SUI_F: u16 = 3400;
const SUI_ALLOWED_DELTA: u16 = 800;

#[test]
fn test_prop_reduce_sui_epochs() {
    println!(
        "\nprop_reduce + derive_reduced_params on Sui epochs — t = {}, f = {}, δ_allowed = {}\n",
        SUI_T, SUI_F, SUI_ALLOWED_DELTA
    );
    println!("| epoch |   n |     W |    W' |  W/W' |  t' |  f' |     δ | δ + 2d |");
    println!("|------:|----:|------:|------:|------:|----:|----:|------:|-------:|");

    for (epoch_name, contents) in SUI_EPOCH_DATA {
        let weights = parse_sui_epoch(contents);
        let n_parties = weights.len();
        let nodes_vec = build_sui_nodes(&weights);
        let original_nodes = Nodes::<RistrettoPoint>::new(nodes_vec.clone()).unwrap();
        let total_weight = original_nodes.total_weight() as u32;
        // Sanity: Sui basis-point convention.
        assert_eq!(
            total_weight, 10000,
            "epoch {} should sum to 10000",
            epoch_name
        );

        // Stage 1: search the divisor — depends only on the weights and δ_allowed.
        let reduced = Nodes::<RistrettoPoint>::prop_reduce(nodes_vec.clone(), SUI_ALLOWED_DELTA, 1)
            .expect("prop_reduce should succeed on Sui epoch data");

        let new_total = reduced.total_weight() as u32;
        let total_weight_u16 = original_nodes.total_weight();
        let new_total_u16 = reduced.total_weight();

        // Stage 2: derive (t', f') in closed form from the Stage-1 output.
        let (new_t, new_f) = derive_reduced_params(SUI_T, SUI_F, total_weight_u16, new_total_u16);

        // Reduction actually shrinks the committee size at this budget.
        assert!(
            new_total < total_weight,
            "epoch {}: expected reduction (W = {}, W' = {})",
            epoch_name,
            total_weight,
            new_total
        );
        assert!(new_total >= 1);
        assert!(new_t >= 1);
        // t > f in original space => t' >= f' after both ceilings, but the strict
        // inequality t' > f' is *not* guaranteed (the two ceilings can collapse).
        assert!(
            new_t >= new_f,
            "epoch {}: t > f should give t' >= f' (got t' = {}, f' = {})",
            epoch_name,
            new_t,
            new_f
        );

        // Each reduced weight is `floor(w_i / D)` for some D, hence at most w_i.
        for (orig, red) in nodes_vec.iter().zip(reduced.iter()) {
            assert!(red.weight <= orig.weight);
            assert_eq!(orig.id, red.id);
        }

        // Verify the Stage-1 search criterion δ + 2d ≤ δ_allowed (scaled by W'):
        //   Σ max(w_i * W' - w'_i * W, 0) + 2 * W ≤ δ_allowed * W'.
        let delta_scaled: i128 = nodes_vec
            .iter()
            .zip(reduced.iter())
            .map(|(orig, red)| {
                let lhs = (orig.weight as i128) * (new_total as i128);
                let rhs = (red.weight as i128) * (total_weight as i128);
                (lhs - rhs).max(0)
            })
            .sum();
        let lhs_scaled = delta_scaled + 2 * (total_weight as i128);
        let rhs_scaled = (SUI_ALLOWED_DELTA as i128) * (new_total as i128);
        assert!(
            lhs_scaled <= rhs_scaled,
            "epoch {}: (δ + 2d) * W' = {} > δ_allowed * W' = {}",
            epoch_name,
            lhs_scaled,
            rhs_scaled
        );

        // t' must equal the closed-form formula: t' = ceil(t * W' / W).
        let expected_t = ((SUI_T as u64) * (new_total as u64)).div_ceil(total_weight as u64) as u16;
        assert_eq!(
            new_t, expected_t,
            "epoch {}: t' mismatch (expected ceil(t*W'/W) = {}, got {})",
            epoch_name, expected_t, new_t
        );

        // f' must equal ceil(f * W' / W).
        let expected_f = ((SUI_F as u64) * (new_total as u64)).div_ceil(total_weight as u64) as u16;
        assert_eq!(
            new_f, expected_f,
            "epoch {}: f' mismatch (expected {}, got {})",
            epoch_name, expected_f, new_f
        );

        // Liveness sanity check: a coalition with original weight ≥ t + f + δ_allowed
        // must reach reduced weight ≥ t' + f' under any unilateral reduction. We
        // verify this against the actual reduction by computing the smallest reduced
        // weight a coalition of total original weight ≥ t + f + δ_allowed could carry.
        // (Worst case under the unilateral inequality is w'(S) = (w(S) - δ) / d.)
        let live_threshold = (SUI_T as i128) + (SUI_F as i128) + (SUI_ALLOWED_DELTA as i128);
        let lower_bound_w_prime_scaled =
            (live_threshold * (new_total as i128) - delta_scaled) / (total_weight as i128);
        let target = (new_t as i128) + (new_f as i128);
        assert!(
            lower_bound_w_prime_scaled >= target,
            "epoch {}: live coalition w(S) ≥ t+f+δ_allowed should give w'(S) ≥ t'+f' \
             (got lower bound on w'(S) = {}, target = {})",
            epoch_name,
            lower_bound_w_prime_scaled,
            target
        );

        let delta = (delta_scaled as f64) / (new_total as f64);
        let combined = delta + 2.0 * (total_weight as f64 / new_total as f64);
        println!(
            "|  {:>3} | {:>3} | {:>5} | {:>5} | {:>4.1}× | {:>3} | {:>3} | {:>5.2} | {:>6.2} |",
            epoch_name,
            n_parties,
            total_weight,
            new_total,
            total_weight as f64 / new_total as f64,
            new_t,
            new_f,
            delta,
            combined,
        );
    }
}

#[test]
fn test_prop_reduce_modular_reuse() {
    // Stage 1 is independent of (t, f), so a single Stage-1 reduction can be reused
    // across multiple Stage-2 calls. We exercise this on every Sui epoch with a
    // family of (t, f) pairs satisfying t > f at W = 10000.
    let tf_pairs: &[(u16, u16)] = &[
        (4000, 3400),
        (5000, 3300),
        (6000, 3000),
        (6700, 3300),
        (7000, 2000),
    ];

    for (epoch_name, contents) in SUI_EPOCH_DATA {
        let weights = parse_sui_epoch(contents);
        let nodes_vec = build_sui_nodes(&weights);
        let original = Nodes::<RistrettoPoint>::new(nodes_vec.clone()).unwrap();
        let w = original.total_weight();

        // One Stage-1 call.
        let reduced =
            Nodes::<RistrettoPoint>::prop_reduce(nodes_vec.clone(), SUI_ALLOWED_DELTA, 1).unwrap();
        let w_prime = reduced.total_weight();

        // Many Stage-2 calls reusing the same `reduced`.
        for (t, f) in tf_pairs {
            let (t_prime, f_prime) = derive_reduced_params(*t, *f, w, w_prime);
            // t > f in original space => t' >= f' after ceilings.
            assert!(
                t_prime >= f_prime,
                "epoch {} (t={}, f={}): t > f should give t' >= f' (got t'={}, f'={})",
                epoch_name,
                t,
                f,
                t_prime,
                f_prime
            );
            // Stage-2 formulas (closed form, no cap).
            let expected_t = ((*t as u64) * (w_prime as u64)).div_ceil(w as u64) as u16;
            let expected_f = ((*f as u64) * (w_prime as u64)).div_ceil(w as u64) as u16;
            assert_eq!(t_prime, expected_t);
            assert_eq!(f_prime, expected_f);
        }
    }
}

#[test]
fn test_prop_reduce_vs_new_reduced_on_sui_epochs() {
    // prop_reduce uses fractional divisors and the exact δ accounting, so its W'
    // should not exceed new_reduced_with_f's W' at the same budget - even
    // though prop_reduce reserves an extra 2d for ceiling overheads in the
    // search criterion.
    println!(
        "\nprop_reduce vs new_reduced_with_f on Sui epochs — t = {}, f = {}, δ_allowed = {}\n",
        SUI_T, SUI_F, SUI_ALLOWED_DELTA
    );
    println!("| epoch | prop_reduce W' | new_reduced_with_f W' | smaller by |");
    println!("|------:|---------------:|----------------------:|-----------:|");

    for (epoch_name, contents) in SUI_EPOCH_DATA {
        let weights = parse_sui_epoch(contents);
        let nodes_vec = build_sui_nodes(&weights);

        let prop_nodes =
            Nodes::<RistrettoPoint>::prop_reduce(nodes_vec.clone(), SUI_ALLOWED_DELTA, 1).unwrap();
        let (legacy_nodes, _, _) = Nodes::<RistrettoPoint>::new_reduced_with_f(
            nodes_vec.clone(),
            SUI_T,
            SUI_F,
            SUI_ALLOWED_DELTA,
            1,
        )
        .unwrap();

        let prop_w = prop_nodes.total_weight();
        let legacy_w = legacy_nodes.total_weight();

        assert!(
            prop_w <= legacy_w,
            "epoch {}: prop_reduce W' = {} should be ≤ new_reduced_with_f W' = {}",
            epoch_name,
            prop_w,
            legacy_w
        );

        let ratio = (legacy_w as f64) / (prop_w as f64);
        println!(
            "|  {:>3} | {:>14} | {:>21} | {:>9.2}× |",
            epoch_name, prop_w, legacy_w, ratio,
        );
    }
}

#[test]
fn test_reduce_with_lower_bounds() {
    let number_of_nodes = 100;
    let node_vec = get_nodes::<RistrettoPoint>(number_of_nodes);
    let nodes = Nodes::new(node_vec.clone()).unwrap();
    let t = nodes.total_weight() / 3;

    // No extra gap, should return the inputs
    let (new_nodes, new_t) = Nodes::new_reduced(node_vec.clone(), t, 1, 1).unwrap();
    assert_eq!(nodes, new_nodes);
    assert_eq!(t, new_t);

    // 10% gap
    let (new_nodes1, _new_t1) =
        Nodes::new_reduced(node_vec.clone(), t, nodes.total_weight() / 10, 1).unwrap();
    let (new_nodes2, _new_t2) = Nodes::new_reduced(
        node_vec.clone(),
        t,
        nodes.total_weight() / 10,
        nodes.total_weight() / 3,
    )
    .unwrap();
    assert!(new_nodes1.total_weight() < new_nodes2.total_weight());
    assert!(new_nodes2.total_weight() >= nodes.total_weight() / 3);
    assert!(new_nodes2.total_weight() < nodes.total_weight());
}
