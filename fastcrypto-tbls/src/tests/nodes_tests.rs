// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies;
use crate::nodes::{Node, Nodes};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use rand::thread_rng;

#[test]
fn test_reduce() {
    let sk = ecies::PrivateKey::<RistrettoPoint>::new(&mut thread_rng());
    let pk = ecies::PublicKey::<RistrettoPoint>::from_private_key(&sk);
    for number_of_nodes in [10, 50, 100, 150, 200, 250, 300, 350, 400] {
        let node_vec = (0..number_of_nodes)
            .map(|i| Node {
                id: i,
                pk: pk.clone(),
                weight: 5 + i,
            })
            .collect();
        let nodes = Nodes::new(node_vec).unwrap();
        let t = (nodes.n() / 3) as u16;

        // No extra gap, should return the inputs
        let (new_nodes, new_t) = nodes.reduce(t, 1);
        assert_eq!(nodes, new_nodes);
        assert_eq!(t, new_t);

        // 10% gap
        let (new_nodes, _new_t) = nodes.reduce(t, (nodes.n() / 10) as u16);
        // Estimate the real factor d
        let d = nodes.iter().last().unwrap().weight / new_nodes.iter().last().unwrap().weight;
        // The loss per node is on average (d - 1) / 2
        // We use 9 instead of 10 to compensate wrong value of d
        assert!((d - 1) / 2 * number_of_nodes < ((nodes.n() / 9) as u16));
    }
}
