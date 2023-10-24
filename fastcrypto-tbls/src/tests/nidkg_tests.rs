// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies;
use crate::nidkg::Party;
use crate::nodes::Node;
use crate::random_oracle::RandomOracle;
use fastcrypto::groups::bls12381::G1Element;
use rand::thread_rng;

// const MSG: [u8; 4] = [1, 2, 3, 4];

type G = G1Element;

pub fn gen_ecies_keys(n: u16) -> Vec<(u16, ecies::PrivateKey<G>, ecies::PublicKey<G>)> {
    (0..n)
        .map(|id| {
            let sk = ecies::PrivateKey::<G>::new(&mut thread_rng());
            let pk = ecies::PublicKey::<G>::from_private_key(&sk);
            (id, sk, pk)
        })
        .collect()
}

pub fn setup_party(
    id: usize,
    threshold: u32,
    keys: &[(u16, ecies::PrivateKey<G>, ecies::PublicKey<G>)],
) -> Party<G> {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<G> {
            id: *id,
            pk: pk.clone(),
            weight: *id + 1,
        })
        .collect();
    Party::<G>::new(
        keys.get(id).unwrap().1.clone(),
        nodes,
        threshold,
        RandomOracle::new("dkg"),
        &mut thread_rng(),
    )
    .unwrap()
}

#[test]
fn test_dkg_e2e_4_parties_threshold_2() {
    let mut rng = thread_rng();
    let keys = gen_ecies_keys(4); // total weight of 10

    let d0 = setup_party(0, 3, &keys);
    let d1 = setup_party(1, 3, &keys);
    let d2 = setup_party(2, 3, &keys);
    // The third party is ignored (emulating a byzantine party).
    let _d3 = setup_party(3, 3, &keys);

    let m0 = d0.create_message(&mut thread_rng());
    let m1 = d1.create_message(&mut thread_rng());
    let m2 = d2.create_message(&mut thread_rng());

    assert!(d0.verify_message(&m1, &mut rng).is_ok());
    assert!(d1.verify_message(&m2, &mut rng).is_ok());
    assert!(d2.verify_message(&m0, &mut rng).is_ok());

    let mut bad_m2 = m2.clone();
    Party::<G>::modify_message_swap_partial_pks(&mut bad_m2, 1, 2);
    assert!(d1.verify_message(&bad_m2, &mut rng).is_err());
    // TODO: test more failures

    assert!(d0.is_above_t(&[m0.clone(), m1.clone()]).is_ok());
    assert!(d0.is_above_t(&[m2.clone()]).is_ok());
    assert!(d0.is_above_t(&[m1.clone()]).is_err());

    let verified = [m0.clone(), m1.clone(), m2.clone()];
    let final_pks0 = d0.compute_final_pks(&verified);
    let final_pks1 = d1.compute_final_pks(&verified);
    assert_eq!(final_pks0, final_pks1);

    let (_share0, _complaints0) = d2.process_message(&m0, &mut rng);
    let (_share1, _complaints1) = d2.process_message(&m1, &mut rng);
    let (_share2, _complaints2) = d2.process_message(&m2, &mut rng);
    // TODO: tests complaints, etc

    let partial_pks_in_g2 = d0.create_partial_pks_in_g2();
    assert!(
        Party::<G1Element>::verify_partial_pks_in_g2(&m0, &partial_pks_in_g2, &mut rng).is_ok()
    );

    //
    // // Use the shares from 01 and o4 to sign a message.
    // type S = ThresholdBls12381MinSig;
    // let sig1 = S::partial_sign(&o1.share, &MSG);
    // let sig4 = S::partial_sign(&o4.share, &MSG);
    //
    // S::partial_verify(&o1.vss_pk, &MSG, &sig1).unwrap();
    // S::partial_verify(&o4.vss_pk, &MSG, &sig4).unwrap();
    //
    // let sigs = vec![sig1, sig4];
    // let sig = S::aggregate(d1.threshold(), &sigs).unwrap();
    // S::verify(o1.vss_pk.c0(), &MSG, &sig).unwrap();
}
