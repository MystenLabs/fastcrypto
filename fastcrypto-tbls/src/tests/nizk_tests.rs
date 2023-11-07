// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nizk::{DLNizk, DdhTupleNizk};
use crate::random_oracle::RandomOracle;
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use rand::thread_rng;
use serde::Serialize;

#[generic_tests::define]
mod point_tests {
    use super::*;

    #[test]
    fn test_dl_nizk<G: GroupElement + Serialize>()
    where
        G::ScalarType: FiatShamirChallenge,
    {
        let x = G::ScalarType::rand(&mut thread_rng());
        let g_x = G::generator() * x;

        let nizk = DLNizk::create(&x, &g_x, &RandomOracle::new("test"), &mut thread_rng());
        assert!(nizk.verify(&g_x, &RandomOracle::new("test")).is_ok());
        assert!(nizk.verify(&g_x, &RandomOracle::new("test2")).is_err());
        assert!(nizk
            .verify(&G::generator(), &RandomOracle::new("test"))
            .is_err());
    }

    #[test]
    fn test_ddh_nizk<G: GroupElement + Serialize>()
    where
        G::ScalarType: FiatShamirChallenge,
    {
        let x1 = G::ScalarType::rand(&mut thread_rng());
        let x2 = G::ScalarType::rand(&mut thread_rng());
        let g_x1 = G::generator() * x1;
        let g_x2 = G::generator() * x2;
        let g_x1_x2 = g_x1 * x2;

        let nizk = DdhTupleNizk::create(
            &x2,
            &g_x1,
            &g_x2,
            &g_x1_x2,
            &RandomOracle::new("test"),
            &mut thread_rng(),
        );
        assert!(nizk
            .verify(&g_x1, &g_x2, &g_x1_x2, &RandomOracle::new("test"))
            .is_ok());
        assert!(nizk
            .verify(&g_x1, &g_x2, &g_x1_x2, &RandomOracle::new("test2"))
            .is_err());
        assert!(nizk
            .verify(&g_x1, &g_x2, &g_x2, &RandomOracle::new("test"))
            .is_err());
    }

    #[instantiate_tests(<RistrettoPoint>)]
    mod ristretto_point {}

    #[instantiate_tests(<G1Element>)]
    mod g1_element {}

    #[instantiate_tests(<G2Element>)]
    mod g2_element {}
}
