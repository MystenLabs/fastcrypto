// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use fastcrypto::nizk::{DLNizk, DdhTupleNizk};
use fastcrypto::random_oracle::RandomOracle;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[generic_tests::define]
mod point_tests {
    use super::*;

    #[test]
    fn test_dl_nizk<G: GroupElement + Serialize + DeserializeOwned>()
    where
        G::ScalarType: FiatShamirChallenge + DeserializeOwned,
    {
        // basic flow
        let x = G::ScalarType::rand(&mut thread_rng());
        let g_x = G::generator() * x;
        let nizk = DLNizk::create(&x, &g_x, &RandomOracle::new("test"), &mut thread_rng());
        assert!(nizk.verify(&g_x, &RandomOracle::new("test")).is_ok());
        assert!(nizk.verify(&g_x, &RandomOracle::new("test2")).is_err());
        assert!(nizk
            .verify(&G::generator(), &RandomOracle::new("test"))
            .is_err());

        // x_g=inf should be rejected
        let zero = G::ScalarType::zero();
        let inf = G::zero();
        let g = G::generator();
        let invalid_nizk =
            DLNizk::create(&zero, &inf, &RandomOracle::new("test"), &mut thread_rng());
        assert!(invalid_nizk
            .verify(&inf, &RandomOracle::new("test"))
            .is_err());
        assert!(invalid_nizk.verify(&g, &RandomOracle::new("test")).is_err());

        // serde
        let as_bytes = bcs::to_bytes(&nizk).unwrap();
        let nizk2: DLNizk<G> = bcs::from_bytes(&as_bytes).unwrap();
        assert_eq!(nizk, nizk2);
        let as_bytes = bcs::to_bytes(&(G::generator(), G::ScalarType::generator())).unwrap();
        assert!(bcs::from_bytes::<DLNizk<G>>(&as_bytes).is_ok());
        let as_bytes = bcs::to_bytes(&(G::zero(), G::ScalarType::generator())).unwrap();
        assert!(bcs::from_bytes::<DLNizk<G>>(&as_bytes).is_err());
        let as_bytes = bcs::to_bytes(&(G::generator(), G::ScalarType::zero())).unwrap();
        assert!(bcs::from_bytes::<DLNizk<G>>(&as_bytes).is_err());
    }

    #[test]
    fn test_ddh_nizk<G: GroupElement + Serialize + DeserializeOwned>()
    where
        G::ScalarType: FiatShamirChallenge + DeserializeOwned,
    {
        // basic flow
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

        // x_g/h_g/h=inf should be rejected
        let invalid_nizk = DdhTupleNizk::create(
            &x2,
            &g_x1,
            &g_x2,
            &g_x1_x2,
            &RandomOracle::new("test"),
            &mut thread_rng(),
        );
        assert!(invalid_nizk
            .verify(&G::zero(), &g_x2, &g_x1_x2, &RandomOracle::new("test"))
            .is_err());
        assert!(invalid_nizk
            .verify(&g_x1, &G::zero(), &g_x1_x2, &RandomOracle::new("test"))
            .is_err());
        assert!(invalid_nizk
            .verify(&g_x1, &g_x2, &G::zero(), &RandomOracle::new("test"))
            .is_err());

        // serde
        let as_bytes = bcs::to_bytes(&nizk).unwrap();
        let nizk2: DdhTupleNizk<G> = bcs::from_bytes(&as_bytes).unwrap();
        assert_eq!(nizk, nizk2);
        let as_bytes =
            bcs::to_bytes(&(G::generator(), G::generator(), G::ScalarType::generator())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_ok());
        let as_bytes =
            bcs::to_bytes(&(G::zero(), G::generator(), G::ScalarType::generator())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_err());
        let as_bytes =
            bcs::to_bytes(&(G::generator(), G::zero(), G::ScalarType::generator())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_err());
        let as_bytes =
            bcs::to_bytes(&(G::generator(), G::generator(), G::ScalarType::zero())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_err());
    }

    #[instantiate_tests(<RistrettoPoint>)]
    mod ristretto_point {}

    #[instantiate_tests(<G1Element>)]
    mod g1_element {}

    #[instantiate_tests(<G2Element>)]
    mod g2_element {}
}
