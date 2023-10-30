// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nizk::DLNizk;
use crate::random_oracle::RandomOracle;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as Sc};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::thread_rng;

#[test]
fn test_random_oracle() {
    let ro1 = RandomOracle::new("dkg [43, 62, 50, ca, b8, db, f5, 62, de, 50, 36, 2e, 93, 34, b9, 32, bd, b1, 7e, 1f, bd, 69, 62, 11, 1d, 3e, 17, f2, 2f, 83, ce, 2b] 0");
    let ro2 = ro1.extend("encs 142");

    let x = Sc::rand(&mut thread_rng());
    let g_x = G2Element::generator() * x;
    let nizk = DLNizk::create(&x, &g_x, &ro2, &mut thread_rng());
    assert!(nizk.verify(&g_x, &ro2).is_ok());

    let eph = Hex::decode("b30ba04a72aa15a0b8c104b2578ee479fba81057b221646d0308c9dc24c5e4911b5e3bae12eedc67a89350b01067aabb16cea3090ff5f462ae85ae1de8f3f7730eed695d98d89694a234fbf59d5df5de0900607aa39a56a1746f32da26b88df5").unwrap();
    let eph = G2Element::from_byte_array(&eph.try_into().unwrap()).unwrap();

    let nizk_0 = Hex::decode("b939f69ae5d2047e6eee7fd1167e97c5066de302578f37a9d0dd3040c40bace792e07d050aa086b9a5382c0f4cbf297c17e5693703be633a1297ee1cc6e4ff11a3fb113654d722d6b3f1d81cc2d6e323d6dbd3f7b5290e7e30235476d4e203ed").unwrap();
    let nizk_0 = G2Element::from_byte_array(&nizk_0.try_into().unwrap()).unwrap();
    let nizk_1 =
        Hex::decode("444311b0deeb5a809241915008ff1a0b7384efa3c03ae8092aa6813bc3566bfb").unwrap();
    let nizk_1 = Sc::from_byte_array(&nizk_1.try_into().unwrap()).unwrap();

    let nizk = DLNizk::<G2Element>(nizk_0, nizk_1);
    assert!(nizk.verify(&eph, &ro2).is_ok());
}
