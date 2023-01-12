// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies::*;
use crate::random_oracle::RandomOracle;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use rand::thread_rng;

const MSG: &[u8; 4] = b"test";

type Group = RistrettoPoint;

#[test]
fn test_decryption() {
    let sk = PrivateKey::<Group>::new(&mut thread_rng());
    let pk = PublicKey::<Group>::from_private_key(&sk);
    let encryption = pk.encrypt(MSG, &mut thread_rng());
    let decrypted = sk.decrypt(&encryption);
    assert_eq!(MSG, decrypted.as_slice());
}

#[test]
fn test_recovery_package() {
    let sk = PrivateKey::<Group>::new(&mut thread_rng());
    let pk = PublicKey::<Group>::from_private_key(&sk);
    let encryption = pk.encrypt(MSG, &mut thread_rng());
    let ro = RandomOracle::new("test");
    let pkg = sk.create_recovery_package(&encryption, &ro, &mut thread_rng());
    let decrypted = pk
        .decrypt_with_recovery_package(&pkg, &ro, &encryption)
        .unwrap();
    assert_eq!(MSG, decrypted.as_slice());

    // Should fail for a different RO.
    assert!(pk
        .decrypt_with_recovery_package(&pkg, &RandomOracle::new("test2"), &encryption)
        .is_err());

    // Same package will fail on a different encryption
    let encryption = pk.encrypt(MSG, &mut thread_rng());
    assert!(pk
        .decrypt_with_recovery_package(&pkg, &ro, &encryption)
        .is_err());
}
