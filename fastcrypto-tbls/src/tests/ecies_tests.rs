// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies::*;
use crate::random_oracle::RandomOracle;
use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use fastcrypto::traits::KeyPair;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;

const MSG: &[u8; 4] = b"test";

#[generic_tests::define]
mod point_tests {
    use super::*;

    #[test]
    fn test_decryption<Group: GroupElement + Serialize + DeserializeOwned>()
    where
        Group::ScalarType: FiatShamirChallenge,
    {
        let sk = PrivateKey::<Group>::new(&mut thread_rng());
        let pk = PublicKey::<Group>::from_private_key(&sk);
        let encryption = pk.encrypt(MSG, &mut thread_rng());
        let decrypted = sk.decrypt(&encryption);
        assert_eq!(MSG, decrypted.as_slice());
    }

    #[test]
    fn test_recovery_package<Group: GroupElement + Serialize + DeserializeOwned>()
    where
        Group::ScalarType: FiatShamirChallenge,
    {
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

    #[test]
    fn test_multi_rec<Group: GroupElement + Serialize + DeserializeOwned>()
    where
        Group::ScalarType: FiatShamirChallenge,
    {
        let ro = RandomOracle::new("test");
        let keys_and_msg = (0..10u32)
            .map(|i| {
                let sk = PrivateKey::<Group>::new(&mut thread_rng());
                let pk = PublicKey::<Group>::from_private_key(&sk);
                (sk, pk, format!("test {}", i))
            })
            .collect::<Vec<_>>();

        let mr_enc = MultiRecipientEncryption::encrypt(
            &keys_and_msg
                .iter()
                .map(|(_, pk, msg)| (pk.clone(), msg.as_bytes().to_vec()))
                .collect::<Vec<_>>(),
            &ro,
            &mut thread_rng(),
        );

        assert!(mr_enc.verify(&ro).is_ok());

        for (i, (sk, _, msg)) in keys_and_msg.iter().enumerate() {
            let enc = mr_enc.get_encryption(i).unwrap();
            let decrypted = sk.decrypt(&enc);
            assert_eq!(msg.as_bytes(), &decrypted);
        }

        // test empty messages
        let mr_enc = MultiRecipientEncryption::encrypt(
            &keys_and_msg
                .iter()
                .map(|(_, pk, _)| (pk.clone(), vec![]))
                .collect::<Vec<_>>(),
            &ro,
            &mut thread_rng(),
        );
        assert!(mr_enc.verify(&ro).is_err());
    }

    #[instantiate_tests(<RistrettoPoint>)]
    mod ristretto_point {}

    #[instantiate_tests(<G1Element>)]
    mod g1_element {}

    #[instantiate_tests(<G2Element>)]
    mod g2_element {}
}

#[test]
fn test_blskeypair_to_group() {
    let pair = BLS12381KeyPair::generate(&mut thread_rng());
    let (pk, sk) = (pair.public().clone(), pair.private());
    let pk: G2Element = bcs::from_bytes(pk.as_ref()).expect("should work");
    let ecies_pk = PublicKey::<G2Element>::from(pk);
    let sk: Scalar = bcs::from_bytes(sk.as_ref()).expect("should work");
    let ecies_sk = PrivateKey::<G2Element>::from(sk);
    assert_eq!(
        ecies_pk,
        PublicKey::<G2Element>::from_private_key(&ecies_sk)
    );
    assert_eq!(*ecies_pk.as_element(), G2Element::generator() * sk);
}
