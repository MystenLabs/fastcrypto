// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1::*;
use crate::random_oracle::RandomOracle;
use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use fastcrypto::traits::KeyPair;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[generic_tests::define]
mod point_tests {
    use super::*;
    use fastcrypto::groups::HashToGroupElement;

    #[test]
    fn test_multi_rec<Group: GroupElement + Serialize + DeserializeOwned>()
    where
        Group::ScalarType: FiatShamirChallenge,
        Group: HashToGroupElement,
    {
        let ro = RandomOracle::new("test");
        let keys_and_msg = (0..10u32)
            .map(|i| {
                let sk = PrivateKey::<Group>::new(&mut thread_rng());
                let pk = PublicKey::<Group>::from_private_key(&sk);
                (
                    sk,
                    pk,
                    format!(
                        "test {} 12345678901234567890123456789012345678901234567890",
                        i
                    ),
                )
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
        assert!(mr_enc.verify(&ro.extend("bla")).is_err());

        for (i, (sk, _, msg)) in keys_and_msg.iter().enumerate() {
            let decrypted = sk.decrypt(&mr_enc, &ro, i);
            assert_eq!(msg.as_bytes(), &decrypted);
        }

        // test empty messages
        let mr_enc2 = MultiRecipientEncryption::encrypt(
            &keys_and_msg
                .iter()
                .map(|(_, pk, _)| (pk.clone(), vec![]))
                .collect::<Vec<_>>(),
            &ro,
            &mut thread_rng(),
        );
        assert!(mr_enc2.verify(&ro).is_err());

        // test recovery package
        let recovery_ro = ro.extend("recovery");
        let mr_enc2 = MultiRecipientEncryption::encrypt(
            &keys_and_msg
                .iter()
                .map(|(_, pk, msg)| (pk.clone(), msg.as_bytes().to_vec()))
                .collect::<Vec<_>>(),
            &ro,
            &mut thread_rng(),
        );

        for (i, (sk, pk, msg)) in keys_and_msg.iter().enumerate() {
            let pkg = sk.create_recovery_package(&mr_enc, &recovery_ro, &mut thread_rng());
            let decrypted = mr_enc
                .decrypt_with_recovery_package(&pkg, &recovery_ro, &ro, &pk, i)
                .unwrap();
            assert_eq!(msg.as_bytes(), &decrypted);

            // Should fail for a different RO.
            assert!(mr_enc
                .decrypt_with_recovery_package(&pkg, &recovery_ro.extend("bla"), &ro, &pk, i)
                .is_err());

            // Same package will fail on a different encryption
            assert!(mr_enc2
                .decrypt_with_recovery_package(&pkg, &recovery_ro, &ro, &pk, i)
                .is_err());
        }
    }

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
