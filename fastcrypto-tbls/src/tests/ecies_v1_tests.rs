// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1::*;
use crate::ecies_v1::{PrivateKey, PublicKey};
use crate::random_oracle::RandomOracle;
use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar, SCALAR_LENGTH};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use fastcrypto::traits::KeyPair;
use rand::prelude::StdRng;
use rand::{thread_rng, SeedableRng};
use serde::{de::DeserializeOwned, Serialize};

#[generic_tests::define]
mod point_tests {
    use super::*;
    use crate::ecies_v1::{PrivateKey, PublicKey};
    use fastcrypto::groups::HashToGroupElement;
    use zeroize::Zeroize;

    #[allow(clippy::multiple_bound_locations)]
    #[test]
    fn test_multi_rec<Group: GroupElement + Serialize + DeserializeOwned>()
    where
        Group::ScalarType: FiatShamirChallenge + Zeroize,
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
            let decrypted = mr_enc.decrypt(sk, &ro, i);
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
            let pkg = mr_enc.create_recovery_package(sk, &recovery_ro, &mut thread_rng());
            let decrypted = mr_enc
                .decrypt_with_recovery_package(&pkg, &recovery_ro, &ro, pk, i)
                .unwrap();
            assert_eq!(msg.as_bytes(), &decrypted);

            // Should fail for a different RO.
            assert!(mr_enc
                .decrypt_with_recovery_package(&pkg, &recovery_ro.extend("bla"), &ro, pk, i)
                .is_err());

            // Same package will fail on a different encryption
            assert!(mr_enc2
                .decrypt_with_recovery_package(&pkg, &recovery_ro, &ro, pk, i)
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

#[test]
fn test_zeroization_on_drop() {
    let ptr: *const u8;
    {
        let sk = PrivateKey::<G2Element>::new(&mut thread_rng());
        ptr = std::ptr::addr_of!(sk.0) as *const u8;
    }

    unsafe {
        for i in 0..SCALAR_LENGTH {
            assert_eq!(*ptr.add(i), 0);
        }
    }
}

#[test]
fn test_regression_g2() {
    let ro = RandomOracle::new("test");
    let keys_and_msg = (0..10u128)
        .map(|i| {
            let sk = PrivateKey::<G2Element>::from(Scalar::from(i * 1234));
            let pk = PublicKey::<G2Element>::from_private_key(&sk);
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

    let mut rng = StdRng::from_seed([1; 32]);
    let mr_enc = MultiRecipientEncryption::encrypt(
        &keys_and_msg
            .iter()
            .map(|(_, pk, msg)| (pk.clone(), msg.as_bytes().to_vec()))
            .collect::<Vec<_>>(),
        &ro,
        &mut rng,
    );
    let expected_enc = "a746a1921b8381e14c387b09523266cc6997349210935e505356a48a4627847a14dffb7d2b2f72ec057b7560893a068516cad16499396a4f6c6d5e776d32f80710a1c5a1fd4a2962e8b3ff7e62efdeca5669a0be7264022306e250235a35f739a10302ea516450215a7a02bc9ce2ff8fcdfeea84cd4d9bbb525fd08823189f0920614cb118d97d84c3f8eb867f0ac6260d444084dd0da224c685de0daf1ae093d71fe8747bdf039da7aa86d6cf44625c159c25c43de4ad2d32b8a4efd91b54760a392baa2efb3f97c92cf54fb262cdceb3d131f01b76194d32b3289ebe00f6842eeab92165a0eaad7708e47c903be2db490e288994a5d4e4db21a33933b272af3039a2d8e721ada5cc1d50e169153e6a70f4c5a1151db5dc20412e9011479408482834e4d7c74ff8597d2ae539218b9ff64b8df13739c5412ef6faf592621f0ee09555de3aee714472c282b75338be1fd7c3f4887bb75b816c8ffc8b4c3a25f21daf8472db5e182ff624569ab802ac39cf0ddb2842172b44e82ff9e7ee20ec75008c96b7cad8c7b83632ad2a3095dd9db042cdc8cd49d4b54be4ec195533161c017be1efacbc3ed2be3951f2133c000cfb3dd2a680e92e0418d429cbeeb974b15ec5135aa0f71855c092cf43ad2f7faeebfe44fef744ee8000b9b7d76f0a8ed43b5b0b395153744e2e9dd8e04344169b9b56b1878d7b1db43ce852dce30e3c37220aad0b56305c8a93b0384d496465f904d5c39f7c442bf2ed550c6abd390d10c020525232dfafaa95332edc5e813281f9e0bdf658718a5e9de958299444e74e29dae88fe8cd95ffad55d78162362bab7a73fadf482a7239f572931b6a6989e655f706eab4af6f2802572a208e0d27d8da46e6750988e8ee516bf214d245be46345bb147b0c194b302422ae9816558d23a3903c34f1165b686f8be5d8cef0e83454dc7c165852972a3fd984f099ea00f3dde245ca52d83cf482f5975140bfb674578d15b3296b1687838fa396485abb6bd08916b0324334f22b157ecbe55e9bbfd208b7527041b88eac94e55cb285af4d557a1830a6dba971fee66feeedf50aaf4be1ce455846d64a495ce6205107c1dd359c1dce653bd961fce91cc784d118385848585043b750641428b50d551152eb7aadccee70bf4f5e346549240de07764148e85fc907796e376deadbd1068295053bba131f72f0ce57054063b7b7027810a05ff00cb41813d14d033fbd2c9f26c0b4323d8b0d0828ae22f3b4475624999e34f3f516924a91db8c205d2331a811bdba8e29b6014b8e30e472ba5166d7caff61211707665710407df109d88a99f018f4ae448e5908a47769a638d66767df0a4f7fe41406abfb6176cddaba6863544671eaf60beb2af4fe4fa2597ec6834db65e67afc1";
    assert_eq!(hex::encode(bcs::to_bytes(&mr_enc).unwrap()), expected_enc);

    let pkg = mr_enc.create_recovery_package(&keys_and_msg[1].0, &ro, &mut rng);
    let expected_pkg = "b19d4237df93dccdca2de9b95d67c2e0e5a7d4584c0e478e87f33883382a64ff6d0119504aa81820970c093f893d762015d33a21e8e8ca8d511ef16d08aa50d523d1c93cf405a9fb52c0e3dfa556edb4ed39a448ead4c7de3c8273f155f97f2284664935f15759ea6c06f068a4c418c6d475c314f3d8af66061f6b19ca5eb77cefa3cc6ad3fcfb8d465cb59469a2fe4602ac502962b1e050156eddfac3da47a89c6b29209da7637dfb126d96c969ad752e2b11d89ba519206e2016c010732b7f92a65e573739f26d973226cb966306fde491bdf9e94a29b8618a3bdfae5babe01a6d9af01cca2b1bbb1d4c71b0acaf8518b7c9715255751a96ff3678dd044f647e24969c7b45eac6896335fc32c3ee46cefacf45fc39bcea38fb0ed72d904f711642f30c37aec84e2fb9b833dedb370d19e1d05416ba579969b9623c4d48ed79";
    assert_eq!(hex::encode(bcs::to_bytes(&pkg).unwrap()), expected_pkg);
}
