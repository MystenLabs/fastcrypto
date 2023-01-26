// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    encoding::{Encoding, Hex},
    hash::{HashFunction, Sha256},
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature},
    signature_service::SignatureService,
    traits::{EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};
#[cfg(feature = "copy_key")]
use proptest::arbitrary::Arbitrary;
use proptest::{prelude::*, strategy::Strategy};
use rand::{rngs::StdRng, SeedableRng as _};
use rust_secp256k1::{constants, ecdsa::Signature};
use signature::{Signer, Verifier};
use wycheproof::ecdsa::{TestName::EcdsaSecp256k1Sha256, TestSet};
use wycheproof::TestResult;

pub fn keys() -> Vec<Secp256k1KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);

    (0..4)
        .map(|_| Secp256k1KeyPair::generate(&mut rng))
        .collect()
}

#[test]
fn serialize_deserialize() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();

    let bytes = bincode::serialize(&public_key).unwrap();
    let pk2 = bincode::deserialize::<Secp256k1PublicKey>(&bytes).unwrap();
    assert_eq!(public_key.as_ref(), pk2.as_ref());

    let private_key = kpref.private();
    let bytes = bincode::serialize(&private_key).unwrap();
    let privkey = bincode::deserialize::<Secp256k1PrivateKey>(&bytes).unwrap();
    let bytes2 = bincode::serialize(&privkey).unwrap();
    assert_eq!(bytes, bytes2);

    let signature = Secp256k1Signature::default();
    let bytes = bincode::serialize(&signature).unwrap();
    let sig = bincode::deserialize::<Secp256k1Signature>(&bytes).unwrap();
    let bytes2 = bincode::serialize(&sig).unwrap();
    assert_eq!(bytes, bytes2);

    // test serde_json serialization
    let serialized = serde_json::to_string(&signature).unwrap();
    println!("{:?}", serialized);
    let deserialized: Secp256k1Signature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, signature);
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = Secp256k1PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), public_key.as_ref());
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Secp256k1PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
#[cfg(feature = "copy_key")]
fn test_copy_key_pair() {
    let kp = keys().pop().unwrap();
    let kp_copied = kp.copy();

    assert_eq!(kp.public().as_bytes(), kp_copied.public().as_bytes());
    assert_eq!(kp.private().as_bytes(), kp_copied.private().as_bytes());
}

#[test]
#[cfg(feature = "copy_key")]
fn serialize_private_key_only_for_keypair() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|kp| {
        let sk = kp.copy().private();
        let serialized_kp = bincode::serialize(&kp).unwrap();
        let serialized_sk = bincode::serialize(&sk).unwrap();
        assert_eq!(serialized_sk, serialized_kp);
    });
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world!");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <Secp256k1Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig.as_ref(), signature.as_ref())
}

#[test]
fn verify_valid_signature() {
    let kp: Secp256k1KeyPair = Secp256k1PrivateKey::from_bytes(&[
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
        102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ])
    .unwrap()
    .into();

    // Sign over raw message
    let message: &[u8] = b"Hello, world!";

    // Pin a signature using a deterministic private key bytes. This is useful to compare test result with typescript implementation.
    // See: https://github.com/MystenLabs/sui/tree/main/sdk/typescript/test/unit/cryptography/secp256k1-keypair.test.ts
    let signature = kp.sign(message);
    assert_eq!(Hex::encode(signature.clone()), "25d450f191f6d844bf5760c5c7b94bc67acc88be76398129d7f43abdef32dc7f7f1a65b7d65991347650f3dd3fa3b3a7f9892a0608521cbcf811ded433b31f8b");

    // Verify the signature.
    assert!(kp.public().verify(message, &signature).is_ok());
}

#[test]
fn verify_valid_signature_against_hashed_msg() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message. Hashed with sha256 internally.
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);

    // Verify the signature against hashed message.
    assert!(kp
        .public()
        .verify_hashed(Sha256::digest(message).as_ref(), &signature)
        .is_ok());
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Secp256k1PublicKey>, Vec<Secp256k1Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let (pubkeys, signatures): (Vec<Secp256k1PublicKey>, Vec<Secp256k1Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    (message.to_vec(), pubkeys, signatures)
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = Secp256k1Signature::default();

    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Secp256k1PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_hashed_failed_if_message_unhashed() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message (hashed to keccak256 internally).
    let message: &[u8] = &[0u8; 1];
    let signature = kp.sign(message);

    // Verify the signature against unhashed msg fails.
    assert!(kp.public().verify_hashed(message, &signature).is_err());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    // Verify the signature against good digest passes.
    let signature = kp.sign(digest.as_ref());
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());

    // Verify the signature against bad digest fails.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Sha256::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = signature_tests::signature_test_inputs_different_msg::<Secp256k1KeyPair>();
    let res = Secp256k1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = signature_tests::signature_test_inputs_different_msg::<Secp256k1KeyPair>();
    inputs.signatures[0] = Secp256k1Signature::default();
    let res = Secp256k1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn fail_to_verify_if_upper_s() {
    // Test case from https://github.com/fjl/go-ethereum/blob/41c854a60fad2ad9bb732857445624c7214541db/crypto/signature_test.go#L79
    let msg =
        hex::decode("d301ce462d3e639518f482c7f03821fec1e602018630ce621e1e7851c12343a6").unwrap();
    let pk = Secp256k1PublicKey::from_bytes(
        &hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap(),
    )
    .unwrap();

    let mut internal_sig = Signature::from_compact(&hex::decode("638a54215d80a6713c8d523a6adc4e6e73652d859103a36b700851cb0e61b66b8ebfc1a610c57d732ec6e0a8f06a9a7a28df5051ece514702ff9cdff0b11f454").unwrap()).unwrap();

    let sig =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&internal_sig.serialize_compact()).unwrap();

    // Failed to verify with upper S.
    assert!(pk.verify_hashed(&msg, &sig).is_err());

    // Normalize S to be less than N/2.
    internal_sig.normalize_s();
    let normalized_sig =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&internal_sig.serialize_compact()).unwrap();
    assert!(pk.verify_hashed(&msg, &normalized_sig).is_ok());
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();

    // Spawn the signature service.
    let service = SignatureService::new(kp);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let signature = service.request_signature(digest).await;

    // Verify the signature we received.
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Secp256k1KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, constants::SECRET_KEY_SIZE) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is set to ONE_KEY (workaround to all zero SecretKey considered as invalid)
    unsafe {
        for i in 0..constants::SECRET_KEY_SIZE - 1 {
            assert_eq!(*ptr.add(i), 0);
        }
        assert_eq!(*ptr.add(constants::SECRET_KEY_SIZE - 1), 1);
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, constants::SECRET_KEY_SIZE) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

proptest::proptest! {
    #[test]
    #[cfg(feature = "copy_key")]
    fn test_k256_against_secp256k1_lib(
        r in <[u8; 32]>::arbitrary()
) {
        let message: &[u8] = b"hello world!";
        let mut rng = StdRng::from_seed(r);

        // construct private key with arbitrary seed and sign
        let key_pair = Secp256k1KeyPair::generate(&mut rng);
        let key_pair_copied = key_pair.copy();
        let key_pair_copied_2 = key_pair.copy();
        let key_pair_copied_3 = key_pair.copy();

        let signature: Secp256k1Signature = key_pair.try_sign(message).unwrap();
        assert!(key_pair.public().verify(message, &signature).is_ok());

        // Use k256 to construct private key with the same bytes and sign the same message
        let priv_key_1 = k256::ecdsa::SigningKey::from_bytes(key_pair_copied_3.private().as_bytes()).unwrap();
        let pub_key_1 = priv_key_1.verifying_key();
        let signature_1: k256::ecdsa::Signature = priv_key_1.sign(message);
        assert!(pub_key_1.verify(message, &signature_1).is_ok());

        // Two private keys are serialized as the same
        assert_eq!(key_pair_copied.private().as_bytes(), priv_key_1.to_bytes().as_slice());

        // Two pubkeys are the same
        assert_eq!(
            key_pair.public().as_bytes(),
            pub_key_1.to_bytes().as_slice()
        );

        // Same signatures produced from both implementations
        assert_eq!(signature.as_ref(), ToFromBytes::as_bytes(&signature_1));

        // Use fastcrypto keypair to verify a signature constructed by k256
        let secp_sig1 = bincode::deserialize::<Secp256k1Signature>(signature_1.as_ref()).unwrap();
        assert!(key_pair_copied_2.public().verify(message, &secp_sig1).is_ok());

        // Use k256 keypair to verify sig constructed by fastcrypto
        let typed_sig = k256::ecdsa::Signature::try_from(signature.as_ref()).unwrap();
        assert!(pub_key_1.verify(message, &typed_sig).is_ok());
    }
}

#[test]
fn wycheproof_test() {
    let test_set = TestSet::load(EcdsaSecp256k1Sha256).unwrap();
    for test_group in test_set.test_groups {
        let pk = Secp256k1PublicKey::from_uncompressed(&test_group.key.key);
        for test in test_group.tests {
            let bytes = match Signature::from_der(&test.sig) {
                Ok(mut s) => {
                    // The secp256k1 crate fails on high-s values (https://docs.rs/secp256k1/0.24.1/secp256k1/ecdsa/struct.Signature.html#method.normalize_s)
                    s.normalize_s();
                    s.serialize_compact()
                }
                Err(_) => {
                    assert_eq!(test.result, TestResult::Invalid);
                    continue;
                }
            };

            let mut res = TestResult::Invalid;
            let sig = <Secp256k1Signature as ToFromBytes>::from_bytes(&bytes).unwrap();
            if pk
                .verify_hashed(Sha256::digest(test.msg.as_slice()).as_ref(), &sig)
                .is_ok()
            {
                res = TestResult::Valid;
            }

            assert_eq!(map_result(test.result), res);
        }
    }
}

fn map_result(t: TestResult) -> TestResult {
    match t {
        TestResult::Valid => TestResult::Valid,
        _ => TestResult::Invalid, // Treat Acceptable as Invalid
    }
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Secp256k1PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for Secp256k1PrivateKey>"
        );
    });
}

#[test]
fn test_default_values() {
    let _default_pubkey = Secp256k1PublicKey::default();
    let _default_signature = Secp256k1Signature::default();
}

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = Secp256k1KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Secp256k1KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Secp256k1KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }
}
