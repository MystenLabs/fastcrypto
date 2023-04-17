// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::Encoding;
use crate::test_helpers::verify_serialization;
use crate::traits::{InsecureDefault, Signer};
use crate::{
    ed25519::{
        Ed25519AggregateSignature, Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey,
        Ed25519Signature, ED25519_PRIVATE_KEY_LENGTH,
    },
    encoding::Base64,
    hash::{HashFunction, Sha256, Sha3_256},
    hmac::hkdf_generate_from_ikm,
    signature_service::SignatureService,
    test_helpers,
    traits::{AggregateAuthenticator, EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};
use proptest::prelude::*;
use proptest::strategy::Strategy;
use rand::{rngs::StdRng, SeedableRng as _};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use wycheproof::{eddsa::TestSet, TestResult};

pub fn keys() -> Vec<Ed25519KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| Ed25519KeyPair::generate(&mut rng)).collect()
}

#[test]
fn serialize_deserialize() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let default_pk = Ed25519PublicKey::insecure_default();
    let sk = kp.private();
    let message = b"hello, narwhal";
    let sig = keys().pop().unwrap().sign(message);
    let default_sig = Ed25519Signature::default();

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&default_pk, Some(default_pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));
    verify_serialization(&default_sig, Some(default_sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));
}

#[test]
fn test_serialize_deserialize_aggregate_signatures() {
    // Test empty aggregate signature
    let sig = Ed25519AggregateSignature::default();
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: Ed25519AggregateSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: Ed25519AggregateSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.sigs, sig.sigs);

    // Note that we do not check if the serialized variant equals as_ref() since the serialized
    // variant begins with a length prefix (of the vector of signatures).
}

#[test]
fn test_serialization_vs_test_vector() {
    // Test vector from https://www.rfc-editor.org/rfc/rfc8032#page-24.
    let sk =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let pk =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let m = hex::decode("").unwrap();
    let sig = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();

    let recovered_sk: Ed25519PrivateKey = bincode::deserialize(&sk).unwrap();
    let recovered_pk: Ed25519PublicKey = bincode::deserialize(&pk).unwrap();
    let recovered_sig: Ed25519Signature = bincode::deserialize(&sig).unwrap();

    let kp: Ed25519KeyPair = recovered_sk.into();
    let signature = kp.sign(&m);
    let serialized_signature = bincode::serialize(&signature).unwrap();
    assert_eq!(serialized_signature, sig);
    assert!(recovered_pk.verify(&m, &recovered_sig).is_ok());
}

#[test]
fn test_serde_signatures_human_readable() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);

    let serialized = serde_json::to_string(&signature).unwrap();
    assert_eq!(
        format!(r#""{}""#, Base64::encode(signature.sig.to_bytes())),
        serialized
    );
    let deserialized: Ed25519Signature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), signature.as_ref());
}

#[test]
fn key_pair_from_string_roundtrip() {
    let kp = keys().pop().unwrap();
    let kp_str = Base64::encode(kp.as_ref());
    let recovered = Ed25519KeyPair::from_str(&kp_str).unwrap();
    assert_eq!(kp, recovered);
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = Ed25519PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Ed25519PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}
#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <Ed25519Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Sha256::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let (pubkeys, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    (digest.to_vec(), pubkeys, signatures)
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = <Ed25519Signature as ToFromBytes>::from_bytes(&[0u8; 64]).unwrap();

    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Ed25519PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_aggregate_signaature() {
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = Ed25519AggregateSignature::aggregate(&signatures).unwrap();

    let res = aggregated_signature.verify(&pubkeys[..], &digest);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_aggregate_signature_length_mismatch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = Ed25519AggregateSignature::aggregate(&signatures).unwrap();

    let res = aggregated_signature.verify(&pubkeys[..2], &digest);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_invalid_aggregate_signature_public_key_switch() {
    let (digest, mut pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = Ed25519AggregateSignature::aggregate(&signatures).unwrap();

    pubkeys[0] = keys()[3].public().clone();

    let res = aggregated_signature.verify(&pubkeys[..], &digest);
    assert!(res.is_err(), "{:?}", res);
}

fn verify_batch_aggregate_signature_inputs() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<Ed25519PublicKey>,
    Vec<Ed25519PublicKey>,
    Ed25519AggregateSignature,
    Ed25519AggregateSignature,
) {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let digest1 = Sha256::digest(message1);
    let (pubkeys1, signatures1): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest1.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();
    let aggregated_signature1 = Ed25519AggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, worl!";
    let digest2 = Sha256::digest(message2);
    let (pubkeys2, signatures2): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(2)
        .map(|kp| {
            let sig = kp.sign(digest2.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature2 = Ed25519AggregateSignature::aggregate(&signatures2).unwrap();
    (
        digest1.to_vec(),
        digest2.to_vec(),
        pubkeys1,
        pubkeys2,
        aggregated_signature1,
        aggregated_signature2,
    )
}

#[test]
fn verify_batch_aggregate_signature() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_ok());
}

#[test]
fn verify_batch_missing_parameters_length_mismatch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Fewer pubkeys than signatures
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());

    // Fewer messages than signatures
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..]]
    )
    .is_err());
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());
}

#[test]
fn verify_batch_missing_keys_in_batch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Pubkeys missing at the end
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[1..].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // Pubkeys missing at the start
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[..pubkeys2.len() - 1].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // add an extra signature to both aggregated_signature that batch_verify takes in
    let mut signatures1_with_extra = aggregated_signature1;
    let kp = &keys()[0];
    let sig = kp.sign(&digest1);
    let res = signatures1_with_extra.add_signature(sig);
    assert!(res.is_ok());

    let mut signatures2_with_extra = aggregated_signature2;
    let kp = &keys()[0];
    let sig2 = kp.sign(&digest1);
    let res = signatures2_with_extra.add_signature(sig2);
    assert!(res.is_ok());

    assert!(Ed25519AggregateSignature::batch_verify(
        &[&signatures1_with_extra, &signatures2_with_extra],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
}

#[test]
fn test_to_from_bytes_aggregate_signatures() {
    // Test empty aggregate signature
    let sig = Ed25519AggregateSignature::default();
    let serialized = sig.as_bytes();
    let deserialized = Ed25519AggregateSignature::from_bytes(serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    let serialized = sig.as_bytes();
    let deserialized = Ed25519AggregateSignature::from_bytes(serialized).unwrap();
    assert_eq!(deserialized, sig);
}

#[test]
fn test_add_signatures_to_aggregate() {
    let pks: Vec<Ed25519PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = Ed25519AggregateSignature::default();
    // Test populated aggregate signature
    keys().into_iter().take(3).enumerate().for_each(|(i, kp)| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();

        // Verify that the binary representation is updated for each added signature
        let reconstructed = Ed25519AggregateSignature::from_bytes(sig1.as_ref()).unwrap();
        assert!(reconstructed.verify(&pks[..i], message).is_err());
        assert!(reconstructed.verify(&pks[..i + 1], message).is_ok());
    });

    assert!(sig1.verify(&pks, message).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = Ed25519AggregateSignature::default();

    let kp = &keys()[0];
    let sig = Ed25519AggregateSignature::aggregate(&[kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    let aggregated_signature = Ed25519AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<Ed25519Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_add_signatures_to_aggregate_different_messages() {
    let pks: Vec<Ed25519PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let messages: Vec<&[u8]> = vec![b"hello", b"world", b"!!!!!"];

    // Test 'add signature'
    let mut sig1 = Ed25519AggregateSignature::default();
    // Test populated aggregate signature
    for (i, kp) in keys().into_iter().take(3).enumerate() {
        let sig = kp.sign(messages[i]);
        sig1.add_signature(sig).unwrap();
    }

    assert!(sig1.verify_different_msg(&pks, &messages).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = Ed25519AggregateSignature::default();

    let kp = &keys()[0];
    let sig = Ed25519AggregateSignature::aggregate(&[kp.sign(messages[0])]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2
        .verify_different_msg(&pks[0..1], &messages[0..1])
        .is_ok());

    let aggregated_signature = Ed25519AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .zip(&messages)
            .take(3)
            .skip(1)
            .map(|(kp, message)| kp.sign(message))
            .collect::<Vec<Ed25519Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify_different_msg(&pks, &messages).is_ok());

    // Mismatch in number of pks and messages
    assert!(sig2.verify_different_msg(&pks, &messages[0..1]).is_err());
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = test_helpers::signature_test_inputs_different_msg::<Ed25519KeyPair>();
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = test_helpers::signature_test_inputs_different_msg::<Ed25519KeyPair>();

    // Mismatch between number of messages, signatures and public keys provided
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures[0..1],
    );
    assert!(res.is_err(), "{:?}", res);

    // One signature invalid
    inputs.signatures[0] = Ed25519Signature::default();
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);

    // No signatures provided
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg::<&[u8]>(&[], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn test_default_values() {
    let valid_kp = keys().pop().unwrap();
    let valid_sig = valid_kp.sign(b"message");
    let default_sig = Ed25519Signature::default();
    let valid_pk = valid_kp.public().clone();
    let default_pk = Ed25519PublicKey::insecure_default();
    let valid_agg_sig = Ed25519AggregateSignature::aggregate(&[valid_sig.clone()]).unwrap();
    let default_agg_sig = Ed25519AggregateSignature::default();

    // Default sig should fail (for both types of keys)
    assert!(valid_pk.verify(b"message", &default_sig).is_err());
    assert!(default_pk.verify(b"message", &default_sig).is_err());

    // Verification with default pk should fail.
    assert!(default_pk.verify(b"message", &valid_sig).is_err());

    // Verifications with one of the default values should fail.
    assert!(valid_agg_sig
        .verify(&[valid_pk.clone()], b"message")
        .is_ok());
    assert!(valid_agg_sig
        .verify(&[default_pk.clone()], b"message")
        .is_err());
    assert!(default_agg_sig.verify(&[valid_pk], b"message").is_err());
    assert!(default_agg_sig.verify(&[default_pk], b"message").is_err());
}

#[test]
fn test_hkdf_generate_from_ikm() {
    let seed = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];
    let salt = &[3, 2, 1];
    let kp = hkdf_generate_from_ikm::<Sha3_256, Ed25519KeyPair>(seed, salt, &[]).unwrap();
    let kp2 = hkdf_generate_from_ikm::<Sha3_256, Ed25519KeyPair>(seed, salt, &[]).unwrap();
    assert_eq!(kp.private().as_bytes(), kp2.private().as_bytes());
}

#[test]
#[cfg(feature = "copy_key")]
fn test_copy_key_pair() {
    let kp = keys().pop().unwrap();
    let kp_copied = kp.copy();

    assert_eq!(kp.public().0.as_bytes(), kp_copied.public().0.as_bytes());
    assert_eq!(kp.private().0.as_bytes(), kp_copied.private().0.as_bytes());
}

#[test]
fn keypair_from_signing_key() {
    // Create two equal keypairs.
    let kp1 = keys().pop().unwrap();
    let kp2 = keys().pop().unwrap();
    assert_eq!(kp1, kp2);

    let signing_key = kp1.private().0.clone();
    let restored_kp = Ed25519KeyPair::from(signing_key);
    assert_eq!(kp2, restored_kp);
}

#[test]
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign(b"Hello, world!");
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

#[test]
fn fmt_aggregate_signature() {
    // Test empty aggregate signature
    let sig = Ed25519AggregateSignature::default();
    assert_eq!(sig.to_string(), "[]");

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    assert_eq!(
        sig.to_string(),
        format!(
            "[\"{}\", \"{}\", \"{}\"]",
            Base64::encode(signatures[0].as_bytes()),
            Base64::encode(signatures[1].as_bytes()),
            Base64::encode(signatures[2].as_bytes())
        )
    );
}

#[test]
fn hash_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();

    let mut hasher = DefaultHasher::new();
    public_key.hash(&mut hasher);
    let digest = hasher.finish();

    let mut other_hasher = DefaultHasher::new();
    public_key.as_bytes().hash(&mut other_hasher);
    let expected = other_hasher.finish();
    assert_eq!(expected, digest);
}

#[test]
fn fmt_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    assert_eq!(
        public_key.to_string(),
        Base64::encode(public_key.as_bytes())
    );
}

#[test]
fn debug_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    assert_eq!(
        format!("{:?}", public_key),
        Base64::encode(public_key.as_bytes())
    );
}

#[test]
fn public_key_ordering() {
    let pk1 = keys().pop().unwrap().public().clone();
    let pk2 = keys().pop().unwrap().public().clone();
    assert_eq!(pk1.as_bytes().cmp(pk2.as_bytes()), pk1.cmp(&pk2));
    assert_eq!(
        pk1.as_bytes().cmp(pk2.as_bytes()),
        pk1.partial_cmp(&pk2).unwrap()
    );
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

// Checks if the private keys zeroed out
#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.0) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        // SigningKey.zeroize() zeroizes seed and s value in the struct,
        // (the rest does not contain private key material), hence shifting the bytes by 192.
        // pub struct SigningKey {
        //     seed: [u8; 32],
        //     s: Scalar,
        //     prefix: [u8; 32],
        //     vk: VerificationKey,
        // }
        // Starting at index 192 is precisely the 32 bytes of the private key.
        unsafe {
            for (i, &byte) in sk_bytes.iter().enumerate().take(ED25519_PRIVATE_KEY_LENGTH) {
                assert_eq!(*ptr.add(i + 192), byte);
            }
        }

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, ED25519_PRIVATE_KEY_LENGTH) };
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Starting at index 192 where the 32 bytes of the private key lives, is zeroized.
    unsafe {
        for i in 0..ED25519_PRIVATE_KEY_LENGTH {
            assert_eq!(*ptr.add(i + 192), 0);
        }
    }

    // Check that self.bytes is taken by the OnceCell default value.
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, ED25519_PRIVATE_KEY_LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn wycheproof_test() {
    let test_set = TestSet::load(wycheproof::eddsa::TestName::Ed25519).unwrap();
    for test_group in test_set.test_groups {
        let pk = Ed25519PublicKey::from_bytes(&test_group.key.pk).unwrap();
        for test in test_group.tests {
            let sig = match <Ed25519Signature as ToFromBytes>::from_bytes(&test.sig) {
                Ok(s) => s,
                Err(_) => {
                    assert_eq!(test.result, TestResult::Invalid);
                    continue;
                }
            };
            match pk.verify(&test.msg, &sig) {
                Ok(_) => assert_eq!(test.result, TestResult::Valid),
                Err(_) => assert_eq!(test.result, TestResult::Invalid),
            }
        }
    }
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Ed25519PrivateKey>");
        assert_eq!(format!("{:?}", sk), "<elided secret for Ed25519PrivateKey>");
    });
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

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = Ed25519KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Ed25519KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Ed25519KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }
}

#[test]
fn ed25519_speccheck() {
    let msgs = [
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
    ];

    let pks = [
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];

    let sigs = [
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
    ];

    // TODO: What should we expect?
    let expected = [
        true, true, true, true, true, true, false, false, false, true, true, true,
    ];

    for i in 0..12 {
        let msg = hex::decode(msgs[i]).unwrap();
        let pk = Ed25519PublicKey::from_bytes(&hex::decode(pks[i]).unwrap()).unwrap();
        let sig = Ed25519Signature::from_bytes(&hex::decode(sigs[i]).unwrap()).unwrap();

        assert_eq!(expected[i], pk.verify(&msg, &sig).is_ok());
    }
}
