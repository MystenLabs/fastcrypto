// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::hash::Digest;
use crate::signature_service::SignatureService;
use crate::traits::InsecureDefault;
use crate::unsecure::hash::XXH128Unsecure;
use crate::unsecure::signature::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::{
    hash::{Blake2b256, HashFunction},
    hmac::hkdf_generate_from_ikm,
    traits::{
        AggregateAuthenticator, EncodeDecodeBase64, KeyPair, Signer, ToFromBytes, VerifyingKey,
    },
    unsecure::signature::{
        UnsecureAggregateSignature, UnsecureKeyPair, UnsecurePrivateKey, UnsecurePublicKey,
        UnsecureSignature,
    },
};
use rand::{rngs::StdRng, SeedableRng as _};
use std::str::FromStr;

pub fn keys() -> Vec<UnsecureKeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| UnsecureKeyPair::generate(&mut rng))
        .collect()
}

#[test]
fn serialize_deserialize() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();

    let bytes = bincode::serialize(&public_key).unwrap();
    let pk2 = bincode::deserialize::<UnsecurePublicKey>(&bytes).unwrap();
    assert_eq!(*public_key, pk2);

    let private_key = kpref.private();
    let bytes = bincode::serialize(&private_key).unwrap();
    let privkey = bincode::deserialize::<UnsecurePrivateKey>(&bytes).unwrap();
    let bytes2 = bincode::serialize(&privkey).unwrap();
    assert_eq!(bytes, bytes2);
}

#[test]
fn test_serde_signatures_non_human_readable() {
    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let sig = keys().pop().unwrap().sign(message);
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: UnsecureSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, sig);
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = UnsecurePublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = UnsecurePrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}
#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <UnsecureSignature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);

    let signature = kp.sign(&digest.digest);

    // Verify the signature.
    assert!(kp.public().verify(&digest.digest, &signature).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
    let mut signature = kp.sign(&digest.digest);

    // Modify the signature
    signature.0[3] ^= 1;

    // Verification should fail.
    assert!(kp.public().verify(&digest.digest, &signature).is_err());
}

#[test]
fn different_messages_give_different_signatures() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    let message1 = b"message1";

    // Make signature.
    let signature1 = kp.sign(b"message1");
    assert!(kp.public().verify(message1, &signature1).is_ok());

    let message2 = b"message2";
    let signature2 = kp.sign(b"message2");
    assert!(kp.public().verify(message2, &signature2).is_ok());

    // Signatures are different and should not verify on other messages
    assert_ne!(signature1, signature2);
    assert!(kp.public().verify(message1, &signature2).is_err());
    assert!(kp.public().verify(message2, &signature1).is_err());
}

#[test]
fn verify_valid_batch() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
    let (pubkeys, signatures): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(&digest.digest);
            (kp.public().clone(), sig)
        })
        .unzip();

    // Verify the batch.
    let res = UnsecurePublicKey::verify_batch_empty_fail(&digest.digest, &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
    let (pubkeys, mut signatures): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(&digest.digest);
            (kp.public().clone(), sig)
        })
        .unzip();

    // Modify one of the signatures
    signatures[1].0[0] ^= 1;

    // Verify the batch.
    let res = UnsecurePublicKey::verify_batch_empty_fail(&digest.digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_aggregate_signature() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
    let (pubkeys, signatures): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(&digest.digest);
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature = UnsecureAggregateSignature::aggregate(&signatures).unwrap();

    // // Verify the batch.
    let res = aggregated_signature.verify(&pubkeys[..], &digest.digest);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_aggregate_signature() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
    let (pubkeys, mut signatures): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(&digest.digest);
            (kp.public().clone(), sig)
        })
        .unzip();

    // Modify one of the signatures
    signatures[1].0[0] ^= 1;

    let aggregated_signature = UnsecureAggregateSignature::aggregate(&signatures).unwrap();

    // // Verify the batch.
    let res = aggregated_signature.verify(&pubkeys[..], &digest.digest);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_aggregate_signature() {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let digest1 = Blake2b256::digest(message1);
    let (pubkeys1, signatures1): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(&digest1.digest);
            (kp.public().clone(), sig)
        })
        .unzip();
    let aggregated_signature1 = UnsecureAggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, world!";
    let digest2 = Blake2b256::digest(message2);
    let (pubkeys2, signatures2): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(2)
        .map(|kp| {
            let sig = kp.sign(&digest2.digest);
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature2 = UnsecureAggregateSignature::aggregate(&signatures2).unwrap();

    assert!(UnsecureAggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1[..].iter(), pubkeys2[..].iter()],
        &[&digest1.digest[..], &digest2.digest[..]]
    )
    .is_ok());
}

#[test]
fn test_serialize_deserialize_aggregate_signatures() {
    // Test empty aggregate signature
    let sig = UnsecureAggregateSignature::default();
    let serialized = bincode::serialize(&sig).unwrap();
    let _deserialized: UnsecureAggregateSignature = bincode::deserialize(&serialized).unwrap();

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<UnsecurePublicKey>, Vec<UnsecureSignature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = UnsecureAggregateSignature::aggregate(&signatures).unwrap();
    let serialized = bincode::serialize(&sig).unwrap();
    let _deserialized: UnsecureAggregateSignature = bincode::deserialize(&serialized).unwrap();
}

#[test]
fn test_add_signatures_to_aggregate() {
    let (kps, pks): (Vec<UnsecureKeyPair>, Vec<UnsecurePublicKey>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| (kp.clone(), kp.public().clone()))
        .unzip();

    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = UnsecureAggregateSignature::default();
    // Test populated aggregate signature
    kps.clone().into_iter().for_each(|kp| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();
    });

    assert!(sig1.verify(&pks, message).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = UnsecureAggregateSignature::default();

    let kp = &kps[0];
    let sig = UnsecureAggregateSignature::aggregate(&vec![kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    //let signatures: Vec<UnsecureSignature> = ;
    let aggregated_signature = UnsecureAggregateSignature::aggregate(
        &kps.into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<UnsecureSignature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_add_signatures_to_aggregate_different_messages() {
    let kps = keys();
    let pks: Vec<UnsecurePublicKey> = kps.iter().take(3).map(|kp| kp.public().clone()).collect();
    let messages: Vec<&[u8]> = vec![b"hello", b"world", b"!!!!!"];

    // Test 'add signature'
    let mut sig1 = UnsecureAggregateSignature::default();
    // Test populated aggregate signature
    for (i, kp) in kps.iter().take(3).enumerate() {
        let sig = kp.sign(messages[i]);
        sig1.add_signature(sig).unwrap();
    }

    assert!(sig1.verify_different_msg(&pks, &messages).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = UnsecureAggregateSignature::default();

    let kp = &kps[0];
    let sig = UnsecureAggregateSignature::aggregate(&[kp.sign(messages[0])]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2
        .verify_different_msg(&pks[0..1], &messages[0..1])
        .is_ok());

    let aggregated_signature = UnsecureAggregateSignature::aggregate(
        &kps.iter()
            .zip(&messages)
            .take(3)
            .skip(1)
            .map(|(kp, message)| kp.sign(message))
            .collect::<Vec<UnsecureSignature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify_different_msg(&pks, &messages).is_ok());
}

#[test]
fn test_hkdf_generate_from_ikm() {
    let seed = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];
    let salt = &[3, 2, 1];
    let kp =
        hkdf_generate_from_ikm::<crate::hash::Sha3_256, UnsecureKeyPair>(seed, salt, &[]).unwrap();
    let kp2 =
        hkdf_generate_from_ikm::<crate::hash::Sha3_256, UnsecureKeyPair>(seed, salt, &[]).unwrap();
    assert_eq!(kp.private().as_bytes(), kp2.private().as_bytes());
}

#[test]
#[cfg(feature = "copy_key")]
fn test_copy_key_pair() {
    let kp = keys().pop().unwrap();
    let kp_copied = kp.copy();

    assert_eq!(kp.public().as_bytes(), kp_copied.public().as_bytes());
    assert_eq!(kp.private().as_bytes(), kp_copied.private().as_bytes());
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
    let digest = Blake2b256::digest(message);
    let signature = service.request_signature(digest).await;

    // Verify the signature we received.
    assert!(pk.verify(digest.digest.as_slice(), &signature).is_ok());
}

#[test]
fn scheme_test() {
    let kp = keys().pop().unwrap();
    let pk = kp.public();

    // Expected signature scheme: signature = H(pk || message) where H(x) = XXH128(x) || XXH128(x) || XXH128(x).
    let message = b"Hello, world!";
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(&pk.0);
    digest_input.extend_from_slice(message);
    let single_digest = XXH128Unsecure::digest(digest_input).digest;

    let mut digest_bytes = Vec::new();
    digest_bytes.extend_from_slice(&single_digest);
    digest_bytes.extend_from_slice(&single_digest);
    digest_bytes.extend_from_slice(&single_digest);
    let expected_signature =
        UnsecureSignature::from(Digest::<48>::new(digest_bytes[..48].try_into().unwrap()));
    let signature = kp.sign(message);

    assert_eq!(signature, expected_signature);
}

#[test]
fn default_public_key() {
    assert_eq!(
        UnsecurePublicKey::insecure_default().0,
        [0u8; PUBLIC_KEY_LENGTH]
    );
}

#[test]
fn default_signature() {
    assert_eq!(UnsecureSignature::default().0, [0u8; SIGNATURE_LENGTH]);
}

#[test]
fn fmt_public_key() {
    let pk = keys().pop().unwrap().public().clone();
    assert_eq!(pk.to_string(), Base64::encode(pk.as_bytes()));
}

#[test]
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign(b"Hello, world!");
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

#[test]
fn keypair_to_from_bytes() {
    let kp = keys().pop().unwrap();
    let bytes = kp.as_ref();
    let reconstructed = UnsecureKeyPair::from_bytes(bytes).unwrap();
    assert_eq!(kp, reconstructed);
}

#[test]
fn keypair_from_string() {
    let kp = keys().pop().unwrap();
    let as_string = Base64::encode(kp.as_ref());
    let reconstructed = UnsecureKeyPair::from_str(&as_string).unwrap();
    assert_eq!(kp, reconstructed);
}

#[test]
fn fmt_aggregate_signature() {
    let aggregated_signature = UnsecureAggregateSignature::default();
    assert_eq!(
        aggregated_signature.to_string(),
        Base64::encode(aggregated_signature.as_bytes())
    );
}

#[test]
fn aggregate_signature_to_from_bytes() {
    let aggregated_signature = UnsecureAggregateSignature::default();
    let bytes = aggregated_signature.as_ref();
    let reconstructed = UnsecureAggregateSignature::from_bytes(bytes).unwrap();
    assert_eq!(aggregated_signature.as_ref(), reconstructed.as_ref());
}
