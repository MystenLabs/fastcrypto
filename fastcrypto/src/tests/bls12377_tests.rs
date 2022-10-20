// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12377::{
    BLS12377AggregateSignature, BLS12377KeyPair, BLS12377PrivateKey, BLS12377PublicKey,
    BLS12377PublicKeyBytes, BLS12377Signature,
};
use crate::{
    hash::{Blake2b256, HashFunction},
    traits::{AggregateAuthenticator, EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
    SignatureService,
};

use crate::bls12377::CELO_BLS_PRIVATE_KEY_LENGTH;
use rand::{rngs::StdRng, SeedableRng as _};
use signature::{Signer, Verifier};

pub fn keys() -> Vec<BLS12377KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| BLS12377KeyPair::generate(&mut rng))
        .collect()
}

fn sign_with_keypairs(
    keys: Vec<BLS12377KeyPair>,
    digest_ref: &[u8],
) -> (Vec<BLS12377PublicKey>, Vec<BLS12377Signature>) {
    keys.into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest_ref);
            (kp.public().clone(), sig)
        })
        .unzip()
}

fn signature_test_inputs() -> (Vec<u8>, Vec<BLS12377PublicKey>, Vec<BLS12377Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
    let (pubkeys, signatures) = sign_with_keypairs(keys(), digest.as_ref());

    (digest.to_vec(), pubkeys, signatures)
}

fn verify_batch_aggregate_signature_inputs() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<BLS12377PublicKey>,
    Vec<BLS12377PublicKey>,
    BLS12377AggregateSignature,
    BLS12377AggregateSignature,
) {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let digest1 = Blake2b256::digest(message1);
    let (pubkeys1, signatures1) = sign_with_keypairs(keys(), digest1.as_ref());

    let aggregated_signature1 = BLS12377AggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, worl!";
    let digest2 = Blake2b256::digest(message2);
    let (pubkeys2, signatures2) = sign_with_keypairs(keys(), digest2.as_ref());

    let aggregated_signature2 = BLS12377AggregateSignature::aggregate(&signatures2).unwrap();
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
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = BLS12377PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = BLS12377PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <BLS12377Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);

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
    let digest = Blake2b256::digest(message);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Blake2b256::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = BLS12377PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = BLS12377Signature::default();

    let res = BLS12377PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = BLS12377PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = BLS12377PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = BLS12377PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_aggregate_signaature() {
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = BLS12377AggregateSignature::aggregate(&signatures).unwrap();

    let res = aggregated_signature.verify(&pubkeys[..], &digest);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_aggregate_signature_length_mismatch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = BLS12377AggregateSignature::aggregate(&signatures).unwrap();

    let res = aggregated_signature.verify(&pubkeys[..2], &digest);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_invalid_aggregate_signature_public_key_switch() {
    let (digest, mut pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = BLS12377AggregateSignature::aggregate(&signatures).unwrap();

    pubkeys[0] = keys()[3].public().clone();

    let res = aggregated_signature.verify(&pubkeys[..], &digest);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_aggregate_signature() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..], &digest2[..]],
    )
    .is_ok());
}

#[test]
fn verify_batch_missing_parameters_length_mismatch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Fewer pubkeys than signatures
    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]],
    )
    .is_err());
    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]],
    )
    .is_err());

    // Fewer messages than signatures
    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..]],
    )
    .is_err());
    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]],
    )
    .is_err());
}

#[test]
fn verify_batch_missing_keys_in_batch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Pubkeys missing at the end
    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[1..].iter()],
        &[&digest1[..], &digest2[..]],
    )
    .is_err());

    // Pubkeys missing at the start
    assert!(BLS12377AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[..pubkeys2.len() - 1].iter()],
        &[&digest1[..], &digest2[..]],
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

    assert!(BLS12377AggregateSignature::batch_verify(
        &[&signatures1_with_extra, &signatures2_with_extra],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]],
    )
    .is_err());
}

#[test]
fn test_add_signatures_to_aggregate() {
    let pks: Vec<BLS12377PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = BLS12377AggregateSignature::default();
    // Test populated aggregate signature
    keys().into_iter().take(3).for_each(|kp| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();
    });

    assert!(sig1.verify(&pks, message).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12377AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12377AggregateSignature::aggregate(&vec![kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    let aggregated_signature = BLS12377AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<BLS12377Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_public_key_bytes_conversion() {
    let kp = keys().pop().unwrap();
    let pk_bytes: BLS12377PublicKeyBytes = kp.public().into();
    let rebuilded_pk: BLS12377PublicKey = pk_bytes.try_into().unwrap();
    assert_eq!(kp.public().as_bytes(), rebuilded_pk.as_bytes());
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();

    // Spawn the signature service.
    let mut service = SignatureService::new(kp);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = Blake2b256::digest(message);
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
        let kp = BLS12377KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        // Assert the exact location in SecretKey is stored as private key bytes.
        unsafe {
            for (i, &byte) in sk_bytes
                .iter()
                .enumerate()
                .take(CELO_BLS_PRIVATE_KEY_LENGTH)
            {
                assert_eq!(*ptr.add(i + 41), byte);
            }
        }
        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, CELO_BLS_PRIVATE_KEY_LENGTH) };
        // Assert that this is equal to sk_bytes before deletion.
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Assert the exact position in SecretKey is no longer private key bytes.
    unsafe {
        for (i, &byte) in sk_bytes
            .iter()
            .enumerate()
            .take(CELO_BLS_PRIVATE_KEY_LENGTH)
        {
            assert_ne!(*ptr.add(i + 41), byte);
        }
    }

    // Check that self.bytes is reset to OnceCell default.
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, CELO_BLS_PRIVATE_KEY_LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}
