// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::Encoding;
use crate::test_helpers::{signature_test_inputs_different_msg, verify_serialization};
use crate::traits::InsecureDefault;
use crate::traits::Signer;
use crate::{
    bls12381::{BLS_G1_LENGTH, BLS_G2_LENGTH, BLS_PRIVATE_KEY_LENGTH},
    encoding::Base64,
    hash::{HashFunction, Sha256, Sha3_256},
    hmac::hkdf_generate_from_ikm,
    traits::{
        AggregateAuthenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes, VerifyingKey,
    },
};
use proptest::{collection, prelude::*};
use rand::{rngs::StdRng, SeedableRng as _};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

// We use the following macro in order to run all tests for both min_sig and min_pk.
macro_rules! define_tests { () => {
pub fn keys() -> Vec<BLS12381KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| BLS12381KeyPair::generate(&mut rng))
        .collect()
}

//
// Serialization tests
//

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = BLS12381PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
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
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = BLS12381PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <BLS12381Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

#[test]
fn test_serialize_deserialize_standard_sig() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    pk.validate().unwrap(); // just a sanity check
    let sk = kp.private();
    let message = b"hello, narwhal";
    let sig = keys().pop().unwrap().sign(message);
    let default_sig = BLS12381Signature::default();

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));
    verify_serialization(&default_sig, Some(default_sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));
    let kp_b64 = kp.encode_base64();
    assert_eq!(BLS12381KeyPair::from_str(&kp_b64).unwrap(), kp);
}

#[test]
fn test_serialize_deserialize_aggregate_signatures() {
    // Default aggregated sig
    let default_sig = BLS12381AggregateSignature::default();
    verify_serialization(&default_sig, Some(default_sig.as_bytes()));
    assert_eq!(default_sig.as_bytes(), BLS12381Signature::default().as_bytes());
    // Standard aggregated sig
    let message = b"hello, narwhal";
    let (_, signatures): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();
    let sig = BLS12381AggregateSignature::aggregate(&signatures).unwrap();
    verify_serialization(&sig, Some(sig.as_bytes()));
    // BLS12381AggregateSignatureAsBytes
    let sig_as_bytes = BLS12381AggregateSignatureAsBytes::from(&sig);
    verify_serialization(&sig_as_bytes, Some(sig.as_bytes()));
}

#[test]
fn test_human_readable_signatures() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);

    let serialized = serde_json::to_string(&signature).unwrap();
    assert_eq!(
        format!(
            "\"{}\"",
            Base64::encode(&signature.sig.to_bytes())
        ),
        serialized
    );
    let deserialized: BLS12381Signature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, signature);
}

//
// Signature verification tests
//

fn signature_test_inputs() -> (Vec<u8>, Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let (pubkeys, signatures): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
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
fn test_pk_verify() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);
    assert!(kp.public().verify(message, &signature).is_ok());

    // Invalid signatures - different message and an empty message.
    let other_message: &[u8] = b"Bad message!";
    assert!(kp.public().verify(other_message, &signature).is_err());
    assert!(kp.public().verify(&[], &signature).is_err());
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = BLS12381Signature::default();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = BLS12381PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = signature_test_inputs_different_msg::<BLS12381KeyPair>();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {

    // Should fail on empty inputs
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg::<&[u8]>(
        &[],
        &[],
        &[],
    );
    assert!(res.is_err(), "{:?}", res);

    // Should fail on mismatch in input sizes
    let mut inputs = signature_test_inputs_different_msg::<BLS12381KeyPair>();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests[0..2],
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);

    // Should fail with one invalid signature
    inputs.signatures[0] = BLS12381Signature::default();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

//
// Aggregated signatures and batch verification tests
//

fn verify_batch_aggregate_signature_inputs() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<BLS12381PublicKey>,
    Vec<BLS12381PublicKey>,
    BLS12381AggregateSignature,
    BLS12381AggregateSignature,
) {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let (pubkeys1, signatures1): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message1);
            (kp.public().clone(), sig)
        })
        .unzip();
    let aggregated_signature1 = BLS12381AggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, worl!";
    let (pubkeys2, signatures2): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(2)
        .map(|kp| {
            let sig = kp.sign(message2);
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature2 = BLS12381AggregateSignature::aggregate(&signatures2).unwrap();
    (
        message1.to_vec(),
        message2.to_vec(),
        pubkeys1,
        pubkeys2,
        aggregated_signature1,
        aggregated_signature2,
    )
}

#[test]
fn batch_verify_aggregate_signature() {
    let (msg1, msg2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&msg1[..], &msg2[..]]
    )
    .is_ok());

    // Test failure when checking with a wrong message.
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&msg1[..], &msg1[..]]
    )
    .is_err());
}

#[test]
fn batch_verify_missing_parameters_length_mismatch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Fewer PubKeys than signatures
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());

    // Fewer messages than signatures
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..]]
    )
    .is_err());
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());
}

#[test]
fn batch_verify_missing_keys_in_batch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // PubKeys missing at the end
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[1..].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // PubKeys missing at the start
    assert!(BLS12381AggregateSignature::batch_verify(
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

    assert!(BLS12381AggregateSignature::batch_verify(
        &[&signatures1_with_extra, &signatures2_with_extra],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
}

#[test]
fn test_add_signatures_to_aggregate() {
    let pks: Vec<BLS12381PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = BLS12381AggregateSignature::default();
    assert!(sig1.verify(&pks, message).is_err());

    // Test populated aggregate signature
    keys().into_iter().take(3).enumerate().for_each(|(i, kp)| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();

        // Verify that the binary representation (the OnceCell) is updated for each added signature
        let reconstructed = BLS12381AggregateSignature::from_bytes(sig1.as_ref()).unwrap();
        assert!(reconstructed.verify(&pks[..i], message).is_err());
        assert!(reconstructed.verify(&pks[..i+1], message).is_ok());
    });

    assert!(sig1.verify(&pks, message).is_ok());
    let other_message = b"hello, narwhal2";
    assert!(sig1.verify(&pks, other_message).is_err());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12381AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12381AggregateSignature::aggregate(&[kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    let aggregated_signature = BLS12381AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<BLS12381Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();
    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_add_signatures_to_aggregate_different_messages() {
    let pks: Vec<BLS12381PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let messages: Vec<&[u8]> = vec![b"hello", b"world", b"!!!!!"];

    // Test 'add signature'
    let mut sig1 = BLS12381AggregateSignature::default();
    // Test populated aggregate signature
    for (i, kp) in keys().into_iter().take(3).enumerate() {
        let sig = kp.sign(messages[i]);
        sig1.add_signature(sig).unwrap();
    }

    assert!(sig1.verify_different_msg(&pks, &messages).is_ok());
    let other_messages: Vec<&[u8]> = vec![b"hello", b"world!", b"!!!!"];
    assert!(sig1.verify_different_msg(&pks, &other_messages).is_err());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12381AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12381AggregateSignature::aggregate(&[kp.sign(messages[0])]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2
        .verify_different_msg(&pks[0..1], &messages[0..1])
        .is_ok());

    let aggregated_signature = BLS12381AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .zip(&messages)
            .take(3)
            .skip(1)
            .map(|(kp, message)| kp.sign(message))
            .collect::<Vec<BLS12381Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();
    assert!(sig2.verify_different_msg(&pks, &messages).is_ok());
}

#[test]
fn test_signature_aggregation() {
    let mut rng = StdRng::from_seed([0; 32]);
    let msg = b"message";

    // Valid number of signatures
    for size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192] {
        let blst_keypairs: Vec<_> = (0..size)
            .map(|_| BLS12381KeyPair::generate(&mut rng))
            .collect();
        let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(msg)).collect();
        assert!(BLS12381AggregateSignature::aggregate(&blst_signatures).is_ok());
    }

    // Invalid number of signatures
    let blst_keypairs: Vec<_> = (0..0)
        .map(|_| BLS12381KeyPair::generate(&mut rng))
        .collect();
    let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(msg)).collect();
    assert!(BLS12381AggregateSignature::aggregate(&blst_signatures).is_err());
}

//
// Other tests
//

#[test]
fn test_hkdf_generate_from_ikm() {
    let seed = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];
    let salt = &[3, 2, 1];
    let kp = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(seed, salt, &[]).unwrap();
    let kp2 = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(seed, salt, &[]).unwrap();

    assert_eq!(kp.private().as_bytes(), kp2.private().as_bytes());
}

// Checks if the private keys zeroed out
#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = BLS12381KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, BLS12381PrivateKey::LENGTH) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is zeroized
    unsafe {
        for i in 0..BLS12381PrivateKey::LENGTH {
            assert_eq!(*ptr.add(i), 0);
        }
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, BLS12381PrivateKey::LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for BLS12381PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for BLS12381PrivateKey>"
        );
    });
}

#[test]
fn test_verify_with_default_values() {
    let valid_kp = keys().pop().unwrap();
    let valid_sig = valid_kp.sign(b"message");
    let default_sig = BLS12381Signature::default();
    let valid_pk = valid_kp.public().clone();
    let default_pk = BLS12381PublicKey::insecure_default();
    let valid_agg_sig = BLS12381AggregateSignature::aggregate(&[valid_sig.clone()]).unwrap();
    let default_agg_sig = BLS12381AggregateSignature::default();

    // Default sig should fail (for both types of keys)
    assert!(valid_pk.verify(b"message", &default_sig).is_err());
    assert!(default_pk.verify(b"message", &default_sig).is_err());

    // Verification with default pk should fail.
    assert!(default_pk.verify(b"message", &valid_sig).is_err());

    // Verifications with one of the default values should fail.
    assert!(valid_agg_sig.verify(&[valid_pk.clone()], b"message").is_ok());
    assert!(valid_agg_sig.verify(&[default_pk.clone()], b"message").is_err());
    assert!(default_agg_sig.verify(&[valid_pk.clone()], b"message").is_err());
    assert!(default_agg_sig.verify(&[default_pk.clone()], b"message").is_err());
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

#[test]
 fn fmt_public_key() {
     let kpref = keys().pop().unwrap();
     let public_key = kpref.public();

     // Display
     assert_eq!(
         format!("{}", public_key),
         Base64::encode(public_key.as_bytes())
     );

     // Debug
     assert_eq!(
         format!("{:?}", public_key),
         Base64::encode(public_key.as_bytes())
     );
 }

#[test]
 fn hash_signature() {
     let sig = keys().pop().unwrap().sign(b"Hello, world!");

     let mut hasher = DefaultHasher::new();
     sig.hash(&mut hasher);
     let digest = hasher.finish();

     let mut other_hasher = DefaultHasher::new();
     sig.as_bytes().hash(&mut other_hasher);
     let expected = other_hasher.finish();
     assert_eq!(expected, digest);
 }

#[test]
 fn fmt_signature() {
     let sig = keys().pop().unwrap().sign(b"Hello, world!");
     assert_eq!(format!("{}", sig), Base64::encode(sig.as_bytes()));

     let aggregate_sig = BLS12381AggregateSignature::aggregate(&[sig.clone()]).unwrap();
     assert_eq!(format!("{}", aggregate_sig), Base64::encode(aggregate_sig.as_bytes()));
 }

//
// Proptests
//


// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = BLS12381KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            BLS12381KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

prop_compose! {
    fn valid_signature(pk: BLS12381PrivateKey)
                      (msg in any::<[u8; 32]>()) -> ([u8; 32], BLS12381Signature) {
            (msg, pk.sign(&msg))
    }
}

prop_compose! {
  fn maybe_valid_sig(pk: BLS12381PrivateKey)
                    (disc in bool::arbitrary(),
                    (msg, sig) in valid_signature(pk))
                       -> ([u8; 32], BLS12381Signature) {
    if disc {
      (msg, sig)
    } else {
      let mut rng = StdRng::from_seed([0; 32]);
      let mut msg = msg;
      rng.fill_bytes(&mut msg);
      (msg, sig)
    }
  }
}

fn arb_sig_triplet() -> impl Strategy<Value = (BLS12381PublicKey, [u8; 32], BLS12381Signature)> {
    arb_keypair()
        .prop_flat_map(|kp| {
            let pk: BLS12381PublicKey = kp.public().clone();
            (Just(pk), maybe_valid_sig(kp.private()))
        })
        .prop_flat_map(|(pk, (msg, sig))| (Just(pk), Just(msg), Just(sig)))
        .no_shrink()
}

const BLS_MAX_SIGNATURES: usize = 100;

fn aggregate_treewise(sigs: &[BLS12381Signature]) -> BLS12381AggregateSignature {
    if sigs.len() <= 1 {
        return sigs
            .first()
            .map(|s| {
                let mut res = BLS12381AggregateSignature::default();
                res.add_signature(s.clone()).unwrap();
                res
            })
            .unwrap_or_default();
    } else {
        let mid = sigs.len() / 2;
        let (left, right) = sigs.split_at(mid);
        let left = aggregate_treewise(left);
        let right = aggregate_treewise(right);
        let mut res = BLS12381AggregateSignature::default();
        res.add_aggregate(left).unwrap();
        res.add_aggregate(right).unwrap();
        res
    }
}

proptest! {
    // Tests that serde does not panic
    #[test]
    fn test_basic_deser_publickey(bits in collection::vec(any::<u8>(), BLS_G2_LENGTH..=BLS_G2_LENGTH)) {
        let _ = BLS12381PublicKey::from_bytes(&bits);
    }

    #[test]
    fn test_basic_deser_privatekey(bits in collection::vec(any::<u8>(), BLS_PRIVATE_KEY_LENGTH..=BLS_PRIVATE_KEY_LENGTH)) {
        let _ = BLS12381PrivateKey::from_bytes(&bits);
    }

    #[test]
    fn test_basic_deser_signature(bits in collection::vec(any::<u8>(), BLS_G1_LENGTH..=BLS_G1_LENGTH)) {
        let _ = <BLS12381Signature as ToFromBytes>::from_bytes(&bits);
    }

    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: BLS12381KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }

    // Tests that signature verif does not panic
    #[test]
    fn test_basic_verify_signature(
        (pk, msg, sig) in arb_sig_triplet()
    ) {
        let _ = pk.verify(&msg, &sig);
    }


    // Test compatibility between aggregate and iterated verification
    #[test]
    fn test_aggregate_verify_distinct_messages(
        triplets in collection::vec(arb_sig_triplet(), 1..=BLS_MAX_SIGNATURES)
    ){
        let mut aggr = BLS12381AggregateSignature::default();
        let (pks_n_msgs, sigs): (Vec<_>, Vec<_>) = triplets.into_iter().map(|(pk, msg, sig)| ((pk, msg), sig)).unzip();
        for sig in sigs.clone() {
            aggr.add_signature(sig).unwrap();
        }
        let (pks, msgs): (Vec<_>, Vec<_>) = pks_n_msgs.into_iter().unzip();

        let res_aggregated = aggr.verify_different_msg(&pks, &msgs.iter().map(|m| m.as_ref()).collect::<Vec<_>>());
        let iterated_bits = sigs.iter().zip(pks.iter().zip(msgs.iter())).map(|(sig, (pk, msg))| pk.verify(msg, sig)).collect::<Vec<_>>();
        let res_iterated = iterated_bits.iter().all(|b| b.is_ok());

        assert_eq!(res_aggregated.is_ok(), res_iterated, "Aggregated: {:?}, iterated: {:?}", res_aggregated, iterated_bits);
    }

    #[test]
    fn test_aggregate_verify_distinct_messages_treewise(
        triplets in collection::vec(arb_sig_triplet(), 1..=BLS_MAX_SIGNATURES)
    ){
        let (pks_n_msgs, sigs): (Vec<_>, Vec<_>) = triplets.into_iter().map(|(pk, msg, sig)| ((pk, msg), sig)).unzip();
        let aggr = aggregate_treewise(&sigs);
        let (pks, msgs): (Vec<_>, Vec<_>) = pks_n_msgs.into_iter().unzip();

        let res_aggregated = aggr.verify_different_msg(&pks, &msgs.iter().map(|m| m.as_ref()).collect::<Vec<_>>());
        let iterated_bits = sigs.iter().zip(pks.iter().zip(msgs.iter())).map(|(sig, (pk, msg))| pk.verify(msg, sig)).collect::<Vec<_>>();
        let res_iterated = iterated_bits.iter().all(|b| b.is_ok());

        assert_eq!(res_aggregated.is_ok(), res_iterated, "Aggregated: {:?}, iterated: {:?}", res_aggregated, iterated_bits);
    }

}
}} // macro_rules! define_tests

pub mod min_sig {
    use super::*;
    use crate::bls12381::min_sig::{
        BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
        BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
    };
    define_tests!();

    #[test]
    fn regression_test() {
        // Generated from a random secret key and stored here for regression testing.
        let secret =
            hex::decode("266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb")
                .unwrap();
        let public = hex::decode("8c66dc2c1ea9e53f0985c17b4e7af19912b6d3c40e0c5920a5a12509b4eb3619f5e07ec56ea77f0b30629ba1cc72d75b139460782a5f0e2f89fb4c42b4b8a5fae3d260102220e63d0754e7e1846deefd3988eade4ed37f1385437d19de1a1618").unwrap();
        let signature = hex::decode("89dff2dc1e9428b9437d50b37f8160eca790110ea2a79b6c88a43a16953466f8e391ff65842b067a1c9441c7c2cebce0").unwrap();

        let sk = BLS12381PrivateKey::from_bytes(&secret).unwrap();
        let pk = BLS12381PublicKey::from(&sk);
        let message = b"hello, narwhal";
        let sig = sk.sign(message);

        assert_eq!(sk.as_bytes(), secret);
        assert_eq!(pk.as_bytes(), public);
        assert_eq!(sig.as_bytes(), signature);
    }
}

pub mod min_pk {
    use super::*;
    use crate::bls12381::min_pk::{
        BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
        BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
    };
    define_tests!();

    #[test]
    fn regression_test() {
        // Generated from a random secret key and stored here for regression testing.
        let secret =
            hex::decode("266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb")
                .unwrap();
        let public = hex::decode("b157f238403a5b980546fd19ca48f79a2613e3e3a91d14ee69908b8816e4c53665370b2fbd0db62cc4aa0e8caeedc9b5").unwrap();
        let signature = hex::decode("8dec0b9a1a629cc96c57144ee8e7dd5c93acb465286f1214df3b8482c3f16e10db4277ead785f5d5bc77b4e51affd2580dead4d0d21cf20fc5e2b4bec2586c2bd6c73fee76c11f214871f77dada4c578034c3b978f1cccb82bdd78fe5ee67de1").unwrap();

        let sk = BLS12381PrivateKey::from_bytes(&secret).unwrap();
        let pk = BLS12381PublicKey::from(&sk);
        let message = b"hello, narwhal";
        let sig = sk.sign(message);

        assert_eq!(sk.as_bytes(), secret);
        assert_eq!(pk.as_bytes(), public);
        assert_eq!(sig.as_bytes(), signature);
    }

    #[test]
    fn test_verify_drand_signature() {
        // Regression test of an actual response from Drand.
        let key = hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap();
        let sig = hex::decode("a2cd8577944b84484ef557a7f92f0d5092779497cc470b1b97680b8f7c807d97250d310b801c7c2185c7c8a21032d45403b97530ca87bd8f05d0cf4ffceb4bcb9bf7184fb604967db7e9e6ea555bc51b25a9e41fbd51181f712aa73aaec749fe").unwrap();

        let round: u64 = 2373935;
        let prev_sig = hex::decode("a96aace596906562dc525dba4dff734642d71b334d51324f9c9bcb5a3d6caf14b05cde91d6507bf4615cb4285e5b4efd1358ebc46b80b51e338f9dc46cca17cf2e046765ba857c04101a560887fa81aef101a5bb3b2350884558bd3adc72be37").unwrap();

        let mut sha = Sha256::new();
        sha.update(prev_sig);
        sha.update(round.to_be_bytes());
        let msg = sha.finalize().digest;

        let key = BLS12381PublicKey::from_bytes(&key).unwrap();
        let sig = <BLS12381Signature as ToFromBytes>::from_bytes(&sig).unwrap();
        assert!(key.verify(&msg, &sig).is_ok());
    }
}
