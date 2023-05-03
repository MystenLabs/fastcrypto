// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use p256::ecdsa::Signature;
use p256::elliptic_curve::scalar::IsHigh;
use p256::Scalar;
use proptest::{prelude::*, strategy::Strategy};
use rand::{rngs::StdRng, SeedableRng as _};
use rust_secp256k1::constants::SECRET_KEY_SIZE;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use wycheproof::ecdsa::{TestName::EcdsaSecp256r1Sha256, TestSet};
use wycheproof::TestResult;

use crate::encoding::{Base64, Encoding};
use crate::hash::{Blake2b256, Keccak256};
use crate::secp256r1::recoverable::SECP256R1_RECOVERABLE_SIGNATURE_LENGTH;
use crate::test_helpers::verify_serialization;
use crate::traits::Signer;
use crate::{
    hash::{HashFunction, Sha256},
    secp256r1::{Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1Signature},
    signature_service::SignatureService,
    test_helpers,
    traits::{EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};

const MSG: &[u8] = b"Hello, world!";

pub fn keys() -> Vec<Secp256r1KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| Secp256r1KeyPair::generate(&mut rng))
        .collect()
}

#[test]
fn serialize_deserialize() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let sk = kp.private();
    let sig = keys().pop().unwrap().sign(MSG);

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = Secp256r1PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), public_key.as_ref());
}

#[test]
fn test_public_key_recovery_error() {
    // incorrect length
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&[0u8; 1]).is_err());

    // invalid recovery id at index 65
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&[4u8; 65]).is_err());

    // Invalid signature: Zeros in signatures are not allowed
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(
        &[0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH]
    )
    .is_err());
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
fn public_key_from_bytes() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let pk_bytes = pk.as_ref();
    let rebuilt_pk = <Secp256r1PublicKey as ToFromBytes>::from_bytes(pk_bytes).unwrap();
    assert_eq!(rebuilt_pk, pk);

    // check for failure
    let mut pk_bytes = pk.as_ref().to_vec();
    pk_bytes.pop();
    assert!(<Secp256r1PublicKey as ToFromBytes>::from_bytes(&pk_bytes).is_err());
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Secp256r1PrivateKey::decode_base64(&export);
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
fn key_pair_from_string_roundtrip() {
    let kp = keys().pop().unwrap();
    let kp_str = Base64::encode(kp.as_ref());
    let recovered = Secp256r1KeyPair::from_str(&kp_str).unwrap();
    assert_eq!(kp, recovered);
}

#[test]
fn private_key_from_bytes() {
    let kp = keys().pop().unwrap();
    let sk = kp.private();
    let sk_bytes = sk.as_ref();
    let rebuilt_sk = <Secp256r1PrivateKey as ToFromBytes>::from_bytes(sk_bytes).unwrap();
    assert_eq!(rebuilt_sk, sk);

    // check for failure
    let mut sk_bytes = sk.as_ref().to_vec();
    sk_bytes.pop();
    assert!(<Secp256r1PrivateKey as ToFromBytes>::from_bytes(&sk_bytes).is_err());
}

#[test]
fn non_canonical_secret_key() {
    // Secret keys should be scalars between 0 and the base point order

    let zero =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&zero).is_err());

    let one =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&one).is_ok());

    let order_minus_one =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&order_minus_one).is_ok());

    let order =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&order).is_err());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world!");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <Secp256r1Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig.as_ref(), signature.as_ref());
    // check for failure
    let mut sig_bytes = signature.as_ref().to_vec();
    sig_bytes.pop();
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&sig_bytes).is_err());
}

#[test]
fn fail_on_r_or_s_zero() {
    // Verification (split_scalars) panics if r or s is zero, so we check that this is caught in deserialization.

    // Build valid signature
    let signature = keys().pop().unwrap().sign(b"Hello, world!");
    let sig_bytes = signature.as_ref();

    // Set r to zero
    let mut r_is_zero = [0u8; 64];
    r_is_zero[0..32].copy_from_slice(&Scalar::ZERO.to_bytes());
    r_is_zero[32..64].copy_from_slice(&sig_bytes[32..64]);
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&r_is_zero).is_err());

    // Set s to zero
    let mut s_is_zero = [0u8; 64];
    s_is_zero[0..32].copy_from_slice(&sig_bytes[0..32]);
    s_is_zero[32..64].copy_from_slice(&Scalar::ZERO.to_bytes());
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&s_is_zero).is_err());
}

#[test]
fn hash_signature() {
    let sig = keys().pop().unwrap().sign(MSG);

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
    let sig = keys().pop().unwrap().sign(MSG);
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message, hashed to keccak256.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn verify_hashed_failed_if_different_hash() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message (hashed to keccak256 internally).
    let message: &[u8] = &[0u8; 1];
    let signature = kp.sign_with_hash::<Keccak256>(message);

    // Verify the signature using other hash function.
    assert!(kp
        .public()
        .verify_with_hash::<Blake2b256>(message, &signature)
        .is_err());
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Secp256r1PublicKey>, Vec<Secp256r1Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let (pubkeys, signatures): (Vec<Secp256r1PublicKey>, Vec<Secp256r1Signature>) = keys()
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

    let res = Secp256r1PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures.swap(0, 1);

    assert!(Secp256r1PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures).is_err())
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Secp256r1PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Secp256r1PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Secp256r1PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
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
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());

    // Verify the signature against bad digest fails.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Sha256::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = test_helpers::signature_test_inputs_different_msg::<Secp256r1KeyPair>();
    let res = Secp256r1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = test_helpers::signature_test_inputs_different_msg::<Secp256r1KeyPair>();
    inputs.signatures.swap(0, 1);
    let res = Secp256r1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn fail_to_verify_if_upper_s() {
    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let pk = Secp256r1PublicKey::from_bytes(
        &hex::decode("0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a").unwrap(),
    )
    .unwrap();
    let sig = <Secp256r1Signature as ToFromBytes>::from_bytes(&hex::decode("63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be9120b2963fe63a35b44847a7888db981d1ccf0753a4673b094fed274a6589deb982a").unwrap()).unwrap();

    // Assert that S is in upper half
    assert_ne!(sig.sig.s().is_high().unwrap_u8(), 0);

    // Failed to verify with upper S.
    assert!(pk.verify(&digest.digest, &sig).is_err());

    let normalized = sig.sig.normalize_s().unwrap();

    // Normalize S to be less than N/2.
    let normalized_sig = Secp256r1Signature::from_bytes(normalized.to_bytes().as_slice()).unwrap();

    // Verify with normalized lower S.
    assert!(pk.verify(&digest.digest, &normalized_sig).is_ok());
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

    //    digest.into()

    // Verify the signature we received.
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Secp256r1KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] = unsafe { std::slice::from_raw_parts(bytes_ptr, SECRET_KEY_SIZE) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is set to ONE_KEY (workaround to all zero SecretKey considered as invalid)
    unsafe {
        assert_eq!(*ptr, 1);
        for i in 1..SECRET_KEY_SIZE {
            assert_eq!(*ptr.add(i), 0);
        }
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] = unsafe { std::slice::from_raw_parts(bytes_ptr, SECRET_KEY_SIZE) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

// TODO: If we find another crate impl'ing ecdsa secp256r1 with recovery, we could use this test to compare it with our implementation.
// proptest::proptest! {
//     #[test]
//     #[cfg(feature = "copy_key")]
//     fn test_k256_against_Secp256r1_lib_with_recovery(
//         r in <[u8; 32]>::arbitrary()
// ) {
//         let message: &[u8] = b"hello world!";
//         let hashed_msg = rust_Secp256r1::Message::from_slice(Keccak256::digest(message).as_ref()).unwrap();
//
//         // construct private key with bytes and signs message
//         let priv_key = <Secp256r1PrivateKey as ToFromBytes>::from_bytes(&r).unwrap();
//         let key_pair = Secp256r1KeyPair::from(priv_key);
//         let key_pair_copied = key_pair.copy();
//         let key_pair_copied_2 = key_pair.copy();
//         let signature: Secp256r1Signature = key_pair.sign(message);
//         assert!(key_pair.public().verify(message, &signature).is_ok());
//
//         // construct a signature with r, s, v where v is flipped from the original signature.
//         let bytes = ToFromBytes::as_bytes(&signature);
//         let mut flipped_bytes = [0u8; 65];
//         flipped_bytes[..64].copy_from_slice(&bytes[..64]);
//         if bytes[64] == 0 {
//             flipped_bytes[64] = 1;
//         } else {
//             flipped_bytes[64] = 0;
//         }
//         let malleated_signature: Secp256r1Signature = <Secp256r1Signature as signature::Signature>::from_bytes(&flipped_bytes).unwrap();
//
//         // malleable(altered) signature with opposite sign fails to verify
//         assert!(key_pair.public().verify(message, &malleated_signature).is_err());
//
//         // use k256 to construct private key with the same bytes and signs the same message
//         let priv_key_1 = k256::ecdsa::SigningKey::from_bytes(&r).unwrap();
//         let pub_key_1 = priv_key_1.verifying_key();
//         let signature_1: k256::ecdsa::recoverable::Signature = priv_key_1.sign(message);
//         assert!(pub_key_1.verify(message, &signature_1).is_ok());
//
//         // two private keys are serialized the same
//         assert_eq!(key_pair_copied.private().as_bytes(), priv_key_1.to_bytes().as_slice());
//
//         // two pubkeys are the same
//         assert_eq!(
//             key_pair.public().as_bytes(),
//             pub_key_1.to_bytes().as_slice()
//         );
//
//         // same recovered pubkey are recovered
//         let recovered_key = signature.sig.recover(&hashed_msg).unwrap();
//         let recovered_key_1 = signature_1.recover_verifying_key(message).expect("couldn't recover pubkey");
//         assert_eq!(recovered_key.serialize(),recovered_key_1.to_bytes().as_slice());
//
//         // same signatures produced from both implementations
//         assert_eq!(signature.as_ref(), ToFromBytes::as_bytes(&signature_1));
//
//         // use ffi-implemented keypair to verify sig constructed by k256
//         let sig_bytes_1 = bincode::serialize(&signature_1.as_ref()).unwrap();
//         let secp_sig1 = bincode::deserialize::<Secp256r1Signature>(&sig_bytes_1).unwrap();
//         assert!(key_pair_copied_2.public().verify(message, &secp_sig1).is_ok());
//
//         // use k256 keypair to verify sig constructed by ffi-implementation
//         let typed_sig = k256::ecdsa::recoverable::Signature::try_from(signature.as_ref()).unwrap();
//         assert!(pub_key_1.verify(message, &typed_sig).is_ok());
//     }
// }

#[test]
fn wycheproof_test_nonrecoverable() {
    let test_set = TestSet::load(EcdsaSecp256r1Sha256).unwrap();
    for test_group in test_set.test_groups {
        let pk = Secp256r1PublicKey::from_bytes(&test_group.key.key).unwrap();
        for test in test_group.tests {
            let signature = match Signature::from_der(&test.sig) {
                Ok(s) => Secp256r1Signature::from_bytes(
                    // Wycheproof tests do not enforce low s but we do, so we need to normalize
                    s.normalize_s().unwrap_or(s).to_bytes().as_slice(),
                )
                .unwrap(),
                Err(_) => {
                    assert_eq!(map_result(test.result), TestResult::Invalid);
                    continue;
                }
            };

            let mut res = TestResult::Invalid;
            if pk.verify(test.msg.as_slice(), &signature).is_ok() {
                res = TestResult::Valid;
            }
            assert_eq!(map_result(test.result), res, "{}", test.comment);
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
        assert_eq!(format!("{}", sk), "<elided secret for Secp256r1PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for Secp256r1PrivateKey>"
        );
    });
}

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = Secp256r1KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Secp256r1KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Secp256r1KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }
}
