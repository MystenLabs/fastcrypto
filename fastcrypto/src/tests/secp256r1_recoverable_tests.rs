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
use wycheproof::ecdsa::{TestName::EcdsaSecp256r1Sha256, TestSet};
use wycheproof::TestResult;

use crate::encoding::{Base64, Encoding};
use crate::hash::Blake2b256;
use crate::secp256r1::{
    Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1Signature,
};
use crate::{
    hash::{HashFunction, Sha256},
    secp256r1::recoverable::Secp256r1RecoverableSignature,
    signature_service::SignatureService,
    traits::{EncodeDecodeBase64, KeyPair, ToFromBytes},
};

use crate::secp256r1::recoverable::SECP256R1_RECOVERABLE_SIGNATURE_LENGTH;
use crate::test_helpers::verify_serialization;
use crate::traits::VerifyingKey;
use crate::traits::{RecoverableSignature, RecoverableSigner, VerifyRecoverable};

const MSG: &[u8] = b"Hello, world!";

pub fn keys() -> Vec<Secp256r1KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);

    (0..4)
        .map(|_| Secp256r1KeyPair::generate(&mut rng))
        .collect()
}

#[test]
fn serialize_deserialize() {
    // The other types (pk, sk, keypair) are tested in the nonrecoverable tests.
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    verify_serialization(&sig, Some(sig.as_bytes()));
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
fn test_public_key_recovery() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature: Secp256r1RecoverableSignature = kp.sign_recoverable(message);
    let recovered_key = signature.recover(message).unwrap();
    assert_eq!(recovered_key, *kp.public());
}

#[test]
fn test_public_key_recovery_error() {
    // incorrect length
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&[0u8; 1]).is_err());

    // TODO: Uncomment when recovery byte is added
    // invalid recovery id at index 65
    // assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&[4u8; 65]).is_err());

    // Invalid signature: Zeros in signatures are not allowed
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(
        &[0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH]
    )
    .is_err());
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
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign_recoverable(b"Hello, world!");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig =
        <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig.as_ref(), signature.as_ref());
    // check for failure
    let mut sig_bytes = signature.as_ref().to_vec();
    sig_bytes.pop();
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&sig_bytes).is_err());
}

#[test]
fn fail_on_r_or_s_zero() {
    // Verification (split_scalars) panics if r or s is zero, so we check that this is caught in deserialization.

    // Build valid signature
    let signature = keys().pop().unwrap().sign_recoverable(b"Hello, world!");
    let sig_bytes = signature.as_ref();

    // Set r to zero
    let mut r_is_zero = [0u8; 65];
    r_is_zero[0..32].copy_from_slice(&Scalar::ZERO.to_bytes());
    r_is_zero[32..64].copy_from_slice(&sig_bytes[32..64]);
    r_is_zero[64] = sig_bytes[64];
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&r_is_zero).is_err());

    // Set s to zero
    let mut s_is_zero = [0u8; 65];
    s_is_zero[0..32].copy_from_slice(&sig_bytes[0..32]);
    s_is_zero[32..64].copy_from_slice(&Scalar::ZERO.to_bytes());
    s_is_zero[64] = sig_bytes[64];
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&s_is_zero).is_err());
}

#[test]
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

#[test]
fn hash_signature() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);

    let mut hasher = DefaultHasher::new();
    sig.hash(&mut hasher);
    let digest = hasher.finish();

    let mut other_hasher = DefaultHasher::new();
    sig.as_bytes().hash(&mut other_hasher);
    let expected = other_hasher.finish();
    assert_eq!(expected, digest);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message, hashed to keccak256.
    let message: &[u8] = b"Hello, world!";

    let signature = kp.sign_recoverable(message.as_ref());

    // Verify the signature.
    assert!(kp
        .public()
        .verify_recoverable(message.as_ref(), &signature)
        .is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";

    // Verify the signature against good message passes.
    let signature = kp.sign_recoverable(message);
    assert!(kp.public().verify_recoverable(message, &signature).is_ok());

    // Verify the signature against bad digest fails.
    let bad_message: &[u8] = b"Bad message!";

    assert!(kp
        .public()
        .verify_recoverable(bad_message, &signature)
        .is_err());
}

#[test]
fn verify_hashed_failed_if_different_hash_function() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message.
    let message: &[u8] = &[0u8; 1];
    let signature = kp.sign_recoverable_with_hash::<Sha256>(message);

    // Verify the signature using other hash function fails.
    assert!(kp
        .public()
        .verify_recoverable_with_hash::<Blake2b256>(message, &signature)
        .is_err());
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
    let sig = Secp256r1RecoverableSignature::from_bytes(&hex::decode("63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be9120b2963fe63a35b44847a7888db981d1ccf0753a4673b094fed274a6589deb982a00").unwrap()).unwrap();

    // Assert that S is in upper half
    assert_ne!(sig.sig.s().is_high().unwrap_u8(), 0);

    // Failed to verify with upper S.
    assert!(pk.verify_recoverable(&digest.digest, &sig).is_err());

    let normalized = sig.sig.normalize_s().unwrap();

    // Normalize S to be less than N/2.
    let normalized_sig =
        Secp256r1RecoverableSignature::from_uncompressed(normalized.to_bytes().as_slice()).unwrap();

    // Verify with normalized lower S.
    assert!(pk
        .verify_recoverable(&digest.digest, &normalized_sig)
        .is_ok());
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

#[test]
fn wycheproof_test() {
    let test_set = TestSet::load(EcdsaSecp256r1Sha256).unwrap();
    for test_group in test_set.test_groups {
        let pk = Secp256r1PublicKey::from_bytes(&test_group.key.key).unwrap();
        for test in test_group.tests {
            let signature = match &Signature::from_der(&test.sig) {
                Ok(s) => Secp256r1RecoverableSignature::from_uncompressed(s.to_bytes().as_slice())
                    .unwrap(),
                Err(_) => {
                    assert_eq!(map_result(test.result), TestResult::Invalid);
                    continue;
                }
            };

            let bytes = signature.as_ref();

            // Wycheproof tests do not provide a recovery id, iterate over all possible ones to verify.
            let mut n_bytes = [0u8; 65];
            n_bytes[..64].copy_from_slice(&bytes[..64]);
            let mut res = TestResult::Invalid;

            for i in 0..4 {
                n_bytes[64] = i;
                let sig =
                    <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&n_bytes).unwrap();
                if pk.verify_recoverable(test.msg.as_slice(), &sig).is_ok() {
                    res = TestResult::Valid;
                    break;
                } else {
                    continue;
                }
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

#[test]
fn test_recoverable_nonrecoverable_conversion() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign_recoverable(message);
    assert!(kp.public().verify_recoverable(message, &signature).is_ok());

    let nonrecoverable_signature = Secp256r1Signature::try_from(&signature).unwrap();
    assert!(kp
        .public()
        .verify(message, &nonrecoverable_signature)
        .is_ok());

    let recovered_signature = Secp256r1RecoverableSignature::try_from_nonrecoverable(
        &nonrecoverable_signature,
        kp.public(),
        message,
    )
    .unwrap();
    assert!(kp
        .public()
        .verify_recoverable(message, &recovered_signature)
        .is_ok());
}

#[test]
fn test_invalid_nonrecoverable_conversion() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message.
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign_recoverable(message);
    let nonrecoverable_signature = Secp256r1Signature::try_from(&signature).unwrap();

    // Try to convert a nonrecoverable signature to a recoverable one with a different message.
    let other_message: &[u8] = b"Hello, other world!";
    assert!(Secp256r1RecoverableSignature::try_from_nonrecoverable(
        &nonrecoverable_signature,
        kp.public(),
        other_message,
    )
    .is_err());
}
