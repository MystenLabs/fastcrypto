// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::signature::{Signer as ExternalSigner, Verifier as ExternalVerifier};
use p384::ecdsa::Signature;
use p384::elliptic_curve::scalar::IsHigh;
use proptest::{prelude::*, strategy::Strategy};
use rand::{rngs::StdRng, SeedableRng as _};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use wycheproof::ecdsa::{TestName, TestSet};
use wycheproof::TestResult;

use crate::encoding::{Base64, Encoding};
use crate::hash::{Blake2b256, Keccak256, Sha512};
use crate::secp384r1::{
    SECP384R1_PRIVATE_KEY_LENGTH, SECP384R1_PUBLIC_KEY_LENGTH, SECP384R1_SIGNATURE_LENGTH,
};
use crate::test_helpers::verify_serialization;
use crate::traits::Signer;
use crate::{
    hash::{HashFunction, Sha256, Sha384},
    secp384r1::{Secp384r1KeyPair, Secp384r1PrivateKey, Secp384r1PublicKey, Secp384r1Signature},
    test_helpers,
    traits::{EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};

const MSG: &[u8] = b"Hello, world!";

pub fn keys() -> Vec<Secp384r1KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| Secp384r1KeyPair::generate(&mut rng))
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
    let import = Secp384r1PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), public_key.as_ref());
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
    let rebuilt_pk = <Secp384r1PublicKey as ToFromBytes>::from_bytes(pk_bytes).unwrap();
    assert_eq!(rebuilt_pk, pk);

    // check for failure
    let mut pk_bytes = pk.as_ref().to_vec();
    pk_bytes.pop();
    assert!(<Secp384r1PublicKey as ToFromBytes>::from_bytes(&pk_bytes).is_err());
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Secp384r1PrivateKey::decode_base64(&export);
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
    let recovered = Secp384r1KeyPair::from_str(&kp_str).unwrap();
    assert_eq!(kp, recovered);
}

#[test]
fn private_key_from_bytes() {
    let kp = keys().pop().unwrap();
    let sk = kp.private();
    let sk_bytes = sk.as_ref();
    let rebuilt_sk = <Secp384r1PrivateKey as ToFromBytes>::from_bytes(sk_bytes).unwrap();
    assert_eq!(rebuilt_sk, sk);

    // check for failure
    let mut sk_bytes = sk.as_ref().to_vec();
    sk_bytes.pop();
    assert!(<Secp384r1PrivateKey as ToFromBytes>::from_bytes(&sk_bytes).is_err());
}

#[test]
fn non_canonical_secret_key() {
    // Secret keys should be scalars between 0 and the base point order

    let zero = vec![0u8; SECP384R1_PRIVATE_KEY_LENGTH];
    assert!(Secp384r1PrivateKey::from_bytes(&zero).is_err());

    let mut one = vec![0u8; SECP384R1_PRIVATE_KEY_LENGTH];
    one[SECP384R1_PRIVATE_KEY_LENGTH - 1] = 1;
    assert!(Secp384r1PrivateKey::from_bytes(&one).is_ok());

    let order_minus_one = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52972").unwrap();
    assert!(Secp384r1PrivateKey::from_bytes(&order_minus_one).is_ok());

    let order = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973").unwrap();
    assert!(Secp384r1PrivateKey::from_bytes(&order).is_err());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(MSG);
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <Secp384r1Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig.as_ref(), signature.as_ref());
    // check for failure
    let mut sig_bytes = signature.as_ref().to_vec();
    sig_bytes.pop();
    assert!(<Secp384r1Signature as ToFromBytes>::from_bytes(&sig_bytes).is_err());
}

#[test]
fn fail_on_r_or_s_zero() {
    // Verification (split_scalars) panics if r or s is zero, so we check that this is caught in deserialization.

    // Build valid signature
    let signature = keys().pop().unwrap().sign(MSG);
    let sig_bytes = signature.as_ref();

    // Set r to zero
    let mut r_is_zero = [0u8; SECP384R1_SIGNATURE_LENGTH];
    r_is_zero[48..96].copy_from_slice(&sig_bytes[48..96]);
    assert!(<Secp384r1Signature as ToFromBytes>::from_bytes(&r_is_zero).is_err());

    // Set s to zero
    let mut s_is_zero = [0u8; SECP384R1_SIGNATURE_LENGTH];
    s_is_zero[0..48].copy_from_slice(&sig_bytes[0..48]);
    assert!(<Secp384r1Signature as ToFromBytes>::from_bytes(&s_is_zero).is_err());
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

    // Sign over raw message, hashed to sha384.
    let digest = Sha384::digest(MSG);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn verify_hashed_failed_if_different_hash() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message, hashed to keccak256.
    let message: &[u8] = &[0u8; 1];
    let signature = kp.sign_with_hash::<Keccak256, 32>(message);

    // Verify the signature using other hash functions fails.
    assert!(kp
        .public()
        .verify_with_hash::<Blake2b256, 32>(message, &signature)
        .is_err());
    assert!(kp
        .public()
        .verify_with_hash::<Sha384, 48>(message, &signature)
        .is_err());

    // Verify the signature using the same hash function succeeds.
    assert!(kp
        .public()
        .verify_with_hash::<Keccak256, 32>(message, &signature)
        .is_ok());
}

#[test]
fn sign_and_verify_with_sha256() {
    let kp = keys().pop().unwrap();
    let signature = kp.sign_with_hash::<Sha256, 32>(MSG);
    assert!(kp
        .public()
        .verify_with_hash::<Sha256, 32>(MSG, &signature)
        .is_ok());

    // The signature is also valid for the p384 crate using the same (padded) prehash.
    let external_pk = p384::ecdsa::VerifyingKey::from_sec1_bytes(kp.public().as_ref()).unwrap();
    let external_sig = Signature::from_slice(signature.as_ref()).unwrap();
    assert!(external_pk
        .verify_prehash(&Sha256::digest(MSG).digest, &external_sig)
        .is_ok());
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Secp384r1PublicKey>, Vec<Secp384r1Signature>) {
    // Make signatures.
    let digest = Sha384::digest(MSG);
    let (pubkeys, signatures): (Vec<Secp384r1PublicKey>, Vec<Secp384r1Signature>) = keys()
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

    let res = Secp384r1PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures.swap(0, 1);

    assert!(Secp384r1PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures).is_err())
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Secp384r1PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Secp384r1PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Secp384r1PublicKey::verify_batch_empty_fail(
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
    let digest = Sha384::digest(MSG);

    // Verify the signature against good digest passes.
    let signature = kp.sign(digest.as_ref());
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());

    // Verify the signature against bad digest fails.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Sha384::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = test_helpers::signature_test_inputs_different_msg::<Secp384r1KeyPair>();
    let res = Secp384r1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = test_helpers::signature_test_inputs_different_msg::<Secp384r1KeyPair>();
    inputs.signatures.swap(0, 1);
    let res = Secp384r1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_high_s_signature() {
    // Unlike secp256r1, high-s signatures are valid (matching the p384 crate and standard ECDSA
    // implementations, e.g. for X.509 certificate chains).
    let kp = keys().pop().unwrap();
    let signature = kp.sign(MSG);

    // Compute the malleated signature (r, n - s) and pick the high-s variant.
    let (r, s) = signature.sig.split_scalars();
    let high_s = if bool::from(s.is_high()) {
        *s.as_ref()
    } else {
        -*s.as_ref()
    };
    let high_sig_external = Signature::from_scalars(r.to_bytes(), high_s.to_bytes()).unwrap();
    let high_sig = Secp384r1Signature::from_bytes(high_sig_external.to_bytes().as_slice()).unwrap();
    assert!(bool::from(high_sig.sig.s().is_high()));

    // Both this implementation and the p384 crate accept the high-s signature.
    assert!(kp.public().verify(MSG, &high_sig).is_ok());
    let external_pk = p384::ecdsa::VerifyingKey::from_sec1_bytes(kp.public().as_ref()).unwrap();
    assert!(external_pk.verify(MSG, &high_sig_external).is_ok());
}

#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();
    let mut privkey_memory_before_drop = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Secp384r1KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        // The in-memory representation of the private key before it is dropped.
        privkey_memory_before_drop.extend_from_slice(unsafe {
            std::slice::from_raw_parts(ptr, SECP384R1_PRIVATE_KEY_LENGTH)
        });

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, SECP384R1_PRIVATE_KEY_LENGTH) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that the memory of self.privkey has been overwritten. Contrary to the corresponding
    // test for secp256r1, we do not check for an exact pattern here because the in-memory
    // representation of a p384 scalar is an implementation detail of the p384 crate.
    let privkey_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(ptr, SECP384R1_PRIVATE_KEY_LENGTH) };
    assert_ne!(privkey_memory, &privkey_memory_before_drop[..]);

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, SECP384R1_PRIVATE_KEY_LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn wycheproof_test() {
    // Wycheproof does not have a test set for secp384r1 with SHA-256, so we use the SHA-384 and
    // SHA-512 sets.
    run_wycheproof_test(TestName::EcdsaSecp384r1Sha384);
    run_wycheproof_test(TestName::EcdsaSecp384r1Sha512);
}

fn run_wycheproof_test(test_name: TestName) {
    let test_set = TestSet::load(test_name).unwrap();
    for test_group in test_set.test_groups {
        let pk = Secp384r1PublicKey::from_bytes(&test_group.key.key).unwrap();
        let external_pk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&test_group.key.key).unwrap();
        for test in test_group.tests {
            let signature = match Signature::from_der(&test.sig) {
                Ok(s) => Secp384r1Signature::from_bytes(s.to_bytes().as_slice()).unwrap(),
                Err(_) => {
                    assert_eq!(map_result(test.result), TestResult::Invalid);
                    continue;
                }
            };

            let our_result = match test_name {
                TestName::EcdsaSecp384r1Sha384 => pk.verify(&test.msg, &signature),
                TestName::EcdsaSecp384r1Sha512 => {
                    pk.verify_with_hash::<Sha512, 64>(&test.msg, &signature)
                }
                _ => panic!("Unsupported test set"),
            };

            // This implementation accepts exactly the same signatures as the p384 crate.
            let external_digest = match test_name {
                TestName::EcdsaSecp384r1Sha384 => Sha384::digest(&test.msg).to_vec(),
                TestName::EcdsaSecp384r1Sha512 => Sha512::digest(&test.msg).to_vec(),
                _ => panic!("Unsupported test set"),
            };
            let external_result = external_pk.verify_prehash(&external_digest, &signature.sig);
            assert_eq!(
                our_result.is_ok(),
                external_result.is_ok(),
                "{}",
                test.comment
            );

            let expected = map_result(test.result);
            let actual = if our_result.is_ok() {
                TestResult::Valid
            } else {
                TestResult::Invalid
            };
            assert_eq!(expected, actual, "{}", test.comment);
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
fn test_rfc6979_vectors() {
    // Test vectors from RFC 6979, appendix A.2.6 (ECDSA over P-384 with SHA-384).
    let sk = Secp384r1PrivateKey::from_bytes(&hex::decode("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5").unwrap()).unwrap();
    let kp = Secp384r1KeyPair::from(sk);

    let sig = kp.sign(b"sample");
    assert_eq!(hex::encode(sig.as_ref()).to_uppercase(), "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE4699EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8");

    let sig = kp.sign(b"test");
    assert_eq!(hex::encode(sig.as_ref()).to_uppercase(), "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DBDDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5");
}

#[test]
fn test_sign_matches_p384_crate() {
    // The signatures produced by this implementation are identical to those produced by the p384
    // crate on the same inputs.
    let messages: [&[u8]; 4] = [b"Hello, world!", b"", &[0u8; 100], &[0xffu8; 48]];
    for kp in keys() {
        let external_sk = p384::ecdsa::SigningKey::from_slice(kp.as_ref()).unwrap();
        for msg in messages {
            let signature = kp.sign(msg);
            let external_sig: Signature = external_sk.sign(msg);
            assert_eq!(signature.as_ref(), external_sig.to_bytes().as_slice());
        }
    }
}

#[test]
fn test_verify_signature_from_p384_crate() {
    // Signatures produced by the p384 crate are accepted by this implementation and vice versa.
    let kp = keys().pop().unwrap();
    let external_sk = p384::ecdsa::SigningKey::from_slice(kp.as_ref()).unwrap();
    let external_pk = p384::ecdsa::VerifyingKey::from(&external_sk);

    let external_sig: Signature = external_sk.sign(MSG);
    let signature = Secp384r1Signature::from_bytes(external_sig.to_bytes().as_slice()).unwrap();
    assert!(kp.public().verify(MSG, &signature).is_ok());

    let signature = kp.sign(MSG);
    let external_sig = Signature::from_slice(signature.as_ref()).unwrap();
    assert!(external_pk.verify(MSG, &external_sig).is_ok());
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Secp384r1PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for Secp384r1PrivateKey>"
        );
    });
}

#[test]
fn test_public_key_and_signature_lengths() {
    let kp = keys().pop().unwrap();
    assert_eq!(kp.public().as_ref().len(), SECP384R1_PUBLIC_KEY_LENGTH);
    assert_eq!(kp.as_ref().len(), SECP384R1_PRIVATE_KEY_LENGTH);
    let sig = kp.sign(MSG);
    assert_eq!(sig.as_ref().len(), SECP384R1_SIGNATURE_LENGTH);
}

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = Secp384r1KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Secp384r1KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Secp384r1KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn test_equivalence_to_p384_crate(
        kp in arb_keypair(),
        msg in any::<Vec<u8>>(),
    ){
        // Sign and verify with this implementation.
        let signature = kp.sign(&msg);
        assert!(kp.public().verify(&msg, &signature).is_ok());

        // The p384 crate produces an identical signature and accepts ours.
        let external_sk = p384::ecdsa::SigningKey::from_slice(kp.as_ref()).unwrap();
        let external_pk = p384::ecdsa::VerifyingKey::from(&external_sk);
        let external_sig: Signature = external_sk.sign(&msg);
        assert_eq!(signature.as_ref(), external_sig.to_bytes().as_slice());
        assert!(external_pk.verify(&msg, &external_sig).is_ok());

        // A modified signature is rejected by both implementations.
        let mut modified = <[u8; 96]>::try_from(signature.as_ref()).unwrap();
        modified[0] ^= 1;
        if let Ok(modified_sig) = <Secp384r1Signature as ToFromBytes>::from_bytes(&modified) {
            assert!(kp.public().verify(&msg, &modified_sig).is_err());
            assert!(external_pk.verify(&msg, &modified_sig.sig).is_err());
        }
    }
}
