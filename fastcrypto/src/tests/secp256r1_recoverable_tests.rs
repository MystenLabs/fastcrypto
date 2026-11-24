// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ecdsa::RecoveryId;
use once_cell::sync::Lazy;
use p256::ecdsa::Signature;
use p256::elliptic_curve::bigint::ArrayEncoding;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::scalar::IsHigh;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::Curve;
use p256::{NistP256, Scalar, U256};
use proptest::collection;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest::{prelude::*, strategy::Strategy};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use wycheproof::ecdsa::TestName;

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::hash::{Blake2b256, HashFunction, Keccak256, Sha256, Sha3_256};
use crate::secp256r1::recoverable::{
    Secp256r1RecoverableSignature, SECP256R1_RECOVERABLE_SIGNATURE_LENGTH,
};
use crate::secp256r1::{Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature};
use crate::secp256r1_tests::{
    add_small, check_wycheproof, is_high_s, keys, negate_s, p256_verify, GROUP_ORDER, HONEST_KEYS,
    MESSAGES, MSG, RFC6979_PRIVATE_KEY, RFC6979_PUBLIC_KEY, RFC6979_SHA256_SIGNATURES, SIG_LENGTH,
};
use crate::test_helpers::verify_serialization;
use crate::traits::{
    KeyPair, RecoverableSignature, RecoverableSigner, Signer, ToFromBytes, VerifyRecoverable,
    VerifyingKey,
};

//
// Helper functions
//

const RECOVERABLE_SIG_LENGTH: usize = SECP256R1_RECOVERABLE_SIGNATURE_LENGTH;

/// p - n, big-endian. Recovery ids 2 and 3 say that x(R) = r + n, which is only an x-coordinate
/// if r < p - n.
const FIELD_MODULUS_MINUS_ORDER: [u8; 32] =
    hex_literal::hex!("000000000000000000000000000000004319055358e8617b0c46353d039cdaae");

/// 2^256 - n, big-endian. With recovery id 2 or 3, r + n overflows 256 bits iff r >= 2^256 - n.
const ORDER_COMPLEMENT: [u8; 32] =
    hex_literal::hex!("00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf");

/// The signature r = 3, s = 1. x = n + 3 is the smallest x-coordinate on the curve that is at
/// least n, so with recovery id 2 or 3 this signature recovers a key: the one for which it is the
/// signature with nonce point R = (n + 3, y). Honest signers essentially never have such an R.
const CRAFTED_SIGNATURE: [u8; SIG_LENGTH] = hex_literal::hex!(
    "00000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001"
);

/// The keys that `CRAFTED_SIGNATURE` recovers on `MSG` with SHA-256 and recovery ids 2 and 3.
const CRAFTED_RECOVERED_KEYS: [[u8; 33]; 2] = [
    hex_literal::hex!("0285dc02d700fb5627abc211f5fba32140b25f37220205bd997df4d77c51fe7c14"),
    hex_literal::hex!("028f0c3940cc61790f9a84d2bed73a8a2d038ef0aff3d57412c8f5d158327c56a8"),
];

/// The recoverable signatures of `HONEST_KEYS[i]` on `MESSAGES[j]`, for the proptests.
static HONEST_RECOVERABLE_SIGNATURES: Lazy<Vec<Vec<Vec<u8>>>> = Lazy::new(|| {
    HONEST_KEYS
        .iter()
        .map(|kp| {
            MESSAGES
                .iter()
                .map(|msg| kp.sign_recoverable(msg).as_bytes().to_vec())
                .collect()
        })
        .collect()
});

/// Recovery with the ecdsa crate, an independent implementation, of the compressed public key
/// from a 65-byte recoverable signature on the message hashed with `H`.
fn ecdsa_recover<H: HashFunction<32>>(signature: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let recovery_id = RecoveryId::from_byte(signature[SIG_LENGTH])?;
    let signature = Signature::from_slice(&signature[..SIG_LENGTH]).ok()?;
    let pk = p256::ecdsa::VerifyingKey::recover_from_prehash(
        &H::digest(msg).digest,
        &signature,
        recovery_id,
    )
    .ok()?;
    Some(pk.to_encoded_point(true).as_bytes().to_vec())
}

//
// Serialization tests
//

#[test]
fn serialize_deserialize() {
    // The other types (pk, sk, keypair) are tested in the nonrecoverable tests.
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    verify_serialization(&sig, Some(sig.as_bytes()));
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
fn test_public_key_recovery_error() {
    // incorrect length
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&[0u8; 1]).is_err());

    // Invalid signature: Zeros in signatures are not allowed
    assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(
        &[0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH]
    )
    .is_err());

    // Only 65 bytes are accepted, and the recovery id must be in 0..=3 (so 27 and 28, as in
    // Ethereum, are rejected). r and s must be in [1, n - 1]: verification (split_scalars) panics if
    // r or s is zero.
    let honest = keys().pop().unwrap().sign_recoverable(MSG);
    for len in [0, SIG_LENGTH, RECOVERABLE_SIG_LENGTH + 1] {
        let mut bytes = honest.as_bytes().to_vec();
        bytes.resize(len, 0);
        assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).is_err());
    }
    for recovery_id in 0..=u8::MAX {
        let mut bytes = honest.as_bytes().to_vec();
        bytes[SIG_LENGTH] = recovery_id;
        let decoded = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes);
        assert_eq!(decoded.is_ok(), recovery_id <= 3);
        if let Ok(decoded) = decoded {
            assert_eq!(decoded.as_bytes(), bytes);
        }
    }
    for offset in [0, 32] {
        for value in [[0; 32], GROUP_ORDER, [0xff; 32]] {
            let mut bytes = honest.as_bytes().to_vec();
            bytes[offset..offset + 32].copy_from_slice(&value);
            assert!(<Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).is_err());
        }
    }
}

//
// Signature verification tests
//

#[test]
fn test_public_key_recovery() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature: Secp256r1RecoverableSignature = kp.sign_recoverable(message);
    let recovered_key = signature.recover(message).unwrap();
    assert_eq!(recovered_key, *kp.public());
}

#[test]
fn verify_invalid_signature() {
    let kp = keys().pop().unwrap();
    let signature = kp.sign_recoverable(MSG);
    assert!(kp.public().verify_recoverable(MSG, &signature).is_ok());

    // Another message or another key fails.
    assert!(kp
        .public()
        .verify_recoverable(b"Bad message!", &signature)
        .is_err());
    assert!(keys()[0]
        .public()
        .verify_recoverable(MSG, &signature)
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
    let mut normalized_bytes = normalized.to_bytes().to_vec();
    normalized_bytes.push(0);
    let normalized_sig =
        <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&normalized_bytes).unwrap();

    // Verify with normalized lower S.
    assert!(pk
        .verify_recoverable(&digest.digest, &normalized_sig)
        .is_ok());
}

#[test]
fn recover_with_hash_functions() {
    // The Move native secp256r1_ecrecover recovers with Keccak-256 (hash = 0) or SHA-256 (hash =
    // 1), with the current or, before a protocol flag, the legacy recovery. Both agree with the
    // ecdsa crate here.
    for kp in keys() {
        let pk = kp.public();
        let sha256 = kp.sign_recoverable_with_hash::<Sha256>(MSG);
        let keccak256 = kp.sign_recoverable_with_hash::<Keccak256>(MSG);
        assert_eq!(kp.sign_recoverable(MSG).as_bytes(), sha256.as_bytes());
        assert_eq!(
            &sha256.as_bytes()[..SIG_LENGTH],
            kp.sign_with_hash::<Sha256>(MSG).as_bytes()
        );
        assert_eq!(
            &keccak256.as_bytes()[..SIG_LENGTH],
            kp.sign_with_hash::<Keccak256>(MSG).as_bytes()
        );

        assert_eq!(&sha256.recover_with_hash::<Sha256>(MSG).unwrap(), pk);
        assert_eq!(&sha256.recover_with_hash_legacy::<Sha256>(MSG).unwrap(), pk);
        assert_eq!(&keccak256.recover_with_hash::<Keccak256>(MSG).unwrap(), pk);
        assert_eq!(
            &keccak256
                .recover_with_hash_legacy::<Keccak256>(MSG)
                .unwrap(),
            pk
        );
        assert_eq!(
            ecdsa_recover::<Sha256>(sha256.as_bytes(), MSG).unwrap(),
            pk.as_bytes()
        );
        assert_eq!(
            ecdsa_recover::<Keccak256>(keccak256.as_bytes(), MSG).unwrap(),
            pk.as_bytes()
        );

        // With the other hash function, another key or none is recovered.
        assert_ne!(
            sha256.recover_with_hash::<Keccak256>(MSG).ok().as_ref(),
            Some(pk)
        );
        assert_ne!(
            keccak256.recover_with_hash::<Sha256>(MSG).ok().as_ref(),
            Some(pk)
        );
        assert!(pk
            .verify_recoverable_with_hash::<Keccak256>(MSG, &sha256)
            .is_err());
    }
}

#[test]
fn recover_high_s_with_flipped_recovery_id() {
    // (r, n - s) is the signature for the nonce point -R, so with the y-parity bit of the recovery
    // id flipped, it recovers the same key. Recovery does not require a low s, unlike verify, so
    // both signatures are accepted, as in the ecdsa crate and Ethereum's ecrecover.
    for kp in keys() {
        let honest = kp.sign_recoverable(MSG);
        let mut twin = negate_s(honest.as_bytes());
        twin[SIG_LENGTH] ^= 1;
        assert!(is_high_s(&twin));
        let twin_signature =
            <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&twin).unwrap();
        assert_eq!(&twin_signature.recover(MSG).unwrap(), kp.public());
        assert!(kp.public().verify_recoverable(MSG, &twin_signature).is_ok());
        assert_eq!(
            ecdsa_recover::<Sha256>(&twin, MSG).unwrap(),
            kp.public().as_bytes()
        );

        // The signature it contains is rejected by verify.
        assert!(kp
            .public()
            .verify(MSG, &Secp256r1Signature::from(&twin_signature))
            .is_err());
    }

    // Likewise for the RFC 6979 signature on "sample", whose s is high.
    let (msg, rfc_signature) = RFC6979_SHA256_SIGNATURES[0];
    let mut bytes = rfc_signature.to_vec();
    bytes.push(0);
    let signature = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).unwrap();
    assert_eq!(
        signature.recover(msg).unwrap().as_bytes(),
        RFC6979_PUBLIC_KEY
    );
}

#[test]
fn recover_with_recovery_ids_2_and_3() {
    // With recovery ids 0 and 1, x(R) = r = 3, which is not an x-coordinate on the curve. With 2
    // and 3, x(R) = n + 3, and the recovered keys are those of the ecdsa crate. The signature then
    // verifies under the recovered key, which tests verification for x(R) >= n.
    for recovery_id in 0..4 {
        let mut bytes = CRAFTED_SIGNATURE.to_vec();
        bytes.push(recovery_id);
        let signature = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).unwrap();
        let recovered = signature.recover(MSG);
        assert_eq!(
            recovered.as_ref().ok().map(|pk| pk.as_bytes().to_vec()),
            ecdsa_recover::<Sha256>(&bytes, MSG)
        );
        if recovery_id < 2 {
            assert!(recovered.is_err());
            continue;
        }
        let pk = recovered.unwrap();
        assert_eq!(
            pk.as_bytes(),
            CRAFTED_RECOVERED_KEYS[recovery_id as usize - 2]
        );
        assert_eq!(
            signature.recover_with_hash_legacy::<Sha256>(MSG).unwrap(),
            pk
        );
        assert!(pk
            .verify(MSG, &Secp256r1Signature::from(&signature))
            .is_ok());
        assert!(p256_verify::<Sha256>(
            pk.as_bytes(),
            MSG,
            &CRAFTED_SIGNATURE
        ));
    }
}

#[test]
fn recover_fails_if_key_is_identity() {
    // With R = k G, r = x(R) and s = z / k, where z is the hash of the message, the recovered key
    // r^-1 (s R - z G) is the identity, which is not a public key.
    let k = Scalar::from(7u64);
    let big_r = (p256::ProjectivePoint::GENERATOR * k)
        .to_affine()
        .to_encoded_point(false);
    let r = <Scalar as Reduce<U256>>::reduce_bytes(big_r.x().unwrap());
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&Sha256::digest(MSG).digest.into());
    let s = z * k.invert().unwrap();
    let mut bytes = Signature::from_scalars(r, s).unwrap().to_bytes().to_vec();
    bytes.push(big_r.y().unwrap()[31] & 1);
    let signature = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).unwrap();
    assert!(signature.recover(MSG).is_err());
    assert!(signature.recover_with_hash_legacy::<Sha256>(MSG).is_err());
    assert_eq!(ecdsa_recover::<Sha256>(&bytes, MSG), None);

    // With -R instead, the key is r^-1 (-s R - z G) = -2 z r^-1 G, which is not the identity.
    bytes[SIG_LENGTH] ^= 1;
    let signature = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).unwrap();
    assert!(signature.recover(MSG).is_ok());
}

// Shift r by 2^256 - n and set the x-reduced bit: r + n wraps back to x(R), so legacy
// recovery returns a key for the wrong r. Current recovery rejects it.
#[test]
fn legacy_recovery_accepts_wrapped_r() {
    let kp = keys().pop().unwrap();
    let msg = b"Hello, world!";
    let honest = kp.sign_recoverable(msg);

    let mut bytes = [0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH];
    bytes.copy_from_slice(honest.as_ref());
    let r = U256::from_be_slice(&bytes[..32]);
    let shifted = r.wrapping_add(&U256::ZERO.wrapping_sub(&NistP256::ORDER));
    assert!(shifted > r && shifted < NistP256::ORDER);
    bytes[..32].copy_from_slice(&shifted.to_be_byte_array());
    bytes[64] |= 2;
    let wrapped = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).unwrap();

    assert_eq!(
        &honest.recover_with_hash_legacy::<Sha256>(msg).unwrap(),
        kp.public()
    );

    assert_eq!(
        wrapped.recover(msg).unwrap_err(),
        FastCryptoError::InvalidSignature
    );
    let legacy_pk = wrapped.recover_with_hash_legacy::<Sha256>(msg).unwrap();
    assert_ne!(&legacy_pk, kp.public());
    assert!(legacy_pk
        .verify(msg, &Secp256r1Signature::from(&wrapped))
        .is_err());
}

// Lets put r + n in [p, 2^256): it fits in 256 bits but is no field element. Strict recovery
// rejects it at the bound check, legacy recovery when decompression fails.
#[test]
fn recovery_rejects_x_at_or_above_p() {
    let kp = keys().pop().unwrap();
    let msg = b"Hello, world!";
    let honest = kp.sign_recoverable(msg);

    let mut bytes = [0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH];
    bytes.copy_from_slice(honest.as_ref());
    let p = U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    // r = (p - n) + (r mod 2^223) keeps r < n and r + n < p + 2^223 < 2^256.
    let low =
        U256::from_be_slice(&bytes[..32]) & (U256::ONE.shl_vartime(223).wrapping_sub(&U256::ONE));
    let shifted = p.wrapping_sub(&NistP256::ORDER).wrapping_add(&low);
    assert!(shifted < NistP256::ORDER);
    bytes[..32].copy_from_slice(&shifted.to_be_byte_array());
    bytes[64] |= 2;
    let sig = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).unwrap();

    assert_eq!(
        sig.recover(msg).unwrap_err(),
        FastCryptoError::InvalidSignature
    );
    assert!(sig.recover_with_hash_legacy::<Sha256>(msg).is_err());
}

#[test]
fn rfc6979_test_vectors_recoverable() {
    // The recoverable signature is the normalized signature of RFC 6979, A.2.5, followed by the
    // recovery id, and it recovers the RFC's public key.
    let kp = Secp256r1KeyPair::from_bytes(&RFC6979_PRIVATE_KEY).unwrap();
    for ((msg, _), recovery_id) in RFC6979_SHA256_SIGNATURES.iter().zip([1, 0]) {
        let signature = kp.sign_recoverable(msg);
        assert_eq!(&signature.as_bytes()[..SIG_LENGTH], kp.sign(msg).as_bytes());
        assert_eq!(signature.recovery_id, recovery_id);
        assert_eq!(
            signature.recover(msg).unwrap().as_bytes(),
            RFC6979_PUBLIC_KEY
        );
    }
}

#[test]
fn wycheproof_test() {
    // Wycheproof gives no recovery id, so a signature is accepted if it recovers the key with one of
    // them. Recovery accepts a high s, so all valid signatures are accepted.
    fn verify<H: HashFunction<32>>(pk: &Secp256r1PublicKey, msg: &[u8], signature: &[u8]) -> bool {
        (0..4).any(|recovery_id| {
            let mut bytes = signature.to_vec();
            bytes.push(recovery_id);
            <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes).is_ok_and(
                |signature| {
                    pk.verify_recoverable_with_hash::<H>(msg, &signature)
                        .is_ok()
                },
            )
        })
    }
    assert_eq!(
        check_wycheproof(
            TestName::EcdsaSecp256r1Sha256,
            false,
            true,
            verify::<Sha256>
        ),
        (174, 71)
    );
    assert_eq!(
        check_wycheproof(
            TestName::EcdsaSecp256r1Sha256P1363,
            true,
            true,
            verify::<Sha256>
        ),
        (173, 70)
    );
    assert_eq!(
        check_wycheproof(
            TestName::EcdsaSecp256r1Sha3_256,
            false,
            true,
            verify::<Sha3_256>
        ),
        (178, 75)
    );
}

#[test]
fn test_recoverable_nonrecoverable_conversion() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign_recoverable(message);
    assert!(kp.public().verify_recoverable(message, &signature).is_ok());

    let nonrecoverable_signature = Secp256r1Signature::from(&signature);
    assert!(kp
        .public()
        .verify(message, &nonrecoverable_signature)
        .is_ok());
}

//
// Other tests
//

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
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

//
// Proptests
//

/// One of the honest recoverable signatures, as (key index, message index, signature).
fn arb_honest_recoverable_signature() -> impl Strategy<Value = (usize, usize, Vec<u8>)> {
    (0..HONEST_KEYS.len(), 0..MESSAGES.len())
        .prop_map(|(i, j)| (i, j, HONEST_RECOVERABLE_SIGNATURES[i][j].clone()))
}

/// Values of r around the bounds for recovery ids 2 and 3 (p - n and 2^256 - n), 3 (see
/// `CRAFTED_SIGNATURE`), small values for which r + n is often an x-coordinate, the bounds of
/// [1, n - 1] and arbitrary values.
fn arb_r_bytes() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        Just(CRAFTED_SIGNATURE[..32].try_into().unwrap()),
        (-2i64..=1).prop_map(|delta| add_small(&FIELD_MODULUS_MINUS_ORDER, delta)),
        (-2i64..=1).prop_map(|delta| add_small(&ORDER_COMPLEMENT, delta)),
        any::<[u8; 16]>().prop_map(|low| {
            let mut bytes = [0; 32];
            bytes[16..].copy_from_slice(&low);
            bytes
        }),
        Just([0; 32]),
        Just(GROUP_ORDER),
        any::<[u8; 32]>(),
    ]
}

/// Recoverable signatures with the key and message to recover them with: honest signatures,
/// other recovery ids, high-s twins with and without the recovery id flipped, r or s replaced,
/// bit flips, other lengths and arbitrary bytes.
fn arb_recoverable_input() -> impl Strategy<Value = (usize, usize, Vec<u8>)> {
    prop_oneof![
        2 => arb_honest_recoverable_signature(),
        1 => (arb_honest_recoverable_signature(), prop_oneof![0..4u8, any::<u8>()]).prop_map(
            |((i, j, mut signature), recovery_id)| {
                signature[SIG_LENGTH] = recovery_id;
                (i, j, signature)
            }
        ),
        1 => (arb_honest_recoverable_signature(), any::<bool>()).prop_map(
            |((i, j, signature), flip)| {
                let mut twin = negate_s(&signature);
                twin[SIG_LENGTH] ^= flip as u8;
                (i, j, twin)
            }
        ),
        1 => (arb_honest_recoverable_signature(), 0..MESSAGES.len())
            .prop_map(|((i, _, signature), j)| (i, j, signature)),
        2 => (arb_honest_recoverable_signature(), arb_r_bytes(), 0..4u8).prop_map(
            |((i, j, mut signature), r, recovery_id)| {
                signature[..32].copy_from_slice(&r);
                signature[SIG_LENGTH] = recovery_id;
                (i, j, signature)
            }
        ),
        1 => (arb_honest_recoverable_signature(), any::<[u8; 32]>()).prop_map(
            |((i, j, mut signature), s)| {
                signature[32..SIG_LENGTH].copy_from_slice(&s);
                (i, j, signature)
            }
        ),
        1 => (arb_honest_recoverable_signature(), 0..RECOVERABLE_SIG_LENGTH * 8).prop_map(
            |((i, j, mut signature), bit)| {
                signature[bit / 8] ^= 1 << (bit % 8);
                (i, j, signature)
            }
        ),
        1 => (arb_honest_recoverable_signature(), 0..2 * RECOVERABLE_SIG_LENGTH).prop_map(
            |((i, j, mut signature), len)| {
                signature.resize(len, 0);
                (i, j, signature)
            }
        ),
        1 => (
            0..HONEST_KEYS.len(),
            0..MESSAGES.len(),
            collection::vec(any::<u8>(), RECOVERABLE_SIG_LENGTH)
        ),
    ]
}

proptest! {
    #[test]
    fn test_recover_adversarial_signatures((i, j, bytes) in arb_recoverable_input()) {
        let pk = HONEST_KEYS[i].public();
        let msg = MESSAGES[j];

        // Decoding accepts exactly 65 bytes r || s || v with r and s in [1, n - 1] and v <= 3.
        let decoded = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes);
        prop_assert_eq!(
            decoded.is_ok(),
            bytes.len() == RECOVERABLE_SIG_LENGTH
                && bytes[SIG_LENGTH] <= 3
                && Signature::from_slice(&bytes[..SIG_LENGTH]).is_ok()
        );
        let Ok(signature) = decoded else {
            return Ok(());
        };
        prop_assert_eq!(signature.as_bytes(), &bytes[..]);

        // Recovery agrees with the ecdsa crate, and verify_recoverable compares the recovered key.
        let recovered = signature.recover(msg);
        prop_assert_eq!(
            recovered.as_ref().ok().map(|pk| pk.as_bytes().to_vec()),
            ecdsa_recover::<Sha256>(&bytes, msg)
        );
        let recovers_pk = recovered.as_ref().is_ok_and(|recovered| recovered == pk);
        prop_assert_eq!(pk.verify_recoverable(msg, &signature).is_ok(), recovers_pk);

        // The inputs never sign with the honest keys, so only the honest signature and its high-s
        // twin with the other recovery id recover the key.
        if recovers_pk {
            let honest = &HONEST_RECOVERABLE_SIGNATURES[i][j];
            let mut twin = negate_s(honest);
            twin[SIG_LENGTH] ^= 1;
            prop_assert!(&bytes == honest || bytes == twin);
        }

        // Legacy recovery differs only if r + n overflows 256 bits for recovery ids 2 and 3.
        let overflows = bytes[SIG_LENGTH] >= 2 && bytes[..32] >= ORDER_COMPLEMENT[..];
        if !overflows {
            prop_assert_eq!(signature.recover_with_hash_legacy::<Sha256>(msg).ok(), recovered.ok());
        }
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // A good part of the adversarial inputs above decode and recover a key, some of them with
    // recovery ids 2 and 3 and some the signer's key.
    const SAMPLES: usize = 500;
    let mut runner = TestRunner::deterministic();
    let (mut decoded, mut recovered, mut recovered_x_reduced, mut recovered_signer) = (0, 0, 0, 0);
    for _ in 0..SAMPLES {
        let (i, j, bytes) = arb_recoverable_input()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let Ok(signature) = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(&bytes)
        else {
            continue;
        };
        decoded += 1;
        let Ok(pk) = signature.recover(MESSAGES[j]) else {
            continue;
        };
        recovered += 1;
        recovered_x_reduced += (signature.recovery_id >= 2) as usize;
        recovered_signer += (&pk == HONEST_KEYS[i].public()) as usize;
    }
    println!("decoded {decoded}, recovered {recovered}, with recovery id 2 or 3 {recovered_x_reduced}, signer {recovered_signer}");
    assert!(decoded > SAMPLES / 2, "{decoded}");
    assert!(recovered > SAMPLES / 3, "{recovered}");
    assert!(recovered_x_reduced > SAMPLES / 100, "{recovered_x_reduced}");
    assert!(recovered_signer > SAMPLES / 10, "{recovered_signer}");
}
