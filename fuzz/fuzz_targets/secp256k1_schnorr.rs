// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! BIP-340 Schnorr signatures from `groups::secp256k1::schnorr`, which Hashi uses to decode and
//! verify signatures from other validators. Public keys, signatures and private keys are decoded
//! from bytes (raw, BCS and JSON), and signing and verification are compared with libsecp256k1.
//! The inputs are arbitrary, or derived from an honest signature by a key from the input: a byte
//! changed, r or s replaced (by values near p and n, or r by the x-coordinate of another point),
//! s negated or changed by a small amount, another public key or another message.
//!
//! Invariants: nothing panics; public keys decode iff libsecp256k1 parses them as x-only keys, and
//! round trip; private keys decode iff they are in [1, n - 1] and give libsecp256k1's public key;
//! decoded signatures round trip; BCS and JSON agree with the byte decoders; decoding and verifying
//! accepts exactly what libsecp256k1 accepts; signing with 32 bytes of auxiliary randomness gives
//! libsecp256k1's signature.

#![no_main]

#[path = "secp256k1_group_common.rs"]
mod secp256k1_group_common;

use arbitrary::Arbitrary;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::groups::secp256k1::schnorr::{
    SchnorrPrivateKey, SchnorrPublicKey, SchnorrSignature,
};
use fastcrypto::serde_helpers::ToFromByteArray;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use secp256k1_group_common::{add_small, FIELD_MODULUS, GROUP_ORDER};
use serde::de::DeserializeOwned;

/// A libsecp256k1 context, checked once against BIP-340 test vector 0 to make sure that the
/// cryptography is real.
static SECP: Lazy<Secp256k1<secp256k1::All>> = Lazy::new(|| {
    let secp = Secp256k1::new();
    let public_key =
        hex_literal::hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    let mut signature = hex_literal::hex!("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
    assert!(libsecp256k1_verifies(
        &secp,
        &public_key,
        &[0; 32],
        &signature
    ));
    signature[63] ^= 1;
    assert!(!libsecp256k1_verifies(
        &secp,
        &public_key,
        &[0; 32],
        &signature
    ));
    secp
});

#[derive(Arbitrary, Debug)]
enum PublicKeyInput {
    /// The public key of the signer.
    Signer,
    Raw([u8; 32]),
}

#[derive(Arbitrary, Debug)]
enum SignatureInput {
    Honest,
    Raw([u8; 64]),
    /// The honest signature with a byte (by index) xored.
    ChangedByte(u8, u8),
    R([u8; 32]),
    S([u8; 32]),
    /// n - s.
    NegateS,
    /// s + d modulo n.
    SPlusSmall(i8),
    /// s = n + d, so s >= n for d >= 0.
    SNearOrder(i8),
    /// r = p + d, so r >= p for d >= 0, and r = p - 3 is on the curve.
    RNearModulus(i8),
    /// r replaced by the x-coordinate of k * G, which is on the curve.
    RFromMultiple(u64),
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// A secret key that is not in [1, n - 1] is replaced by 1 for signing.
    secret_key: [u8; 32],
    message: Vec<u8>,
    aux_rand: [u8; 32],
    public_key: PublicKeyInput,
    signature: SignatureInput,
    /// Verify on another message.
    other_message: Option<Vec<u8>>,
}

fn libsecp256k1_verifies(
    secp: &Secp256k1<secp256k1::All>,
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    XOnlyPublicKey::from_byte_array(*public_key).is_ok_and(|pk| {
        secp.verify_schnorr(
            &secp256k1::schnorr::Signature::from_byte_array(*signature),
            message,
            &pk,
        )
        .is_ok()
    })
}

/// Checks that BCS and JSON decode the same values as `from_byte_array`, compared by encoding.
fn check_serde<T, const N: usize>(bytes: &[u8; N], decoded: &Option<[u8; N]>)
where
    T: ToFromByteArray<N> + DeserializeOwned,
{
    let bcs = bcs::from_bytes::<T>(bytes).ok().map(|t| t.to_byte_array());
    assert_eq!(&bcs, decoded);
    let json = serde_json::to_string(&Base64::encode(bytes)).unwrap();
    let json = serde_json::from_str::<T>(&json)
        .ok()
        .map(|t| t.to_byte_array());
    assert_eq!(&json, decoded);
}

fuzz_target!(|input: Input| {
    let secp = &*SECP;

    // Private keys.
    let sk = SchnorrPrivateKey::from_byte_array(&input.secret_key);
    let expected_key = SecretKey::from_byte_array(input.secret_key).ok();
    assert_eq!(sk.is_ok(), expected_key.is_some());
    check_serde::<SchnorrPrivateKey, 32>(
        &input.secret_key,
        &sk.as_ref().ok().map(|sk| sk.to_byte_array()),
    );
    let (sk, expected_key) = match (sk, expected_key) {
        (Ok(sk), Some(expected_key)) => (sk, expected_key),
        _ => {
            let mut one = [0; 32];
            one[31] = 1;
            (
                SchnorrPrivateKey::from_byte_array(&one).unwrap(),
                SecretKey::from_byte_array(one).unwrap(),
            )
        }
    };
    let key_pair = Keypair::from_secret_key(secp, &expected_key);
    let signer = SchnorrPublicKey::from(&sk).to_byte_array();
    assert_eq!(signer, key_pair.x_only_public_key().0.serialize());

    // Signing.
    let honest = sk
        .sign(&input.message, &input.aux_rand)
        .unwrap()
        .to_byte_array();
    let expected = secp.sign_schnorr_with_aux_rand(&input.message, &key_pair, &input.aux_rand);
    assert_eq!(honest, expected.to_byte_array());

    // Public keys.
    let public_key = match input.public_key {
        PublicKeyInput::Signer => signer,
        PublicKeyInput::Raw(bytes) => bytes,
    };
    let pk = SchnorrPublicKey::from_byte_array(&public_key);
    assert_eq!(
        pk.is_ok(),
        XOnlyPublicKey::from_byte_array(public_key).is_ok()
    );
    let pk_bytes = pk.as_ref().ok().map(|pk| pk.to_byte_array());
    assert!(pk_bytes.is_none_or(|bytes| bytes == public_key));
    check_serde::<SchnorrPublicKey, 32>(&public_key, &pk_bytes);

    // Signatures.
    let mut signature = honest;
    match input.signature {
        SignatureInput::Honest => {}
        SignatureInput::Raw(bytes) => signature = bytes,
        SignatureInput::ChangedByte(index, xor) => signature[index as usize % 64] ^= xor,
        SignatureInput::R(r) => signature[..32].copy_from_slice(&r),
        SignatureInput::S(s) => signature[32..].copy_from_slice(&s),
        SignatureInput::NegateS => {
            let s = k256::Scalar::from_repr(<[u8; 32]>::try_from(&honest[32..]).unwrap().into())
                .unwrap();
            signature[32..].copy_from_slice(&(-s).to_bytes());
        }
        SignatureInput::SPlusSmall(delta) => {
            let s = k256::Scalar::from_repr(<[u8; 32]>::try_from(&honest[32..]).unwrap().into())
                .unwrap();
            let d = k256::Scalar::from(delta.unsigned_abs() as u64);
            let s = if delta >= 0 { s + d } else { s - d };
            signature[32..].copy_from_slice(&s.to_bytes());
        }
        SignatureInput::SNearOrder(delta) => {
            signature[32..].copy_from_slice(&add_small(&GROUP_ORDER, delta))
        }
        SignatureInput::RNearModulus(delta) => {
            signature[..32].copy_from_slice(&add_small(&FIELD_MODULUS, delta))
        }
        SignatureInput::RFromMultiple(k) => {
            let point = (k256::ProjectivePoint::GENERATOR * k256::Scalar::from(k)).to_affine();
            if let Some(x) = point.to_encoded_point(true).x() {
                signature[..32].copy_from_slice(x);
            }
        }
    }
    let sig = SchnorrSignature::from_byte_array(&signature);
    let sig_bytes = sig.as_ref().ok().map(|sig| sig.to_byte_array());
    assert!(sig_bytes.is_none_or(|bytes| bytes == signature));
    check_serde::<SchnorrSignature, 64>(&signature, &sig_bytes);

    // Verification.
    let message = input.other_message.as_ref().unwrap_or(&input.message);
    let verifies = match (&pk, &sig) {
        (Ok(pk), Ok(sig)) => pk.verify(message, sig).is_ok(),
        _ => false,
    };
    assert_eq!(
        verifies,
        libsecp256k1_verifies(secp, &public_key, message, &signature)
    );
});
