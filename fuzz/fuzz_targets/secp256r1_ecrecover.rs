// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Recovers public keys from (signature, message, hash function) inputs the way Sui's
//! `ecdsa_r1::secp256r1_ecrecover` Move native does: `from_bytes` for the 65-byte signature, then
//! `recover_with_hash` (or `recover_with_hash_legacy` before the protocol flag
//! `secp256r1_ecrecover_checks_x_below_p`) with Keccak-256 for flag 0 and SHA-256 for flag 1,
//! returning the compressed key. The signature is either arbitrary bytes or derived from a fixed
//! key pair.
//!
//! Invariants: nothing panics; recovery agrees with the ecdsa crate; legacy recovery agrees with
//! it unless r + n overflows 256 bits; a recovered key is a valid compressed public key under which
//! the signature verifies once s is normalized (so the output of `secp256r1_ecrecover` is accepted
//! by `secp256r1_verify`); and the fixed key is only recovered from its own signature and that
//! signature's high-s form.

#![no_main]

#[path = "secp256r1_common.rs"]
mod secp256r1_common;

use arbitrary::Arbitrary;
use fastcrypto::hash::{Keccak256, Sha256};
use fastcrypto::secp256r1::recoverable::Secp256r1RecoverableSignature;
use fastcrypto::secp256r1::{Secp256r1PublicKey, Secp256r1Signature};
use fastcrypto::traits::{KeyPair, RecoverableSignature, RecoverableSigner, ToFromBytes};
use libfuzzer_sys::fuzz_target;
use secp256r1_common::{
    digest, ecdsa_recover, is_high_s, negate_s, SignatureInput, KECCAK256, KEY, ORDER_COMPLEMENT,
    RECOVERABLE_SIG_LENGTH, SHA256, SIG_LENGTH,
};

#[derive(Arbitrary, Debug)]
struct Input {
    signature: SignatureInput,
    msg: Vec<u8>,
    hash: u8,
}

/// The fixed key's recoverable signature, with SHA-256 for flags other than Keccak-256.
fn sign(msg: &[u8], hash: u8) -> Vec<u8> {
    match hash {
        KECCAK256 => KEY.sign_recoverable_with_hash::<Keccak256>(msg),
        _ => KEY.sign_recoverable_with_hash::<Sha256>(msg),
    }
    .as_bytes()
    .to_vec()
}

/// Replaces s by n - s and flips the recovery id, which recovers the same key.
fn high_s(signature: &[u8]) -> Vec<u8> {
    let mut bytes = negate_s(signature);
    bytes[SIG_LENGTH] ^= 1;
    bytes
}

/// What the secp256r1_ecrecover Move native does, with the current or the legacy recovery.
fn secp256r1_ecrecover(signature: &[u8], msg: &[u8], hash: u8, legacy: bool) -> Option<Vec<u8>> {
    let signature = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(signature).ok()?;
    let pk = match (hash, legacy) {
        (KECCAK256, false) => signature.recover_with_hash::<Keccak256>(msg),
        (SHA256, false) => signature.recover_with_hash::<Sha256>(msg),
        (KECCAK256, true) => signature.recover_with_hash_legacy::<Keccak256>(msg),
        (SHA256, true) => signature.recover_with_hash_legacy::<Sha256>(msg),
        _ => return None,
    };
    Some(pk.ok()?.as_bytes().to_vec())
}

/// Verification with the given hash function flag, as in the secp256r1_verify Move native.
fn verify(signature: &[u8], public_key: &Secp256r1PublicKey, msg: &[u8], hash: u8) -> bool {
    let signature = <Secp256r1Signature as ToFromBytes>::from_bytes(signature).unwrap();
    match hash {
        KECCAK256 => public_key
            .verify_with_hash::<Keccak256>(msg, &signature)
            .is_ok(),
        _ => public_key
            .verify_with_hash::<Sha256>(msg, &signature)
            .is_ok(),
    }
}

fuzz_target!(|input: Input| {
    let honest = sign(&input.msg, input.hash);
    let honest_high_s = high_s(&honest);
    let signature = input.signature.bytes(&honest, &honest_high_s);

    let recovered = secp256r1_ecrecover(&signature, &input.msg, input.hash, false);
    let recovered_legacy = secp256r1_ecrecover(&signature, &input.msg, input.hash, true);

    let Some(digest) = digest(&input.msg, input.hash) else {
        assert!(recovered.is_none() && recovered_legacy.is_none());
        return;
    };
    assert_eq!(
        recovered,
        ecdsa_recover(&signature, &digest),
        "disagrees with the ecdsa crate"
    );
    let overflows = signature.len() == RECOVERABLE_SIG_LENGTH
        && signature[SIG_LENGTH] >= 2
        && signature[..32] >= ORDER_COMPLEMENT[..];
    if !overflows {
        assert_eq!(recovered_legacy, recovered, "legacy recovery differs");
    }

    if let Some(pk) = &recovered {
        let decoded = Secp256r1PublicKey::from_bytes(pk).unwrap();
        assert_eq!(decoded.as_bytes(), &pk[..]);
        let normalized = match is_high_s(&signature) {
            true => negate_s(&signature[..SIG_LENGTH]),
            false => signature[..SIG_LENGTH].to_vec(),
        };
        assert!(verify(&normalized, &decoded, &input.msg, input.hash));
    }

    // Only the owner can produce signatures that recover the fixed key.
    assert_eq!(
        recovered.as_deref() == Some(KEY.public().as_bytes()),
        signature == honest || signature == honest_high_s,
        "recovered the fixed key from another signature"
    );
});
