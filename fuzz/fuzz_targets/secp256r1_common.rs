// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Shared by the secp256r1 fuzz targets: the hash function flags of Sui's Move natives, independent
//! implementations to compare with (p256 for decoding and verification, the ecdsa crate for
//! recovery), and inputs derived from a fixed key pair, so that the fuzzer also explores keys and
//! signatures close to valid ones. None of fastcrypto's secp256r1 dependencies change behaviour
//! under `cfg(fuzzing)`.

#![allow(dead_code)]

use arbitrary::Arbitrary;
use ecdsa::RecoveryId;
use fastcrypto::hash::{HashFunction, Keccak256, Sha256};
use fastcrypto::secp256r1::Secp256r1KeyPair;
use fastcrypto::traits::KeyPair;
use hex_literal::hex;
use once_cell::sync::Lazy;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::{rngs::StdRng, SeedableRng};

/// The hash function flags of Sui's `secp256r1_verify` and `secp256r1_ecrecover` Move natives.
/// Other flags are rejected.
pub const KECCAK256: u8 = 0;
pub const SHA256: u8 = 1;

pub const PK_LENGTH: usize = 33;
pub const SIG_LENGTH: usize = 64;
pub const RECOVERABLE_SIG_LENGTH: usize = 65;
pub const SK_LENGTH: usize = 32;

/// The order n of the group, big-endian.
pub const GROUP_ORDER: [u8; 32] =
    hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/// floor(n / 2), big-endian. A signature has a low s if s <= floor(n / 2).
const HALF_GROUP_ORDER: [u8; 32] =
    hex!("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

/// 2^256 - n, big-endian. With recovery id 2 or 3, r + n overflows 256 bits iff r >= 2^256 - n.
pub const ORDER_COMPLEMENT: [u8; 32] =
    hex!("00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf");

/// The fixed key pair. Inputs never sign with it.
pub static KEY: Lazy<Secp256r1KeyPair> =
    Lazy::new(|| Secp256r1KeyPair::generate(&mut StdRng::from_seed([1; 32])));

/// The digest of a message with the hash function of a flag, or `None` for other flags.
pub fn digest(msg: &[u8], hash: u8) -> Option<[u8; 32]> {
    match hash {
        KECCAK256 => Some(Keccak256::digest(msg).digest),
        SHA256 => Some(Sha256::digest(msg).digest),
        _ => None,
    }
}

/// Whether the s of r || s (followed by anything) is greater than n / 2.
pub fn is_high_s(signature: &[u8]) -> bool {
    signature[32..SIG_LENGTH] > HALF_GROUP_ORDER[..]
}

/// Replaces s by n - s in r || s (followed by anything).
pub fn negate_s(signature: &[u8]) -> Vec<u8> {
    let sig = Signature::from_slice(&signature[..SIG_LENGTH]).unwrap();
    let negated = Signature::from_scalars(sig.r(), -*sig.s()).unwrap();
    let mut bytes = signature.to_vec();
    bytes[..SIG_LENGTH].copy_from_slice(&negated.to_bytes());
    bytes
}

/// ECDSA verification with p256, which unlike fastcrypto accepts a high s.
pub fn p256_verify(pk: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
    match (
        VerifyingKey::from_sec1_bytes(pk),
        Signature::from_slice(signature),
    ) {
        (Ok(pk), Ok(signature)) => pk.verify_prehash(digest, &signature).is_ok(),
        _ => false,
    }
}

/// Recovery with the ecdsa crate of the compressed public key from r || s || v.
pub fn ecdsa_recover(signature: &[u8], digest: &[u8; 32]) -> Option<Vec<u8>> {
    if signature.len() != RECOVERABLE_SIG_LENGTH {
        return None;
    }
    let recovery_id = RecoveryId::from_byte(signature[SIG_LENGTH])?;
    let signature = Signature::from_slice(&signature[..SIG_LENGTH]).ok()?;
    let pk = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id).ok()?;
    Some(pk.to_encoded_point(true).as_bytes().to_vec())
}

#[derive(Arbitrary, Debug)]
pub enum SignatureInput {
    Raw(Vec<u8>),
    /// The fixed key's signature on the message.
    Honest,
    /// The fixed key's signature on the message with one bit flipped.
    FlipBit(u16),
    /// The other form of the fixed key's signature: s replaced by n - s (and, for a recoverable
    /// signature, the other recovery id).
    HighS,
    /// The fixed key's signature with r replaced. Small values of r (zero high bytes) with recovery
    /// id 2 or 3 often recover a key, since r + n is then an x-coordinate.
    ReplaceR {
        r: [u8; 32],
        high_zero_bytes: u8,
    },
    /// The fixed key's signature with s replaced.
    ReplaceS([u8; 32]),
    /// The fixed key's recoverable signature with another recovery id.
    RecoveryId(u8),
}

impl SignatureInput {
    /// The signature bytes, given the fixed key's signature and its other form.
    pub fn bytes(&self, honest: &[u8], high_s: &[u8]) -> Vec<u8> {
        let mut bytes = honest.to_vec();
        match self {
            SignatureInput::Raw(raw) => bytes = raw.clone(),
            SignatureInput::Honest => (),
            SignatureInput::FlipBit(bit) => {
                let bit = *bit as usize % (bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
            }
            SignatureInput::HighS => bytes = high_s.to_vec(),
            SignatureInput::ReplaceR { r, high_zero_bytes } => {
                bytes[..32].copy_from_slice(r);
                let zeros = *high_zero_bytes as usize % 32;
                bytes[..zeros].fill(0);
            }
            SignatureInput::ReplaceS(s) => bytes[32..SIG_LENGTH].copy_from_slice(s),
            SignatureInput::RecoveryId(recovery_id) => {
                if let Some(last) = bytes.get_mut(SIG_LENGTH) {
                    *last = *recovery_id;
                }
            }
        }
        bytes
    }
}
