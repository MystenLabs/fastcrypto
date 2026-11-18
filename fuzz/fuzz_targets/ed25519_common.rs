// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Shared by the Ed25519 fuzz targets: attacker-chosen inputs, the small-order encodings, and an
//! independent ZIP215 verifier and RFC 8032 signer written on curve25519-dalek 4 (ed25519-consensus
//! uses the curve25519-dalek-ng fork).

#![allow(dead_code)]

use arbitrary::Arbitrary;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use sha2::{Digest, Sha512};

pub const PK_LENGTH: usize = 32;
pub const SIG_LENGTH: usize = 64;
pub const SK_LENGTH: usize = 32;

/// The order ℓ of the prime-order subgroup, little-endian.
pub const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The field modulus p = 2^255 - 19, little-endian.
pub const FIELD_MODULUS: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const SIGN_BIT: u8 = 0x80;

/// The canonical encodings of the eight points of small order. The first one is the identity.
pub const SMALL_ORDER_CANONICAL: [[u8; PK_LENGTH]; 8] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [0; 32],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0x80,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
];

fn with_sign_bit(mut encoding: [u8; PK_LENGTH]) -> [u8; PK_LENGTH] {
    encoding[31] |= SIGN_BIT;
    encoding
}

/// The encoding y + p of a field element y < 19 (y + p < 2^255), as ZIP215 accepts it.
pub fn non_canonical_field_encoding(y: u8) -> [u8; PK_LENGTH] {
    let mut encoding = FIELD_MODULUS;
    encoding[0] += y % 19;
    encoding
}

/// The 14 encodings of small-order points: the 8 canonical ones, then (0, 1) and (0, -1) with the
/// sign bit set, and y + p for y = 0 and y = 1 with either sign.
pub fn small_order_encodings() -> Vec<[u8; PK_LENGTH]> {
    let mut encodings = SMALL_ORDER_CANONICAL.to_vec();
    encodings.push(with_sign_bit(SMALL_ORDER_CANONICAL[0]));
    encodings.push(with_sign_bit(SMALL_ORDER_CANONICAL[1]));
    for y in [0, 1] {
        let encoding = non_canonical_field_encoding(y);
        encodings.extend([encoding, with_sign_bit(encoding)]);
    }
    encodings
}

fn decompress(encoding: &[u8; PK_LENGTH]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*encoding).decompress()
}

fn challenge(r: &[u8], pk: &[u8], msg: &[u8]) -> Scalar {
    let hash: [u8; 64] = Sha512::new()
        .chain_update(r)
        .chain_update(pk)
        .chain_update(msg)
        .finalize()
        .into();
    Scalar::from_bytes_mod_order_wide(&hash)
}

fn expand_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let hash: [u8; 64] = Sha512::digest(seed).into();
    let mut a = [0u8; 32];
    a.copy_from_slice(&hash[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    (
        Scalar::from_bytes_mod_order(a),
        hash[32..].try_into().unwrap(),
    )
}

pub fn reference_public_key(seed: &[u8; 32]) -> [u8; PK_LENGTH] {
    EdwardsPoint::mul_base(&expand_seed(seed).0)
        .compress()
        .to_bytes()
}

/// RFC 8032 signing, with the small-order points `SMALL_ORDER_CANONICAL[torsion_r % 8]` and
/// `SMALL_ORDER_CANONICAL[torsion_a % 8]` added to R and to the public key (0 gives RFC 8032).
pub fn reference_sign(
    seed: &[u8; 32],
    msg: &[u8],
    torsion_r: u8,
    torsion_a: u8,
) -> ([u8; PK_LENGTH], [u8; SIG_LENGTH]) {
    let (a, prefix) = expand_seed(seed);
    let torsion = |i: u8| decompress(&SMALL_ORDER_CANONICAL[i as usize % 8]).unwrap();
    let pk = (EdwardsPoint::mul_base(&a) + torsion(torsion_a))
        .compress()
        .to_bytes();
    let hash: [u8; 64] = Sha512::new()
        .chain_update(prefix)
        .chain_update(msg)
        .finalize()
        .into();
    let r = Scalar::from_bytes_mod_order_wide(&hash);
    let big_r = (EdwardsPoint::mul_base(&r) + torsion(torsion_r))
        .compress()
        .to_bytes();
    let s = r + challenge(&big_r, &pk, msg) * a;
    let mut sig = [0u8; SIG_LENGTH];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(s.as_bytes());
    (pk, sig)
}

/// ZIP215 verification: A and R decode (non-canonical encodings allowed), s < ℓ, and
/// [8]([s]B - R - [k]A) = 0 with k computed over the given encodings.
pub fn reference_verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <[u8; PK_LENGTH]>::try_from(pk),
        <[u8; SIG_LENGTH]>::try_from(sig),
    ) else {
        return false;
    };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: Option<Scalar> = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into();
    match (decompress(&pk), decompress(&r), s) {
        (Some(a), Some(big_r), Some(s)) => {
            (EdwardsPoint::mul_base(&s) - big_r - challenge(&r, &pk, msg) * a)
                .mul_by_cofactor()
                .is_identity()
        }
        _ => false,
    }
}

/// Whether the bytes decode to a point.
pub fn reference_decodes(pk: &[u8]) -> bool {
    <[u8; PK_LENGTH]>::try_from(pk).is_ok_and(|pk| decompress(&pk).is_some())
}

/// Verification from bytes, the way Sui's `ed25519_verify` Move native does it.
pub fn verify_bytes(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    match (
        Ed25519PublicKey::from_bytes(pk),
        <Ed25519Signature as ToFromBytes>::from_bytes(sig),
    ) {
        (Ok(pk), Ok(sig)) => pk.verify(msg, &sig).is_ok(),
        _ => false,
    }
}

/// An attacker-chosen public key.
#[derive(Arbitrary, Debug, Clone)]
pub enum Key {
    /// Any bytes.
    Bytes(Vec<u8>),
    /// One of the 14 small-order encodings.
    SmallOrder(u8),
    /// y or y + p for a small y, with either sign.
    SmallY { y: u8, plus_p: bool, sign: bool },
    /// The public key of a seed, plus a small-order point (index 0 adds nothing).
    Seed { seed: [u8; 32], torsion: u8 },
}

/// An attacker-chosen signature, for a given public key and message.
#[derive(Arbitrary, Debug, Clone)]
pub enum Sig {
    /// Any bytes.
    Bytes(Vec<u8>),
    /// R of small order and s as given.
    SmallOrderR { r: u8, s: [u8; 32] },
    /// R = [s]B, which verifies under any small-order key.
    BaseMultiple { s: [u8; 32] },
    /// If the key is `Key::Seed`, the signature of its owner with a small-order point added to R.
    Owner { torsion: u8 },
    /// `Owner`, then one bit flipped.
    FlippedBit { torsion: u8, bit: u16 },
    /// `Owner`, then s replaced by s + ℓ.
    AddGroupOrder { torsion: u8 },
}

impl Key {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Key::Bytes(bytes) => bytes.clone(),
            Key::SmallOrder(i) => {
                let encodings = small_order_encodings();
                encodings[*i as usize % encodings.len()].to_vec()
            }
            Key::SmallY { y, plus_p, sign } => {
                let mut encoding = if *plus_p {
                    non_canonical_field_encoding(*y)
                } else {
                    let mut encoding = [0u8; PK_LENGTH];
                    encoding[0] = y % 19;
                    encoding
                };
                if *sign {
                    encoding = with_sign_bit(encoding);
                }
                encoding.to_vec()
            }
            Key::Seed { seed, torsion } => reference_sign(seed, b"", 0, *torsion).0.to_vec(),
        }
    }
}

impl Sig {
    pub fn bytes(&self, key: &Key, msg: &[u8]) -> Vec<u8> {
        let owner = |torsion: u8| match key {
            Key::Seed {
                seed,
                torsion: torsion_a,
            } => reference_sign(seed, msg, torsion, *torsion_a).1,
            _ => [0u8; SIG_LENGTH],
        };
        match self {
            Sig::Bytes(bytes) => bytes.clone(),
            Sig::SmallOrderR { r, s } => {
                let encodings = small_order_encodings();
                [&encodings[*r as usize % encodings.len()][..], &s[..]].concat()
            }
            Sig::BaseMultiple { s } => {
                let s = Scalar::from_bytes_mod_order(*s);
                let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
                [&r[..], s.as_bytes()].concat()
            }
            Sig::Owner { torsion } => owner(*torsion).to_vec(),
            Sig::FlippedBit { torsion, bit } => {
                let mut sig = owner(*torsion);
                let bit = *bit as usize % (SIG_LENGTH * 8);
                sig[bit / 8] ^= 1 << (bit % 8);
                sig.to_vec()
            }
            Sig::AddGroupOrder { torsion } => {
                let mut sig = owner(*torsion);
                let mut carry = 0u16;
                for i in 0..32 {
                    let digit = sig[32 + i] as u16 + GROUP_ORDER[i] as u16 + carry;
                    sig[32 + i] = digit as u8;
                    carry = digit >> 8;
                }
                sig.to_vec()
            }
        }
    }
}
