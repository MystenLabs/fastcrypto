// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Kani proofs for the Ed25519 parsers.
//!
//! Each harness checks every input up to a bounded length, not just random samples. It proves:
//! * no panic on any input;
//! * the parser accepts exactly the lengths it should;
//! * the parser is canonical: whatever it accepts serializes back to the same bytes.
//!
//! Run with:
//! `cargo kani -p fastcrypto -Z stubbing --harness ed25519`

use crate::ed25519::{
    Ed25519AggregateSignature, Ed25519PublicKey, Ed25519Signature, ED25519_PUBLIC_KEY_LENGTH,
    ED25519_SIGNATURE_LENGTH,
};
use crate::traits::ToFromBytes;
use curve25519_dalek_ng::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek_ng::edwards::{CompressedEdwardsY, EdwardsPoint};

#[kani::proof]
#[kani::unwind(70)]
fn ed25519_signature_from_bytes() {
    let bytes = kani::vec::any_vec::<u8, { ED25519_SIGNATURE_LENGTH + 2 }>();
    let result = Ed25519Signature::from_bytes(&bytes);
    // Every other length is rejected, and no 64-byte input is.
    assert_eq!(result.is_ok(), bytes.len() == ED25519_SIGNATURE_LENGTH);
    if let Ok(sig) = result {
        assert_eq!(sig.as_ref(), bytes.as_slice());
    }
}

/// Before #962, an input whose length was not a multiple of 64 parsed successfully and lost its
/// trailing bytes. One signature plus one stray byte is enough to reach that case.
#[kani::proof]
#[kani::unwind(70)]
fn ed25519_aggregate_signature_from_bytes() {
    let bytes = kani::vec::any_vec::<u8, { ED25519_SIGNATURE_LENGTH + 1 }>();
    let result = Ed25519AggregateSignature::from_bytes(&bytes);
    // Lengths that aren't a multiple of 64 are rejected; multiples of 64, including 0, are not.
    assert_eq!(
        result.is_ok(),
        bytes.len().is_multiple_of(ED25519_SIGNATURE_LENGTH)
    );
    if let Ok(aggregate) = result {
        assert_eq!(aggregate.as_ref(), bytes.as_slice());
    }
}

/// Replaces point decompression, whose field square root is far too slow for Kani. The parser
/// keeps the input bytes and only negates the point, so these properties don't depend on which
/// point comes back. The solver chooses between "not on the curve" and a fixed valid point.
fn decompress_stub(_: &CompressedEdwardsY) -> Option<EdwardsPoint> {
    if kani::any() {
        Some(ED25519_BASEPOINT_POINT)
    } else {
        None
    }
}

#[kani::proof]
#[kani::stub(
    curve25519_dalek_ng::edwards::CompressedEdwardsY::decompress,
    decompress_stub
)]
#[kani::unwind(40)]
fn ed25519_public_key_from_bytes() {
    let bytes = kani::vec::any_vec::<u8, { ED25519_PUBLIC_KEY_LENGTH + 2 }>();
    let result = Ed25519PublicKey::from_bytes(&bytes);
    // Every other length is rejected. A 32-byte input can still fail if it isn't on the curve.
    if bytes.len() != ED25519_PUBLIC_KEY_LENGTH {
        assert!(result.is_err());
    }
    if let Ok(pk) = result {
        assert_eq!(pk.as_ref(), bytes.as_slice());
    }
}
