// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a set of functions for emulating the outputs of a DKG protocol, and can be
//! used as inputs to threshold BLS.
//!
//! ```rust
//! # use fastcrypto_tbls::fake_tbls_key_generator::{*, Scheme};
//! # use tbls::sig::{SignatureScheme, ThresholdScheme};
//! let threshold: u32 = 2;
//! let epoch: u64 = 10;
//! const MSG: [u8; 4] = [1, 2, 3, 4];
//! // Validators generate their shares and sign messages.
//! let (share1, _, _) = geneate_partial_key_pair(threshold, epoch, 1);
//! let sig1 = Scheme::partial_sign(&share1, &MSG).unwrap();
//!
//! let (share2, _, _) = geneate_partial_key_pair(threshold, epoch, 2);
//! let sig2 = Scheme::partial_sign(&share2, &MSG).unwrap();
//!
//! // Anyone can check and aggregate partial signatures, and verify the full signature.
//! let (bls_pk, vss_pk) = geneate_public_key(threshold, epoch);
//! Scheme::partial_verify(&vss_pk, &MSG, &sig1).unwrap();
//! Scheme::partial_verify(&vss_pk, &MSG, &sig2).unwrap();
//!
//! let sig = Scheme::aggregate(threshold.try_into().unwrap(), &[sig1, sig2]).unwrap();
//! Scheme::verify(&bls_pk, &MSG, &sig).unwrap();
//! ```
//!

use tbls;
use tbls::curve::group::{Element, Scalar as SC};

// Use G2 for keys and G1 for signatures.
type Scalar = tbls::curve::bls12381::Scalar;
type Point = tbls::curve::bls12381::G2;
type Group = tbls::curve::bls12381::G2Curve;

/// tBLS signature scheme, to be used for partial signing and signature verification.
pub type Scheme = tbls::schemes::bls12_381::G2Scheme;
/// A single share of tBLS.
pub type Share = tbls::sig::Share<Scalar>;
/// Full BLS private key.
pub type PrivateBlsKey = Scalar;
/// Full BLS public key.
pub type PublicBlsKey = Point;
/// Commitment on the coefficients of a polynomial, used to verify shares.
pub type PublicVssKey = tbls::primitives::poly::PublicPoly<Group>;

fn get_private_key(epoch: u64) -> PrivateBlsKey {
    let mut sk = Scalar::new();
    sk.set_int(epoch);
    sk
}

/// Emulate the output of DKG for a given id.
pub fn geneate_partial_key_pair(
    threshold: u32,
    epoch: u64,
    id: u32,
) -> (Share, PublicBlsKey, PublicVssKey) {
    let mut coefficients: Vec<Scalar> = (0..threshold).into_iter().map(|_| Scalar::one()).collect();
    *coefficients.get_mut(0).unwrap() = get_private_key(epoch);

    let public_coefficients = coefficients
        .iter()
        .map(|c| {
            let mut p = Point::one();
            p.mul(c);
            p
        })
        .collect::<Vec<_>>();
    let private_poly = tbls::primitives::poly::PrivatePoly::<Group>::from(coefficients);
    let public_poly = tbls::primitives::poly::PublicPoly::<Group>::from(public_coefficients);

    let share = private_poly.eval(id);

    (share, public_poly.get(0), public_poly)
}

/// Emulate the public output of DKG.
pub fn geneate_public_key(threshold: u32, epoch: u64) -> (PublicBlsKey, PublicVssKey) {
    let (_, bls_pk, vss_pk) = geneate_partial_key_pair(threshold, epoch, 1);
    (bls_pk, vss_pk)
}

/// Emulate the output of the key recovery protocol.
pub fn geneate_full_key_pair(epoch: u64) -> (PrivateBlsKey, PublicBlsKey) {
    (get_private_key(epoch), Point::one())
}
