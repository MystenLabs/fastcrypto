// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a set of functions for **emulating** the outputs of a DKG protocol. Those
//! outputs can be used as inputs to the threshold-BLS functions.
//!
//! These functions are **NOT SECURE** and intended to be used only as an interim alternative until
//! the DKG protocol is implemented.
//!
//! ```rust
//! use std::num::NonZeroU32;
//! use fastcrypto_tbls::mocked_dkg;
//! use fastcrypto_tbls::types::ThresholdBls12381MinSig;
//! use fastcrypto_tbls::tbls::ThresholdBls;
//!
//! let threshold: u32 = 2;
//! let epoch: u64 = 10;
//! const MSG: [u8; 4] = [1, 2, 3, 4];
//!
//! // Parties get their private shares from the mock.
//! let (share1, _, _) = mocked_dkg::generate_share_and_public_keys(threshold, epoch, NonZeroU32::new(1).unwrap());
//! let (share2, _, _) = mocked_dkg::generate_share_and_public_keys(threshold, epoch, NonZeroU32::new(2).unwrap());
//!
//! // Parties may sign messages with their shares.
//! let sig1 = ThresholdBls12381MinSig::partial_sign(&share1, &MSG);
//! let sig2 = ThresholdBls12381MinSig::partial_sign(&share2, &MSG);
//!
//! // Anyone can check partial signatures.
//! let (bls_pk, vss_pk) = mocked_dkg::generate_public_keys(threshold, epoch);
//! assert!(ThresholdBls12381MinSig::partial_verify(&vss_pk, &MSG, &sig1).is_ok());
//! assert!(ThresholdBls12381MinSig::partial_verify(&vss_pk, &MSG, &sig2).is_ok());
//!
//! // Anyone can aggregate the partial signatures and verify the full signature.
//! let sig = ThresholdBls12381MinSig::aggregate(threshold, &[sig1, sig2]).unwrap();
//! assert!(ThresholdBls12381MinSig::verify(&bls_pk, &MSG, &sig).is_ok());
//! ```
//!

use crate::polynomial::{PrivatePoly, PublicPoly};
use crate::tbls;
use crate::types::{
    PrivateBlsKey, PublicBlsKey, PublicVssKey, Share, ShareIndex, ThresholdBls12381MinSig,
};
use fastcrypto::groups::GroupElement;

type Scalar = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Private;

fn get_private_key(epoch: u64) -> PrivateBlsKey {
    PrivateBlsKey::from(epoch + 1)
}

/// Emulate the output of DKG for a given id.
pub fn generate_share_and_public_keys(
    threshold: u32,
    epoch: u64,
    id: ShareIndex,
) -> (Share, PublicBlsKey, PublicVssKey) {
    // The private polynomial is c_0 = epoch and c_i = 1.
    let mut coefficients: Vec<Scalar> = (0..threshold)
        .into_iter()
        .map(|_| Scalar::generator())
        .collect();
    *coefficients.get_mut(0).unwrap() = get_private_key(epoch);
    let private_poly = PrivatePoly::<Scalar>::from(coefficients);
    let public_poly: PublicPoly<PublicBlsKey> = private_poly.commit();

    let share = private_poly.eval(id);
    (share, *public_poly.c0(), public_poly)
}

/// Emulate the public output of DKG.
pub fn generate_public_keys(threshold: u32, epoch: u64) -> (PublicBlsKey, PublicVssKey) {
    let (_, bls_pk, vss_pk) =
        generate_share_and_public_keys(threshold, epoch, ShareIndex::new(1).unwrap());
    (bls_pk, vss_pk)
}

/// Emulate the output of the previous key recovery protocol.
pub fn generate_full_key_pair(epoch: u64) -> (PrivateBlsKey, PublicBlsKey) {
    let private = get_private_key(epoch);
    let public = PublicBlsKey::generator();
    (private, public * private)
}
