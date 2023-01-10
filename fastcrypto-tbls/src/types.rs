// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::tbls;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{bls12381, GroupElement, HashToGroupElement, Pairing};
use fastcrypto::polynomial::{Eval, PublicPoly};

/// Implementation of [ThresholdBls] for BLS12-381-min-sig. A variant for BLS12-381-min-pk can be
/// defined in a similar way if needed in the future.
pub struct ThresholdBls12381MinSig {}

impl tbls::ThresholdBls for ThresholdBls12381MinSig {
    type Private = bls12381::Scalar;
    type Public = bls12381::G2Element;
    type Signature = bls12381::G1Element;

    fn verify_pairings(
        pk: &Self::Public,
        sig: &Self::Signature,
        msg: &[u8],
    ) -> Result<(), FastCryptoError> {
        let hashed_message = Self::Signature::hash_to_group_element(msg);
        // e(sig, g2)
        let left = sig.pairing(&Self::Public::generator());
        // e(H(m), pk)
        let right = hashed_message.pairing(pk);
        match left == right {
            true => Ok(()),
            false => Err(FastCryptoError::InvalidInput),
        }
    }
}

// Shorter to use types.
pub type Share = Eval<<ThresholdBls12381MinSig as tbls::ThresholdBls>::Private>;
pub type PrivateBlsKey = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Private;
pub type PublicBlsKey = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Public;
pub type PublicVssKey = PublicPoly<<ThresholdBls12381MinSig as tbls::ThresholdBls>::Public>;
pub type Signature = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Signature;
pub type RawSignature = bls12381::G1ElementAsBytes;
