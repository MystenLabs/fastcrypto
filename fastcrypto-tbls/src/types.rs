// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, PublicPoly};
use crate::tbls;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{bls12381, GroupElement, HashToGroupElement, Pairing, Scalar};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::num::NonZeroU16;
use std::ops::Add;

/// Implementation of [ThresholdBls] for BLS12-381-min-sig. A variant for BLS12-381-min-pk can be
/// defined in a similar way if needed in the future.
pub struct ThresholdBls12381MinSig {}

impl tbls::ThresholdBls for ThresholdBls12381MinSig {
    type Private = bls12381::Scalar;
    type Public = bls12381::G2Element;
    type Signature = bls12381::G1Element;

    fn verify(pk: &Self::Public, msg: &[u8], sig: &Self::Signature) -> FastCryptoResult<()> {
        let hashed_message = Self::Signature::hash_to_group_element(msg);
        // e(sig, g2)
        let left = sig.pairing(&Self::Public::generator());
        // e(H(m), pk)
        let right = hashed_message.pairing(pk);
        match left == right {
            true => Ok(()),
            false => Err(FastCryptoError::InvalidSignature),
        }
    }
}

/// tBLS with ThresholdBls12381MinSig types.
///
pub type Share = Eval<<ThresholdBls12381MinSig as tbls::ThresholdBls>::Private>;
pub type PrivateBlsKey = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Private;
pub type PublicBlsKey = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Public;
pub type PublicVssKey = PublicPoly<<ThresholdBls12381MinSig as tbls::ThresholdBls>::Public>;
pub type Signature = <ThresholdBls12381MinSig as tbls::ThresholdBls>::Signature;
pub type RawSignature = bls12381::G1ElementAsBytes;

/// Indexes of shares/private keys (0 is reserved for the secret itself).
pub type ShareIndex = NonZeroU16;

/// Wrapper of a value that is associated with a specific index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedValue<A> {
    pub index: ShareIndex,
    pub value: A,
}

#[inline]
pub(crate) fn to_scalar<C: Scalar>(index: impl Borrow<ShareIndex>) -> C {
    C::from(index.borrow().get() as u128)
}

/// Helper function to add two evaluations.
/// Panics if the indices are not equal.
pub fn sum<S>((a, b): (&Eval<S>, &Eval<S>)) -> Eval<S>
where
    for<'b> &'b S: Add<&'b S, Output = S>,
{
    assert_eq!(a.index, b.index);
    Eval {
        value: &a.value + &b.value,
        index: a.index,
    }
}
