// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, PublicPoly};
use crate::{ecies, tbls};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{bls12381, GroupElement, HashToGroupElement, Pairing};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

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

/// Basic wrapper of a set of values that are not associated with indexes, assuming the indexes are known to all
/// parties. Used to reduce the size of the messages in the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnindexedValues<A> {
    pub values: Vec<A>,
}

impl<A> From<Vec<IndexedValue<A>>> for UnindexedValues<A> {
    fn from(index_values: Vec<IndexedValue<A>>) -> Self {
        let mut values: Vec<A> = Vec::with_capacity(index_values.len());
        for v in index_values {
            values.push(v.value);
        }
        Self { values }
    }
}

impl<A> UnindexedValues<A> {
    pub fn add_indexes(self, indexes: &[ShareIndex]) -> FastCryptoResult<Vec<IndexedValue<A>>> {
        if self.values.len() != indexes.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let values = self
            .values
            .into_iter()
            .zip(indexes)
            .map(|(value, index)| IndexedValue {
                index: *index,
                value,
            })
            .collect();
        Ok(values)
    }
}

/// ECIES related types with Ristretto points.
///
pub type PrivateEciesKey = ecies::PrivateKey<RistrettoPoint>;
pub type PublicEciesKey = ecies::PublicKey<RistrettoPoint>;
pub type EciesEncryption = ecies::Encryption<RistrettoPoint>;
pub type RecoveryPackage = ecies::RecoveryPackage<RistrettoPoint>;
