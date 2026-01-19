// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError::InvalidProof;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::groups::Scalar;
use crate::traits::AllowedRng;
use bulletproofs::PedersenGens;
use derive_more::{Add, Sub};
use serde::{Deserialize, Serialize};

// TODO: We don't need to have this point in decompressed form in order to just verify the commitment, but it's convenient when using the homomorphic property.
#[derive(Clone, Debug, PartialEq, Eq, Add, Sub, Serialize, Deserialize)]
pub struct PedersenCommitment(pub(crate) RistrettoPoint);

#[derive(Clone, Debug, PartialEq, Eq, Add, Sub, Serialize, Deserialize)]
pub struct Blinding(pub(crate) RistrettoScalar);

impl PedersenCommitment {
    pub(crate) fn from_blinding(value: &RistrettoScalar, blinding: &Blinding) -> Self {
        Self(RistrettoPoint(
            PedersenGens::default().commit(value.0, blinding.0 .0),
        ))
    }

    pub fn commit(value: &RistrettoScalar, rng: &mut impl AllowedRng) -> (Self, Blinding) {
        let blinding = Blinding(RistrettoScalar::rand(rng));
        (Self::from_blinding(value, &blinding), blinding)
    }

    pub fn verify(&self, value: &RistrettoScalar, blinding: &Blinding) -> FastCryptoResult<()> {
        if RistrettoPoint(PedersenGens::default().commit(value.0, blinding.0 .0)) == self.0 {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }
}
