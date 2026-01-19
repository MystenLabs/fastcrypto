// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError::InvalidProof;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::groups::{FiatShamirChallenge, Scalar};
use crate::traits::AllowedRng;
use bulletproofs::PedersenGens;
use derive_more::{Add, Sub};
use serde::{Deserialize, Serialize};

// TODO: We don't need to have this point in decompressed form in order to just verify the commitment, but it's convenient when using the homomorphic property.
#[derive(Clone, Debug, PartialEq, Eq, Add, Sub, Serialize, Deserialize)]
pub struct PedersenCommitment(pub(crate) RistrettoPoint);

#[derive(Clone, Debug, PartialEq, Eq, Add, Sub, Serialize, Deserialize)]
pub struct BlindingFactor(pub(crate) RistrettoScalar);

// TODO: Is this needed?
pub struct ProofOfKnowledge(RistrettoPoint, RistrettoScalar, RistrettoScalar);

impl PedersenCommitment {
    pub(crate) fn from_blinding_factor(
        value: &RistrettoScalar,
        blinding_factor: &RistrettoScalar,
    ) -> Self {
        Self(RistrettoPoint(
            PedersenGens::default().commit(value.0, blinding_factor.0),
        ))
    }

    pub fn commit(value: &RistrettoScalar, rng: &mut impl AllowedRng) -> (Self, BlindingFactor) {
        let blinding_factor = RistrettoScalar::rand(rng);
        (
            Self::from_blinding_factor(value, &blinding_factor),
            BlindingFactor(blinding_factor),
        )
    }

    pub fn verify(
        &self,
        value: &RistrettoScalar,
        blinding_factor: &BlindingFactor,
    ) -> FastCryptoResult<()> {
        if RistrettoPoint(PedersenGens::default().commit(value.0, blinding_factor.0 .0)) == self.0 {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }

    /// Create a proof-of-knowledge for a given commitment: The prover knows a valid combination of value and blinding factor.
    pub fn create_proof_of_knowledge(
        &self,
        value: &RistrettoScalar,
        blinding_factor: &BlindingFactor,
        rng: &mut impl AllowedRng,
    ) -> ProofOfKnowledge {
        let t1 = RistrettoScalar::rand(rng);
        let t2 = RistrettoScalar::rand(rng);
        let t = RistrettoPoint(
            PedersenGens::default().B * t1.0 + PedersenGens::default().B_blinding * t2.0,
        );
        let challenge = ProofOfKnowledge::challenge(self, &t);
        let s1 = value * challenge + t1;
        let s2 = blinding_factor.0 * challenge + t2;
        ProofOfKnowledge(t, s1, s2)
    }
}

impl ProofOfKnowledge {
    fn challenge(commitment: &PedersenCommitment, t: &RistrettoPoint) -> RistrettoScalar {
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&(commitment, t)).unwrap(),
        )
    }

    pub fn verify(&self, commitment: &PedersenCommitment) -> FastCryptoResult<()> {
        let lhs =
            PedersenGens::default().B * self.1 .0 + PedersenGens::default().B_blinding * self.2 .0;
        let challenge = Self::challenge(commitment, &self.0);
        let rhs = commitment.0 * challenge + self.0;
        if lhs == rhs.0 {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }
}
