// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError::InvalidProof;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::groups::Scalar;
use crate::traits::AllowedRng;
use bulletproofs::PedersenGens;
use derive_more::{Add, Mul, Sub};
use serde::{Deserialize, Serialize};

// TODO: We don't need to have this point in decompressed form in order to just verify the commitment, but it's convenient when using the homomorphic property.
#[derive(Clone, Debug, PartialEq, Eq, Add, Sub, Mul, Serialize, Deserialize)]
pub struct PedersenCommitment(pub(crate) RistrettoPoint);

#[derive(Clone, Debug, PartialEq, Eq, Add, Sub, Mul, Serialize, Deserialize)]
pub struct Blinding(pub(crate) RistrettoScalar);

impl PedersenCommitment {
    pub fn from_blinding(value: &RistrettoScalar, blinding: &Blinding) -> Self {
        Self(RistrettoPoint(
            PedersenGens::default().commit(value.0, blinding.0 .0),
        ))
    }

    pub fn commit(value: &RistrettoScalar, rng: &mut impl AllowedRng) -> (Self, Blinding) {
        let blinding = Blinding::rand(rng);
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

impl Blinding {
    pub fn rand(rng: &mut impl AllowedRng) -> Self {
        Self(RistrettoScalar::rand(rng))
    }
}

#[test]
fn test_commitment() {
    use crate::groups::GroupElement;

    let mut rng = rand::thread_rng();
    let value_1 = RistrettoScalar::from(1u64);
    let (commitment_1, bf_1) = PedersenCommitment::commit(&value_1, &mut rng);
    assert!(commitment_1.verify(&value_1, &bf_1).is_ok());

    let invalid_commitment = PedersenCommitment(commitment_1.0 + RistrettoPoint::generator());
    assert!(invalid_commitment.verify(&value_1, &bf_1).is_err());

    let invalid_bf = Blinding(bf_1.0 + RistrettoScalar::from(1u64));
    assert!(commitment_1.verify(&value_1, &invalid_bf).is_err());

    let invalid_value = value_1 + RistrettoScalar::from(1u64);
    assert!(commitment_1.verify(&invalid_value, &bf_1).is_err());
}

#[test]
fn test_additive_commitments() {
    let mut rng = rand::thread_rng();

    let value_1 = RistrettoScalar::from(1u64);
    let (commitment_1, bf_1) = PedersenCommitment::commit(&value_1, &mut rng);

    let value_2 = RistrettoScalar::from(2u64);
    let (commitment_2, bf_2) = PedersenCommitment::commit(&value_2, &mut rng);

    let commitment_3 = commitment_1 + commitment_2;
    let bf_3 = bf_1 + bf_2;
    let expected_value = value_1 + value_2;
    commitment_3.verify(&expected_value, &bf_3).unwrap();
}

#[test]
fn test_scaled_commitments() {
    let mut rng = rand::thread_rng();

    let value_1 = RistrettoScalar::from(7u64);
    let (commitment_1, bf_1) = PedersenCommitment::commit(&value_1, &mut rng);

    let s = RistrettoScalar::from(5u64);

    let commitment_2 = commitment_1 * s;
    let bf_2 = bf_1 * s;

    let expected_value = value_1 * s;
    commitment_2.verify(&expected_value, &bf_2).unwrap();
}
