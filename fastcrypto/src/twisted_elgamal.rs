// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError::{InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar, RISTRETTO_POINT_BYTE_LENGTH};
use crate::groups::{Doubling, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use crate::pedersen::{Blinding, PedersenCommitment};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use bulletproofs::PedersenGens;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

lazy_static! {
    static ref G: RistrettoPoint = RistrettoPoint(PedersenGens::default().B);
    static ref H: RistrettoPoint = RistrettoPoint(PedersenGens::default().B_blinding);
}

pub struct PublicKey(RistrettoPoint);
pub struct PrivateKey(RistrettoScalar);

pub fn generate_keypair(rng: &mut impl AllowedRng) -> (PublicKey, PrivateKey) {
    let sk = PrivateKey(RistrettoScalar::rand(rng));
    (pk_from_sk(&sk), sk)
}

pub fn pk_from_sk(sk: &PrivateKey) -> PublicKey {
    PublicKey(*H * sk.0.inverse().unwrap())
}

// TODO: Encryptions of the same message can reuse commitments
#[derive(Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    commitment: PedersenCommitment,
    decryption_handle: RistrettoPoint,
}

impl Ciphertext {
    pub fn encrypt(
        public_key: &PublicKey,
        message: u32,
        rng: &mut impl AllowedRng,
    ) -> (Self, Blinding) {
        let blinding = Blinding::rand(rng);
        (
            Self {
                decryption_handle: public_key.0 * blinding.0,
                commitment: PedersenCommitment::from_blinding(
                    &RistrettoScalar::from(message as u64),
                    &blinding,
                ),
            },
            blinding,
        )
    }

    pub fn decrypt(
        &self,
        private_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u32>,
    ) -> FastCryptoResult<u32> {
        let mut c = self.commitment.0 - self.decryption_handle * private_key.0;
        for x_low in 0..1u32 << 16 {
            if let Some(x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + (x_high << 16));
            }
            c -= *G;
        }
        Err(InvalidInput)
    }
}

/// A proof that a given ciphertext is for the message 0.
pub struct ZeroProof {
    y_p: RistrettoPoint,
    y_d: RistrettoPoint,
    z: RistrettoScalar,
}

impl ZeroProof {
    pub fn prove(ciphertext: &Ciphertext, sk: &PrivateKey, rng: &mut impl AllowedRng) -> Self {
        let y = RistrettoScalar::rand(rng);
        let pk = pk_from_sk(sk);

        let y_p = pk.0 * y;
        let y_d = ciphertext.decryption_handle * y;
        let challenge = Self::challenge(ciphertext, &pk.0, &y_p, &y_d);
        let z = sk.0 * challenge + y;
        Self { y_p, y_d, z }
    }

    fn challenge(
        ciphertext: &Ciphertext,
        pk: &RistrettoPoint,
        y_p: &RistrettoPoint,
        y_d: &RistrettoPoint,
    ) -> RistrettoScalar {
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&(ciphertext, pk, y_p, y_d)).unwrap(),
        )
    }

    pub fn verify(&self, ciphertext: &Ciphertext, pk: &PublicKey) -> FastCryptoResult<()> {
        let challenge = -Self::challenge(ciphertext, &pk.0, &self.y_p, &self.y_d);
        if RistrettoPoint::multi_scalar_mul(&[self.z, challenge], &[pk.0, *H]).unwrap() == self.y_p
            && RistrettoPoint::multi_scalar_mul(
                &[self.z, challenge],
                &[ciphertext.decryption_handle, ciphertext.commitment.0],
            )
            .unwrap()
                == self.y_d
        {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }
}

/// This represents a ZK proof that a ciphertext has the same message as the value of an other commitment.
pub struct EqualityProof {
    y: (RistrettoPoint, RistrettoPoint, RistrettoPoint),
    z: (RistrettoScalar, RistrettoScalar, RistrettoScalar),
}

impl EqualityProof {
    pub fn prove(
        value: &RistrettoScalar,
        ciphertext: &Ciphertext,
        other_commitment: &PedersenCommitment,
        other_blinding: &Blinding,
        sk: &PrivateKey,
        rng: &mut impl AllowedRng,
    ) -> Self {
        let pk = pk_from_sk(sk);
        let r = (
            RistrettoScalar::rand(rng),
            RistrettoScalar::rand(rng),
            RistrettoScalar::rand(rng),
        );

        let y = (
            pk.0 * r.0,
            RistrettoPoint::multi_scalar_mul(&[r.1, r.0], &[*G, ciphertext.decryption_handle])
                .unwrap(),
            RistrettoPoint::multi_scalar_mul(&[r.1, r.2], &[*G, *H]).unwrap(),
        );

        let challenge = Self::challenge(ciphertext, other_commitment, &pk.0, &y);

        let z = (
            challenge * sk.0 + r.0,
            challenge * value + r.1,
            challenge * other_blinding.0 + r.2,
        );

        Self { y, z }
    }

    fn challenge(
        ciphertext: &Ciphertext,
        other_commitment: &PedersenCommitment,
        pk: &RistrettoPoint,
        y: &(RistrettoPoint, RistrettoPoint, RistrettoPoint),
    ) -> RistrettoScalar {
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&(ciphertext, other_commitment, pk, y)).unwrap(),
        )
    }

    pub fn verify(
        &self,
        ciphertext: &Ciphertext,
        other_commitment: &PedersenCommitment,
        pk: &PublicKey,
    ) -> FastCryptoResult<()> {
        let challenge = -Self::challenge(ciphertext, other_commitment, &pk.0, &self.y);
        if self.y
            == (
                RistrettoPoint::multi_scalar_mul(&[self.z.0, challenge], &[pk.0, *H]).unwrap(),
                RistrettoPoint::multi_scalar_mul(
                    &[self.z.1, self.z.0, challenge],
                    &[*G, ciphertext.decryption_handle, ciphertext.commitment.0],
                )
                .unwrap(),
                RistrettoPoint::multi_scalar_mul(
                    &[self.z.1, self.z.2, challenge],
                    &[*G, *H, other_commitment.0],
                )
                .unwrap(),
            )
        {
            Ok(())
        } else {
            Err(InvalidProof)
        }
    }
}

pub struct AggregateCiphertext {
    commitment: PedersenCommitment,
    decryption_handles: Vec<RistrettoPoint>,
}

impl AggregateCiphertext {
    pub fn encrypt(
        pks: &[RistrettoPoint],
        message: u32,
        rng: &mut impl AllowedRng,
    ) -> (Self, Blinding) {
        let blinding = Blinding::rand(rng);
        (
            Self {
                decryption_handles: pks.iter().map(|pk| pk * blinding.0).collect(),
                commitment: PedersenCommitment::from_blinding(
                    &RistrettoScalar::from(message as u64),
                    &blinding,
                ),
            },
            blinding,
        )
    }

    pub fn encryption(&self, index: usize) -> FastCryptoResult<Ciphertext> {
        if index >= self.decryption_handles.len() {
            return Err(InvalidInput);
        }
        Ok(Ciphertext {
            commitment: self.commitment.clone(),
            decryption_handle: self.decryption_handles[index],
        })
    }
}

/// Precompute discrete log table for use in decryption. This only needs to be computed once.
///
/// The table contains a mapping from integers <i>x</i> in the range <i>0, .., 2<sup>16</sup>-1</i> to Ristretto points <i>(2<sup>16</sup> x) G<i>.
pub fn precompute_table() -> HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u32> {
    let step = G.repeated_doubling(16);
    let mut point = RistrettoPoint::zero();
    let mut table = HashMap::with_capacity(1 << 16);
    for x_high in 0..1 << 16 {
        table.insert(point.to_byte_array(), x_high);
        point += step;
    }
    table
}

#[test]
fn test_round_trip() {
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let message = 1234567890u32;
    let (ciphertext, _) = Ciphertext::encrypt(&pk, message, &mut rand::thread_rng());

    // This table can be reused, so it only has to be computed once
    let table = precompute_table();
    assert_eq!(ciphertext.decrypt(&sk, &table).unwrap(), message);
}

#[test]
fn test_zero_proof() {
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let (ciphertext, _) = Ciphertext::encrypt(&pk, 0, &mut rand::thread_rng());
    let proof = ZeroProof::prove(&ciphertext, &sk, &mut rand::thread_rng());
    proof.verify(&ciphertext, &pk).unwrap();
}

#[test]
fn test_equality_proof() {
    let value = 12345u32;
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, _) = Ciphertext::encrypt(&pk, value, &mut rng);
    let (other_commitment, blinding) =
        PedersenCommitment::commit(&RistrettoScalar::from(value as u64), &mut rng);
    let proof = EqualityProof::prove(
        &RistrettoScalar::from(value as u64),
        &ciphertext,
        &other_commitment,
        &blinding,
        &sk,
        &mut rng,
    );
    proof.verify(&ciphertext, &other_commitment, &pk).unwrap();
}

#[test]
fn encrypt_and_range_proof() {
    let value = 1234u32;
    let range = crate::bulletproofs::Range::Bits32;
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, blinding) = Ciphertext::encrypt(&pk, value, &mut rng);
    let domain = b"test";
    let range_proof = crate::bulletproofs::RangeProof::prove_with_blinding(
        value as u64,
        blinding.clone(),
        &range,
        domain,
        &mut rng,
    )
    .unwrap();

    assert_eq!(&range_proof.blinding, &blinding);
    assert_eq!(&range_proof.commitment, &ciphertext.commitment);
    assert!(range_proof
        .proof
        .verify(&range_proof.commitment, &range, domain)
        .is_ok());

    assert_eq!(ciphertext.decrypt(&sk, &precompute_table()).unwrap(), value);
}
