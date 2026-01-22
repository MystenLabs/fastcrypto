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
use derive_more::{Add, Mul, Sub};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::successors;

lazy_static! {
    static ref G: RistrettoPoint = RistrettoPoint(PedersenGens::default().B);
    static ref H: RistrettoPoint = RistrettoPoint(PedersenGens::default().B_blinding);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKey(RistrettoScalar);

pub fn generate_keypair(rng: &mut impl AllowedRng) -> (PublicKey, PrivateKey) {
    let sk = PrivateKey(RistrettoScalar::rand(rng));
    (pk_from_sk(&sk), sk)
}

pub fn pk_from_sk(sk: &PrivateKey) -> PublicKey {
    PublicKey(*H * sk.0.inverse().unwrap())
}

// TODO: Encryptions of the same message can reuse commitments
#[derive(Debug, Add, Sub, Mul, Serialize, Deserialize)]
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
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
    ) -> FastCryptoResult<u32> {
        let mut c = self.commitment.0 - self.decryption_handle * private_key.0;
        for x_low in 0..1 << 16 {
            if let Some(&x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + ((x_high as u32) << 16));
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

/// This represents a ZK proof that two ciphertext are for the same message.
pub struct EqualityProof {
    y: (
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
    ),
    z: (RistrettoScalar, RistrettoScalar, RistrettoScalar),
}

impl EqualityProof {
    pub fn prove(
        value: &RistrettoScalar,
        ciphertext: &Ciphertext,
        sk: &PrivateKey,
        other_ciphertext: &Ciphertext,
        other_blinding: &Blinding,
        other_pk: &PublicKey,
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
            other_pk.0 * r.2,
        );

        let challenge = Self::challenge(ciphertext, &pk, other_ciphertext, other_pk, &y);

        let z = (
            challenge * sk.0 + r.0,
            challenge * value + r.1,
            challenge * other_blinding.0 + r.2,
        );

        Self { y, z }
    }

    fn challenge(
        ciphertext: &Ciphertext,
        pk: &PublicKey,
        other_ciphertext: &Ciphertext,
        other_pk: &PublicKey,
        y: &(
            RistrettoPoint,
            RistrettoPoint,
            RistrettoPoint,
            RistrettoPoint,
        ),
    ) -> RistrettoScalar {
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&(ciphertext, pk, other_ciphertext, other_pk, y)).unwrap(),
        )
    }

    pub fn verify(
        &self,
        ciphertext: &Ciphertext,
        pk: &PublicKey,
        other_ciphertext: &Ciphertext,
        other_pk: &PublicKey,
    ) -> FastCryptoResult<()> {
        let challenge = -Self::challenge(ciphertext, pk, other_ciphertext, other_pk, &self.y);
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
                    &[*G, *H, other_ciphertext.commitment.0],
                )
                .unwrap(),
                RistrettoPoint::multi_scalar_mul(
                    &[self.z.2, challenge],
                    &[other_pk.0, other_ciphertext.decryption_handle],
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

pub struct MultiRecipientEncryption {
    commitment: PedersenCommitment,
    decryption_handles: Vec<RistrettoPoint>,
}

impl MultiRecipientEncryption {
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
/// The table contains a mapping from Ristretto points <i>(2<sup>16</sup> x) G<i> to <i>x</i> for all <i>x</i> in the range <i>0, .., 2<sup>16</sup>-1</i>.
pub fn precompute_table() -> HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16> {
    let step = G.repeated_doubling(16);
    successors(Some(RistrettoPoint::zero()), |p| Some(p + step))
        .enumerate()
        .map(|(i, p)| (p.to_byte_array(), i as u16))
        .take(1 << 16)
        .collect()
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

    let (other_pk, _) = generate_keypair(&mut rng);
    let (other_ciphertext, other_blinding) = Ciphertext::encrypt(&other_pk, value, &mut rng);
    let proof = EqualityProof::prove(
        &RistrettoScalar::from(value as u64),
        &ciphertext,
        &sk,
        &other_ciphertext,
        &other_blinding,
        &other_pk,
        &mut rng,
    );
    proof
        .verify(&ciphertext, &pk, &other_ciphertext, &other_pk)
        .unwrap();
}

#[test]
fn encrypt_and_range_proof() {
    let value = 1234u32;
    let range = crate::bulletproofs::Range::Bits32;
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, blinding) = Ciphertext::encrypt(&pk, value, &mut rng);
    let domain = b"test";
    let range_proof =
        crate::bulletproofs::RangeProof::prove(value as u64, &blinding, &range, domain, &mut rng)
            .unwrap();

    assert!(range_proof
        .verify(&ciphertext.commitment, &range, domain, &mut rng)
        .is_ok());

    assert_eq!(ciphertext.decrypt(&sk, &precompute_table()).unwrap(), value);
}

#[test]
fn linear_encryptions() {
    let value_1 = 12u32;
    let value_2 = 34u32;
    let s = 7u32;
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let (ciphertext_1, _) = Ciphertext::encrypt(&pk, value_1, &mut rand::thread_rng());
    let (ciphertext_2, _) = Ciphertext::encrypt(&pk, value_2, &mut rand::thread_rng());
    let ciphertext_3 = ciphertext_1 + ciphertext_2 * RistrettoScalar::from(s as u64);
    assert_eq!(
        ciphertext_3.decrypt(&sk, &precompute_table()).unwrap(),
        value_1 + value_2 * s
    );
}
