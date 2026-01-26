// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError::InvalidInput;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar, RISTRETTO_POINT_BYTE_LENGTH};
use crate::groups::{Doubling, GroupElement, Scalar};
use crate::nizk::DdhTupleNizk;
use crate::pedersen::{Blinding, PedersenCommitment, G, H};
use crate::random_oracle::RandomOracle;
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use derive_more::{Add, Mul, Sub};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::successors;

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKey(RistrettoScalar);

#[derive(Debug, Serialize, Deserialize)]
pub struct ZeroProof(DdhTupleNizk<RistrettoPoint>);

pub fn generate_keypair(rng: &mut impl AllowedRng) -> (PublicKey, PrivateKey) {
    let sk = PrivateKey(RistrettoScalar::rand(rng));
    (pk_from_sk(&sk), sk)
}

pub fn pk_from_sk(sk: &PrivateKey) -> PublicKey {
    PublicKey(*G * sk.0)
}

// TODO: Encryptions of the same message can reuse commitments
#[derive(Debug, Clone, Add, Sub, Mul, Serialize, Deserialize)]
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
                commitment: PedersenCommitment::new(
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
        let mut c = self.commitment.0 - (self.decryption_handle / private_key.0)?;
        for x_low in 0..1 << 16 {
            if let Some(&x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + ((x_high as u32) << 16));
            }
            c -= *H;
        }
        Err(InvalidInput)
    }

    /// Create a PoK of a private key such that the given encryption is of the message 0.
    pub fn zero_proof(
        &self,
        private_key: &PrivateKey,
        random_oracle: &RandomOracle,
        rng: &mut impl AllowedRng,
    ) -> ZeroProof {
        let pk = pk_from_sk(private_key);
        ZeroProof(DdhTupleNizk::create(
            &private_key.0,
            &self.commitment.0,
            &pk.0,
            &self.decryption_handle,
            random_oracle,
            rng,
        ))
    }
}

impl ZeroProof {
    pub fn verify(
        &self,
        encryption: &Ciphertext,
        pk: &PublicKey,
        random_oracle: &RandomOracle,
    ) -> FastCryptoResult<()> {
        self.0.verify(
            &encryption.commitment.0,
            &pk.0,
            &encryption.decryption_handle,
            random_oracle,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
                commitment: PedersenCommitment::new(
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
    let step = H.repeated_doubling(16);
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
    let random_oracle = RandomOracle::new("zero_proof_test");
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, _) = Ciphertext::encrypt(&pk, 0, &mut rng);
    let zero_proof = ciphertext.zero_proof(&sk, &random_oracle, &mut rng);
    zero_proof.verify(&ciphertext, &pk, &random_oracle).unwrap();

    let (other_ciphertext, _) = Ciphertext::encrypt(&pk, 1, &mut rng);
    let other_zero_proof = other_ciphertext.zero_proof(&sk, &random_oracle, &mut rng);
    other_zero_proof
        .verify(&ciphertext, &pk, &random_oracle)
        .unwrap_err();
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

#[test]
fn test_equality() {
    let value = 123u32;
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let encryption_1 = Ciphertext::encrypt(&pk, value, &mut rand::thread_rng());
    let encryption_2 = Ciphertext::encrypt(&pk, value, &mut rand::thread_rng());

    let diff = encryption_1.0.clone() - encryption_2.0;

    let random_oracle = RandomOracle::new("zero_proof_test");
    let mut rng = rand::thread_rng();

    diff.zero_proof(&sk, &random_oracle, &mut rng)
        .verify(&diff, &pk, &random_oracle)
        .unwrap();

    let other_value = 1234u32;
    let encryption_3 = Ciphertext::encrypt(&pk, other_value, &mut rand::thread_rng());
    let other_diff = encryption_1.0 - encryption_3.0;
    other_diff
        .zero_proof(&sk, &random_oracle, &mut rng)
        .verify(&other_diff, &pk, &random_oracle)
        .unwrap_err();
}
