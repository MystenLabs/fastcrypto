// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bulletproofs::{Range, RangeProof};
use crate::error::FastCryptoError::InvalidInput;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar, RISTRETTO_POINT_BYTE_LENGTH};
use crate::groups::{Doubling, GroupElement, Scalar};
use crate::nizk::DdhTupleNizk;
use crate::pedersen::{Blinding, PedersenCommitment, G, H};
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
    pub fn zero_proof(&self, private_key: &PrivateKey, rng: &mut impl AllowedRng) -> ZeroProof {
        let pk = pk_from_sk(private_key);
        ZeroProof(DdhTupleNizk::create(
            &private_key.0,
            &RistrettoPoint::generator(),
            &self.commitment.0,
            &pk.0,
            &self.decryption_handle,
            rng,
        ))
    }
}

impl ZeroProof {
    pub fn verify(&self, encryption: &Ciphertext, pk: &PublicKey) -> FastCryptoResult<()> {
        self.0.verify(
            &RistrettoPoint::generator(),
            &encryption.commitment.0,
            &pk.0,
            &encryption.decryption_handle,
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

pub struct VerifiableCiphertext {
    pub ciphertexts: Vec<Ciphertext>,
    pub range_proof: RangeProof,
}

impl VerifiableCiphertext {
    pub fn seal(
        public_key: &PublicKey,
        messages: &[u32],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, Vec<Blinding>)> {
        let (ciphertexts, blindings): (Vec<Ciphertext>, Vec<Blinding>) = messages
            .iter()
            .map(|&m| Ciphertext::encrypt(public_key, m, rng))
            .unzip();
        let messages_u64: Vec<u64> = messages.iter().map(|&m| m as u64).collect();
        let range_proof = RangeProof::prove_batch(&messages_u64, &blindings, &Range::Bits32, rng)?;
        Ok((
            Self {
                ciphertexts,
                range_proof,
            },
            blindings, // TODO: do we need to return these? Probably better to return the combined value.
        ))
    }

    pub fn verify(&self, rng: &mut impl AllowedRng) -> FastCryptoResult<()> {
        let commitments: Vec<PedersenCommitment> = self
            .ciphertexts
            .iter()
            .map(|ct| ct.commitment.clone())
            .collect();
        self.range_proof
            .verify_batch(&commitments, &Range::Bits32, rng)
    }

    pub fn open(
        &self,
        private_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Vec<u32>> {
        self.verify(rng)?;
        self.ciphertexts
            .iter()
            .map(|ct| ct.decrypt(private_key, table))
            .collect()
    }
}

pub struct VerifiableKeyEncapsulation {
    pub verifiable_ciphertext: VerifiableCiphertext,
    pub r: RistrettoScalar,
    pub key_proof: DdhTupleNizk<RistrettoPoint>
}

impl VerifiableKeyEncapsulation {
    pub fn seal(
        public_key: &PublicKey, 
        private_key: &PrivateKey, 
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation {
        let private_key_bytes = private_key.0.to_byte_array();
        let limbs: Vec<u32> = (0..8)
            .map(|i| u32::from_le_bytes(private_key_bytes[4*i..4*(i+1)].try_into().unwrap()))
            .collect();
        let (verifiable_ciphertext, blindings) = VerifiableCiphertext::seal(public_key, &limbs, rng).unwrap();
        let b = RistrettoScalar::from(1u64 << 32); // 2**32
        let mut e = RistrettoScalar::from(1u64); // 2**(i * 32) for i = 0..7
        let mut r = RistrettoScalar::from(0u64); // r = sum_i(r_i * 2**(i * 32))
        for ri in &blindings {
            r += ri.0 * e;
            e *= b;
        }
        let key_proof = DdhTupleNizk::create(
            &private_key.0,
            &*G,
            &*H,
            &(*G * private_key.0),
            &(*H * private_key.0),
            rng,
        );
        VerifiableKeyEncapsulation{ 
            verifiable_ciphertext,
            r, // TODO: doublecheck if it's okay to "leak" r
            key_proof 
        }
    }

    pub fn verify(
        &self, 
        public_key: 
        &PublicKey, 
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        self.verifiable_ciphertext.verify(rng)?;
        let b = RistrettoScalar::from(1u64 << 32); // 2**32
        let mut e = RistrettoScalar::from(1u64);
        let mut c = RistrettoPoint::zero();
        for ct in &self.verifiable_ciphertext.ciphertexts {
            c += ct.commitment.0 * e;
            e *= b;
        }
        self.key_proof.verify(
            &*G, 
            &*H, 
            &public_key.0, 
            &(c - *G * self.r)
        )
    }

    pub fn open(
        &self,
        public_key: &PublicKey,
        decryption_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<PrivateKey> {
        self.verify(public_key, rng)?;
        let limbs = self.verifiable_ciphertext.open(decryption_key, table, rng)?;
        let mut private_key_bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            private_key_bytes[4*i..4*i+4].copy_from_slice(&limb.to_le_bytes());
        }
        let private_key = RistrettoScalar::from_byte_array(&private_key_bytes)?;
        Ok(PrivateKey(private_key))
    }
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
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, _) = Ciphertext::encrypt(&pk, 0, &mut rng);
    let zero_proof = ciphertext.zero_proof(&sk, &mut rng);
    zero_proof.verify(&ciphertext, &pk).unwrap();

    let (other_ciphertext, _) = Ciphertext::encrypt(&pk, 1, &mut rng);
    let other_zero_proof = other_ciphertext.zero_proof(&sk, &mut rng);
    other_zero_proof.verify(&ciphertext, &pk).unwrap_err();
}

#[test]
fn encrypt_and_range_proof() {
    let value = 1234u32;
    let range = crate::bulletproofs::Range::Bits32;
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, blinding) = Ciphertext::encrypt(&pk, value, &mut rng);
    let range_proof =
        crate::bulletproofs::RangeProof::prove(value as u64, &blinding, &range, &mut rng).unwrap();

    assert!(range_proof
        .verify(&ciphertext.commitment, &range, &mut rng)
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

    let mut rng = rand::thread_rng();

    diff.zero_proof(&sk, &mut rng).verify(&diff, &pk).unwrap();

    let other_value = 1234u32;
    let encryption_3 = Ciphertext::encrypt(&pk, other_value, &mut rand::thread_rng());
    let other_diff = encryption_1.0 - encryption_3.0;
    other_diff
        .zero_proof(&sk, &mut rng)
        .verify(&other_diff, &pk)
        .unwrap_err();
}

#[test]
fn test_verifiable_ciphertext() {
    let mut rng = rand::thread_rng();
    let (public_key, private_key) = generate_keypair(&mut rng);
    let table = precompute_table();
    let messages: Vec<u32> = vec![1, 23, 456, 789, 987, 654, 32, 1];
    let (verifiable_ciphertext, _blindings) =
        VerifiableCiphertext::seal(&public_key, &messages, &mut rng).unwrap();
    assert!(verifiable_ciphertext.verify(&mut rng).is_ok());
    let decrypted_messages = verifiable_ciphertext
        .open(&private_key, &table, &mut rng)
        .unwrap();
    assert_eq!(messages, decrypted_messages);
}

#[test]
fn test_verifiable_key_encapsulation() {
    let mut rng = rand::thread_rng();
    let table = precompute_table();
    let (pk_send, sk_send) = generate_keypair(&mut rng);
    let (pk_recv, sk_recv) = generate_keypair(&mut rng);
    let encapsulation = VerifiableKeyEncapsulation::seal(&pk_recv, &sk_send, &mut rng);
    assert!(encapsulation.verify(&pk_send, &mut rng).is_ok());
    let recovered_private_key = encapsulation.open(&pk_send, &sk_recv, &table, &mut rng).unwrap();
    assert_eq!(recovered_private_key.0, sk_send.0);
}
