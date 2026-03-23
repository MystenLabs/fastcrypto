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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

/// A verifiable ciphertext is a collection of 32-bit ciphertexts ct_i and a 32-bit batch range proof showing that each
/// ct_i lies in the range [0, 2^32-1]. Supports encryption towards multiple recipients.
pub struct VerifiableCiphertext<const N: usize> {
    pub commitments: [PedersenCommitment; N],
    pub decryption_handles: Vec<[RistrettoPoint; N]>,
    pub range_proof: RangeProof,
}

impl<const N: usize> VerifiableCiphertext<N> {
    /// Seal `N` messages to multiple recipient public keys where `N` is a power of two.
    pub fn batch_seal(
        public_keys: &[PublicKey],
        messages: &[u32; N],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, [Blinding; N])> {
        assert!(N.is_power_of_two(), "N must be a power of two");
    let messages = messages.map(|m| m as u64);
    let blindings = array::from_fn(|_| Blinding::rand(rng));
    let commitments = array::from_fn(|i| {
        PedersenCommitment::new(&RistrettoScalar::from(messages[i]), &blindings[i])
    });
    let decryption_handles: Vec<[RistrettoPoint; N]> = public_keys
        .iter()
        .map(|pk| blindings.each_ref().map(|b| pk.0 * b.0))
        .collect();
    let range_proof = RangeProof::prove_batch(&messages, &blindings, &Range::Bits32, rng)?;
        Ok((
            Self {
                commitments,
                decryption_handles,
                range_proof,
            },
            blindings,
        ))
    }

    /// Seal a message to a single recipient public key
    pub fn seal(
        public_key: &PublicKey,
        messages: &[u32; N],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, [Blinding; N])> {
        Self::batch_seal(&[public_key], messages, rng)
    }

    /// Verify the range proof corresponding to this ciphertext
    pub fn verify(&self, rng: &mut impl AllowedRng) -> FastCryptoResult<()> {
        self.range_proof
            .verify_batch(&self.commitments, &Range::Bits32, rng)
    }

    /// Open the ciphertext of a single recipient identified by the provided index
    pub fn open(
        &self,
        idx: usize,
        decryption_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Vec<u32>> {
        if idx >= self.decryption_handles.len() {
            return Err(InvalidInput);
        }
        self.verify(rng)?;
        self.commitments
            .iter()
            .zip(self.decryption_handles[idx].iter())
            .map(|(commitment, handle)| {
                Ciphertext {
                    commitment: commitment.clone(),
                    decryption_handle: *handle,
                }
                .decrypt(decryption_key, table)
            })
            .collect()
    }
}

/// A verifiable key encapsulation allows to verifiably encrypt a private key. The private key is encrypted into a
/// verifiable ciphertext containing a batch range proof. An additional DLEQ NIZK proof shows that the encrypted private
/// key limbs match the corresponding public key. Supports encryption towards multiple recipients.
pub struct VerifiableKeyEncapsulation {
    pub verifiable_ciphertext: VerifiableCiphertext<8>,
    pub dleq_proof: DdhTupleNizk<RistrettoPoint>,
    pub r: RistrettoScalar,
}

impl VerifiableKeyEncapsulation {
    /// Verifiably encrypt a private key to multiple recipient public keys
    pub fn batch_seal(
        public_keys: &[PublicKey],
        private_key: &PrivateKey,
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation {
        // Re-arrange private key into 32-bit limbs
        let private_key_bytes = private_key.0.to_byte_array();
        let limbs: [u32; 8] = std::array::from_fn(|i| {
            u32::from_le_bytes(private_key_bytes[4 * i..4 * (i + 1)].try_into().unwrap())
        });
        // Encrypt 32-bit key limbs with Twisted ElGamal and create a batch range proof
        let (verifiable_ciphertext, blindings) =
            VerifiableCiphertext::batch_seal(public_keys, &limbs, rng).unwrap();
        // Create DLEQ NIZK proof (G, H, sk * G, sk * H) for private key sk
        let dleq_proof = DdhTupleNizk::create(
            &private_key.0,
            &*G,
            &*H,
            &(*G * private_key.0),
            &(*H * private_key.0),
            rng,
        );
        // Compute r = sum_i(r_i * 2^{32i}) for range proof blinding factors r_i which is required for the DLEQ NIZK proof verification
        let b = RistrettoScalar::from(1u64 << 32); // 2**32
        let (r, _) = blindings.iter().fold(
            (RistrettoScalar::from(0u64), RistrettoScalar::from(1u64)),
            |(r_acc, e), ri| (r_acc + ri.0 * e, e * b),
        );
        VerifiableKeyEncapsulation {
            verifiable_ciphertext,
            dleq_proof,
            r, // TODO: doublecheck if it's okay to "leak" r
        }
    }

    /// Verifiably encrypt a private key to a single recipient public key
    pub fn seal(
        public_key: &PublicKey,
        private_key: &PrivateKey,
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation {
        Self::batch_seal(&[public_key], private_key, rng)
    }

    /// Verify the range proof and DLEQ NIZK proof corresponding to this key encapsulation
    pub fn verify(
        &self,
        public_key: &PublicKey,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        // Verify range proofs
        self.verifiable_ciphertext.verify(rng)?;
        // Compute C = sum_i(C_i * 2^{32i}) for range proof commitments C_i; note: C = sk * H + r * G
        let b = RistrettoScalar::from(1u64 << 32); // 2**32
        let (c, _) = self.verifiable_ciphertext.commitments.iter().fold(
            (RistrettoPoint::zero(), RistrettoScalar::from(1u64)),
            |(c_acc, e), ci| (c_acc + ci.0 * e, e * b),
        );
        // Verify DLEQ NIZK proof
        self.dleq_proof.verify(
            &*G,
            &*H,
            &public_key.0,      // sk * G
            &(c - *G * self.r), // C - r * G = sk * H
        )
    }

    /// Open the key encapsulation for a single recipient public key identified by the provided index
    pub fn open(
        &self,
        idx: usize,
        public_key: &PublicKey,
        decryption_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<PrivateKey> {
        // Verify ciphertext
        self.verify(public_key, rng)?;
        // Decrypt 32-bit private key limbs
        let limbs = self
            .verifiable_ciphertext
            .open(idx, decryption_key, table, rng)?;
        // Recover private key bytes
        let mut private_key_bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            private_key_bytes[4 * i..4 * i + 4].copy_from_slice(&limb.to_le_bytes());
        }
        let private_key = RistrettoScalar::from_byte_array(&private_key_bytes)?;
        if pk_from_sk(&PrivateKey(private_key)) != *public_key {
            return Err(InvalidInput);
        }
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
    let messages: [u32; 8] = [1, 23, 456, 789, 987, 654, 32, 1];
    let (verifiable_ciphertext, _blindings) =
        VerifiableCiphertext::seal(&public_key, &messages, &mut rng).unwrap();
    assert!(verifiable_ciphertext.verify(&mut rng).is_ok());
    let decrypted_messages = verifiable_ciphertext
        .open(0, &private_key, &table, &mut rng)
        .unwrap();
    assert_eq!(messages.as_slice(), decrypted_messages);
}

#[test]
fn test_verifiable_key_encapsulation() {
    let mut rng = rand::thread_rng();
    let table = precompute_table();
    let (pk_snd, sk_snd) = generate_keypair(&mut rng); // sender key pair
    let (pk_rcv, sk_rcv) = generate_keypair(&mut rng); // receiver key pair
    let encapsulation = VerifiableKeyEncapsulation::seal(&pk_rcv, &sk_snd, &mut rng);
    assert!(encapsulation.verify(&pk_snd, &mut rng).is_ok());
    let recovered_private_key = encapsulation
        .open(0, &pk_snd, &sk_rcv, &table, &mut rng)
        .unwrap();
    assert_eq!(recovered_private_key.0, sk_snd.0);
}

#[test]
fn test_verifiable_key_encapsulation_batch() {
    let mut rng = rand::thread_rng();
    let table = precompute_table();

    // Sender key pair (private key being encrypted)
    let (pk_snd, sk_snd) = generate_keypair(&mut rng);

    // Three recipient key pairs
    let (pk_rcv_0, sk_rcv_0) = generate_keypair(&mut rng);
    let (pk_rcv_1, sk_rcv_1) = generate_keypair(&mut rng);
    let (pk_rcv_2, sk_rcv_2) = generate_keypair(&mut rng);

    let encapsulation = VerifiableKeyEncapsulation::batch_seal(
        &[&pk_rcv_0, &pk_rcv_1, &pk_rcv_2],
        &sk_snd,
        &mut rng,
    );

    // Verification passes for the sender's public key
    assert!(encapsulation.verify(&pk_snd, &mut rng).is_ok());

    // Each recipient can independently recover the sender's private key
    let recovered_0 = encapsulation
        .open(0, &pk_snd, &sk_rcv_0, &table, &mut rng)
        .unwrap();
    let recovered_1 = encapsulation
        .open(1, &pk_snd, &sk_rcv_1, &table, &mut rng)
        .unwrap();
    let recovered_2 = encapsulation
        .open(2, &pk_snd, &sk_rcv_2, &table, &mut rng)
        .unwrap();
    assert_eq!(recovered_0.0, sk_snd.0);
    assert_eq!(recovered_1.0, sk_snd.0);
    assert_eq!(recovered_2.0, sk_snd.0);

    // A recipient cannot open another recipient's slot with their own key
    assert!(encapsulation
        .open(1, &pk_snd, &sk_rcv_0, &table, &mut rng)
        .is_err());
}
