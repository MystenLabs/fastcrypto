// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of Pedersen Commitments and [Bulletproofs](https://crypto.stanford.edu/bulletproofs/), which are short non-interactive zero-knowledge proofs that require no trusted setup.
//!
//! # Example
//! ```rust
//! # use fastcrypto::bulletproofs::*;
//! use rand::{thread_rng, RngCore};
//! let value = 300;
//! let upper_bound = 16;
//! let mut blinding = [0u8; 32];
//! thread_rng().fill_bytes(&mut blinding);
//! let (commitment, range_proof) =
//!    BulletproofsRangeProof::prove_bit_length(value, blinding, upper_bound, b"MY_DOMAIN").unwrap();
//! assert!(range_proof.verify_bit_length(&commitment, upper_bound, b"MY_DOMAIN").is_ok());
//! ```
use std::ops;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use once_cell::sync::OnceCell;
use serde::{de, Deserialize, Serialize};

use crate::{error::FastCryptoError, traits::ToFromBytes};

//
// Pedersen commitments
//

const PEDERSEN_COMMITMENT_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    point: RistrettoPoint,
    bytes: OnceCell<[u8; PEDERSEN_COMMITMENT_LENGTH]>,
}

impl PedersenCommitment {
    ///
    /// Creates a new Pedersen commitment from a value, and a blinding factor
    ///
    pub fn new(
        value: [u8; PEDERSEN_COMMITMENT_LENGTH],
        blinding_factor: [u8; PEDERSEN_COMMITMENT_LENGTH],
    ) -> Self {
        let generators = PedersenGens::default();
        let value = Scalar::from_bits(value);
        let blinding = Scalar::from_bits(blinding_factor);
        let point = generators.commit(value, blinding);

        PedersenCommitment {
            point,
            bytes: OnceCell::new(),
        }
    }
}

impl ops::Add<PedersenCommitment> for PedersenCommitment {
    type Output = PedersenCommitment;

    fn add(self, rhs: PedersenCommitment) -> PedersenCommitment {
        PedersenCommitment {
            point: self.point + rhs.point,
            bytes: OnceCell::new(),
        }
    }
}

impl ops::Sub<PedersenCommitment> for PedersenCommitment {
    type Output = PedersenCommitment;

    fn sub(self, rhs: PedersenCommitment) -> PedersenCommitment {
        PedersenCommitment {
            point: self.point - rhs.point,
            bytes: OnceCell::new(),
        }
    }
}

impl AsRef<[u8]> for PedersenCommitment {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init(|| self.point.compress().to_bytes())
    }
}

impl ToFromBytes for PedersenCommitment {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != PEDERSEN_COMMITMENT_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(
                PEDERSEN_COMMITMENT_LENGTH,
            ));
        }
        let point = CompressedRistretto::from_slice(bytes);
        let decompressed_point = point.decompress().ok_or(FastCryptoError::InvalidInput)?;

        Ok(PedersenCommitment {
            point: decompressed_point,
            bytes: OnceCell::new(),
        })
    }
}

impl Serialize for PedersenCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.as_ref();
        serializer.serialize_bytes(bytes)
    }
}

impl<'de> Deserialize<'de> for PedersenCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes = Vec::deserialize(deserializer)?;
        PedersenCommitment::from_bytes(&bytes[..]).map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl PartialEq for PedersenCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Eq for PedersenCommitment {}

impl PartialOrd for PedersenCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for PedersenCommitment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

///
/// Bulletproof Range Proofs
///

#[derive(Debug)]
pub struct BulletproofsRangeProof {
    proof: RangeProof,
    bytes: OnceCell<Vec<u8>>,
}

impl BulletproofsRangeProof {
    /// Prove that the value is an unsigned integer with bit length bits, this is equivalent
    /// to proving that the value is an integer within the range [0, 2^bits)
    /// Function only works for bits = 8, 16, 32, 64.
    pub fn prove_bit_length(
        value: u64,
        blinding: [u8; 32],
        bits: usize,
        domain: &'static [u8],
    ) -> Result<(PedersenCommitment, Self), FastCryptoError> {
        // Although this is also checked in the bulletproofs library, we check again
        // to avoid unexpected behaviour in the case of library updates
        if !(bits == 8 || bits == 16 || bits == 32 || bits == 64) {
            return Err(FastCryptoError::InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, 1);
        let mut prover_transcript = Transcript::new(domain);
        let blinding = Scalar::from_bits(blinding);

        let (proof, commitment) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            value,
            &blinding,
            bits,
        )
        .map_err(|_| signature::Error::new())?;

        Ok((
            PedersenCommitment {
                point: commitment.decompress().ok_or_else(signature::Error::new)?,
                bytes: OnceCell::new(),
            },
            BulletproofsRangeProof {
                proof,
                bytes: OnceCell::new(),
            },
        ))
    }

    /// Verifies that commitment is a Pedersen commitment of some value
    /// with an unsigned bit length `bits`. This is equivalent to
    /// proving that the value is an integer within the range [0, 2^bits)
    /// Function only works for bits = 8, 16, 32, 64.
    pub fn verify_bit_length(
        &self,
        commitment: &PedersenCommitment,
        bits: usize,
        domain: &'static [u8],
    ) -> Result<(), FastCryptoError> {
        // Although this is also checked in the bulletproofs library, we check again
        // to avoid unexpected behaviour in the case of library updates
        if !(bits == 8 || bits == 16 || bits == 32 || bits == 64) {
            return Err(FastCryptoError::InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, 1);
        let mut verifier_transcript = Transcript::new(domain);

        self.proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &CompressedRistretto::from_slice(commitment.as_bytes()),
                bits,
            )
            .map_err(|_| FastCryptoError::GeneralError("Failed to verify proof".to_string()))
    }
}

impl AsRef<[u8]> for BulletproofsRangeProof {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init(|| self.proof.to_bytes())
    }
}

impl ToFromBytes for BulletproofsRangeProof {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let proof = RangeProof::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(BulletproofsRangeProof {
            proof,
            bytes: OnceCell::new(),
        })
    }
}
