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

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use derive_more::{Add, From, Sub};
use merlin::Transcript;
use once_cell::sync::OnceCell;

use crate::error::FastCryptoError::{GeneralOpaqueError, InvalidInput};
use crate::serde_helpers::ToFromByteArray;
use crate::{
    error::FastCryptoError, serialize_deserialize_with_to_from_byte_array, traits::ToFromBytes,
};

use serde::de;
use serde::Deserialize;

//
// Pedersen commitments
//

// TODO: The scalars (value and blinding) are created from the lower 255 bits of a 256 bit scalar, so we should require that the last bit is zero or use the scalars directly.

const PEDERSEN_COMMITMENT_LENGTH: usize = 32;

#[derive(Debug, Clone, From, Add, Sub, PartialEq, Eq)]
pub struct PedersenCommitment {
    point: RistrettoPoint,
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
        generators.commit(value, blinding).into()
    }
}

impl ToFromByteArray<PEDERSEN_COMMITMENT_LENGTH> for PedersenCommitment {
    fn from_byte_array(bytes: &[u8; PEDERSEN_COMMITMENT_LENGTH]) -> Result<Self, FastCryptoError> {
        let point = CompressedRistretto::from_slice(bytes);
        point.decompress().ok_or(InvalidInput).map(Self::from)
    }

    fn to_byte_array(&self) -> [u8; PEDERSEN_COMMITMENT_LENGTH] {
        self.point.compress().to_bytes()
    }
}

serialize_deserialize_with_to_from_byte_array!(PedersenCommitment);

///
/// Bulletproof Range Proofs
///

#[derive(Debug)]
pub struct BulletproofsRangeProof {
    proof: RangeProof,
    bytes: OnceCell<Vec<u8>>,
}

impl From<RangeProof> for BulletproofsRangeProof {
    fn from(proof: RangeProof) -> Self {
        Self {
            proof,
            bytes: OnceCell::new(),
        }
    }
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
        .map_err(|_| GeneralOpaqueError)?;

        Ok((
            commitment.decompress().ok_or(GeneralOpaqueError)?.into(),
            proof.into(),
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
                &CompressedRistretto::from_slice(&commitment.to_byte_array()),
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
        RangeProof::from_bytes(bytes)
            .map_err(|_| InvalidInput)
            .map(Self::from)
    }
}
