// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of Pedersen Commitments and [Bulletproofs](https://crypto.stanford.edu/bulletproofs/), which are short non-interactive zero-knowledge proofs that require no trusted setup.
//!
//! # Example
//! ```rust
//! # use fastcrypto::bulletproofs::*;
//! use rand::{thread_rng, RngCore};
//! use fastcrypto::groups::ristretto255::RistrettoScalar;
//! # use fastcrypto::groups::Scalar;
//! let value = 300;
//! let upper_bound = 16;
//! let mut blinding = RistrettoScalar::rand(&mut thread_rng());
//! let range_proof =
//!    RangeProof::prove_bit_length(value, blinding, upper_bound, b"MY_DOMAIN").unwrap();
//! assert!(range_proof.verify_bit_length(upper_bound, b"MY_DOMAIN").is_ok());
//! ```

use crate::error::FastCryptoError::{GeneralOpaqueError, InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::RistrettoScalar;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as ExternalRangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

///
/// Bulletproof Range Proofs
///

#[derive(Debug, Serialize, Deserialize)]
pub struct RangeProof {
    proof: ExternalRangeProof,
    commitment: CompressedRistretto,
}

impl RangeProof {
    /// Prove that the value is an unsigned integer with bit length bits, this is equivalent
    /// to proving that the value is an integer within the range [0, 2^bits).
    /// Returns an `InvalidInput` error if bits is not one of 8, 16, 32, 64.
    pub fn prove_bit_length(
        value: u64,
        blinding: RistrettoScalar,
        bits: usize,
        domain: &'static [u8],
    ) -> FastCryptoResult<Self> {
        // Although this is also checked in the bulletproofs library, we check again
        // to avoid unexpected behaviour in the case of library updates
        if !(bits == 8 || bits == 16 || bits == 32 || bits == 64) {
            return Err(InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, 1);
        let mut prover_transcript = Transcript::new(domain);

        ExternalRangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            value,
            &blinding.0,
            bits,
        )
        .map(|(proof, commitment)| Self { proof, commitment })
        .map_err(|_| GeneralOpaqueError)
    }

    /// Verifies that a range proof that a value is an integer within the range [0, 2^bits).
    /// Function only works for bits = 8, 16, 32, 64.
    pub fn verify_bit_length(&self, bits: usize, domain: &'static [u8]) -> FastCryptoResult<()> {
        // Although this is also checked in the bulletproofs library, we check again
        // to avoid unexpected behaviour in the case of library updates
        if !(bits == 8 || bits == 16 || bits == 32 || bits == 64) {
            return Err(InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, 1);
        let mut verifier_transcript = Transcript::new(domain);

        self.proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &self.commitment,
                bits,
            )
            .map_err(|_| InvalidProof)
    }
}

pub struct AggregateRangeProof {
    proof: ExternalRangeProof,
    commitments: Vec<CompressedRistretto>,
}

impl AggregateRangeProof {
    /// Create a proof that all the given `values` are smaller than <i>2<sup>bits</sup></i>.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> smaller than <i>2<sup>bits</sup></i>,
    /// * `values.len() != blinding_factors.len()`,
    /// * `values.len()` is not a power of 2,
    /// * `bits` is not one of 8, 16, 32, 64.
    pub fn prove_bit_length(
        values: &[u64],
        blinding_factors: &[RistrettoScalar],
        bits: usize,
        domain: &'static [u8],
    ) -> FastCryptoResult<Self> {
        if values.iter().any(|v| v.ilog2() as usize >= bits)
            || values.len() != blinding_factors.len()
            || !values.len().is_power_of_two()
            || !(bits == 8 || bits == 16 || bits == 32 || bits == 64)
        {
            return Err(InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, values.len());
        let mut prover_transcript = Transcript::new(domain);

        ExternalRangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            values,
            &blinding_factors.iter().map(|b| b.0).collect::<Vec<_>>(),
            bits,
        )
        .map(|(proof, commitments)| Self { proof, commitments })
        .map_err(|_| GeneralOpaqueError)
    }

    pub fn verify_bit_length(&self, bits: usize, domain: &'static [u8]) -> FastCryptoResult<()> {
        if !(bits == 8 || bits == 16 || bits == 32 || bits == 64) {
            return Err(InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, self.commitments.len());
        let mut verifier_transcript = Transcript::new(domain);

        self.proof
            .verify_multiple(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &self.commitments,
                bits,
            )
            .map_err(|_| InvalidProof)
    }
}
