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
//!    RangeProof::prove_bit_length(value, upper_bound, blinding, b"MY_DOMAIN").unwrap();
//! assert!(range_proof.verify_bit_length(upper_bound, b"MY_DOMAIN").is_ok());
//! ```

use crate::error::FastCryptoError::{GeneralOpaqueError, InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::groups::Scalar;
use crate::pedersen::{Blinding, PedersenCommitment};
use crate::traits::AllowedRng;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as ExternalRangeProof};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// Bulletproof Range Proofs
#[derive(Debug, Serialize, Deserialize)]
pub struct RangeProof(ExternalRangeProof);

/// The output of [RangeProof::prove].
pub struct RangeProofOutput {
    /// The bulletproof range proof.
    pub proof: RangeProof,

    /// A commitment to the value used in the range proof.
    pub commitment: PedersenCommitment,

    /// The blinding factor. The prover should keep this secret until the commitment needs to be revealed.
    pub blinding: Blinding,
}

/// The output of [RangeProof::prove_aggregated].
pub struct AggregateRangeProofOutput {
    /// The bulletproof range proof.
    pub proof: RangeProof,

    /// Commitments to the value used in the range proof.
    pub commitments: Vec<PedersenCommitment>,

    /// The blinding factors. The prover should keep these secret until the commitment needs to be revealed.
    pub blindings: Vec<Blinding>,
}

impl RangeProof {
    /// Prove that the value is an unsigned integer with bit length bits, this is equivalent
    /// to proving that the value is an integer within the range [0, 2^bits).
    /// Returns an `InvalidInput` error if `bits` is not one of 8, 16, 32, 64.
    pub fn prove(
        value: u64,
        bits: usize,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProofOutput> {
        Self::prove_aggregated(&[value], bits, domain, rng).map(|value| RangeProofOutput {
            proof: value.proof,
            commitment: value.commitments[0].clone(),
            blinding: value.blindings[0].clone(),
        })
    }

    pub fn prove_with_blinding(
        value: u64,
        blinding: Blinding,
        bits: usize,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProofOutput> {
        Self::prove_aggregated_with_blindings(&[value], vec![blinding], bits, domain, rng).map(
            |value| RangeProofOutput {
                proof: value.proof,
                commitment: value.commitments[0].clone(),
                blinding: value.blindings[0].clone(),
            },
        )
    }

    /// Verifies that a range proof that the commitment is to an integer in the range [0, 2^bits).
    /// Function only works for bits = 8, 16, 32, 64.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        blinding: &Blinding,
        bits: usize,
        domain: &'static [u8],
    ) -> FastCryptoResult<()> {
        self.verify_aggregated(&[commitment.clone()], &[blinding.clone()], bits, domain)
    }

    /// Create a proof that all the given `values` are smaller than <i>2<sup>bits</sup></i>.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> smaller than <i>2<sup>bits</sup></i>,
    /// * `values.len()` is not a power of 2,
    /// * `bits` is not one of 8, 16, 32, 64.
    pub fn prove_aggregated(
        values: &[u64],
        bits: usize,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<AggregateRangeProofOutput> {
        Self::prove_aggregated_with_blindings(
            values,
            values
                .iter()
                .map(|_| Blinding(RistrettoScalar::rand(rng)))
                .collect::<Vec<_>>(),
            bits,
            domain,
            rng,
        )
    }

    /// Create a proof that all the given `values` are smaller than <i>2<sup>bits</sup></i> using the given blinding factors.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> smaller than <i>2<sup>bits</sup></i>,
    /// * `values.len() != blindings.len()`,
    /// * `values.len()` is not a power of 2,
    /// * `bits` is not one of 8, 16, 32, 64.
    pub fn prove_aggregated_with_blindings(
        values: &[u64],
        blindings: Vec<Blinding>,
        bits: usize,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<AggregateRangeProofOutput> {
        if values.iter().any(|v| v.ilog2() as usize >= bits)
            || blindings.len() != values.len()
            || !values.len().is_power_of_two()
            || !(bits == 8 || bits == 16 || bits == 32 || bits == 64)
        {
            return Err(InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, values.len());
        let mut prover_transcript = Transcript::new(domain);

        // TODO: Can we avoid calculating the Pedersen commitments here if they are already available?
        ExternalRangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            values,
            &blindings.iter().map(|b| b.0 .0).collect::<Vec<_>>(),
            bits,
            rng,
        )
        .map(|(proof, commitments)| {
            AggregateRangeProofOutput {
                proof: RangeProof(proof),
                // TODO: There's an unnecessary compression happening inside the external crate
                commitments: commitments
                    .iter()
                    .map(|c| PedersenCommitment(RistrettoPoint(c.decompress().unwrap())))
                    .collect(),
                blindings,
            }
        })
        .map_err(|_| GeneralOpaqueError)
    }

    /// Verifies that a range proof that all commitments are too integers in the range [0, 2^bits).
    /// Function only works for bits = 8, 16, 32, 64.
    pub fn verify_aggregated(
        &self,
        commitments: &[PedersenCommitment],
        blindings: &[Blinding],
        bits: usize,
        domain: &'static [u8],
    ) -> FastCryptoResult<()> {
        if !(bits == 8 || bits == 16 || bits == 32 || bits == 64) {
            return Err(InvalidInput);
        }

        if commitments.len() != blindings.len() {
            return Err(InvalidInput);
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(bits, commitments.len());
        let mut verifier_transcript = Transcript::new(domain);

        self.0
            .verify_multiple(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &commitments
                    .iter()
                    .map(|c| c.0 .0.compress())
                    .collect::<Vec<_>>(),
                bits,
            )
            .map_err(|_| InvalidProof)
    }
}
