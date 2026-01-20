// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of Pedersen Commitments and [Bulletproofs](https://crypto.stanford.edu/bulletproofs/), which are short non-interactive zero-knowledge proofs that require no trusted setup.
//!
//! # Example
//! ```rust
//! # use fastcrypto::bulletproofs::*;
//! use rand::{thread_rng, RngCore};
//! use fastcrypto::bulletproofs::Range::Bits16;
//! # use fastcrypto::groups::ristretto255::RistrettoScalar;
//! # use fastcrypto::groups::Scalar;
//! let value = 300;
//! let range = Bits16;
//! let output =
//!    RangeProof::prove(value, &range, b"MY_DOMAIN", &mut thread_rng()).unwrap();
//! assert!(output.proof.verify(&output.commitment, &output.blinding, &range, b"MY_DOMAIN").is_ok());
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

pub enum Range {
    /// The range [0,...,2^8).
    Bits8,

    /// The range [0,...,2^16).
    Bits16,

    /// The range [0,...,2^32).
    Bits32,

    /// The range [0,...,2^64).
    Bits64,
}

impl Range {
    pub fn is_in_range(&self, value: u64) -> bool {
        if value == 0 {
            return true;
        }
        value.ilog2() < self.upper_bound_in_bits()
    }

    fn upper_bound_in_bits(&self) -> u32 {
        match self {
            Range::Bits8 => 8,
            Range::Bits16 => 16,
            Range::Bits32 => 32,
            Range::Bits64 => 64,
        }
    }
}

impl RangeProof {
    /// Prove that the `value` is in the given range.
    /// Returns an `InvalidInput` error if the value is not in range.
    pub fn prove(
        value: u64,
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProofOutput> {
        Self::prove_aggregated(&[value], range, domain, rng).map(|value| RangeProofOutput {
            proof: value.proof,
            commitment: value.commitments[0].clone(),
            blinding: value.blindings[0].clone(),
        })
    }

    /// Prove that the `value` is in the given range using the given commitment blinding.
    /// This enables creating proofs for an existing commitment.
    /// Returns an `InvalidInput` error if the value is not in range.
    pub fn prove_with_blinding(
        value: u64,
        blinding: Blinding,
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProofOutput> {
        Self::prove_aggregated_with_blindings(&[value], vec![blinding], range, domain, rng).map(
            |value| RangeProofOutput {
                proof: value.proof,
                commitment: value.commitments[0].clone(),
                blinding: value.blindings[0].clone(),
            },
        )
    }

    /// Verifies a range proof: That the commitment is to a value in the given range.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        blinding: &Blinding,
        range: &Range,
        domain: &'static [u8],
    ) -> FastCryptoResult<()> {
        self.verify_aggregated(&[commitment.clone()], &[blinding.clone()], range, domain)
    }

    /// Create a proof that all the given `values` are in the given range.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> in the range,
    /// * `values.len()` is not a power of 2,
    pub fn prove_aggregated(
        values: &[u64],
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<AggregateRangeProofOutput> {
        Self::prove_aggregated_with_blindings(
            values,
            values
                .iter()
                .map(|_| Blinding(RistrettoScalar::rand(rng)))
                .collect::<Vec<_>>(),
            range,
            domain,
            rng,
        )
    }

    /// Create a proof that all the given `values` are in the range using the given commitment blindings.
    /// This enables creating proofs for existing commitments.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> in the range.
    /// * `values.len() != blindings.len()`,
    /// * `values.len()` is not a power of 2,
    pub fn prove_aggregated_with_blindings(
        values: &[u64],
        blindings: Vec<Blinding>,
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<AggregateRangeProofOutput> {
        if values.iter().any(|&v| !range.is_in_range(v))
            || blindings.len() != values.len()
            || !values.len().is_power_of_two()
        {
            return Err(InvalidInput);
        }

        let bits = range.upper_bound_in_bits() as usize;
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

    /// Verifies that a range proof that all commitments are to values in the given `range`.
    pub fn verify_aggregated(
        &self,
        commitments: &[PedersenCommitment],
        blindings: &[Blinding],
        range: &Range,
        domain: &'static [u8],
    ) -> FastCryptoResult<()> {
        if commitments.len() != blindings.len() {
            return Err(InvalidInput);
        }

        let bits = range.upper_bound_in_bits() as usize;
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

#[test]
fn test_is_in_range() {
    assert!(Range::Bits8.is_in_range(0));
    assert!(Range::Bits8.is_in_range(255));
    assert!(!Range::Bits8.is_in_range(256));
    assert!(Range::Bits16.is_in_range(0));
    assert!(Range::Bits16.is_in_range(65535));
    assert!(!Range::Bits16.is_in_range(65536));
    assert!(Range::Bits32.is_in_range(0));
    assert!(Range::Bits32.is_in_range(4294967295));
    assert!(!Range::Bits32.is_in_range(4294967296));
    assert!(Range::Bits64.is_in_range(0));
    assert!(Range::Bits64.is_in_range(u64::MAX));
}

#[test]
fn test_range_proof_valid() {
    use rand::thread_rng;
    let range = Range::Bits32;
    let output = RangeProof::prove(1u64, &range, b"NARWHAL", &mut thread_rng()).unwrap();
    assert!(output
        .proof
        .verify(&output.commitment, &output.blinding, &range, b"NARWHAL")
        .is_ok());
}
