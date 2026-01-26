// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of Pedersen Commitments and [Bulletproofs](https://crypto.stanford.edu/bulletproofs/), which are short non-interactive zero-knowledge proofs that require no trusted setup.
//!
//! # Example
//! ```rust
//! # use fastcrypto::bulletproofs::*;
//! # use fastcrypto::bulletproofs::Range::Bits16;
//! # use fastcrypto::groups::ristretto255::RistrettoScalar;
//! # use fastcrypto::groups::Scalar;
//! use fastcrypto::pedersen::{Blinding, PedersenCommitment};
//! let value = 300;
//! let range = Bits16;
//! let mut rng = rand::thread_rng();
//! let blinding = Blinding::rand(&mut rng);
//! let proof =
//!    RangeProof::prove(value, &blinding, &range, b"MY_DOMAIN", &mut rng).unwrap();
//! let commitment = PedersenCommitment::new(&RistrettoScalar::from(value), &blinding);
//! assert!(proof.verify(&commitment, &range, b"MY_DOMAIN", &mut rng).is_ok());
//! ```

use crate::error::FastCryptoError::{GeneralOpaqueError, InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::pedersen::{Blinding, PedersenCommitment, GENERATORS};
use crate::traits::AllowedRng;
use bulletproofs::{BulletproofGens, RangeProof as ExternalRangeProof};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// Bulletproof Range Proofs
#[derive(Debug, Serialize, Deserialize)]
pub struct RangeProof(ExternalRangeProof);

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
    /// Prove that the `value` is in the given range using the given commitment blinding.
    /// This enables creating proofs for an existing commitment.
    /// Returns an `InvalidInput` error if the value is not in range.
    pub fn prove(
        value: u64,
        blinding: &Blinding,
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        Self::prove_batch(&[value], &[blinding.clone()], range, domain, rng)
    }

    /// Verifies a range proof: That the commitment is to a value in the given range.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        self.verify_batch(&[commitment.clone()], range, domain, rng)
    }

    /// Create a proof that all the given `values` are in the range using the given commitment blindings.
    /// This enables creating proofs for existing commitments.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> in the range.
    /// * `values.len() != blindings.len()`,
    /// * `values.len()` is not a power of 2,
    pub fn prove_batch(
        values: &[u64],
        blindings: &[Blinding],
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        if values.iter().any(|&v| !range.is_in_range(v))
            || blindings.len() != values.len()
            || !values.len().is_power_of_two()
        {
            return Err(InvalidInput);
        }

        let bits = range.upper_bound_in_bits() as usize;
        let bp_gens = BulletproofGens::new(bits, values.len());
        let mut prover_transcript = Transcript::new(domain);

        // TODO: Can we avoid calculating the Pedersen commitments here?
        ExternalRangeProof::prove_multiple_with_rng(
            &bp_gens,
            &GENERATORS,
            &mut prover_transcript,
            values,
            &blindings.iter().map(|b| b.0 .0).collect::<Vec<_>>(),
            bits,
            rng,
        )
        .map(|(proof, _)| RangeProof(proof))
        .map_err(|_| GeneralOpaqueError)
    }

    /// Verifies that a range proof that all commitments are to values in the given `range`.
    pub fn verify_batch(
        &self,
        commitments: &[PedersenCommitment],
        range: &Range,
        domain: &'static [u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        let bits = range.upper_bound_in_bits() as usize;
        let bp_gens = BulletproofGens::new(bits, commitments.len());
        let mut verifier_transcript = Transcript::new(domain);

        self.0
            .verify_multiple_with_rng(
                &bp_gens,
                &GENERATORS,
                &mut verifier_transcript,
                &commitments
                    .iter()
                    .map(|c| c.0 .0.compress())
                    .collect::<Vec<_>>(),
                bits,
                rng,
            )
            .map_err(|_| InvalidProof)
    }
}

#[test]
fn test_is_in_range() {
    assert!(Range::Bits8.is_in_range(0));
    assert!(Range::Bits8.is_in_range(u8::MAX as u64));
    assert!(!Range::Bits8.is_in_range(1 << 8));
    assert!(Range::Bits16.is_in_range(0));
    assert!(Range::Bits16.is_in_range(u16::MAX as u64));
    assert!(!Range::Bits16.is_in_range(1 << 16));
    assert!(Range::Bits32.is_in_range(0));
    assert!(Range::Bits32.is_in_range(u32::MAX as u64));
    assert!(!Range::Bits32.is_in_range(1 << 32));
    assert!(Range::Bits64.is_in_range(0));
    assert!(Range::Bits64.is_in_range(u64::MAX));
}

#[test]
fn test_range_proof_valid() {
    use crate::groups::ristretto255::RistrettoScalar;

    let range = Range::Bits32;
    let mut rng = rand::thread_rng();
    let blinding = Blinding::rand(&mut rng);

    let value = 1u64;
    let proof = RangeProof::prove(value, &blinding, &range, b"NARWHAL", &mut rng).unwrap();
    let commitment = PedersenCommitment::new(&RistrettoScalar::from(value), &blinding);
    assert!(proof
        .verify(&commitment, &range, b"NARWHAL", &mut rng)
        .is_ok());
}
