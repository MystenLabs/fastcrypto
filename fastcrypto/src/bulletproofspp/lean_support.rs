// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Internals of BP++ for the tests against the Lean model in `lean/harness`.

use crate::bulletproofspp::circuit::{CircuitParams, CircuitProof, Witness};
use crate::bulletproofspp::crs::Generators;
use crate::bulletproofspp::range_proof::Range;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::traits::AllowedRng;

pub use crate::bulletproofspp::transcript::TranscriptLog;

/// The generators for `m` values in `range`.
pub struct Crs {
    pub g: RistrettoPoint,
    pub h_vec: Vec<RistrettoPoint>,
    pub g_vec: Vec<RistrettoPoint>,
}

pub fn crs(range: Range, m: usize) -> FastCryptoResult<Crs> {
    let gens = Generators::new(CircuitParams::new(range, m)?.nm)?;
    Ok(Crs {
        g: gens.g,
        h_vec: gens.h_vec.clone(),
        g_vec: gens.g_vec.clone(),
    })
}

/// The elements of a serialized proof.
pub struct ProofElements {
    pub c_l: RistrettoPoint,
    pub c_o: RistrettoPoint,
    pub c_r: RistrettoPoint,
    pub c_s: RistrettoPoint,
    pub rounds: Vec<(RistrettoPoint, RistrettoPoint)>,
    pub l_final: RistrettoScalar,
    pub n_final: Vec<RistrettoScalar>,
}

pub fn proof_elements(bytes: &[u8]) -> FastCryptoResult<ProofElements> {
    let proof = CircuitProof::from_bytes(bytes)?;
    Ok(ProofElements {
        c_l: proof.c_l,
        c_o: proof.c_o,
        c_r: proof.c_r,
        c_s: proof.c_s,
        rounds: proof.nl_proof.rounds,
        l_final: proof.nl_proof.l_final,
        n_final: proof.nl_proof.n_final,
    })
}

/// The random draws of the prover.
pub struct WitnessDraws {
    pub r_o: Vec<RistrettoScalar>,
    pub r_l: Vec<RistrettoScalar>,
    pub r_r: Vec<RistrettoScalar>,
    pub n_s: Vec<RistrettoScalar>,
    pub l_s: RistrettoScalar,
}

/// What `RangeProof::prove_batch` draws from `rng`.
pub fn witness_draws(
    range: Range,
    values: &[u64],
    blindings: &[RistrettoScalar],
    rng: &mut impl AllowedRng,
) -> FastCryptoResult<WitnessDraws> {
    let params = CircuitParams::new(range, values.len())?;
    let witness = Witness::new(&params, rng, values, blindings);
    Ok(WitnessDraws {
        r_o: witness.r_o,
        r_l: witness.r_l,
        r_r: witness.r_r,
        n_s: witness.n_s,
        l_s: witness.l_s,
    })
}
