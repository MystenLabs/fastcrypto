// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic Schnorr-style (Σ-protocol) proofs of knowledge for a system of `m` linear constraints
//! `Y_i = sum_j x_j * B_ij` over `n` shared witnesses, made non-interactive with Fiat-Shamir (see
//! [Maurer](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf)). Each base `B_ij` is an
//! [Option], so a witness need not occur in every constraint.
//!
//! # Example
//!
//! Proving knowledge of the opening `(x, r)` of a Pedersen commitment `C = x*G + r*H`, along with
//! the fact that the committed value `x` is also the discrete log of `D` w.r.t. `K`:
//!
//! ```
//! use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
//! use fastcrypto::groups::{GroupElement, Scalar};
//! use fastcrypto_zkp::schnorr::Statement;
//! use rand::thread_rng;
//!
//! let rng = &mut thread_rng();
//! let (g, h, k) = (
//!     RistrettoPoint::generator(),
//!     RistrettoPoint::generator() * RistrettoScalar::rand(rng),
//!     RistrettoPoint::generator() * RistrettoScalar::rand(rng),
//! );
//! let (x, r) = (RistrettoScalar::rand(rng), RistrettoScalar::rand(rng));
//! let (c, d) = (g * x + h * r, k * x);
//!
//! let mut builder = Statement::builder(b"example dst", 2);
//! builder
//!     .add_constraint(&c, [Some(g), Some(h)]).unwrap()  // C = x*G + r*H
//!     .add_constraint(&d, [Some(k), None]).unwrap();    // D = x*K
//! let statement = builder.build().unwrap();
//!
//! let proof = statement.prove(&[x, r], rng).unwrap();
//! assert!(statement.verify(&proof).is_ok());
//! ```

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{HashFunction, Sha512};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};
use std::iter::repeat_with;
use std::ops::Neg;

#[cfg(test)]
mod tests;

const DOMAIN: &str = "fastcrypto-schnorr-v1";

/// A single constraint `lhs = sum_j x_j * bases[j]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Constraint<G: GroupElement> {
    lhs: G,
    bases: Vec<Option<G>>,
}

impl<G: MultiScalarMul> Constraint<G> {
    /// The `(scalar, base)` pairs of this constraint, skipping the witnesses absent from it.
    fn terms<'a>(
        &'a self,
        scalars: &'a [G::ScalarType],
    ) -> impl Iterator<Item = (G::ScalarType, G)> + 'a {
        self.bases
            .iter()
            .zip(scalars)
            .filter_map(|(base, scalar)| base.map(|base| (*scalar, base)))
    }

    fn evaluate(&self, scalars: &[G::ScalarType]) -> FastCryptoResult<G> {
        let (scalars, points): (Vec<_>, Vec<_>) = self.terms(scalars).unzip();
        G::multi_scalar_mul(&scalars, &points)
    }
}

/// A system of linear constraints over a shared set of witnesses, which the prover and the verifier
/// must construct identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement<G: GroupElement> {
    dst: Vec<u8>,
    witnesses: usize,
    constraints: Vec<Constraint<G>>,
}

impl<G: GroupElement> Statement<G> {
    /// Create a builder for a statement over `witnesses` witnesses with domain separation tag `dst`.
    pub fn builder(dst: &[u8], witnesses: usize) -> StatementBuilder<G> {
        StatementBuilder {
            dst: dst.to_vec(),
            witnesses,
            constraints: Vec::new(),
        }
    }

    /// The number of witnesses, which is the number of responses in a proof.
    pub fn num_witnesses(&self) -> usize {
        self.witnesses
    }

    /// The number of constraints, which is the number of commitments in a proof.
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}

impl<G> Statement<G>
where
    G: MultiScalarMul + Serialize,
    G::ScalarType: FiatShamirChallenge,
{
    /// Create a proof of knowledge of `witnesses`, given in witness order, returning [InvalidInput]
    /// if they do not match the statement or do not satisfy it.
    pub fn prove<R: AllowedRng>(
        &self,
        witnesses: &[G::ScalarType],
        rng: &mut R,
    ) -> FastCryptoResult<Proof<G>> {
        if witnesses.len() != self.witnesses {
            return Err(InvalidInput);
        }
        if self.constraints.iter().any(|constraint| {
            constraint
                .evaluate(witnesses)
                .ok()
                .is_none_or(|lhs| lhs != constraint.lhs)
        }) {
            return Err(InvalidInput);
        }

        // A_i = sum_j r_j * B_ij for a fresh nonce r_j per witness.
        let nonces: Vec<_> = repeat_with(|| G::ScalarType::rand(rng))
            .take(self.witnesses)
            .collect();
        let commitments = self
            .constraints
            .iter()
            .map(|constraint| constraint.evaluate(&nonces))
            .collect::<FastCryptoResult<Vec<_>>>()?;

        // z_j = r_j + c * x_j for the single challenge c shared by all constraints.
        let challenge = self.challenge(&commitments);
        let responses = nonces
            .into_iter()
            .zip(witnesses)
            .map(|(r, x)| r + challenge * x)
            .collect();

        Ok(Proof {
            commitments,
            responses,
        })
    }

    /// Verify a proof created by [Self::prove] for this exact statement.
    pub fn verify(&self, proof: &Proof<G>) -> FastCryptoResult<()> {
        let challenge = self.checked_challenge(proof)?;

        // Check that sum_j z_j * B_ij - c * Y_i == A_i for all i.
        for (constraint, commitment) in self.constraints.iter().zip(&proof.commitments) {
            let (mut scalars, mut points): (Vec<_>, Vec<_>) =
                constraint.terms(&proof.responses).unzip();
            scalars.push(challenge.neg());
            points.push(constraint.lhs);
            if G::multi_scalar_mul(&scalars, &points)? != *commitment {
                return Err(InvalidProof);
            }
        }
        Ok(())
    }

    /// Verify a proof as [Self::verify] does, but batching all constraints into a single multi-scalar
    /// multiplication weighted by fresh scalars from `rng`, which is faster for many constraints.
    pub fn verify_batched<R: AllowedRng>(
        &self,
        proof: &Proof<G>,
        rng: &mut R,
    ) -> FastCryptoResult<()> {
        let challenge = self.checked_challenge(proof)?;

        let capacity = self.constraints.len() * (self.witnesses + 2);
        let mut scalars = Vec::with_capacity(capacity);
        let mut points = Vec::with_capacity(capacity);
        for (constraint, commitment) in self.constraints.iter().zip(&proof.commitments) {
            let rho = G::ScalarType::rand(rng);
            for (z, base) in constraint.terms(&proof.responses) {
                scalars.push(rho * z);
                points.push(base);
            }
            scalars.push(rho.neg());
            points.push(*commitment);
            scalars.push((rho * challenge).neg());
            points.push(constraint.lhs);
        }
        if G::multi_scalar_mul(&scalars, &points)? != G::zero() {
            return Err(InvalidProof);
        }
        Ok(())
    }

    /// The challenge for `proof`, after checking that its dimensions match this statement.
    fn checked_challenge(&self, proof: &Proof<G>) -> FastCryptoResult<G::ScalarType> {
        if proof.commitments.len() != self.constraints.len()
            || proof.responses.len() != self.witnesses
        {
            return Err(InvalidProof);
        }
        Ok(self.challenge(&proof.commitments))
    }

    fn challenge(&self, commitments: &[G]) -> G::ScalarType {
        let transcript = bcs::to_bytes(&(
            DOMAIN,
            &self.dst,
            self.witnesses as u64,
            &self.constraints,
            commitments,
        ))
        .expect("serialization of group elements never fails");
        G::ScalarType::fiat_shamir_reduction_to_group_element(&Sha512::digest(transcript).digest)
    }
}

pub struct StatementBuilder<G: GroupElement> {
    dst: Vec<u8>,
    witnesses: usize,
    constraints: Vec<Constraint<G>>,
}

impl<G: GroupElement> StatementBuilder<G> {
    /// Add the constraint `lhs = sum_j x_j * bases[j]` with one entry per witness in witness order,
    /// where `None` marks a witness that does not occur in it.
    pub fn add_constraint(
        &mut self,
        lhs: &G,
        bases: impl IntoIterator<Item = Option<G>>,
    ) -> FastCryptoResult<&mut Self> {
        let bases: Vec<Option<G>> = bases.into_iter().collect();
        if bases.len() != self.witnesses || bases.iter().all(Option::is_none) {
            return Err(InvalidInput);
        }
        self.constraints.push(Constraint { lhs: *lhs, bases });
        Ok(self)
    }

    /// Finalize the statement, returning [InvalidInput] if it has no constraints or if some witness
    /// is left unconstrained by all of them.
    pub fn build(self) -> FastCryptoResult<Statement<G>> {
        let Self {
            dst,
            witnesses,
            constraints,
        } = self;
        if witnesses == 0 || constraints.is_empty() {
            return Err(InvalidInput);
        }
        if (0..witnesses).any(|j| {
            constraints
                .iter()
                .all(|constraint| constraint.bases[j].is_none())
        }) {
            return Err(InvalidInput);
        }
        Ok(Statement {
            dst,
            witnesses,
            constraints,
        })
    }
}

/// A proof for a [Statement]: one commitment per constraint and one response per witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof<G: GroupElement> {
    commitments: Vec<G>,
    responses: Vec<G::ScalarType>,
}
