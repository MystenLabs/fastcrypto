// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]

//! Groth16 verifier over the BLS12-381 elliptic curve construction.

use crate::bls12381::conversions::{BlsFr, SCALAR_SIZE};
use ark_bls12_381::Bls12_381;
use ark_serialize::CanonicalDeserialize;
use derive_more::From;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

/// Conversions between arkworks <-> blst
pub mod conversions;

/// Groth16 SNARK verifier
pub mod verifier;

/// API that takes in serialized inputs
pub mod api;

/// A field element in the BLS12-381 construction. Thin wrapper around `conversions::BlsFr`.
#[derive(Debug, From, Copy, Clone)]
pub struct FieldElement(pub(crate) BlsFr);

/// A Groth16 proof in the BLS12-381 construction. Thin wrapper around `ark_groth16::Proof::<ark_bls12_381::Bls12_381>`.
#[derive(Debug, From)]
pub struct Proof(pub(crate) ark_groth16::Proof<Bls12_381>);

/// A Groth16 verifying key in the BLS12-381 construction. Thin wrapper around `ark_groth16::VerifyingKey::<ark_bls12_381::Bls12_381>`.
#[derive(Debug, From)]
pub struct VerifyingKey(pub(crate) ark_groth16::VerifyingKey<Bls12_381>);

impl Proof {
    /// Deserialize a serialized Groth16 proof using arkworks' canonical serialisation format: https://docs.rs/ark-serialize/latest/ark_serialize/.
    pub fn deserialize(proof_points_as_bytes: &[u8]) -> FastCryptoResult<Self> {
        ark_groth16::Proof::<Bls12_381>::deserialize_compressed(proof_points_as_bytes)
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(Proof)
    }
}

impl FieldElement {
    /// Deserialize 32 bytes into a BLS12-381 field element using little-endian format.
    pub(crate) fn deserialize(bytes: &[u8]) -> FastCryptoResult<Self> {
        if bytes.len() != SCALAR_SIZE {
            return Err(FastCryptoError::InputLengthWrong(bytes.len()));
        }
        BlsFr::deserialize_compressed(bytes)
            .map(FieldElement)
            .map_err(|_| FastCryptoError::InvalidInput)
    }

    /// Deserialize a vector of bytes into a vector of BLS12-381 field elements, assuming that each element
    /// is serialized as a chunk of 32 bytes. See also [`FieldElement::deserialize`].
    pub(crate) fn deserialize_vector(bytes: &[u8]) -> FastCryptoResult<Vec<Self>> {
        if bytes.len() % SCALAR_SIZE != 0 {
            return Err(FastCryptoError::InputLengthWrong(bytes.len()));
        }
        let mut field_elements = Vec::new();
        for chunk in bytes.chunks(SCALAR_SIZE) {
            field_elements.push(Self::deserialize(chunk)?);
        }
        Ok(field_elements)
    }
}
