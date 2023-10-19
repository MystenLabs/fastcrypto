// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]
//! Groth16 verifier over the BN254 elliptic curve construction.

use crate::bn254::api::SCALAR_SIZE;
use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalDeserialize;
use derive_more::From;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

/// API that takes in serialized inputs
pub mod api;

/// Groth16 SNARK verifier
pub mod verifier;

/// Poseidon hash function over BN254
pub mod poseidon;

/// Zk login structs and utilities
pub mod zk_login;

/// Zk login entrypoints
pub mod zk_login_api;

/// Zk login utils
pub mod utils;

/// A field element in the BN254 construction. Thin wrapper around `api::Bn254Fr`.
#[derive(Debug, From)]
pub struct FieldElement(pub(crate) ark_bn254::Fr);

/// A Groth16 proof in the BN254 construction. Thin wrapper around `ark_groth16::Proof::<ark_bn254::Bn254>`.
#[derive(Debug, From)]
pub struct Proof(pub(crate) ark_groth16::Proof<ark_bn254::Bn254>);

/// A Groth16 verifying key in the BN254 construction. Thin wrapper around `ark_groth16::VerifyingKey::<ark_bn254::Bn254>`.
#[derive(Debug, From)]
pub struct VerifyingKey(pub(crate) ark_groth16::VerifyingKey<ark_bn254::Bn254>);

impl Proof {
    /// Deserialize a serialized Groth16 proof using arkworks' canonical serialisation format: https://docs.rs/ark-serialize/latest/ark_serialize/.
    pub fn deserialize(proof_points_as_bytes: &[u8]) -> FastCryptoResult<Self> {
        ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_points_as_bytes)
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(Proof)
    }
}

impl FieldElement {
    /// Deserialize 32 bytes into a BN254 field element using little-endian format.
    pub(crate) fn deserialize(bytes: &[u8]) -> FastCryptoResult<FieldElement> {
        if bytes.len() != SCALAR_SIZE {
            return Err(FastCryptoError::InputLengthWrong(bytes.len()));
        }
        Fr::deserialize_compressed(bytes)
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(FieldElement)
    }

    /// Deserialize a vector of bytes into a vector of BN254 field elements, assuming that each element
    /// is serialized as a chunk of 32 bytes. See also [`FieldElement::deserialize`].
    pub(crate) fn deserialize_vector(
        field_element_bytes: &[u8],
    ) -> FastCryptoResult<Vec<FieldElement>> {
        if field_element_bytes.len() % SCALAR_SIZE != 0 {
            return Err(FastCryptoError::InputLengthWrong(field_element_bytes.len()));
        }
        let mut public_inputs = Vec::new();
        for chunk in field_element_bytes.chunks(SCALAR_SIZE) {
            public_inputs.push(FieldElement::deserialize(chunk)?);
        }
        Ok(public_inputs)
    }
}
