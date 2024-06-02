// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]
//! Groth16 verifier over the BN254 elliptic curve construction.

use crate::groth16;
use crate::groth16::api::{FromLittleEndianByteArray, GTSerialize};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bn254::G1Element;
use fastcrypto::groups::bn254::{GTElement, Scalar, GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH};
use fastcrypto::serde_helpers::ToFromByteArray;

/// API that takes in serialized inputs
pub mod api;

/// Poseidon hash function over BN254
pub mod poseidon;

/// Zk login structs and utilities
pub mod zk_login;

/// Zk login entrypoints
pub mod zk_login_api;

/// Zk login utils
pub mod utils;

/// A prepared Groth16 verifying key in the BN254 construction.
pub type PreparedVerifyingKey = groth16::PreparedVerifyingKey<G1Element>;

/// A Groth16 verifying key in the BN254 construction.
pub type VerifyingKey = groth16::VerifyingKey<G1Element>;

/// A Groth16 proof in the BN254 construction.
pub type Proof = groth16::Proof<G1Element>;

impl FromLittleEndianByteArray<SCALAR_LENGTH> for Scalar {
    fn from_little_endian_byte_array(bytes: &[u8; SCALAR_LENGTH]) -> FastCryptoResult<Self> {
        Scalar::from_byte_array(bytes)
    }
}

impl GTSerialize<GT_ELEMENT_BYTE_LENGTH> for GTElement {
    fn to_arkworks_bytes(&self) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
        self.to_byte_array()
    }

    fn from_arkworks_bytes(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        GTElement::from_byte_array(bytes)
    }
}
