// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use std::{iter, ops::Neg, ptr};

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, Fq12};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::G2Prepared;
use ark_groth16::{Groth16, PreparedVerifyingKey as ArkPreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::r1cs::SynthesisError;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

#[cfg(test)]
#[path = "unit_tests/verifier_tests.rs"]
mod verifier_tests;

#[derive(Debug)]
pub struct PreparedVerifyingKey(ArkPreparedVerifyingKey<Bn254>);
