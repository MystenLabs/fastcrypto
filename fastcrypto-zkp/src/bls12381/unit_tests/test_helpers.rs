// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::{Proof, VerifyingKey};
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use fastcrypto::groups::bls12381::{Scalar, SCALAR_LENGTH};
use fastcrypto::serde_helpers::ToFromByteArray;

pub(crate) fn from_arkworks_proof(ark_proof: &ark_groth16::Proof<Bls12_381>) -> Proof {
    let mut proof_bytes = Vec::new();
    ark_proof.serialize_compressed(&mut proof_bytes).unwrap();
    bcs::from_bytes(&proof_bytes).unwrap()
}

pub(crate) fn from_arkworks_vk(ark_vk: &ark_groth16::VerifyingKey<Bls12_381>) -> VerifyingKey {
    let mut vk_bytes = Vec::new();
    ark_vk.serialize_compressed(&mut vk_bytes).unwrap();
    VerifyingKey::from_arkworks_format(&vk_bytes).unwrap()
}

pub(crate) fn from_arkworks_scalar(scalar: &Fr) -> Scalar {
    let mut scalar_bytes = [0u8; SCALAR_LENGTH];
    scalar
        .serialize_compressed(scalar_bytes.as_mut_slice())
        .unwrap();
    scalar_bytes.reverse();
    Scalar::from_byte_array(&scalar_bytes).unwrap()
}
