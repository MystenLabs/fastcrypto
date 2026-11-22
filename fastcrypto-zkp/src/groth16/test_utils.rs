// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for the tests of `verify_groth16_in_bytes` and `prepare_pvk_bytes` on both curves, and
//! byte mutations for proptests. Test modules include this file.

// Not every module that includes this file uses all of it.
#![allow(dead_code)]

use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use fastcrypto::error::FastCryptoResult;
use num_bigint::BigUint;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

/// The indices of the public inputs and the proof in [Inputs]. The four parts of the prepared
/// verifying key come first: vk_gamma_abc, alpha_beta, gamma_neg and delta_neg.
pub(crate) const PUBLIC_INPUTS_PART: usize = 4;
pub(crate) const PROOF_PART: usize = 5;

/// The signature of `verify_groth16_in_bytes`.
pub(crate) type VerifyFn = fn(&[u8], &[u8], &[u8], &[u8], &[u8], &[u8]) -> FastCryptoResult<bool>;

/// The six inputs of `verify_groth16_in_bytes`: the four parts of a prepared verifying key, the
/// public inputs and the proof.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Inputs(pub(crate) [Vec<u8>; 6]);

impl Inputs {
    pub(crate) fn new(pvk: [&str; 4], public_inputs: &str, proof: &str) -> Self {
        Self::from_parts(pvk.map(decode), decode(public_inputs), decode(proof))
    }

    pub(crate) fn from_parts(pvk: [Vec<u8>; 4], public_inputs: Vec<u8>, proof: Vec<u8>) -> Self {
        let [vk_gamma_abc, alpha_beta, gamma_neg, delta_neg] = pvk;
        Self([
            vk_gamma_abc,
            alpha_beta,
            gamma_neg,
            delta_neg,
            public_inputs,
            proof,
        ])
    }

    pub(crate) fn with(mut self, part: usize, bytes: Vec<u8>) -> Self {
        self.0[part] = bytes;
        self
    }

    pub(crate) fn verify_with(&self, verify: VerifyFn) -> FastCryptoResult<bool> {
        let [vk_gamma_abc, alpha_beta, gamma_neg, delta_neg, public_inputs, proof] = &self.0;
        verify(
            vk_gamma_abc,
            alpha_beta,
            gamma_neg,
            delta_neg,
            public_inputs,
            proof,
        )
    }

    /// Applies a mutation. `negate_proof` returns the proof (-A, -B, C) for a proof (A, B, C), or
    /// `None` if the proof doesn't decode.
    pub(crate) fn apply(
        &mut self,
        mutation: &Mutation,
        negate_proof: fn(&[u8]) -> Option<Vec<u8>>,
    ) {
        match mutation {
            Mutation::Bytes(part, m) => m.apply(&mut self.0[*part]),
            Mutation::NegateProof => {
                if let Some(negated) = negate_proof(&self.0[PROOF_PART]) {
                    self.0[PROOF_PART] = negated;
                }
            }
        }
    }
}

pub(crate) fn decode(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

pub(crate) fn compressed<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// The 32-byte little-endian encoding of an integer smaller than 2^256.
pub(crate) fn le_bytes(n: &BigUint) -> Vec<u8> {
    let mut bytes = n.to_bytes_le();
    bytes.resize(32, 0);
    bytes
}

pub(crate) fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_bytes_le(&F::MODULUS.to_bytes_le())
}

/// A change to a byte string.
#[derive(Clone, Debug)]
pub(crate) enum ByteMutation {
    SetByte(Index, u8),
    /// Keeps only the given number of bytes, which is smaller than the length.
    Truncate(Index),
    Append(Vec<u8>),
}

impl ByteMutation {
    pub(crate) fn apply(&self, bytes: &mut Vec<u8>) {
        match self {
            ByteMutation::SetByte(index, value) if !bytes.is_empty() => {
                let index = index.index(bytes.len());
                bytes[index] = *value;
            }
            ByteMutation::Truncate(len) if !bytes.is_empty() => {
                bytes.truncate(len.index(bytes.len()))
            }
            ByteMutation::Append(suffix) => bytes.extend(suffix),
            _ => (),
        }
    }
}

pub(crate) fn arb_byte_mutation() -> impl Strategy<Value = ByteMutation> {
    prop_oneof![
        (any::<Index>(), any::<u8>())
            .prop_map(|(index, value)| ByteMutation::SetByte(index, value)),
        any::<Index>().prop_map(ByteMutation::Truncate),
        vec(any::<u8>(), 1..100).prop_map(ByteMutation::Append),
    ]
}

/// A change to one of the six [Inputs].
#[derive(Clone, Debug)]
pub(crate) enum Mutation {
    Bytes(usize, ByteMutation),
    /// Replaces the proof (A, B, C) by (-A, -B, C), which verifies iff (A, B, C) does.
    NegateProof,
}

pub(crate) fn arb_mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        3 => (0..6usize, arb_byte_mutation()).prop_map(|(part, m)| Mutation::Bytes(part, m)),
        1 => Just(Mutation::NegateProof),
    ]
}
