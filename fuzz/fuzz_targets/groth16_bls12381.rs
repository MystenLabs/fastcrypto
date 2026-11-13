// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The BLS12-381 Groth16 byte API must not panic on any input.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto_zkp::bls12381::api::{
    get_public_inputs_num, prepare_pvk_bytes, verify_groth16_in_bytes,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    vk_gamma_abc: Vec<u8>,
    alpha_beta: Vec<u8>,
    gamma_neg: Vec<u8>,
    delta_neg: Vec<u8>,
    public_inputs: Vec<u8>,
    proof: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = prepare_pvk_bytes(&input.vk_gamma_abc);
    let _ = get_public_inputs_num(input.vk_gamma_abc.len());
    let _ = verify_groth16_in_bytes(
        &input.vk_gamma_abc,
        &input.alpha_beta,
        &input.gamma_neg,
        &input.delta_neg,
        &input.public_inputs,
        &input.proof,
    );
});
