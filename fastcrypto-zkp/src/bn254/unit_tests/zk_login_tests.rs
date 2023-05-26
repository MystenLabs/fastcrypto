// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::zk_login::{verify_groth16_with_fixed_vk, AuxInputs, ProofPoints, PublicInputs};

#[test]
fn test_verify_groth16_in_bytes_api() {
    let aux_inputs = AuxInputs::from_fp("./src/bn254/unit_tests/aux.json").unwrap();
    let public_inputs = PublicInputs::from_fp("./src/bn254/unit_tests/public.json");

    assert_eq!(
        aux_inputs.calculate_all_inputs_hash(),
        public_inputs.get_all_inputs_hash()
    );

    let proof_points = ProofPoints::from_fp("./src/bn254/unit_tests/zkp.json");

    let res = verify_groth16_with_fixed_vk(
        public_inputs.get_serialized_hash(),
        proof_points.get_bytes(),
    );
    assert!(res.is_ok());
}
