// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use crate::bls12381::verifier::PreparedVerifyingKey;
use crate::bls12381::FieldElement;
use crate::dummy_circuits::{DummyCircuit, Fibonacci};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use fastcrypto::encoding::{Encoding, Hex};
use std::ops::Mul;

#[test]
fn test_verify_groth16_in_bytes_api() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut thread_rng();
    let c = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 10,
    };

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
    let proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
    let v = c.a.unwrap().mul(c.b.unwrap());
    let blst_pvk = PreparedVerifyingKey::from(&vk.into());

    let bytes = blst_pvk.serialize().unwrap();
    let vk_gamma_abc_g1_bytes = &bytes[0];
    let alpha_g1_beta_g2_bytes = &bytes[1];
    let gamma_g2_neg_pc_bytes = &bytes[2];
    let delta_g2_neg_pc_bytes = &bytes[3];

    let mut proof_inputs_bytes = vec![];
    v.serialize_compressed(&mut proof_inputs_bytes).unwrap();

    let mut proof_points_bytes = vec![];
    proof.serialize_compressed(&mut proof_points_bytes).unwrap();

    // Success case.
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &proof_inputs_bytes,
        &proof_points_bytes
    )
    .is_ok());

    // Length of verifying key is incorrect.
    let mut modified_bytes = bytes[0].clone();
    modified_bytes.pop();
    assert!(verify_groth16_in_bytes(
        &modified_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &proof_inputs_bytes,
        &proof_points_bytes
    )
    .is_err());

    // Length of public inputs is incorrect.
    let mut modified_proof_inputs_bytes = proof_inputs_bytes.clone();
    modified_proof_inputs_bytes.pop();
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &modified_proof_inputs_bytes,
        &proof_points_bytes
    )
    .is_err());

    // length of proof is incorrect
    let mut modified_proof_points_bytes = proof_points_bytes.to_vec();
    modified_proof_points_bytes.pop();
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &proof_inputs_bytes,
        &modified_proof_points_bytes
    )
    .is_err());
}

#[test]
fn test_prepare_pvk_bytes() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut thread_rng();
    let c = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 10,
    };

    let (_, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();

    let mut vk_bytes = vec![];
    vk.serialize_compressed(&mut vk_bytes).unwrap();

    // Success case.
    assert!(prepare_pvk_bytes(vk_bytes.as_slice()).is_ok());

    // Length of verifying key is incorrect.
    let mut modified_bytes = vk_bytes.clone();
    modified_bytes.pop();
    assert!(prepare_pvk_bytes(&modified_bytes).is_err());

    // Regression test
    let result = prepare_pvk_bytes(&Hex::decode("a84d039ad1ae98eeeee4c8ba9af9b6c5d1cfcb98c3fc92ccfcebd77bcccffa1d170d39da29e9b4aa83b98680cb90bb25946b2b70f9e3565510c5361d5d65cb458a0b3177d612dd340b8f8f8493c2772454e3e8f577a3f77865df851d1a159b800c2ec5bae889029fc419678e83dee900465d60e7ef26f614940e719c6f7c0c7db57464fa0481a93c18d52cb2fbf8dcf0a398b153643614fc1071a54e288edb6402f1d9e00d3408c76d95c16885cc992dff5c6ebee3b739cb22359ab2d126026a1626c43ea7b898a7c1d2904c1bd4bbce5d0b1b16fab8535a52d1b08a5217df2e912ee1b0f4140892afa31d479f78dfbc82ab58a209ad00df6c86ab14841e8daa7a380a6853f28bacf38aad9903b6149fff4b119dea16de8aa3e5050b9d563a01009e061a950c233f66511c8fae2a8c58503059821df7f6defbba8f93d26e412cc07b66a9f3cdd740cce5c8488ce94fc8020000000000000081aabea18713222ac45a6ef3208a09f55ce2dde8a11cc4b12788be2ae77ae318176d631d36d80942df576af651b57a31a95f2e9bcaebbb53a588251634715599f7a7e9d51fe872fe312edf0b39d98f0d7f8b5554f96f759c041ea38b4b1e5e19").unwrap()).unwrap();
    assert_eq!(Hex::encode(&result.clone()[1]), "097ca8074c7f1d661e25d70fc2e6f14aa874dabe3d8a5d7751a012a737d30b59fc0f5f6d4ce0ea6f6c4562912dfb2a1442df06f9f0b8fc2d834ca007c8620823926b2fc09367d0dfa9b205a216921715e13deedd93580c77cae413cbb83134051cb724633c58759c77e4eda4147a54b03b1f443b68c65247166465105ab5065847ae61ba9d8bdfec536212b0dadedc042dab119d0eeea16349493a4118d481761b1e75f559fbad57c926d599e81d98dde586a2cfcc37b49972e2f9db554e5a0ba56bec2d57a8bfed629ae29c95002e3e943311b7b0d1690d2329e874b179ce5d720bd7c5fb5a2f756b37e3510582cb0c0f8fc8047305fc222c309a5a8234c5ff31a7b311aabdcebf4a43d98b69071a9e5796372146f7199ba05f9ca0a3d14b0c421e7f1bd02ac87b365fd8ce992c0f87994d0ca66f75c72fed0ce94ca174fcb9e5092f0474e07e71e9fd687b3daa441193f264ca2059760faa9c5ca5ef38f6ecefef2ac7d8c47df67b99c36efa64f625fe3f55f40ad1865abbdf2ff4c3fc3a162e28b953f6faec70a6a61c76f4dca1eecc86544b88352994495ae7fc7a77d387880e59b2357d9dd1277ae7f7ee9ba00b440e0e6923dc3971de9050a977db59d767195622f200f2bf0d00e4a986e94a6932627954dd2b7da39b4fcb32c991a0190bdc44562ad83d34e0af7656b51d6cde03530b5d523380653130b87346720ad6dd425d8133ffb02f39a95fc70e9707181ecb168bd8d2d0e9e85e262255fecab15f1ada809ecbefa42a7082fa7326a1d494261a8954fe5b215c5b761fb10b7f18");
}

#[test]
fn test_verify_groth16_in_bytes_multiple_inputs() {
    let mut rng = thread_rng();

    let a = Fr::from(123);
    let b = Fr::from(456);

    let params = {
        let circuit = Fibonacci::<Fr>::new(42, a, b);
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap()
    };

    let proof = {
        let circuit = Fibonacci::<Fr>::new(42, a, b);
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &params, &mut rng)
            .unwrap()
    };

    // Proof::write serializes uncompressed and also adds a length to each element, so we serialize
    // each individual element here to avoid that.
    let mut proof_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_bytes).unwrap();
    proof.b.serialize_compressed(&mut proof_bytes).unwrap();
    proof.c.serialize_compressed(&mut proof_bytes).unwrap();

    let pvk = PreparedVerifyingKey::from(&params.vk.into());

    let inputs: Vec<_> = [FieldElement(a), FieldElement(b)].to_vec();
    assert!(pvk.verify(&inputs, &proof.into()).unwrap());

    let pvk = pvk.serialize().unwrap();

    // This circuit has two public inputs:
    let mut inputs_bytes = Vec::new();
    a.serialize_compressed(&mut inputs_bytes).unwrap();
    b.serialize_compressed(&mut inputs_bytes).unwrap();

    assert!(verify_groth16_in_bytes(
        &pvk[0],
        &pvk[1],
        &pvk[2],
        &pvk[3],
        &inputs_bytes,
        &proof_bytes
    )
    .unwrap());

    inputs_bytes[0] += 1;
    assert!(!verify_groth16_in_bytes(
        &pvk[0],
        &pvk[1],
        &pvk[2],
        &pvk[3],
        &inputs_bytes,
        &proof_bytes
    )
    .unwrap());
}
