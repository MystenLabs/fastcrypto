// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use crate::bls12381::verifier::PreparedVerifyingKey;
use crate::bls12381::FieldElement;
use crate::dummy_circuits::{DummyCircuit, Fibonacci};
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
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
    let mut vk_bytes = vec![];
    vk.serialize_compressed(&mut vk_bytes).unwrap();

    let bytes = prepare_pvk_bytes(vk_bytes.as_slice()).unwrap();
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
    .unwrap());

    // Negative test: Replace the A element with a random point.
    let mut modified_proof_points_bytes = proof_points_bytes.clone();
    let _ = &G1Affine::rand(rng)
        .serialize_compressed(&mut modified_proof_points_bytes[0..48])
        .unwrap();
    assert!(!verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &proof_inputs_bytes,
        &modified_proof_points_bytes
    )
    .unwrap());

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

#[test]
fn api_regression_tests() {
    // Prepare VK
    let vk_bytes = hex::decode("835da56c560fbba42fe472c9c6c687986953de12db2adb66c10ecfff8957c1ec28a030dd2512b1ef3afa09fff2b467ddad48984a12c6568511bca1a3662ecfba801f31422f5c4208986bc52186938a2d86745abc9e6e0503b5eb16c5f2a622e108013d74b85f9532d87c391c5b0c49557ce47221e869b329fbe103ca73136c70b708ac61fa0092a238bf9060dc885d0da59dae8e121fd0013e45116a3d63837949b7976fd15e99d9974c654638d5fa1cbd51531a00889c75aeb5a91dd54891fd0b6c37bc2d6817541e4818040b3e2c78451674c5f180a895107070592eabf3386d21a9f6a91adb1f94debadb604f47c6a412f66347289eb47eec60604b31d973697f7f4ffc792fa914e24286f6d277a002ac1275b83a8dad2d84fcc4fc771bbf0854b5e655be18c6089cfc1841cf311e3c43f1ee2cd371d42cc91d61b5b2848f448f9f57229781d6dba2ca8367f2e3f602000000000000009274be44d5c4ec5203e96cb2b3e96468062cf4eebea465b1721889924bbea43d26de7c0b312beb7c09182c278f54c4d2b4092ebefd19ba81e8d5d787b25cd8ca8d03130326032c0e2f01d23cdf4e7a845f2c00a38574182e08d2f9fbe90ca3f7").unwrap();
    let pvk_expected = vec![
        hex::decode("9274be44d5c4ec5203e96cb2b3e96468062cf4eebea465b1721889924bbea43d26de7c0b312beb7c09182c278f54c4d2b4092ebefd19ba81e8d5d787b25cd8ca8d03130326032c0e2f01d23cdf4e7a845f2c00a38574182e08d2f9fbe90ca3f7").unwrap(),
        hex::decode("5e235118ea90b0347c840b5f29df0cb765a81e9d55a0879fad4fda927f559aaa78af3f0d0ac1a0a3debe86e08c608907622cf46ce3be71d559c6bc460a206db1ac7ec28ef8817efd75a4ca6b56243ce2bd00782fd84ee9238c27b64bf68b4a138b22e9829464497fde48632b0a94461c6fc7dffab47d23851e30a484fb823827620b14678cb80ba4125a305b99213619354a7f98923b154ae209440b0e631ec0da2b02946dad1ad20830fe32f92e512843d6f870b0b4fa290e62935f921d470b0b8058af1f51391ebaf4ab1869933cfe37725e654a00f2c4a7099863937f4ce23e01bf7b2cabea888c6b073f47a0f411a3dc9295164e46a665c71c4ee31dd88f4c4d25aee40c832fc79bbb9f0bcbcf3fb3a5868a7027320f719f9ce0d23c620989e30af71459b32abffd7e879adfdc6d3417d552f43fbfa8b295bfd661dfc9fe2ac846c28f8527506ac15b1247dc7800d040e25698d2797be8c357a6883e0eeca928451406c93e0e3a2ea5fecbc5165e6691d164b6fa4de207a338a882600802a835795b29ee7ae73c66d6d22104a77e010d05293fc3fed65772b0da969a63c384ae24720e9c24c373912446400e7b087ecb1cbfe772b574bcf7c2e1e61fe56d9abe57ff5298956aa4ba47dd77c703f0fc4c69ab61d6e6e4161243e490a85b0c9d1dde1764f4924a3fc27de397256eb4822be1ba1faa6840afaa3219570806fe78622dc5ac74cb7352a0e4fa0fff5e0d30b6f87fd1a3e5fd3256f807ea5b5a45911518f4b93ec96f88a771ca33dae1339fcc7047cd0740b5df25e4403051af0b").unwrap(),
        hex::decode("859dae8e121fd0013e45116a3d63837949b7976fd15e99d9974c654638d5fa1cbd51531a00889c75aeb5a91dd54891fd0b6c37bc2d6817541e4818040b3e2c78451674c5f180a895107070592eabf3386d21a9f6a91adb1f94debadb604f47c6").unwrap(),
        hex::decode("8412f66347289eb47eec60604b31d973697f7f4ffc792fa914e24286f6d277a002ac1275b83a8dad2d84fcc4fc771bbf0854b5e655be18c6089cfc1841cf311e3c43f1ee2cd371d42cc91d61b5b2848f448f9f57229781d6dba2ca8367f2e3f6").unwrap(),
    ];
    let pvk_actual = prepare_pvk_bytes(&vk_bytes).unwrap();
    assert_eq!(pvk_expected, pvk_actual);

    // Verify
    let vk_gamma_abc_g1_bytes = hex::decode("896f65ec302f346365c3ebdf8812aa98dc003bd93c663f72d8f9cbb9f2b73b3a1ba0bad12678af22378ac625d414dda8a44e2ed104340b4d9e03fba0e2a3d27efcdfa41fcec60b1071c17089247d6b690bb18fccaccf8a3c0bd8416a160c7c8f8fcdf3f68ae2c9c84d4bc13ef6a64fb865ae36f077f45ee37fa4ebd43da333420a6102befa7fc2fc0c7e85d3722db89a").unwrap();
    let alpha_g1_beta_g2_bytes = hex::decode("ce35f0234d308739dabe6687ea37d794a6542c802fde201625c6d4c55daf9a15fbdc6628b1a8d6db7fb930c58252750e61af062aeba4ea368bc95999f87dbd93995cfc0bd9c539844c3633b6f58951a9988bf1d96b49ef0aca6c98c84a16850557afaebb7e9c2b926ee436a96a3611161605d438b86a1d9933d87afbdaa9cace569b810ded82ec6f23801c3df1bd8203513fec813d706f23e5afe0187fa552d6ea8547e1b82740858e9ef4139ad9a952303a63395461dc7d78e05688afe2c50860ca60a5564f00344cbecdc4ce94ac9fb41106642d7c3d6445d6607b9b963cd05975f4ba9b4674159b5b7458092fce0f532f1a8dfd76aca31d3978a651e020dcd3577674cba022733afb97d96b91f8cc5590ea4147d6130fb24895210b5e2d02d37dcf6b30245ef98543086859016b1f38d56f79100fc608339367b9bf9608e8175e4e602c853281805cb110a1ea2a0ef8c7aa220a49224b2a7de996996d2350dce3905e6cd1e6ab850f3ccccefc1c0b84baa13c9054b32d0d42f869d17f6c06e6831e11b2e65d07fad4b25eb540630505d23635ef1effb35626042c394190d5c5b9062f296546cd5517c9a8352a4310b5469e4321cc1d86db15d6475c1d0652f8e57c220cfe8eb798b3595a516c51bcea81efb0d8dace2521bae3537d721919e8dbb45fbf2ecf47e7483c7d725dbb47ec191c5bf6de4f7487b23fc1c04c6ba7ce2001d64f6236d025b88aaadecdde1482812836fc6f4d6efcbeae1ba2836b5c57399c28b0f58649bf6c7a743bb2e1469d348e1bcfc75ff18976d825d72ab716").unwrap();
    let gamma_g2_neg_pc_bytes = hex::decode("89a91d003a78b3580981407bfd5c1f70b329f7b7479fbbd244be8729def2a3538901ff7be9320cf6f9773e7ba4c2712a0b9061adfd335bf4e378414fe788766e8feb5cdf2a0e5368c8451a40ce1b1c54e5c0e997a37e1e97b228ac222ae49b95").unwrap();
    let delta_g2_neg_pc_bytes = hex::decode("8b0624cf881e828bd01eabe53992962f3bd9e444375900ed2a875a74c705597f80d5c77c5f698346082ca0dda33344f7059702c4ea9044f417e44575337b6d2f85202160a00c30d62a02ad84abc0dcbda1a834fb73021a1c500b0f021e41f868").unwrap();
    let public_inputs_bytes = hex::decode("7b00000000000000000000000000000000000000000000000000000000000000c801000000000000000000000000000000000000000000000000000000000000").unwrap();
    let proof_bytes = hex::decode("826a9c4a653a73bda4782c5ea566e1eb556cd516a820566ec3237f2bf50432777a11c32480ad09d9f7395785cbd4a338a53c93a906cb947d94a07524a57c852cc9daff85d50e6597327a12dd6b588dd39771e87e37ac276d59125714a15d0af204bff8ede3d42b85b8c76b842ae88209113afc886d8f9875ade9293c9059ecfe8a5483b023eb845f20cd0f422e8acdbba51e23ccf4feeaf82a05efd7b803cc9d7244cb53c119a1e4695b945e2663bfc90c639a6ec39237a01a24958585438ab3").unwrap();
    assert!(verify_groth16_in_bytes(
        &vk_gamma_abc_g1_bytes,
        &alpha_g1_beta_g2_bytes,
        &gamma_g2_neg_pc_bytes,
        &delta_g2_neg_pc_bytes,
        &public_inputs_bytes,
        &proof_bytes
    )
    .unwrap());
}
