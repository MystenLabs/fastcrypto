// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use crate::bn254::{PreparedVerifyingKey, VerifyingKey};
use crate::dummy_circuits::{DummyCircuit, Fibonacci};
use ark_bn254::{Bn254, Fq12, Fr, G1Projective, G2Projective};
use ark_ff::{One, Zero};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use std::ops::Mul;

#[path = "./utils.rs"]
mod utils;

fn vk_from_arkworks(vk: ark_groth16::VerifyingKey<Bn254>) -> VerifyingKey {
    VerifyingKey::new(
        G1Projective::from(vk.alpha_g1).into(),
        G2Projective::from(vk.beta_g2).into(),
        G2Projective::from(vk.gamma_g2).into(),
        G2Projective::from(vk.delta_g2).into(),
        vk.gamma_abc_g1
            .iter()
            .map(|x| G1Projective::from(*x).into())
            .collect(),
    )
}

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

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, c, rng).unwrap();
    let v = c.a.unwrap().mul(c.b.unwrap());

    let pvk = PreparedVerifyingKey::from(&vk_from_arkworks(vk));

    let bytes = pvk.serialize_into_parts();
    let vk_gamma_abc_g1_bytes = &bytes[0];
    let alpha_g1_beta_g2_bytes = &bytes[1];
    let gamma_g2_neg_pc_bytes = &bytes[2];
    let delta_g2_neg_pc_bytes = &bytes[3];

    let mut proof_inputs_bytes = vec![];
    v.serialize_compressed(&mut proof_inputs_bytes).unwrap();

    // Proof::write serializes uncompressed and also adds a length to each element, so we serialize
    // each individual element here to avoid that.
    let mut proof_points_bytes = Vec::new();
    proof
        .a
        .serialize_compressed(&mut proof_points_bytes)
        .unwrap();
    proof
        .b
        .serialize_compressed(&mut proof_points_bytes)
        .unwrap();
    proof
        .c
        .serialize_compressed(&mut proof_points_bytes)
        .unwrap();

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

    let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

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
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap()
    };

    let proof = {
        let circuit = Fibonacci::<Fr>::new(42, a, b);
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params, &mut rng).unwrap()
    };

    let pvk = PreparedVerifyingKey::from(&vk_from_arkworks(params.vk)).serialize_into_parts();

    // This circuit has two public inputs:
    let mut inputs_bytes = Vec::new();
    a.serialize_compressed(&mut inputs_bytes).unwrap();
    b.serialize_compressed(&mut inputs_bytes).unwrap();

    // Proof::write serializes uncompressed and also adds a length to each element, so we serialize
    // each individual element here to avoid that.
    let mut proof_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_bytes).unwrap();
    proof.b.serialize_compressed(&mut proof_bytes).unwrap();
    proof.c.serialize_compressed(&mut proof_bytes).unwrap();

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

// Test for verifying the elusiv send-quadra circuits used for private on-chain transfers.
// This circuit has 14 public inputs and ~22.5k constraints. More info about the exact details of it
// can be found at https://github.com/elusiv-privacy/circuits
#[test]
fn test_verify_groth16_elusiv_proof_in_bytes_api() {
    // (Proof bytes, Public inputs bytes)
    let elusiv_sample_proof = (
        vec![
            20, 245, 104, 221, 130, 235, 123, 204, 177, 114, 10, 110, 46, 183, 48, 120, 9, 170, 51,
            85, 158, 26, 189, 62, 237, 16, 46, 203, 175, 122, 245, 47, 128, 87, 105, 124, 179, 152,
            174, 66, 22, 174, 55, 85, 1, 47, 128, 147, 202, 36, 183, 172, 26, 137, 85, 39, 96, 39,
            212, 31, 124, 4, 168, 13, 1, 33, 72, 218, 200, 115, 180, 44, 146, 88, 182, 241, 65,
            111, 36, 248, 138, 83, 92, 147, 174, 50, 206, 139, 56, 181, 15, 123, 0, 238, 20, 11,
            123, 58, 226, 125, 60, 189, 123, 74, 214, 222, 32, 75, 128, 205, 200, 6, 68, 207, 105,
            214, 219, 76, 6, 205, 20, 198, 213, 119, 205, 236, 13, 21,
        ],
        vec![
            187, 105, 172, 219, 4, 178, 82, 24, 207, 213, 168, 195, 53, 95, 53, 171, 213, 192, 159,
            78, 251, 174, 158, 168, 44, 21, 120, 167, 161, 85, 87, 20, 36, 159, 7, 87, 95, 30, 146,
            132, 86, 227, 151, 100, 176, 167, 157, 142, 13, 251, 220, 165, 141, 225, 145, 119, 207,
            238, 113, 199, 253, 149, 78, 5, 119, 251, 160, 26, 10, 92, 220, 11, 212, 148, 56, 59,
            245, 100, 28, 234, 83, 163, 83, 83, 48, 131, 246, 220, 176, 116, 72, 8, 79, 68, 105,
            11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5, 103, 244, 188, 245, 155, 180, 187, 99,
            139, 61, 240, 162, 71, 44, 115, 162, 6, 35, 181, 127, 42, 40, 42, 37, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 175, 11, 110, 47, 171, 92, 39, 63, 36, 183, 61, 144, 105, 250,
            193, 22, 180, 65, 101, 199, 47, 151, 12, 147, 158, 66, 62, 51, 147, 86, 89, 34, 4, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 249, 251, 64, 35, 242, 208, 188, 51, 106, 123, 236, 123, 93, 72,
            26, 61, 110, 224, 247, 245, 114, 29, 253, 212, 174, 130, 115, 44, 183, 49, 31, 23,
        ],
    );

    let vk = vk_from_arkworks(ark_groth16::VerifyingKey {
        alpha_g1: utils::G1Affine_from_str_projective((
            "8057073471822347335074195152835286348058235024870127707965681971765888348219",
            "14493022634743109860560137600871299171677470588934003383462482807829968516757",
            "1",
        )),
        beta_g2: utils::G2Affine_from_str_projective((
            (
                "3572582736973115805854009786889644784414020463323864932822856731322980736092",
                "20796599916820806690555061040933219683613855446136615092456120794141344002056",
            ),
            (
                "6655819316204680004365614375508079580461146204424752037766280753854543388537",
                "21051385956744942198035008062816432434887289184811055343085396392904977398400",
            ),
            ("1", "0"),
        )),
        gamma_g2: utils::G2Affine_from_str_projective((
            (
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ),
            (
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ),
            ("1", "0"),
        )),
        delta_g2: utils::G2Affine_from_str_projective((
            (
                "11998653647826530912022227389593270429577129765091819606672414955204726946137",
                "12850197969502293778482300034606665950383830355768697463743623195959747528569",
            ),
            (
                "3371177482557063281015231215914240035716553874474070718078727302911297506634",
                "12667795686197095991004340383609552078675969789404912385920584439828198138754",
            ),
            ("1", "0"),
        )),
        gamma_abc_g1: [
            [
                "11423936163622682661315257948859256751456935745483672301927753823261895199269",
                "8106299131826030264309317289206035584499915702251874486285904804204850744645",
                "1",
            ],
            [
                "3101734373871983241904605625023311773791709350380811153571118050344636150719",
                "5892752048111020912174143187873113013528793690570548925602265811558514488885",
                "1",
            ],
            [
                "10476231653569587456624794227763775706638536733174066539315272867287760110504",
                "10966166298405300401399180388536732567182096690752823243070979263725671251842",
                "1",
            ],
            [
                "3616644883823724294840639617628786582022507076201411671428851342676842026051",
                "20036054300972762576589546578455562677975529109923089992859054028247449793275",
                "1",
            ],
            [
                "8922146185459718802170954039785431585338226940878465749467742893964332142463",
                "6543899100030899685821688665010402257161600764202006060926513825176262562594",
                "1",
            ],
            [
                "8838880056209295823278313283853562429175894016112442003934942661774390156254",
                "12827213619164270378479427160832201667918020494718807523503415302940668517033",
                "1",
            ],
            [
                "2830281053896850092944028355764636104294475011402565423874976766597400897579",
                "13415270586926186600118105749667385774136247571413308961986554361125375974552",
                "1",
            ],
            [
                "18596510315364411631453906928618372802526744665579937948378160099177646939132",
                "13639164510921866583928930414183864880892036368934098358398305969672652727368",
                "1",
            ],
            [
                "5166155439194150342865876104665292251058885686253625593517703833929767249773",
                "15776325379616919283841092402757993241658241305931554423955510623840777140969",
                "1",
            ],
            [
                "244871576834190719988785477479956000478101720979685216270364011881385785410",
                "5006539956367064800739393540924950096169041851058318954717373683020872268739",
                "1",
            ],
            [
                "3379906259197166810955208903373839920133048860227880343760386881009843909062",
                "20232197429675204807642408172750830052412585778140676948557231371164499652906",
                "1",
            ],
            [
                "5520775405859402378836749033719619657978092778322140710653552702896452870563",
                "2840091105079872357493316251142119838752629278546220113584117974897982339624",
                "1",
            ],
            [
                "520211872811929422003078090188660039184112525356441893145895540025777918752",
                "18510673159743652418577623905535570073301952222198134524503321213201497608215",
                "1",
            ],
            [
                "6431234738107765889030689757699276709534858281277744012577221575246765244517",
                "4178355859219522686761165914894952086513502987193412248095296044093289572534",
                "1",
            ],
            [
                "4759337634951432350348093011115687353434771991388975508607474262950775320629",
                "3583982358135750838996058092244844686884741536705305315993181569552518297411",
                "1",
            ],
        ]
        .into_iter()
        .map(|s| utils::G1Affine_from_str_projective((s[0], s[1], s[2])))
        .collect(),
    });

    let pvk = PreparedVerifyingKey::from(&vk);

    let bytes = pvk.serialize_into_parts();
    let vk_gamma_abc_g1_bytes = &bytes[0];
    let alpha_g1_beta_g2_bytes = &bytes[1];
    let gamma_g2_neg_pc_bytes = &bytes[2];
    let delta_g2_neg_pc_bytes = &bytes[3];

    // Success case.
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &elusiv_sample_proof.1,
        &elusiv_sample_proof.0
    )
    .is_ok());
}

// Test for verifying the elusiv send-quadra circuits used for private on-chain transfers.
// This circuit has 14 public inputs and ~22.5k constraints. More info about the exact details of it
// can be found at https://github.com/elusiv-privacy/circuits
#[test]
fn fail_verify_groth16_invalid_elusiv_proof_in_bytes_api() {
    // (Invalid proof bytes, Valid public inputs bytes) (last 3 bytes changed to 1 2 3)
    let elusiv_sample_proof_invalid_proof = (
        vec![
            187, 105, 172, 219, 4, 178, 82, 24, 207, 213, 168, 195, 53, 95, 53, 171, 213, 192, 159,
            78, 251, 174, 158, 168, 44, 21, 120, 167, 161, 85, 87, 20, 36, 159, 7, 87, 95, 30, 146,
            132, 86, 227, 151, 100, 176, 167, 157, 142, 13, 251, 220, 165, 141, 225, 145, 119, 207,
            238, 113, 199, 253, 149, 78, 5, 119, 251, 160, 26, 10, 92, 220, 11, 212, 148, 56, 59,
            245, 100, 28, 234, 83, 163, 83, 83, 48, 131, 246, 220, 176, 116, 72, 8, 79, 68, 105,
            11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            23, 25, 67, 79,
        ],
        vec![
            187, 105, 172, 219, 4, 178, 82, 24, 207, 213, 168, 195, 53, 95, 53, 171, 213, 192, 159,
            78, 251, 174, 158, 168, 44, 21, 120, 167, 161, 85, 87, 20, 36, 159, 7, 87, 95, 30, 146,
            132, 86, 227, 151, 100, 176, 167, 157, 142, 13, 251, 220, 165, 141, 225, 145, 119, 207,
            238, 113, 199, 253, 149, 78, 5, 119, 251, 160, 26, 10, 92, 220, 11, 212, 148, 56, 59,
            245, 100, 28, 234, 83, 163, 83, 83, 48, 131, 246, 220, 176, 116, 72, 8, 79, 68, 105,
            11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5, 103, 244, 188, 245, 155, 180, 187, 99,
            139, 61, 240, 162, 71, 44, 115, 162, 6, 35, 181, 127, 42, 40, 42, 37, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 175, 11, 110, 247, 71, 92, 39, 63, 36, 183, 61, 144, 105, 250,
            193, 22, 180, 65, 101, 199, 247, 151, 12, 147, 158, 66, 62, 51, 147, 86, 89, 34, 4, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 249, 251, 64, 35, 242, 208, 188, 51, 106, 123, 236, 123, 93, 72,
            26, 61, 110, 224, 247, 245, 114, 29, 253, 212, 174, 130, 115, 44, 183, 49, 31, 23,
        ],
    );

    // (Valid proof bytes, Invalid public inputs bytes) (last 3 bytes changed to 1 2 3)
    let elusiv_sample_proof_invalid_pin = (
        vec![
            20, 245, 104, 221, 130, 235, 123, 204, 177, 114, 10, 110, 46, 183, 48, 120, 9, 170, 51,
            85, 158, 26, 189, 62, 237, 16, 46, 203, 175, 122, 245, 47, 128, 87, 105, 124, 179, 152,
            174, 66, 22, 174, 55, 85, 1, 47, 128, 147, 202, 36, 183, 172, 26, 137, 85, 39, 96, 39,
            212, 31, 124, 4, 168, 13, 1, 33, 72, 218, 200, 115, 180, 44, 146, 88, 182, 241, 65,
            111, 36, 248, 138, 83, 92, 147, 174, 50, 206, 139, 56, 181, 15, 123, 0, 238, 20, 11,
            123, 58, 226, 125, 60, 189, 123, 74, 214, 222, 32, 75, 128, 205, 200, 6, 68, 207, 105,
            214, 219, 76, 6, 205, 20, 198, 213, 119, 205, 236, 13, 21,
        ],
        vec![
            193, 22, 180, 65, 101, 199, 47, 151, 12, 147, 158, 66, 62, 51, 147, 86, 89, 34, 4, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 249, 251, 64, 35, 242, 208, 188, 51, 106, 123, 236, 123, 93, 72,
            26, 61, 110, 224, 247, 245, 114, 29, 253, 212, 174, 130, 115, 44, 183, 1, 2, 3, 139,
            187, 105, 172, 219, 4, 178, 82, 24, 207, 213, 168, 195, 53, 95, 53, 171, 213, 192, 159,
            78, 251, 174, 158, 168, 44, 21, 120, 167, 161, 85, 87, 20, 36, 159, 7, 87, 95, 30, 146,
            132, 86, 227, 151, 100, 176, 167, 157, 142, 13, 251, 220, 165, 141, 225, 145, 119, 207,
            238, 113, 199, 253, 149, 78, 5, 119, 251, 160, 26, 10, 92, 220, 11, 212, 148, 56, 59,
            245, 100, 28, 234, 83, 163, 83, 83, 48, 131, 246, 220, 176, 116, 72, 8, 79, 68, 105,
            11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5, 103, 244, 188, 245, 155, 180, 187, 99,
            61, 240, 162, 71, 44, 115, 162, 6, 35, 181, 127, 42, 40, 42, 37, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 175, 11, 110, 47, 171, 92, 39, 63, 36, 183, 61, 144, 105, 250,
        ],
    );

    let vk: ark_groth16::VerifyingKey<Bn254> = ark_groth16::VerifyingKey {
        alpha_g1: utils::G1Affine_from_str_projective((
            "8057073471822347335074195152835286348058235024870127707965681971765888348219",
            "14493022634743109860560137600871299171677470588934003383462482807829968516757",
            "1",
        )),
        beta_g2: utils::G2Affine_from_str_projective((
            (
                "3572582736973115805854009786889644784414020463323864932822856731322980736092",
                "20796599916820806690555061040933219683613855446136615092456120794141344002056",
            ),
            (
                "6655819316204680004365614375508079580461146204424752037766280753854543388537",
                "21051385956744942198035008062816432434887289184811055343085396392904977398400",
            ),
            ("1", "0"),
        )),
        gamma_g2: utils::G2Affine_from_str_projective((
            (
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ),
            (
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ),
            ("1", "0"),
        )),
        delta_g2: utils::G2Affine_from_str_projective((
            (
                "11998653647826530912022227389593270429577129765091819606672414955204726946137",
                "12850197969502293778482300034606665950383830355768697463743623195959747528569",
            ),
            (
                "3371177482557063281015231215914240035716553874474070718078727302911297506634",
                "12667795686197095991004340383609552078675969789404912385920584439828198138754",
            ),
            ("1", "0"),
        )),
        gamma_abc_g1: [
            [
                "11423936163622682661315257948859256751456935745483672301927753823261895199269",
                "8106299131826030264309317289206035584499915702251874486285904804204850744645",
                "1",
            ],
            [
                "3101734373871983241904605625023311773791709350380811153571118050344636150719",
                "5892752048111020912174143187873113013528793690570548925602265811558514488885",
                "1",
            ],
            [
                "10476231653569587456624794227763775706638536733174066539315272867287760110504",
                "10966166298405300401399180388536732567182096690752823243070979263725671251842",
                "1",
            ],
            [
                "3616644883823724294840639617628786582022507076201411671428851342676842026051",
                "20036054300972762576589546578455562677975529109923089992859054028247449793275",
                "1",
            ],
            [
                "8922146185459718802170954039785431585338226940878465749467742893964332142463",
                "6543899100030899685821688665010402257161600764202006060926513825176262562594",
                "1",
            ],
            [
                "8838880056209295823278313283853562429175894016112442003934942661774390156254",
                "12827213619164270378479427160832201667918020494718807523503415302940668517033",
                "1",
            ],
            [
                "2830281053896850092944028355764636104294475011402565423874976766597400897579",
                "13415270586926186600118105749667385774136247571413308961986554361125375974552",
                "1",
            ],
            [
                "18596510315364411631453906928618372802526744665579937948378160099177646939132",
                "13639164510921866583928930414183864880892036368934098358398305969672652727368",
                "1",
            ],
            [
                "5166155439194150342865876104665292251058885686253625593517703833929767249773",
                "15776325379616919283841092402757993241658241305931554423955510623840777140969",
                "1",
            ],
            [
                "244871576834190719988785477479956000478101720979685216270364011881385785410",
                "5006539956367064800739393540924950096169041851058318954717373683020872268739",
                "1",
            ],
            [
                "3379906259197166810955208903373839920133048860227880343760386881009843909062",
                "20232197429675204807642408172750830052412585778140676948557231371164499652906",
                "1",
            ],
            [
                "5520775405859402378836749033719619657978092778322140710653552702896452870563",
                "2840091105079872357493316251142119838752629278546220113584117974897982339624",
                "1",
            ],
            [
                "520211872811929422003078090188660039184112525356441893145895540025777918752",
                "18510673159743652418577623905535570073301952222198134524503321213201497608215",
                "1",
            ],
            [
                "6431234738107765889030689757699276709534858281277744012577221575246765244517",
                "4178355859219522686761165914894952086513502987193412248095296044093289572534",
                "1",
            ],
            [
                "4759337634951432350348093011115687353434771991388975508607474262950775320629",
                "3583982358135750838996058092244844686884741536705305315993181569552518297411",
                "1",
            ],
        ]
        .into_iter()
        .map(|s| utils::G1Affine_from_str_projective((s[0], s[1], s[2])))
        .collect(),
    };

    let pvk = PreparedVerifyingKey::from(&vk_from_arkworks(vk));

    let bytes = pvk.serialize_into_parts();
    let vk_gamma_abc_g1_bytes = &bytes[0];
    let alpha_g1_beta_g2_bytes = &bytes[1];
    let gamma_g2_neg_pc_bytes = &bytes[2];
    let delta_g2_neg_pc_bytes = &bytes[3];

    // Should fail verification:.
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &elusiv_sample_proof_invalid_proof.1,
        &elusiv_sample_proof_invalid_proof.0
    )
    .is_err());

    // Should fail verification.
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &elusiv_sample_proof_invalid_pin.1,
        &elusiv_sample_proof_invalid_pin.0
    )
    .is_err());
}

#[test]
fn api_regression_tests() {
    // Prepare VK
    let vk_bytes = hex::decode("3c747dd28b1d21b2be3dae04a8c88152d2a5cec5efc800f7a4feea5f938e248298b4d9f57babfa38799f78172df2c303a754945bba9235b39be37826e4c15b273a0f051b814c50a489f6845bfe80521a1e99fbce0c6fda1ba521d4c29ea8d29e3cb543973711905d0cda7dee3c71e7b9460c34e9e7285e03d5fa519e2986a428754b79e5ddb20de39d9afb7b901b4a60c2366c20e658b476206a1710f99146914633127ccae0e459b3d2a8aa39db9a6d5aa91b5f7038bc2bbd7e9e713e6a9b2fb254de7356d1b449f95168ed30e5570715367c99b0e07fd8595517cdb042432b0200000000000000ada96147db3a3bef28beecff2d9bf2814bf07a62722e69486b6e2c3cd26844ac0779d941feabcdc6ae03c87f33fc46877f0261428e29bbf1087e8f858e1dfa88").unwrap();
    let pvk_expected = vec![
        hex::decode("ada96147db3a3bef28beecff2d9bf2814bf07a62722e69486b6e2c3cd26844ac0779d941feabcdc6ae03c87f33fc46877f0261428e29bbf1087e8f858e1dfa88").unwrap(),
        hex::decode("4d6005b84ae8c96c5ecce7218b59b20a8a6b0ae7b0b4f3d3aa42407f161ddf140b4b211677e840d34950a4a780f91a434304870569e2ab9ee2fe4e3b4b712e2a2e2977ee78da6db29c0c012a13442df99620b008e38a9ea65dbb19a00e10412fc8558f6687fc2f8420ba8546e86dd91779897998a4bbd6d38c3cfd1af46f4d28f5bf00faf918a2c1079b216d03036920a89427bf00d01d17da30adbb9710952785b2dbd6a5e4ae828a970a5862c1c04fc082cf2ff694cbeefb92317dfabc3b21f1e3f17e25aaecbeaabfcd76b72fc9ba6494330ce687ed522bb22468e289dd103212f554cefc72ca9f49717f8aeefe807b4c44260391db2088be32142061921adf9efc013ce13a83aaa856a39480356581c8d2369a8c2b80c418607ec5778804703da5bbff5faf2aab898edd35b694ec5cbd6c8924d5ee5dded531875bcd462636133f8dcb4b858f34c02da0a6a4a12283fbe6def67b54f29f515533da05860430048966aeaa077a536cdc20972c2243de0c15febedcd3241d32c50df205f82a").unwrap(),
        hex::decode("3cb543973711905d0cda7dee3c71e7b9460c34e9e7285e03d5fa519e2986a428754b79e5ddb20de39d9afb7b901b4a60c2366c20e658b476206a1710f9914611").unwrap(),
        hex::decode("4633127ccae0e459b3d2a8aa39db9a6d5aa91b5f7038bc2bbd7e9e713e6a9b2fb254de7356d1b449f95168ed30e5570715367c99b0e07fd8595517cdb04243ab").unwrap(),
    ];
    let pvk_actual = prepare_pvk_bytes(&vk_bytes).unwrap();
    assert_eq!(pvk_expected, pvk_actual);

    // Verify
    let vk_gamma_abc_g1_bytes = hex::decode("df35140d037b211901de04f62a417c53c304328304d738bcc4ff623b1e65698765c6fa5f804bac35ce67f2c26e37bd0cba6f8a944a6c8c17a2417c7b88254f000f87f4f3b509521fbd63e8460ef9082880ada8f342803fd2188e5ce75bbb0d06").unwrap();
    let alpha_g1_beta_g2_bytes = hex::decode("b51f110c1840d39a3185436f5307ad47b375ff892acd78cfa2939556eb46d22112f76ffdd8f3be5fabcc44df3a6750edaaf65af3218f58988afedf6b4202b41066a18f1a8e6b06194838ab7331524da9389802cfd1cc87ef800cbf927fe65e1009fd4d603bf4790371ea2272d17f9a1d98f790b04af2fef1f35889b7e54cc210ce1e47a6ecece6f9d20e8c4514db8f74b96db01cd3528e49faf67d40b7e18f12cd4aadf7698d3fbca9d5a660f677a8c9bba800d3a125c9431e151fa9120c9d07c80d5f662fd6630f1c7441ce7c2f65cad89898222976d519fcadcd9a9beb7120625ee32258e4436e31b4661521c68dbd78027a0935423f2f3b74087c3dcc4b15f8c23a499e1b2e0e456d24274eb7e5c2a0ca3338c5e4ec4d31fd3392c32c790e05142edd5fe2e671260f33318826f2ce0e0cbadb2d347a1644d14824a1f2f402c2740188daef879da5139d06160b1bd44788a272e92d33553631cbc9db991f18606ba945064aff9ec7c0d6d0fde961d834783008718783f67c778dd952b1270f").unwrap();
    let gamma_g2_neg_pc_bytes = hex::decode("04d7dbe72328896134ed56890042202827ce6805cd384ab00afa0997b26a8d0905b8d48c57bcbc7e9d8a2ff6771a50f90d96970636a9e7d89aaf7369ce7e4d9f").unwrap();
    let delta_g2_neg_pc_bytes = hex::decode("06639a71c443532e6c7797e0b18926ea09962bd2fdad9a7130df397463afd315b4bfda26cbef66c4f62f6e65a90d70f058df1f57216846e93890f9b2be68ce85").unwrap();
    let public_inputs_bytes = hex::decode("7b00000000000000000000000000000000000000000000000000000000000000c801000000000000000000000000000000000000000000000000000000000000").unwrap();
    let proof_bytes = hex::decode("537a1b8ba0fc0f2b456c59769a58f22fbf9228311f5cc9070e7358e28c51d2033984c58d47b747c7e07bc87520f14e19029042259a21a910040b87533bf3c32613261dbeffd2913f3627895532b49e9cf623fdfa94e4ef9c040086b397ad640c54c165811c46fa50a880a7b8616d2165848b8f631db25b1b1ebf7fe021f4a11a").unwrap();
    assert!(verify_groth16_in_bytes(
        &vk_gamma_abc_g1_bytes,
        &alpha_g1_beta_g2_bytes,
        &gamma_g2_neg_pc_bytes,
        &delta_g2_neg_pc_bytes,
        &public_inputs_bytes,
        &proof_bytes
    )
    .unwrap());

    // Zeros as public inputs
    let vk_gamma_abc_g1_bytes = hex::decode("7329e3fb0f59e62c7a88ec42ca108a94f525298de1fa7640123daa7469fd1102dacd7b18f373a7ecf75fba98b812367196ff4e62ad4653f0feba143a6ec268a9442f7562a719360f83480bf4624adfdb80faaf2302b0a6022caf32de5a120d8d").unwrap();
    let alpha_g1_beta_g2_bytes = hex::decode("b45caf631bc5d75cf3f00a7520380275d826a41b5641e1acba32b29aea45661480ed201e35888a845744ee5565688aedcc4a25f50fedfc169479285476fc7100a1f525423181d8a1088ee24a9b7e8f91d0bc3465493b591172f3a1a8330f911a2681fee88569d6eac0be6e741f2edd22a244f937db29524a3ed9ddd79112202d194bdc21fe7b374fee3cd4b6395ecb14986054a2b3e2348c496ed12f5db1c806dd1df76a9faa0f62118ea4eb217735206196cf16284f7b5d1bb7fdabc323f02022550841d98b365c22d5d962f4c544bab40059dc5cf576a3c31a1e00cd107c2549df1e99e8837b2e8fe9e846a0f8fdbdf0d47f1051bc280d6cf41fa205d1b72a5be7f6dacca14fc38f83adfa72a38c870cb1e2d638bba767677f087ab65bdd12c9f857334cbcb8d4cdffb901c9ce6123d2525bd93765db4214900ba26a26ce06fa5c661f0a38affe716a95876b394cc20b6862dd112e01be3dec14d7f76b441049cbd5ca74358fd4f4c4027f28b7028a4f49f20129eb28b0f0e861e34bf80805").unwrap();
    let gamma_g2_neg_pc_bytes = hex::decode("f43620ffdf673339d95fbd4b40fbce43b7d4487b58b13f8c9ab146de9c992910ee2953bbad19f7374146404f9fb9a4d4c4668d999e1a125357dcfe8d8d6aaa19").unwrap();
    let delta_g2_neg_pc_bytes = hex::decode("fbb7656bf9f28ccfbeb13b78811bd4fb8cc4dcc301bccf8b7f604c60a13caf1996a518acb5ee768617e54dfab6aa3743881a62b2dfd4222fa13d4f85de913216").unwrap();
    let public_inputs_bytes = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let proof_bytes = hex::decode("52ce4e209a74e81322849ec341378c332cdb08ba74cd8804e763d4d1af73778cce951ab584d2100a1fd9edd2eec8e8f929029bdd9cf8f9fdaccb683368e797092f5d1415f6e26a8604dd87a85b66faa68fcb00627952d21dbeb8392e52692c83f0fc821e2bb35e09cfb3316d9266a2de90d79d67344b6d727b6eac573a0a6d8a").unwrap();
    assert!(verify_groth16_in_bytes(
        &vk_gamma_abc_g1_bytes,
        &alpha_g1_beta_g2_bytes,
        &gamma_g2_neg_pc_bytes,
        &delta_g2_neg_pc_bytes,
        &public_inputs_bytes,
        &proof_bytes
    )
    .unwrap());

    // Trivial proof with all zeros/identity elements
    let mut g1_inf_bytes = vec![];
    G1Projective::zero()
        .serialize_compressed(&mut g1_inf_bytes)
        .unwrap();

    let mut vk_gamma_abc_g1_bytes = vec![];
    vk_gamma_abc_g1_bytes.extend_from_slice(&g1_inf_bytes);
    vk_gamma_abc_g1_bytes.extend_from_slice(&g1_inf_bytes);
    vk_gamma_abc_g1_bytes.extend_from_slice(&g1_inf_bytes);

    let mut alpha_g1_beta_g2_bytes = vec![];
    Fq12::one()
        .serialize_compressed(&mut alpha_g1_beta_g2_bytes)
        .unwrap();

    let mut g2_inf_bytes = vec![];
    G2Projective::zero()
        .serialize_compressed(&mut g2_inf_bytes)
        .unwrap();

    let gamma_g2_neg_pc_bytes = g2_inf_bytes.clone();
    let delta_g2_neg_pc_bytes = g2_inf_bytes.clone();
    let public_inputs_bytes = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

    let mut proof_bytes = vec![];
    proof_bytes.extend_from_slice(&g1_inf_bytes);
    proof_bytes.extend_from_slice(&g2_inf_bytes);
    proof_bytes.extend_from_slice(&g1_inf_bytes);

    // The trivial proof should pass verification
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
