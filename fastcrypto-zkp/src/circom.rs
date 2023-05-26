// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;

use serde::Deserialize;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_groth16::{Proof, VerifyingKey};

type StrPair = (String, String);
type StrTriplet = (String, String, String);
type CircomG1 = StrTriplet;
type CircomG2 = (StrPair, StrPair, StrPair);
type CircomICElement = StrTriplet;

pub fn g1_affine_from_str_projective(s: CircomG1) -> G1Affine {
    G1Projective::new(
        s.0.parse::<Fq>().unwrap(),
        s.1.parse::<Fq>().unwrap(),
        s.2.parse::<Fq>().unwrap(),
    )
    .into()
}

pub fn g2_affine_from_str_projective(s: CircomG2) -> G2Affine {
    use ark_bn254::G2Projective;
    G2Projective::new(
        Fq2::new(s.0 .0.parse::<Fq>().unwrap(), s.0 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.1 .0.parse::<Fq>().unwrap(), s.1 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.2 .0.parse::<Fq>().unwrap(), s.2 .1.parse::<Fq>().unwrap()),
    )
    .into()
}

// Note: Not reading vk_alphabeta_12 because it gets computed as part of prepare_verifying_key
#[allow(non_snake_case)]
#[derive(Deserialize, Debug)]
struct CircomVK {
    protocol: String,
    curve: String,
    nPublic: u8,
    vk_alpha_1: CircomG1,
    vk_beta_2: CircomG2,
    vk_gamma_2: CircomG2,
    vk_delta_2: CircomG2,
    IC: Vec<CircomICElement>,
}

// Read a Circom vkey file and return the arkworks verification key
pub fn read_vkey(path: &str) -> VerifyingKey<Bn254> {
    let mut file = File::open(path).unwrap();

    // Deserialize the JSON file
    let vk: CircomVK = serde_json::from_reader(&mut file).unwrap();

    assert!(vk.protocol == "groth16");
    assert!(vk.curve == "bn128");
    assert!(vk.nPublic + 1 == vk.IC.len() as u8);

    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(vk.vk_alpha_1);
    let vk_beta_2 = g2_affine_from_str_projective(vk.vk_beta_2);
    let vk_gamma_2 = g2_affine_from_str_projective(vk.vk_gamma_2);
    let vk_delta_2 = g2_affine_from_str_projective(vk.vk_delta_2);

    // Create a vector of G1Affine elements from the IC
    let mut vk_gamma_abc_g1 = Vec::new();
    for e in vk.IC {
        let g1 = g1_affine_from_str_projective(e);
        vk_gamma_abc_g1.push(g1);
    }

    VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    }
}

#[derive(serde::Deserialize, Debug)]
struct CircomProof {
    pi_a: CircomG1,
    pi_b: CircomG2,
    pi_c: CircomG1,
    protocol: String,
    curve: String,
}

pub fn read_proof(path: &str) -> Proof<Bn254> {
    let mut file = File::open(path).unwrap();

    // Deserialize the JSON file
    let proof: CircomProof = serde_json::from_reader(&mut file).unwrap();

    assert!(proof.protocol == "groth16");
    assert!(proof.curve == "bn128");

    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let a = g1_affine_from_str_projective(proof.pi_a);
    let b = g2_affine_from_str_projective(proof.pi_b);
    let c = g1_affine_from_str_projective(proof.pi_c);

    Proof { a, b, c }
}

type CircomPublicInputs = Vec<String>;
use std::str::FromStr;

pub fn read_public_inputs(path: &str) -> Vec<Fr> {
    let mut file = File::open(path).unwrap();

    let public_inputs: CircomPublicInputs = serde_json::from_reader(&mut file).unwrap();

    let arkworks_public_inputs: Vec<Fr> = public_inputs
        .iter()
        .map(|x| Fr::from_str(x).unwrap())
        .collect();

    arkworks_public_inputs
}
