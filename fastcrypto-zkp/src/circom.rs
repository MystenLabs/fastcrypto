// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_groth16::Proof;

type CircomG1 = Vec<String>;
type CircomG2 = Vec<Vec<String>>;

pub fn g1_affine_from_str_projective(s: CircomG1) -> G1Affine {
    assert!(s.len() == 3);
    G1Projective::new(
        s[0].parse::<Fq>().unwrap(),
        s[1].parse::<Fq>().unwrap(),
        s[2].parse::<Fq>().unwrap(),
    )
    .into()
}

pub fn g2_affine_from_str_projective(s: CircomG2) -> G2Affine {
    assert!(s.len() == 3);
    assert!(s[0].len() == 2);
    assert!(s[1].len() == 2);
    assert!(s[2].len() == 2);
    use ark_bn254::G2Projective;
    G2Projective::new(
        Fq2::new(
            s[0][0].parse::<Fq>().unwrap(),
            s[0][1].parse::<Fq>().unwrap(),
        ),
        Fq2::new(
            s[1][0].parse::<Fq>().unwrap(),
            s[1][1].parse::<Fq>().unwrap(),
        ),
        Fq2::new(
            s[2][0].parse::<Fq>().unwrap(),
            s[2][1].parse::<Fq>().unwrap(),
        ),
    )
    .into()
}

#[derive(serde::Deserialize, Debug)]
pub struct CircomProof {
    pi_a: CircomG1,
    pi_b: CircomG2,
    pi_c: CircomG1,
    pub protocol: String,
}

pub fn read_proof(value: &str) -> Proof<Bn254> {
    // Deserialize the JSON file
    let proof: CircomProof = serde_json::from_str(value).unwrap();

    assert!(proof.protocol == "groth16");

    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let a = g1_affine_from_str_projective(proof.pi_a);
    let b = g2_affine_from_str_projective(proof.pi_b);
    let c = g1_affine_from_str_projective(proof.pi_c);

    Proof { a, b, c }
}

pub type CircomPublicInputs = Vec<String>;
use std::str::FromStr;

pub fn read_public_inputs(value: &str) -> Vec<Fr> {
    let public_inputs: CircomPublicInputs = serde_json::from_str(value).unwrap();

    let arkworks_public_inputs: Vec<Fr> = public_inputs
        .iter()
        .map(|x| Fr::from_str(x).unwrap())
        .collect();

    arkworks_public_inputs
}
