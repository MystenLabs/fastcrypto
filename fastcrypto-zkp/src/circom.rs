// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine};

pub type CircomG1 = [String; 3];
pub type CircomG2 = [[String; 2]; 3];

pub fn g1_affine_from_str_projective(s: CircomG1) -> G1Affine {
    G1Projective::new(
        s[0].parse::<Fq>().unwrap(),
        s[1].parse::<Fq>().unwrap(),
        s[2].parse::<Fq>().unwrap(),
    )
    .into()
}

pub fn g2_affine_from_str_projective(s: CircomG2) -> G2Affine {
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
