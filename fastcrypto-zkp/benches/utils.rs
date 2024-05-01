// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use fastcrypto_zkp::bn254::VerifyingKey;

type StrPair = (&'static str, &'static str);
type StrTriplet = (&'static str, &'static str, &'static str);

pub fn vk_from_arkworks(vk: ark_groth16::VerifyingKey<Bn254>) -> VerifyingKey {
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

#[allow(non_snake_case)]
pub fn G1Affine_from_str_projective(#[allow(clippy::type_complexity)] s: StrTriplet) -> G1Affine {
    G1Projective::new(
        s.0.parse::<Fq>().unwrap(),
        s.1.parse::<Fq>().unwrap(),
        s.2.parse::<Fq>().unwrap(),
    )
    .into()
}

#[allow(non_snake_case)]
pub fn G2Affine_from_str_projective(s: (StrPair, StrPair, StrPair)) -> G2Affine {
    G2Projective::new(
        Fq2::new(s.0 .0.parse::<Fq>().unwrap(), s.0 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.1 .0.parse::<Fq>().unwrap(), s.1 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.2 .0.parse::<Fq>().unwrap(), s.2 .1.parse::<Fq>().unwrap()),
    )
    .into()
}
