// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine};

type StrPair = (&'static str, &'static str);
type StrTriplet = (&'static str, &'static str, &'static str);

#[allow(non_snake_case)]
pub(crate) fn G1Affine_from_str_projective(
    #[allow(clippy::type_complexity)] s: StrTriplet,
) -> G1Affine {
    G1Projective::new(
        s.0.parse::<Fq>().unwrap(),
        s.1.parse::<Fq>().unwrap(),
        s.2.parse::<Fq>().unwrap(),
    )
    .into()
}

#[allow(non_snake_case)]
pub(crate) fn G2Affine_from_str_projective(s: (StrPair, StrPair, StrPair)) -> G2Affine {
    use ark_bn254::G2Projective;
    G2Projective::new(
        Fq2::new(s.0 .0.parse::<Fq>().unwrap(), s.0 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.1 .0.parse::<Fq>().unwrap(), s.1 .1.parse::<Fq>().unwrap()),
        Fq2::new(s.2 .0.parse::<Fq>().unwrap(), s.2 .1.parse::<Fq>().unwrap()),
    )
    .into()
}
