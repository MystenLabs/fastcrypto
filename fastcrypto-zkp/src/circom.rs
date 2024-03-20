// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use fastcrypto::error::FastCryptoError;

/// A G1 point in BN254 serialized as a vector of three strings which is the canonical decimal
/// representation of the projective coordinates in Fq.
pub type CircomG1 = Vec<String>;

/// A G2 point in BN254 serialized as a vector of three vectors each being a vector of two strings
/// which are the canonical decimal representation of the coefficients of the projective coordinates
/// in Fq2.
pub type CircomG2 = Vec<Vec<String>>;

/// Parse a string as a field element in BN254. Return an `FastCryptoError::InvalidInput` error if
/// the parsing fails.
fn parse_field_element(s: &str) -> Result<Fq, FastCryptoError> {
    s.parse::<Fq>().map_err(|_| FastCryptoError::InvalidInput)
}

/// Deserialize a G1 projective point in BN254 serialized as a vector of three strings into an affine
/// G1 point in arkworks format. Return an error if the input is not a vector of three strings or if
/// any of the strings cannot be parsed as a field element.
pub(crate) fn g1_affine_from_str_projective(s: &CircomG1) -> Result<G1Affine, FastCryptoError> {
    if s.len() != 3 {
        return Err(FastCryptoError::InvalidInput);
    }

    let g1: G1Affine = G1Projective::new_unchecked(
        parse_field_element(&s[0])?,
        parse_field_element(&s[1])?,
        parse_field_element(&s[2])?,
    )
    .into();

    if !g1.is_on_curve() || !g1.is_in_correct_subgroup_assuming_on_curve() {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(g1)
}

/// Deserialize a G2 projective point from the BN254 construction serialized as a vector of three
/// vectors each being a vector of two strings into an affine G2 point in arkworks format. Return an
/// error if the input is not a vector of the right format or if any of the strings cannot be parsed
/// as a field element.
pub(crate) fn g2_affine_from_str_projective(s: &CircomG2) -> Result<G2Affine, FastCryptoError> {
    if s.len() != 3 || s[0].len() != 2 || s[1].len() != 2 || s[2].len() != 2 {
        return Err(FastCryptoError::InvalidInput);
    }

    let g2: G2Affine = G2Projective::new_unchecked(
        Fq2::new(
            parse_field_element(&s[0][0])?,
            parse_field_element(&s[0][1])?,
        ),
        Fq2::new(
            parse_field_element(&s[1][0])?,
            parse_field_element(&s[1][1])?,
        ),
        Fq2::new(
            parse_field_element(&s[2][0])?,
            parse_field_element(&s[2][1])?,
        ),
    )
    .into();

    if !g2.is_on_curve() || !g2.is_in_correct_subgroup_assuming_on_curve() {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(g2)
}
