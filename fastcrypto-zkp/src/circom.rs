// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInt, Field, Fp, Zero};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use std::ops::Mul;

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

    if !g1.is_on_curve() {
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
    g2_unchecked_projective_to_affine(
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
}

/// Convert a G2 projective point in BN254 to an affine G2 point in arkworks format. Return an error
/// if the input is not a valid projective point, if it's not on the curve or in the G2 subgroup.
fn g2_unchecked_projective_to_affine(x: Fq2, y: Fq2, z: Fq2) -> FastCryptoResult<G2Affine> {
    if z.is_zero() {
        return Ok(G2Affine::zero());
    }

    let projective = G2Projective::new_unchecked(x, y, z);

    // This is safe to do, even if z = 0 in which case it is interpreted as the point at infinity
    let affine = projective.into_affine();

    if !affine.is_on_curve() {
        return Err(FastCryptoError::InvalidInput);
    }

    // Subgroup check from https://eprint.iacr.org/2022/352.pdf: Check if
    //      (xi^{(p^2 - 1) / 3} * x'^p, xi^{(p^2 - 1) / 2} * y'^p) == [6x^2]P
    // where xi = 9 + u is used in the construction of Fq2, (x', y') are the coordinates of the point in affine form,
    // p is the field size and x is the parameter of the construction (x = 4965661367192848881).

    // xi^{(p^2 - 1) / 3} (hardcoded)
    let coefficient_x = Fq2::new(
        Fp::new(BigInt([
            11088870908804158781,
            13226160682434769676,
            5479733118184829251,
            3437169660107756023,
        ])),
        Fp::new(BigInt([
            1613930359396748194,
            3651902652079185358,
            5450706350010664852,
            1642095672556236320,
        ])),
    );

    // xi^{(p^2 - 1) / 2} (hardcoded)
    let coefficient_y = Fq2::new(
        Fp::new(BigInt([
            15876315988453495642,
            15828711151707445656,
            15879347695360604601,
            449501266848708060,
        ])),
        Fp::new(BigInt([
            9427018508834943203,
            2414067704922266578,
            505728791003885355,
            558513134835401882,
        ])),
    );

    // xi^{(p^2 - 1) / 3} * x'^p
    let x = affine.x.frobenius_map(1).mul(&coefficient_x);

    // xi^{(p^2 - 1) / 2} * y'^p
    let y = affine.y.frobenius_map(1).mul(&coefficient_y);

    // [6x^2]P (hardcoded)
    let rhs = (projective.mul_bigint([17887900258952609094, 8020209761171036667])).into_affine();

    if rhs.x().unwrap() == &x && rhs.y().unwrap() == &y {
        Ok(affine)
    } else {
        Err(FastCryptoError::InvalidInput)
    }
}

#[test]
fn test_parse_g2_as_affine() {
    let g2 = g2_affine_from_str_projective(&vec![
        vec!["1".to_string(), "0".to_string()],
        vec!["0".to_string(), "1".to_string()],
        vec!["0".to_string(), "0".to_string()],
    ]);
    assert!(g2.is_ok());
    assert!(g2.unwrap().is_zero());

    let g2 = g2_unchecked_projective_to_affine(
        Fq2::new(
            parse_field_element(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            parse_field_element(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ),
        Fq2::new(
            parse_field_element(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            parse_field_element(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ),
        Fq2::new(
            parse_field_element("1").unwrap(),
            parse_field_element("0").unwrap(),
        ),
    );
    let affine = g2.unwrap();
    assert!(affine.is_on_curve() && affine.is_in_correct_subgroup_assuming_on_curve());

    // TODO: More tests
}
