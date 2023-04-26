// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_ec::AffineRepr;
#[cfg(test)]
use ark_ec::{CurveGroup, Group};
#[cfg(test)]
use ark_ff::UniformRand;
use ark_ff::PrimeField as ArkworksPrimeField;
use ark_serialize::{CanonicalSerializeWithFlags, EmptyFlags};
use elliptic_curve::bigint::ArrayEncoding;
#[cfg(test)]
use elliptic_curve::group::prime::PrimeCurveAffine;
#[cfg(test)]
use elliptic_curve::ops::Reduce;
use elliptic_curve::scalar::FromUintUnchecked;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
#[cfg(test)]
use elliptic_curve::Field;
use elliptic_curve::PrimeField;
use p256::{FieldBytes, U256};

/// Convert a p256 scalar to an arkworks scalar.
pub(crate) fn fr_p256_to_arkworks(scalar: &p256::Scalar) -> ark_secp256r1::Fr {
    ark_secp256r1::Fr::from_be_bytes_mod_order(scalar.to_bytes().as_slice())
}

/// Convert an arkworks scalar to a p256 scalar.
pub(crate) fn fr_arkworks_to_p256(scalar: &ark_secp256r1::Fr) -> p256::Scalar {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_with_flags(&mut bytes[..], EmptyFlags)
        .unwrap();
    p256::Scalar::from_uint_unchecked(U256::from_le_byte_array(FieldBytes::clone_from_slice(
        bytes.as_slice(),
    )))
}

/// Convert an arkworks field element to a p256 field element.
pub(crate) fn fq_arkworks_to_p256(scalar: &ark_secp256r1::Fq) -> p256::Scalar {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_with_flags(&mut bytes[..], EmptyFlags)
        .unwrap();
    p256::Scalar::from_uint_unchecked(U256::from_le_byte_array(FieldBytes::clone_from_slice(
        bytes.as_slice(),
    )))
}

/// Convert an arkworks field element to a p256 field element.
pub(crate) fn fq_p256_to_arkworks(scalar: &p256::Scalar) -> ark_secp256r1::Fq {
    ark_secp256r1::Fq::from_be_bytes_mod_order(scalar.to_bytes().as_slice())
}

/// Convert an p256 affine point to an arkworks affine point.
pub(crate) fn affine_pt_p256_to_arkworks(point: &p256::AffinePoint) -> ark_secp256r1::Affine {
    if point.is_identity().into() {
        return ark_secp256r1::Affine::zero();
    }
    let encoded_point = point.to_encoded_point(false);
    ark_secp256r1::Affine::new_unchecked(
        ark_secp256r1::Fq::from_be_bytes_mod_order(encoded_point.x().unwrap()),
        ark_secp256r1::Fq::from_be_bytes_mod_order(encoded_point.y().unwrap()),
    )
}

/// Reduce an arkworks field element (modulo field size) to a scalar (modulo subgroup order)
pub(crate) fn arkworks_fq_to_fr(scalar: &ark_secp256r1::Fq) -> ark_secp256r1::Fr {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_with_flags(&mut bytes[..], EmptyFlags)
        .unwrap();
    ark_secp256r1::Fr::from_le_bytes_mod_order(bytes.as_slice())
}

/// Converts an arkworks affine point to a p256 affine point.
pub(crate) fn affine_pt_arkworks_to_p256(point: &ark_secp256r1::Affine) -> p256::AffinePoint {
    if point.is_zero() {
        return p256::AffinePoint::IDENTITY;
    }
    let encoded_point = p256::EncodedPoint::from_affine_coordinates(
        &fq_arkworks_to_p256(point.x().unwrap()).to_bytes(),
        &fq_arkworks_to_p256(point.y().unwrap()).to_bytes(),
        false,
    );
    p256::AffinePoint::from_encoded_point(&encoded_point).unwrap()
}

pub(crate) fn reduce_bytes(bytes: &FieldBytes) -> ark_secp256r1::Fr {
    arkworks_fq_to_fr(&fq_p256_to_arkworks(
        &p256::Scalar::from_repr(*bytes).unwrap(),
    ))
}

#[test]
fn test_fr_p256_to_arkworks() {
    let arkworks_seven = ark_secp256r1::Fr::from(7u32);
    let p256_seven = p256::Scalar::from(7u32);

    let actual_arkworks_seven = fr_p256_to_arkworks(&p256_seven);
    assert_eq!(actual_arkworks_seven, arkworks_seven);

    let actual_p256_seven = fr_arkworks_to_p256(&arkworks_seven);
    assert_eq!(actual_p256_seven, p256_seven);
}

#[test]
fn test_pt_arkworks_to_p256() {
    // G
    assert_eq!(
        p256::AffinePoint::generator(),
        affine_pt_arkworks_to_p256(&ark_secp256r1::Affine::generator())
    );

    // 7G
    assert_eq!(
        (p256::AffinePoint::generator() * p256::Scalar::from(7u32)).to_affine(),
        affine_pt_arkworks_to_p256(
            &(ark_secp256r1::Projective::generator() * ark_secp256r1::Fr::from(7u32)).into_affine()
        )
    );

    // sG
    let random_s = p256::Scalar::random(&mut rand::thread_rng());
    assert_eq!(
        (p256::AffinePoint::generator() * random_s).to_affine(),
        affine_pt_arkworks_to_p256(
            &(ark_secp256r1::Projective::generator() * fr_p256_to_arkworks(&random_s))
                .into_affine()
        )
    );
}

#[test]
fn test_pt_p256_to_arkworks() {
    assert_eq!(
        ark_secp256r1::Affine::generator(),
        affine_pt_p256_to_arkworks(&p256::AffinePoint::generator())
    );
}

#[test]
fn test_arkworks_fq_to_fr() {
    let s = ark_secp256r1::Fq::rand(&mut rand::thread_rng());
    let s_fr = arkworks_fq_to_fr(&s);
    let p256_s = fq_arkworks_to_p256(&s);
    let reduced_s = p256::Scalar::reduce_bytes(&p256_s.to_bytes());
    assert_eq!(fr_arkworks_to_p256(&s_fr), reduced_s);

    assert_eq!(reduce_bytes(&p256_s.to_bytes()), s_fr);
}

#[test]
fn test_fq_p256_to_arkworks() {
    let arkworks_seven = ark_secp256r1::Fq::from(7u32);
    let p256_seven = p256::Scalar::from(7u32);

    let actual_arkworks_seven = fq_p256_to_arkworks(&p256_seven);
    assert_eq!(actual_arkworks_seven, arkworks_seven);

    let actual_p256_seven = fq_arkworks_to_p256(&arkworks_seven);
    assert_eq!(actual_p256_seven, p256_seven);
}
