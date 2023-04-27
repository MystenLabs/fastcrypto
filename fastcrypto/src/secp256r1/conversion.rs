// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains conversion function between scalars (fr), field elements (fq) and elliptic curve
//! points between the representations used by arkworks in ark-secp256r1 and RustCrypto's p256 crate.

use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField as ArkworksPrimeField, Zero};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeWithFlags, EmptyFlags};
use elliptic_curve::bigint::ArrayEncoding;
use elliptic_curve::scalar::FromUintUnchecked;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::{FieldBytes, U256};

/// Convert a p256 scalar to an arkworks scalar.
pub(crate) fn fr_p256_to_arkworks(scalar: &p256::Scalar) -> ark_secp256r1::Fr {
    ark_secp256r1::Fr::from_be_bytes_mod_order(&scalar.to_bytes())
}

/// Convert an arkworks scalar to a p256 scalar.
pub(crate) fn fr_arkworks_to_p256(scalar: &ark_secp256r1::Fr) -> p256::Scalar {
    // This implementation is taken from bls_fr_to_blst_fr in fastcrypto-zkp.
    let mut bytes = [0u8; 32];
    scalar
        .serialize_with_flags(&mut bytes[..], EmptyFlags)
        .unwrap();
    p256::Scalar::from_uint_unchecked(U256::from_le_byte_array(FieldBytes::from(bytes)))
}

/// Convert an arkworks field element to a p256 field element.
pub(crate) fn fq_arkworks_to_p256(scalar: &ark_secp256r1::Fq) -> p256::Scalar {
    // This implementation is taken from bls_fq_to_blst_fp in fastcrypto-zkp.
    let mut bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut bytes[..]).unwrap();
    p256::Scalar::from_uint_unchecked(U256::from_le_byte_array(FieldBytes::from(bytes)))
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

/// Reduce a big-endian integer representation modulo the subgroup order in arkworks representation.
pub(crate) fn reduce_bytes(bytes: &[u8; 32]) -> ark_secp256r1::Fr {
    ark_secp256r1::Fr::from_be_bytes_mod_order(bytes)
}

/// Reduce an arkworks field element (modulo field size) to a scalar (modulo subgroup order)
pub(crate) fn arkworks_fq_to_fr(scalar: &ark_secp256r1::Fq) -> ark_secp256r1::Fr {
    let mut bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut bytes[..]).unwrap();
    ark_secp256r1::Fr::from_le_bytes_mod_order(&bytes)
}

/// Converts an arkworks affine point to a p256 affine point.
pub(crate) fn affine_pt_arkworks_to_p256(point: &ark_secp256r1::Affine) -> p256::AffinePoint {
    if point.is_zero() {
        return p256::AffinePoint::IDENTITY;
    }
    let encoded_point = p256::EncodedPoint::from_affine_coordinates(
        &fq_arkworks_to_p256(point.x().expect("The point should not be zero")).to_bytes(),
        &fq_arkworks_to_p256(point.y().expect("The point should not be zero")).to_bytes(),
        false,
    );
    p256::AffinePoint::from_encoded_point(&encoded_point).unwrap()
}

/// Extract the affine x-coordinate from a projective point. Returns none if the point is the identity.
pub(crate) fn get_affine_x_coordinate(
    point: &ark_secp256r1::Projective,
) -> Option<ark_secp256r1::Fq> {
    if point.is_zero() {
        return None;
    }
    let mut z_inv = point
        .z
        .inverse()
        .expect("z is zero. This should never happen.");
    z_inv.square_in_place();
    Some(point.x * z_inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, Group};
    use ark_ff::UniformRand;
    use elliptic_curve::group::prime::PrimeCurveAffine;
    use elliptic_curve::ops::Reduce;
    use elliptic_curve::Field;

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
        // 0
        assert_eq!(
            p256::AffinePoint::IDENTITY,
            affine_pt_arkworks_to_p256(&ark_secp256r1::Affine::zero())
        );

        // G
        assert_eq!(
            p256::AffinePoint::generator(),
            affine_pt_arkworks_to_p256(&ark_secp256r1::Affine::generator())
        );

        // 7G
        assert_eq!(
            (p256::AffinePoint::generator() * p256::Scalar::from(7u32)).to_affine(),
            affine_pt_arkworks_to_p256(
                &(ark_secp256r1::Projective::generator() * ark_secp256r1::Fr::from(7u32))
                    .into_affine()
            )
        );

        // sG, random s
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
        // 0
        assert_eq!(
            ark_secp256r1::Affine::zero(),
            affine_pt_p256_to_arkworks(&p256::AffinePoint::IDENTITY)
        );

        // G
        assert_eq!(
            ark_secp256r1::Affine::generator() * ark_secp256r1::Fr::from(7u32),
            affine_pt_p256_to_arkworks(
                &(p256::AffinePoint::generator() * p256::Scalar::from(7u32)).to_affine()
            )
        );

        // 7G
        assert_eq!(
            ark_secp256r1::Affine::generator(),
            affine_pt_p256_to_arkworks(&p256::AffinePoint::generator())
        );

        // sG, random s
        let random_s = p256::Scalar::random(&mut rand::thread_rng());
        assert_eq!(
            (ark_secp256r1::Affine::generator() * fr_p256_to_arkworks(&random_s)).into_affine(),
            affine_pt_p256_to_arkworks(&(p256::AffinePoint::generator() * random_s).to_affine())
        );
    }

    #[test]
    fn test_arkworks_fq_to_fr() {
        let s = ark_secp256r1::Fq::rand(&mut rand::thread_rng());
        let s_fr = arkworks_fq_to_fr(&s);
        let p256_s = fq_arkworks_to_p256(&s);
        let reduced_s = p256::Scalar::reduce_bytes(&p256_s.to_bytes());
        assert_eq!(fr_arkworks_to_p256(&s_fr), reduced_s);
        assert_eq!(reduce_bytes(&p256_s.to_bytes().try_into().unwrap()), s_fr);
    }

    #[test]
    fn test_fq_arkworks_to_p256() {
        let arkworks_seven = ark_secp256r1::Fq::from(7u32);
        let p256_seven = p256::Scalar::from(7u32);

        let actual_p256_seven = fq_arkworks_to_p256(&arkworks_seven);
        assert_eq!(actual_p256_seven, p256_seven);
    }
}
