// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains conversion function between scalars (fr), field elements (fq) and elliptic curve
//! points between the representations used by arkworks in ark-secp384r1 and RustCrypto's p384 crate.

#[cfg(test)]
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField as ArkworksPrimeField, Zero};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeWithFlags, EmptyFlags};
use elliptic_curve::bigint::ArrayEncoding;
use elliptic_curve::scalar::FromUintUnchecked;
#[cfg(test)]
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use generic_array::GenericArray;
use p384::{FieldBytes, U384};

/// The size in bytes of a serialized field element or scalar.
const FIELD_BYTES_SIZE: usize = 48;

/// Convert a p384 scalar to an arkworks scalar.
pub(crate) fn fr_p384_to_arkworks(scalar: &p384::Scalar) -> ark_secp384r1::Fr {
    ark_secp384r1::Fr::from_be_bytes_mod_order(&scalar.to_bytes())
}

/// Convert an arkworks scalar to a p384 scalar.
pub(crate) fn fr_arkworks_to_p384(scalar: &ark_secp384r1::Fr) -> p384::Scalar {
    // This implementation is taken from bls_fr_to_blst_fr in fastcrypto-zkp.
    let mut bytes = [0u8; FIELD_BYTES_SIZE];
    scalar
        .serialize_with_flags(&mut bytes[..], EmptyFlags)
        .unwrap();
    p384::Scalar::from_uint_unchecked(U384::from_le_byte_array(GenericArray::clone_from_slice(
        &bytes,
    )))
}

/// Convert an arkworks field element to a p384 field element.
#[cfg(test)]
pub(crate) fn fq_arkworks_to_p384(scalar: &ark_secp384r1::Fq) -> FieldBytes {
    // This implementation is taken from bls_fq_to_blst_fp in fastcrypto-zkp.
    let mut bytes = [0u8; FIELD_BYTES_SIZE];
    scalar.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes.reverse();
    FieldBytes::clone_from_slice(&bytes)
}

/// Convert a p384 affine point to an arkworks affine point.
pub(crate) fn affine_pt_p384_to_projective_arkworks(
    point: &p384::AffinePoint,
) -> ark_secp384r1::Projective {
    if point.is_identity().into() {
        return ark_secp384r1::Projective::zero();
    }
    let encoded_point = point.to_encoded_point(false);
    ark_secp384r1::Projective::from(ark_secp384r1::Affine::new_unchecked(
        ark_secp384r1::Fq::from_be_bytes_mod_order(encoded_point.x().unwrap()),
        ark_secp384r1::Fq::from_be_bytes_mod_order(encoded_point.y().unwrap()),
    ))
}

/// Convert a message digest to an integer representation as defined in the `bits2int` algorithm in
/// section 2.3.2 in "SEC 1: Elliptic Curve Cryptography": If the digest is longer than 48 bytes
/// (384 bits), only the leftmost 384 bits are used, and if it is shorter it is padded with zeros
/// from the left. This is the same encoding used by the p384 crate.
pub(crate) fn digest_to_field_bytes(digest: &[u8]) -> FieldBytes {
    let mut bytes = FieldBytes::default();
    if digest.len() >= FIELD_BYTES_SIZE {
        bytes.copy_from_slice(&digest[..FIELD_BYTES_SIZE]);
    } else {
        bytes[FIELD_BYTES_SIZE - digest.len()..].copy_from_slice(digest);
    }
    bytes
}

/// Reduce a big-endian integer representation modulo the subgroup order in arkworks representation.
pub(crate) fn reduce_bytes(bytes: &FieldBytes) -> ark_secp384r1::Fr {
    ark_secp384r1::Fr::from_be_bytes_mod_order(bytes)
}

/// Reduce an arkworks field element (modulo field size) to a scalar (modulo subgroup order). This also
/// returns a boolean indicating whether a modular reduction was performed.
pub(crate) fn arkworks_fq_to_fr(scalar: &ark_secp384r1::Fq) -> (ark_secp384r1::Fr, bool) {
    let mut bytes = [0u8; FIELD_BYTES_SIZE];
    scalar.serialize_uncompressed(&mut bytes[..]).unwrap();
    let output = ark_secp384r1::Fr::from_le_bytes_mod_order(&bytes);
    (output, output.into_bigint() != scalar.into_bigint())
}

/// Converts an arkworks affine point to a p384 affine point.
#[cfg(test)]
pub(crate) fn affine_pt_arkworks_to_p384(point: &ark_secp384r1::Affine) -> p384::AffinePoint {
    if point.is_zero() {
        return p384::AffinePoint::IDENTITY;
    }
    let encoded_point = p384::EncodedPoint::from_affine_coordinates(
        &fq_arkworks_to_p384(point.x().expect("The point should not be zero")),
        &fq_arkworks_to_p384(point.y().expect("The point should not be zero")),
        false,
    );
    p384::AffinePoint::from_encoded_point(&encoded_point).unwrap()
}

/// Extract the affine x-coordinate from a projective point. Returns none if the point is the identity.
pub(crate) fn get_affine_x_coordinate(
    point: &ark_secp384r1::Projective,
) -> Option<ark_secp384r1::Fq> {
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
    fn test_fr_p384_to_arkworks() {
        let arkworks_seven = ark_secp384r1::Fr::from(7u32);
        let p384_seven = p384::Scalar::from(7u32);

        let actual_arkworks_seven = fr_p384_to_arkworks(&p384_seven);
        assert_eq!(actual_arkworks_seven, arkworks_seven);

        let actual_p384_seven = fr_arkworks_to_p384(&arkworks_seven);
        assert_eq!(actual_p384_seven, p384_seven);
    }

    #[test]
    fn test_pt_arkworks_to_p384() {
        // 0
        assert_eq!(
            p384::AffinePoint::IDENTITY,
            affine_pt_arkworks_to_p384(&ark_secp384r1::Affine::zero())
        );

        // G
        assert_eq!(
            p384::AffinePoint::generator(),
            affine_pt_arkworks_to_p384(&ark_secp384r1::Affine::generator())
        );

        // 7G
        assert_eq!(
            (p384::AffinePoint::generator() * p384::Scalar::from(7u32)).to_affine(),
            affine_pt_arkworks_to_p384(
                &(ark_secp384r1::Projective::generator() * ark_secp384r1::Fr::from(7u32))
                    .into_affine()
            )
        );

        // sG, random s
        let random_s = p384::Scalar::random(&mut rand::thread_rng());
        assert_eq!(
            (p384::AffinePoint::generator() * random_s).to_affine(),
            affine_pt_arkworks_to_p384(
                &(ark_secp384r1::Projective::generator() * fr_p384_to_arkworks(&random_s))
                    .into_affine()
            )
        );
    }

    #[test]
    fn test_pt_p384_to_arkworks() {
        // 0
        assert_eq!(
            ark_secp384r1::Projective::zero(),
            affine_pt_p384_to_projective_arkworks(&p384::AffinePoint::IDENTITY)
        );

        // G
        assert_eq!(
            ark_secp384r1::Projective::generator(),
            affine_pt_p384_to_projective_arkworks(&p384::AffinePoint::generator())
        );

        // 7G
        assert_eq!(
            ark_secp384r1::Projective::generator() * ark_secp384r1::Fr::from(7u32),
            affine_pt_p384_to_projective_arkworks(
                &(p384::AffinePoint::generator() * p384::Scalar::from(7u32)).to_affine()
            )
        );

        // sG, random s
        let random_s = p384::Scalar::random(&mut rand::thread_rng());
        assert_eq!(
            (ark_secp384r1::Projective::generator() * fr_p384_to_arkworks(&random_s)).into_affine(),
            affine_pt_p384_to_projective_arkworks(
                &(p384::AffinePoint::generator() * random_s).to_affine()
            )
        );
    }

    #[test]
    fn test_arkworks_fq_to_fr() {
        let s = ark_secp384r1::Fq::rand(&mut rand::thread_rng());
        let s_fr = arkworks_fq_to_fr(&s).0;
        let p384_s = fq_arkworks_to_p384(&s);
        let reduced_s = p384::Scalar::reduce_bytes(&p384_s);
        assert_eq!(fr_arkworks_to_p384(&s_fr), reduced_s);
        assert_eq!(reduce_bytes(&p384_s), s_fr);
    }

    #[test]
    fn test_fq_arkworks_to_p384() {
        let arkworks_seven = ark_secp384r1::Fq::from(7u32);
        let p384_seven = p384::FieldBytes::from(p384::Scalar::from(7u32));

        let actual_p384_seven = fq_arkworks_to_p384(&arkworks_seven);
        assert_eq!(actual_p384_seven, p384_seven);
    }

    #[test]
    fn test_digest_to_field_bytes() {
        // Shorter digests are padded with zeros from the left.
        let digest_32 = [1u8; 32];
        let bytes = digest_to_field_bytes(&digest_32);
        assert_eq!(bytes[..16], [0u8; 16]);
        assert_eq!(bytes[16..], digest_32);

        // 48 byte digests are used as is.
        let digest_48 = [2u8; 48];
        assert_eq!(digest_to_field_bytes(&digest_48).as_slice(), &digest_48);

        // Longer digests are truncated to the leftmost 384 bits.
        let mut digest_64 = [3u8; 64];
        digest_64[48..].copy_from_slice(&[4u8; 16]);
        assert_eq!(digest_to_field_bytes(&digest_64).as_slice(), &[3u8; 48]);
    }
}
