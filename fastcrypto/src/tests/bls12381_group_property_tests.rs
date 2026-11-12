// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Differential property tests of the BLS12-381 group operations against arkworks.
//!
//! Sui exposes these operations to Move (`sui::bls12381` and `sui::group_ops`), so every validator
//! runs them on untrusted bytes. Our implementation wraps blst with its own code for scalar
//! trimming, multi-scalar multiplication and (de)serialization, so these tests compare it with an
//! independent implementation:
//! * scalar, G1 and G2 arithmetic and multi-scalar multiplication must give the same results;
//! * decoding must accept exactly the canonical encodings of subgroup elements, and decode them to
//!   the same values.
//!
//! GT is not compared directly, since its byte order differs between the two libraries. It is
//! checked through the pairing's bilinearity and consistency with the group operations instead.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

use crate::groups::bls12381::{
    G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar, G1_ELEMENT_BYTE_LENGTH,
    G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};
use crate::groups::{GroupElement, MultiScalarMul, Pairing, Scalar as _};
use crate::serde_helpers::ToFromByteArray;

// ---------------------------------------------------------------------------------------------
// Conversions between the two libraries, through the shared big-endian/zcash encodings.

fn to_fc_scalar(x: &Fr) -> Scalar {
    let bytes: [u8; SCALAR_LENGTH] = x.into_bigint().to_bytes_be().try_into().unwrap();
    Scalar::from_byte_array(&bytes).unwrap()
}

fn ark_scalar_bytes(x: &Fr) -> [u8; SCALAR_LENGTH] {
    x.into_bigint().to_bytes_be().try_into().unwrap()
}

fn compressed<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn uncompressed<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes).unwrap();
    bytes
}

fn to_fc_g1(p: &G1Projective) -> G1Element {
    G1Element::from_byte_array(&compressed(&p.into_affine()).try_into().unwrap()).unwrap()
}

fn to_fc_g2(p: &G2Projective) -> G2Element {
    G2Element::from_byte_array(&compressed(&p.into_affine()).try_into().unwrap()).unwrap()
}

/// Arkworks as a strict decoder: the bytes must be a canonical, validated (on the curve and in
/// the subgroup) encoding. Arkworks alone ignores the remaining bytes of a point whose infinity
/// flag is set, so the re-encoding check is needed to make it canonical.
fn ark_decode_compressed<T: CanonicalDeserialize + CanonicalSerialize>(bytes: &[u8]) -> Option<T> {
    let mut reader = bytes;
    let value = T::deserialize_compressed(&mut reader).ok()?;
    (reader.is_empty() && compressed(&value) == bytes).then_some(value)
}

fn ark_decode_uncompressed<T: CanonicalDeserialize + CanonicalSerialize>(
    bytes: &[u8],
) -> Option<T> {
    let mut reader = bytes;
    let value = T::deserialize_uncompressed(&mut reader).ok()?;
    (reader.is_empty() && uncompressed(&value) == bytes).then_some(value)
}

// ---------------------------------------------------------------------------------------------
// Strategies.

/// Scalars of every bit length (scalar multiplication trims leading zero bytes), plus values
/// around 0 and the modulus.
fn scalar() -> impl Strategy<Value = Fr> {
    prop_oneof![
        1 => (0u64..4).prop_map(Fr::from),
        1 => (1u64..4).prop_map(|k| -Fr::from(k)),
        1 => any::<u64>().prop_map(Fr::from),
        4 => (0usize..=SCALAR_LENGTH, any::<[u8; SCALAR_LENGTH]>()).prop_map(|(len, mut bytes)| {
            bytes[..SCALAR_LENGTH - len].fill(0);
            Fr::from_be_bytes_mod_order(&bytes)
        }),
    ]
}

/// A G1 point as a multiple of the generator; the scalar strategy includes 0, so the identity.
fn g1_point() -> impl Strategy<Value = G1Projective> {
    scalar().prop_map(|k| G1Projective::generator() * k)
}

fn g2_point() -> impl Strategy<Value = G2Projective> {
    scalar().prop_map(|k| G2Projective::generator() * k)
}

/// A byte-level change to an encoding.
#[derive(Clone, Debug)]
enum ByteMutation {
    Flip(Index, u8),
    /// Overwrite the three flag bits (compression, infinity, sign) of the zcash encoding.
    SetFlags(u8),
    /// Replace everything after the flags with zeros, as in an identity encoding.
    ZeroBody,
    /// Replace the x coordinate with the field modulus plus a small value.
    NonCanonicalX(u8),
}

fn byte_mutation() -> impl Strategy<Value = ByteMutation> {
    prop_oneof![
        6 => (any::<Index>(), 1..=u8::MAX).prop_map(|(i, m)| ByteMutation::Flip(i, m)),
        3 => (0..8u8).prop_map(|f| ByteMutation::SetFlags(f << 5)),
        1 => Just(ByteMutation::ZeroBody),
        1 => any::<u8>().prop_map(ByteMutation::NonCanonicalX),
    ]
}

/// The base field modulus, big-endian.
const P: [u8; 48] = hex_literal::hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

fn apply(bytes: &mut [u8], mutation: &ByteMutation) {
    match mutation {
        ByteMutation::Flip(i, mask) => bytes[i.index(bytes.len())] ^= mask,
        ByteMutation::SetFlags(flags) => bytes[0] = (bytes[0] & 0x1f) | flags,
        ByteMutation::ZeroBody => {
            bytes[0] &= 0xe0;
            bytes[1..].fill(0);
        }
        ByteMutation::NonCanonicalX(delta) => {
            // For G2 the first 48 bytes are the imaginary part of x, which is also an Fp element.
            let flags = bytes[0] & 0xe0;
            let mut x = P;
            let (last, carry) = x[47].overflowing_add(*delta);
            x[47] = last;
            if carry {
                x[46] = x[46].wrapping_add(1);
            }
            bytes[..48].copy_from_slice(&x);
            bytes[0] |= flags;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Scalars.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn scalar_arithmetic_matches_arkworks(a in scalar(), b in scalar()) {
        let (fa, fb) = (to_fc_scalar(&a), to_fc_scalar(&b));
        prop_assert_eq!(fa.to_byte_array(), ark_scalar_bytes(&a));
        prop_assert_eq!(fa + fb, to_fc_scalar(&(a + b)));
        prop_assert_eq!(fa - fb, to_fc_scalar(&(a - b)));
        prop_assert_eq!(fa * fb, to_fc_scalar(&(a * b)));
        prop_assert_eq!(-fa, to_fc_scalar(&(-a)));
        match a.inverse() {
            Some(inverse) => {
                prop_assert_eq!(fa.inverse().unwrap(), to_fc_scalar(&inverse));
                prop_assert_eq!((fb / fa).unwrap(), to_fc_scalar(&(b * inverse)));
            }
            None => {
                prop_assert!(fa.inverse().is_err());
                prop_assert!((fb / fa).is_err());
            }
        }
    }

    /// Exactly the integers below the group order decode, and they encode back to the same bytes.
    #[test]
    fn scalar_decoding_accepts_exactly_canonical_encodings(
        bytes in prop_oneof![
            any::<[u8; SCALAR_LENGTH]>(),
            // Values just below and above the group order r.
            (0u8..=255, any::<bool>()).prop_map(|(delta, above)| {
                let mut r = Fr::MODULUS;
                let delta = ark_ff::BigInt::from(delta as u64);
                if above { r.add_with_carry(&delta); } else { r.sub_with_borrow(&delta); }
                r.to_bytes_be().try_into().unwrap()
            }),
        ],
    ) {
        let canonical = ark_ff::BigInt::<4>::try_from(num_bigint::BigUint::from_bytes_be(&bytes))
            .map(|n| n < Fr::MODULUS)
            .unwrap_or(false);
        let decoded = Scalar::from_byte_array(&bytes);
        prop_assert_eq!(decoded.is_ok(), canonical);
        if let Ok(s) = decoded {
            prop_assert_eq!(s.to_byte_array(), bytes);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// G1 and G2.

macro_rules! group_tests {
    ($name:ident, $fc:ty, $ark_proj:ty, $ark_affine:ty, $size:expr, $point:expr, $to_fc:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(128))]

                #[test]
                fn arithmetic_matches_arkworks(p in $point, q in $point, s in scalar()) {
                    let (fp, fq, fs) = ($to_fc(&p), $to_fc(&q), to_fc_scalar(&s));
                    prop_assert_eq!(fp.to_byte_array().to_vec(), compressed(&p.into_affine()));
                    prop_assert_eq!(fp + fq, $to_fc(&(p + q)));
                    prop_assert_eq!(fp - fq, $to_fc(&(p - q)));
                    prop_assert_eq!(-fp, $to_fc(&(-p)));
                    prop_assert_eq!(fp * fs, $to_fc(&(p * s)));
                    match s.inverse() {
                        Some(inverse) => prop_assert_eq!((fp / fs).unwrap(), $to_fc(&(p * inverse))),
                        None => prop_assert!((fp / fs).is_err()),
                    }
                }

                /// Multi-scalar multiplication, including zero scalars, identity points and
                /// repeated points, which take separate paths in our implementation.
                #[test]
                fn multi_scalar_mul_matches_arkworks(
                    terms in vec((scalar(), $point), 1..24),
                    repeat in vec((any::<Index>(), any::<Index>()), 0..4),
                ) {
                    let mut terms = terms;
                    for (from, to) in repeat {
                        let point = terms[from.index(terms.len())].1;
                        let len = terms.len();
                        terms[to.index(len)].1 = point;
                    }
                    let (scalars, points): (Vec<Fr>, Vec<$ark_proj>) = terms.into_iter().unzip();
                    let affine = points.iter().map(|p| p.into_affine()).collect::<Vec<_>>();
                    let expected = <$ark_proj>::msm(&affine, &scalars).unwrap();

                    let fc_scalars = scalars.iter().map(to_fc_scalar).collect::<Vec<_>>();
                    let fc_points = points.iter().map($to_fc).collect::<Vec<_>>();
                    prop_assert_eq!(
                        <$fc>::multi_scalar_mul(&fc_scalars, &fc_points).unwrap(),
                        $to_fc(&expected)
                    );
                    prop_assert!(<$fc>::multi_scalar_mul(&fc_scalars[1..], &fc_points).is_err());
                }

                /// Decoding accepts exactly the canonical compressed encodings of subgroup
                /// elements, and agrees with arkworks on their value.
                #[test]
                fn decoding_matches_arkworks(
                    p in $point,
                    mutations in vec(byte_mutation(), 0..3),
                ) {
                    let mut bytes: [u8; $size] = compressed(&p.into_affine()).try_into().unwrap();
                    for mutation in &mutations {
                        apply(&mut bytes, mutation);
                    }
                    let expected = ark_decode_compressed::<$ark_affine>(&bytes)
                        .map(|a| $to_fc(&a.into_group()));
                    prop_assert_eq!(<$fc>::from_byte_array(&bytes).ok(), expected);
                }
            }
        }
    };
}

group_tests!(
    g1,
    G1Element,
    G1Projective,
    G1Affine,
    G1_ELEMENT_BYTE_LENGTH,
    g1_point(),
    to_fc_g1
);
group_tests!(
    g2,
    G2Element,
    G2Projective,
    G2Affine,
    G2_ELEMENT_BYTE_LENGTH,
    g2_point(),
    to_fc_g2
);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The uncompressed G1 format accepts exactly the canonical uncompressed encodings of
    /// subgroup elements.
    #[test]
    fn g1_uncompressed_decoding_matches_arkworks(
        p in g1_point(),
        mutations in vec(byte_mutation(), 0..3),
    ) {
        let mut bytes: [u8; 2 * G1_ELEMENT_BYTE_LENGTH] =
            uncompressed(&p.into_affine()).try_into().unwrap();
        prop_assert_eq!(
            G1ElementUncompressed::from(&to_fc_g1(&p)).into_byte_array(),
            bytes
        );
        for mutation in &mutations {
            apply(&mut bytes, mutation);
        }
        let expected =
            ark_decode_uncompressed::<G1Affine>(&bytes).map(|a| to_fc_g1(&a.into_group()));
        let decoded =
            G1Element::try_from(&G1ElementUncompressed::from_trusted_byte_array(bytes)).ok();
        prop_assert_eq!(decoded, expected);
    }

    #[test]
    fn g1_uncompressed_sum_matches_arkworks(points in vec(g1_point(), 0..24)) {
        let terms = points
            .iter()
            .map(|p| G1ElementUncompressed::from(&to_fc_g1(p)))
            .collect::<Vec<_>>();
        let expected = points.iter().fold(G1Projective::zero(), |acc, p| acc + p);
        prop_assert_eq!(G1ElementUncompressed::sum(&terms).unwrap(), to_fc_g1(&expected));
    }
}

// ---------------------------------------------------------------------------------------------
// Pairing and GT.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn pairing_is_bilinear_and_consistent_with_gt_operations(
        a in scalar(),
        b in scalar(),
        c in scalar(),
    ) {
        let (fa, fb, fc) = (to_fc_scalar(&a), to_fc_scalar(&b), to_fc_scalar(&c));
        let g1 = G1Element::generator();
        let g2 = G2Element::generator();
        let gt = GTElement::generator();

        prop_assert_eq!(g1.pairing(&g2), gt);
        prop_assert_eq!((g1 * fa).pairing(&(g2 * fb)), gt * (fa * fb));
        prop_assert_eq!(
            G1Element::multi_pairing(&[g1 * fa, g1 * fb], &[g2, g2 * fc]).unwrap(),
            gt * (fa + fb * fc)
        );
        prop_assert_eq!(gt * fa + gt * fb, gt * (fa + fb));
        prop_assert_eq!(gt * fa - gt * fb, gt * (fa - fb));
        prop_assert_eq!(-(gt * fa), gt * (-fa));
        match fa.inverse() {
            Ok(inverse) => prop_assert_eq!((gt / fa).unwrap(), gt * inverse),
            Err(_) => prop_assert!((gt / fa).is_err()),
        }
    }

    /// GT decoding accepts canonical encodings of subgroup elements only, and they encode back to
    /// the same bytes.
    #[test]
    fn gt_decoding_is_canonical(
        a in scalar(),
        mutations in vec((any::<Index>(), 1..=u8::MAX), 0..3),
        field_element in any::<Index>(),
        overflow in any::<Option<u8>>(),
    ) {
        let element = GTElement::generator() * to_fc_scalar(&a);
        let mut bytes = element.to_byte_array();
        for (i, mask) in &mutations {
            bytes[i.index(GT_ELEMENT_BYTE_LENGTH)] ^= mask;
        }
        if let Some(delta) = overflow {
            // Replace one of the twelve Fp coordinates with an encoding of `p + delta`.
            let start = field_element.index(12) * 48;
            let mut x = P;
            let (last, carry) = x[47].overflowing_add(delta);
            x[47] = last;
            if carry {
                x[46] = x[46].wrapping_add(1);
            }
            bytes[start..start + 48].copy_from_slice(&x);
        }
        match GTElement::from_byte_array(&bytes) {
            Ok(decoded) => prop_assert_eq!(decoded.to_byte_array(), bytes),
            Err(_) => prop_assert!(!mutations.is_empty() || overflow.is_some()),
        }
        if mutations.is_empty() && overflow.is_none() {
            prop_assert_eq!(GTElement::from_byte_array(&bytes).unwrap(), element);
        }
    }
}
