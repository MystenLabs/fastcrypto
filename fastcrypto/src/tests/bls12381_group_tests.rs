// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::min_pk::{BLS12381KeyPair, BLS12381Signature, DST_G2};
use crate::bls12381::min_sig::DST_G1;
use crate::encoding::{Base64, Encoding};
use crate::groups::bls12381::{
    buffer_to_scalar_mod_r, reduce_mod_uniform_buffer, G1Element, G1ElementUncompressed, G2Element,
    GTElement, Scalar, FP_BYTE_LENGTH, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH,
    GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};
use crate::groups::{
    FiatShamirChallenge, FromTrustedByteArray, GroupElement, HashToGroupElement, MultiScalarMul,
    Pairing, Scalar as ScalarTrait,
};
use crate::hash::{HashFunction, Sha256};
use crate::serde_helpers::ToFromByteArray;
use crate::test_helpers::verify_serialization;
use crate::traits::Signer;
use crate::traits::VerifyingKey;
use crate::traits::{KeyPair, ToFromBytes};
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_conjugate, blst_fp12_frobenius_map, blst_fp12_inverse,
    blst_fp12_mul, blst_fp_from_bendian, blst_hash_to_g1, blst_hash_to_g2, blst_p1,
    blst_p1_compress, blst_p2, blst_p2_compress, blst_p2_serialize,
};
use hex_literal::hex;
use proptest::{collection, prelude::*};
use rand::{rngs::StdRng, RngCore, SeedableRng as _};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use zeroize::Zeroize;

//
// Helper functions
//

const MSG: &[u8] = b"test message";

/// The base field modulus p, big-endian.
const FIELD_MODULUS: [u8; FP_BYTE_LENGTH] = hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

/// The order r of G1, G2 and GT, big-endian.
const GROUP_ORDER: [u8; SCALAR_LENGTH] =
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

// The flags in the top three bits of the first byte of a point encoding.
const COMPRESSION_FLAG: u8 = 0x80;
const INFINITY_FLAG: u8 = 0x40;
const SORT_FLAG: u8 = 0x20;
const ALL_FLAGS: u8 = COMPRESSION_FLAG | INFINITY_FLAG | SORT_FLAG;

/// The compressed G1 point with x = 4. It is on the curve but not in the prime-order subgroup.
const NON_SUBGROUP_G1: [u8; G1_ELEMENT_BYTE_LENGTH] = hex!("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004");

/// The compressed G2 point with x = 2 (x.c1 = 0 and x.c0 = 2). It is on the curve but not in the
/// prime-order subgroup.
const NON_SUBGROUP_G2: [u8; G2_ELEMENT_BYTE_LENGTH] = hex!("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002");

/// r - 1, the largest canonical scalar.
fn minus_one() -> Scalar {
    -Scalar::generator()
}

/// Adds two big-endian integers of the same length. Returns `None` on overflow.
fn add_big_endian(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    assert_eq!(a.len(), b.len());
    let mut sum = a.to_vec();
    let mut carry = 0u16;
    for (s, b) in sum.iter_mut().zip(b).rev() {
        let digit = *s as u16 + *b as u16 + carry;
        *s = digit as u8;
        carry = digit >> 8;
    }
    (carry == 0).then_some(sum)
}

/// Adds the field modulus to the 48-byte coordinate at `index` of an encoding. The result encodes the
/// same field element but is not reduced. With `flags`, the top three bits of the first byte are
/// flags and are kept. Returns `None` if the sum does not fit.
fn add_modulus(bytes: &[u8], index: usize, flags: bool) -> Option<Vec<u8>> {
    let mut out = bytes.to_vec();
    let mask = if flags { ALL_FLAGS } else { 0 };
    let saved_flags = out[0] & mask;
    out[0] &= !mask;
    let range = index * FP_BYTE_LENGTH..(index + 1) * FP_BYTE_LENGTH;
    let sum = add_big_endian(&out[range.clone()], &FIELD_MODULUS)?;
    out[range].copy_from_slice(&sum);
    if out[0] & mask != 0 {
        return None;
    }
    out[0] |= saved_flags;
    Some(out)
}

/// blst's hash-to-curve to G1 with an arbitrary domain separation tag. `hash_to_group_element` is
/// this function with [DST_G1].
fn hash_to_g1_with_dst(msg: &[u8], dst: &[u8]) -> G1Element {
    let mut point = blst_p1::default();
    let mut compressed = [0u8; G1_ELEMENT_BYTE_LENGTH];
    unsafe {
        blst_hash_to_g1(
            &mut point,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            std::ptr::null(),
            0,
        );
        blst_p1_compress(compressed.as_mut_ptr(), &point);
    }
    G1Element::from_byte_array(&compressed).unwrap()
}

/// blst's hash-to-curve to G2 with an arbitrary domain separation tag. `hash_to_group_element` is
/// this function with [DST_G2]. Also returns the uncompressed encoding x.c1 || x.c0 || y.c1 || y.c0.
fn hash_to_g2_with_dst(msg: &[u8], dst: &[u8]) -> (G2Element, [u8; 2 * G2_ELEMENT_BYTE_LENGTH]) {
    let mut point = blst_p2::default();
    let mut compressed = [0u8; G2_ELEMENT_BYTE_LENGTH];
    let mut uncompressed = [0u8; 2 * G2_ELEMENT_BYTE_LENGTH];
    unsafe {
        blst_hash_to_g2(
            &mut point,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            std::ptr::null(),
            0,
        );
        blst_p2_compress(compressed.as_mut_ptr(), &point);
        blst_p2_serialize(uncompressed.as_mut_ptr(), &point);
    }
    (
        G2Element::from_byte_array(&compressed).unwrap(),
        uncompressed,
    )
}

/// Checks multiplication by 2^k and 2^k - 1 for k = 0, ..., 254, which are scalars of every bit
/// length: G1 and G2 pass the bit length of the scalar to blst, and GT multiplication loops over the
/// bits.
fn check_mul_by_every_bit_length<G: GroupElement<ScalarType = Scalar>>(p: G) {
    let mut two_to_the_k = Scalar::generator();
    let mut expected = p;
    for _ in 0..255 {
        assert_eq!(p * two_to_the_k, expected);
        assert_eq!(p * (two_to_the_k - Scalar::generator()), expected - p);
        two_to_the_k = two_to_the_k + two_to_the_k;
        expected = expected + expected;
    }
}

/// A random element of F_p^12, which is almost never in GT.
fn random_fp12(rng: &mut impl RngCore) -> blst_fp12 {
    let mut f = blst_fp12::default();
    for fp in f
        .fp6
        .iter_mut()
        .flat_map(|fp6| fp6.fp2.iter_mut())
        .flat_map(|fp2| fp2.fp.iter_mut())
    {
        let mut bytes = [0u8; FP_BYTE_LENGTH];
        rng.fill_bytes(&mut bytes);
        // Below p, whose first byte is 0x1a.
        bytes[0] %= 0x1a;
        unsafe { blst_fp_from_bendian(fp, bytes.as_ptr()) };
    }
    f
}

/// f^((p^6 - 1)(p^2 + 1)), the easy part of the final exponentiation. The result lies in the
/// cyclotomic subgroup of F_p^12, but almost never has order r.
fn easy_part_of_final_exponentiation(f: &blst_fp12) -> blst_fp12 {
    let mut conjugate = *f;
    let mut inverse = blst_fp12::default();
    let mut g = blst_fp12::default();
    let mut frobenius = blst_fp12::default();
    let mut result = blst_fp12::default();
    unsafe {
        // f^(p^6) is the conjugate of f.
        blst_fp12_conjugate(&mut conjugate);
        blst_fp12_inverse(&mut inverse, f);
        blst_fp12_mul(&mut g, &conjugate, &inverse);
        blst_fp12_frobenius_map(&mut frobenius, &g, 2);
        blst_fp12_mul(&mut result, &frobenius, &g);
    }
    result
}

/// Checks that decoding `bytes` through serde agrees with `from_byte_array`: BCS and base64 in JSON
/// accept exactly the encodings of the right length that `from_byte_array` accepts, and bincode,
/// which ignores trailing bytes, the ones whose first `N` bytes it accepts. Returns the element.
fn check_serde_agrees<T, const N: usize>(bytes: &[u8]) -> Option<T>
where
    T: ToFromByteArray<N> + Serialize + DeserializeOwned + PartialEq + Debug,
{
    let decode = |b: &[u8]| {
        <[u8; N]>::try_from(b)
            .ok()
            .and_then(|b| T::from_byte_array(&b).ok())
    };
    let expected = decode(bytes);
    assert_eq!(bcs::from_bytes::<T>(bytes).ok(), expected);
    assert_eq!(
        bincode::deserialize::<T>(bytes).ok(),
        bytes.get(..N).and_then(decode)
    );
    let json = format!("\"{}\"", Base64::encode(bytes));
    assert_eq!(serde_json::from_str::<T>(&json).ok(), expected);
    if let Some(element) = &expected {
        assert_eq!(bcs::to_bytes(element).unwrap(), bytes);
        assert_eq!(bincode::serialize(element).unwrap(), bytes);
        assert_eq!(serde_json::to_string(element).unwrap(), json);
    }
    expected
}

/// Decodes `bytes` with `from_byte_array` and checks the properties every decoder must have: an
/// accepted encoding is the canonical encoding of the element, `from_trusted_byte_array` agrees,
/// and serde accepts the same encodings (see [check_serde_agrees]).
fn check_decoding<T, const N: usize>(bytes: &[u8; N]) -> Option<T>
where
    T: ToFromByteArray<N>
        + FromTrustedByteArray<N>
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Debug,
{
    let decoded = check_serde_agrees::<T, N>(bytes);
    if let Some(element) = &decoded {
        assert_eq!(&element.to_byte_array(), bytes, "non-canonical encoding");
        assert_eq!(&T::from_trusted_byte_array(bytes).unwrap(), element);
    }
    decoded
}

/// Compares a decoding with arkworks'. arkworks 0.4 also accepts some encodings that the zcash
/// format rejects, so it may accept an encoding that we reject if `lenient` holds for its result.
fn compare_with_arkworks<P: PartialEq + Debug>(
    ours: Option<P>,
    theirs: Option<P>,
    lenient: impl FnOnce(&P) -> bool,
) -> Result<(), TestCaseError> {
    match (ours, theirs) {
        (Some(ours), Some(theirs)) => prop_assert_eq!(ours, theirs),
        (None, None) => {}
        (None, Some(theirs)) => {
            prop_assert!(lenient(&theirs), "only arkworks accepts {:?}", theirs)
        }
        (Some(ours), None) => prop_assert!(false, "only fastcrypto accepts {:?}", ours),
    }
    Ok(())
}

/// Decodes an uncompressed encoding the way Sui's `uncompressed_g1_to_g1` does.
fn decode_uncompressed(bytes: [u8; 2 * G1_ELEMENT_BYTE_LENGTH]) -> Option<G1Element> {
    G1Element::try_from(&G1ElementUncompressed::from_trusted_byte_array(bytes)).ok()
}

/// The messages of the hash-to-curve test vectors in RFC 9380.
fn rfc9380_messages() -> Vec<Vec<u8>> {
    vec![
        b"".to_vec(),
        b"abc".to_vec(),
        b"abcdef0123456789".to_vec(),
        [b"q128_".as_slice(), &[b'q'; 128]].concat(),
        [b"a512_".as_slice(), &[b'a'; 512]].concat(),
    ]
}

/// Conversions to arkworks' ark-bls12-381, an independent implementation used as an oracle.
mod arkworks {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::hashing::curve_maps::wb::WBMap;
    use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
    use ark_ec::hashing::HashToCurve;
    use ark_ec::pairing::Pairing as _;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_ff::field_hashers::DefaultFieldHasher;
    use ark_ff::{Field, PrimeField, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    pub fn scalar(s: &Scalar) -> Fr {
        Fr::from_be_bytes_mod_order(&s.to_byte_array())
    }

    /// The big-endian integer `bytes` modulo r.
    pub fn reduce(bytes: &[u8]) -> Fr {
        Fr::from_be_bytes_mod_order(bytes)
    }

    pub fn inverse(s: &Fr) -> Option<Fr> {
        s.inverse()
    }

    pub fn g1(p: &G1Element) -> G1Projective {
        G1Affine::deserialize_compressed(&p.to_byte_array()[..])
            .unwrap()
            .into()
    }

    pub fn g2(p: &G2Element) -> G2Projective {
        G2Affine::deserialize_compressed(&p.to_byte_array()[..])
            .unwrap()
            .into()
    }

    /// Converts an element of GT. arkworks encodes the 12 coefficients little-endian and in a
    /// different order.
    pub fn gt(x: &Fq12) -> GTElement {
        let mut ark_bytes = Vec::new();
        x.serialize_uncompressed(&mut ark_bytes).unwrap();
        let mut bytes = [0u8; GT_ELEMENT_BYTE_LENGTH];
        let mut chunks = bytes.chunks_exact_mut(FP_BYTE_LENGTH);
        // The coefficient c[j].c[i].c[k] is at position (i, j, k) for fastcrypto and (j, i, k) for
        // arkworks.
        for i in 0..3 {
            for j in 0..2 {
                for k in 0..2 {
                    let index = (j * 3 + i) * 2 + k;
                    let chunk = chunks.next().unwrap();
                    chunk.copy_from_slice(
                        &ark_bytes[index * FP_BYTE_LENGTH..(index + 1) * FP_BYTE_LENGTH],
                    );
                    chunk.reverse();
                }
            }
        }
        GTElement::from_byte_array(&bytes).unwrap()
    }

    pub fn decode_g1(bytes: &[u8]) -> Option<G1Projective> {
        G1Affine::deserialize_compressed(bytes).ok().map(Into::into)
    }

    pub fn decode_g1_uncompressed(bytes: &[u8]) -> Option<G1Projective> {
        G1Affine::deserialize_uncompressed(bytes)
            .ok()
            .map(Into::into)
    }

    pub fn decode_g2(bytes: &[u8]) -> Option<G2Projective> {
        G2Affine::deserialize_compressed(bytes).ok().map(Into::into)
    }

    pub fn is_zero(p: &impl Zero) -> bool {
        p.is_zero()
    }

    pub fn pairing(p: &G1Projective, q: &G2Projective) -> Fq12 {
        Bls12_381::pairing(p.into_affine(), q.into_affine()).0
    }

    pub fn pow(x: &Fq12, s: &Fr) -> Fq12 {
        x.pow(s.into_bigint())
    }

    pub fn msm<G: VariableBaseMSM>(points: &[G], scalars: &[G::ScalarField]) -> G {
        G::msm(&G::batch_convert_to_mul_base(points), scalars).unwrap()
    }

    pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
        MapToCurveBasedHasher::<
            G1Projective,
            DefaultFieldHasher<sha2::Sha256, 128>,
            WBMap<ark_bls12_381::g1::Config>,
        >::new(DST_G1)
        .unwrap()
        .hash(msg)
        .unwrap()
        .into()
    }

    pub fn hash_to_g2(msg: &[u8]) -> G2Projective {
        MapToCurveBasedHasher::<
            G2Projective,
            DefaultFieldHasher<sha2::Sha256, 128>,
            WBMap<ark_bls12_381::g2::Config>,
        >::new(DST_G2)
        .unwrap()
        .hash(msg)
        .unwrap()
        .into()
    }
}

//
// Arithmetic tests
//

#[test]
fn test_scalar_arithmetic() {
    let zero = Scalar::zero();
    let one = Scalar::generator();

    // r - 1 is the largest scalar, and arithmetic wraps around r.
    assert_eq!(
        minus_one().to_byte_array(),
        hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
    );
    assert_eq!(minus_one() + one, zero);
    assert_eq!(zero - one, minus_one());
    assert_eq!(minus_one() * minus_one(), one);
    assert_eq!(minus_one().inverse().unwrap(), minus_one());
    assert_eq!(-zero, zero);
    assert_eq!(-minus_one(), one);

    // Only inversion of and division by zero fail.
    assert!(zero.inverse().is_err());
    assert!((zero / zero).is_err());
    assert!((minus_one() / zero).is_err());
    assert_eq!((zero / minus_one()).unwrap(), zero);
    assert_eq!(
        (Scalar::from(6) / Scalar::from(3)).unwrap(),
        Scalar::from(2)
    );

    let mut rng = StdRng::from_seed([1; 32]);
    for _ in 0..20 {
        let a = Scalar::rand(&mut rng);
        let b = Scalar::rand(&mut rng);
        assert_eq!((a / a).unwrap(), one);
        assert_eq!(((a * b) / b).unwrap(), a);
        assert_eq!(a.inverse().unwrap() * a, one);
        assert_eq!(a * b, b * a);
        assert_eq!(a - b, -(b - a));
        assert_eq!((a + b) - b, a);
    }

    // From<u128> covers the whole range of u128.
    let max = Scalar::from(u128::MAX);
    assert_eq!(
        max.to_byte_array(),
        hex!("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    );
    assert_eq!(
        max + one,
        Scalar::from(1u128 << 64) * Scalar::from(1u128 << 64)
    );

    // The default implementations of the Scalar and GroupElement traits.
    let factors = [Scalar::from(2), Scalar::from(3), Scalar::from(7)];
    assert_eq!(Scalar::product(factors.into_iter()), Scalar::from(42));
    assert_eq!(Scalar::product(std::iter::empty()), one);
    assert_eq!(
        <Scalar as GroupElement>::sum(factors.into_iter()),
        Scalar::from(12)
    );
    assert_eq!(<Scalar as GroupElement>::sum(std::iter::empty()), zero);

    // Zeroize clears a secret scalar.
    let mut secret = Scalar::rand(&mut rng);
    secret.zeroize();
    assert_eq!(secret, zero);
}

/// The group law and scalar multiplication on the edge cases that the Sui natives let anyone reach:
/// doubling through addition, adding the inverse, the identity, and the scalars 0, 1 and r - 1. Also
/// multiplication by scalars of every bit length.
macro_rules! test_group_arithmetic {
    ($name:ident, $type:ty, $points:expr) => {
        #[test]
        fn $name() {
            let zero = <$type>::zero();
            let s = Scalar::from(12345);
            let points: Vec<$type> = $points;
            for p in points {
                assert_eq!(p + p, p * Scalar::from(2));
                assert_eq!(p + p + p, p * Scalar::from(3));
                assert_eq!(p + (-p), zero);
                assert_eq!(p - p, zero);
                assert_eq!(-(-p), p);
                assert_eq!(p + zero, p);
                assert_eq!(zero + p, p);
                assert_eq!(p - zero, p);
                assert_eq!(zero - p, -p);

                assert_eq!(p * Scalar::zero(), zero);
                assert_eq!(p * Scalar::generator(), p);
                assert_eq!(p * minus_one(), -p);
                assert_eq!(p * minus_one() + p, zero);
                assert_eq!(p * minus_one() * minus_one(), p);
                assert_eq!(p * (minus_one() + Scalar::from(2)), p);
                assert_eq!(zero * minus_one(), zero);

                assert!((p / Scalar::zero()).is_err());
                assert_eq!((p / minus_one()).unwrap(), -p);
                assert_eq!((p / s).unwrap() * s, p);
                assert_eq!((p * s / s).unwrap(), p);

                let mut q = p;
                q += p;
                assert_eq!(q, p * Scalar::from(2));
                q -= p;
                assert_eq!(q, p);
                q *= minus_one();
                assert_eq!(q, -p);
            }
            check_mul_by_every_bit_length(<$type>::generator());
        }
    };
}

test_group_arithmetic!(
    test_g1_arithmetic,
    G1Element,
    vec![
        G1Element::zero(),
        G1Element::generator(),
        G1Element::hash_to_group_element(MSG),
        G1Element::generator() * Scalar::rand(&mut StdRng::from_seed([2; 32])),
    ]
);

test_group_arithmetic!(
    test_g2_arithmetic,
    G2Element,
    vec![
        G2Element::zero(),
        G2Element::generator(),
        G2Element::hash_to_group_element(MSG),
        G2Element::generator() * Scalar::rand(&mut StdRng::from_seed([2; 32])),
    ]
);

test_group_arithmetic!(
    test_gt_arithmetic,
    GTElement,
    vec![
        GTElement::zero(),
        GTElement::generator(),
        G1Element::hash_to_group_element(MSG).pairing(&G2Element::hash_to_group_element(MSG)),
    ]
);

/// MSM agrees with the naive sum for every length up to twice Sui's limit (32), on the inputs that
/// blst's MSM must handle specially: identity points, zero scalars, repeated points and points that
/// cancel. MSM only fails on empty inputs and length mismatches; Sui treats any other error as an
/// invariant violation.
macro_rules! test_msm {
    ($name:ident, $type:ty) => {
        #[test]
        fn $name() {
            let mut rng = StdRng::from_seed([3; 32]);
            let zero = <$type>::zero();
            let p = <$type>::generator() * Scalar::rand(&mut rng);
            let q = <$type>::hash_to_group_element(MSG);
            let s = Scalar::rand(&mut rng);
            // The pools have coprime sizes, so every pair of a scalar and a point occurs.
            let point_pool = [zero, p, -p, q, -q, p + q, <$type>::generator()];
            let scalar_pool = [Scalar::zero(), Scalar::generator(), minus_one(), s, -s];
            for n in 1..=64 {
                let (scalars, points): (Vec<Scalar>, Vec<$type>) = (0..n)
                    .map(|i| {
                        (
                            scalar_pool[i % scalar_pool.len()],
                            point_pool[i % point_pool.len()],
                        )
                    })
                    .unzip();
                let expected = points
                    .iter()
                    .zip(&scalars)
                    .fold(zero, |acc, (p, s)| acc + *p * *s);
                assert_eq!(
                    <$type>::multi_scalar_mul(&scalars, &points).unwrap(),
                    expected
                );
                assert_eq!(<$type>::inner_product(points, scalars), expected);
            }

            // Terms that cancel exactly.
            assert_eq!(<$type>::multi_scalar_mul(&[s, s], &[p, -p]).unwrap(), zero);
            assert_eq!(<$type>::multi_scalar_mul(&[s, -s], &[p, p]).unwrap(), zero);
            assert_eq!(
                <$type>::multi_scalar_mul(&[minus_one(), Scalar::generator()], &[p, p]).unwrap(),
                zero
            );

            // All scalars zero, all points the identity, and all terms equal.
            for n in [1, 2, 31, 32, 33] {
                assert_eq!(
                    <$type>::multi_scalar_mul(&vec![Scalar::zero(); n], &vec![p; n]).unwrap(),
                    zero
                );
                assert_eq!(
                    <$type>::multi_scalar_mul(&vec![s; n], &vec![zero; n]).unwrap(),
                    zero
                );
                assert_eq!(
                    <$type>::multi_scalar_mul(&vec![s; n], &vec![p; n]).unwrap(),
                    p * (s * Scalar::from(n as u128))
                );
            }

            // One identity among many equal terms. Since blst 0.3.11 this bug is triggered only for
            // large inputs (after the fix of
            // https://github.com/supranational/blst/commit/168ff67ce74f2dbace619704bb75a865d0e6c913).
            for n in 2..200 {
                let mut points = vec![<$type>::generator(); n];
                points[rng.next_u32() as usize % n] = zero;
                assert_eq!(
                    <$type>::multi_scalar_mul(&vec![Scalar::generator(); n], &points).unwrap(),
                    <$type>::generator() * Scalar::from((n - 1) as u128)
                );
            }

            // Empty inputs and length mismatches are rejected.
            assert!(<$type>::multi_scalar_mul(&[], &[]).is_err());
            assert!(<$type>::multi_scalar_mul(&[s], &[]).is_err());
            assert!(<$type>::multi_scalar_mul(&[], &[p]).is_err());
            assert!(<$type>::multi_scalar_mul(&[s, s], &[p]).is_err());
            assert!(<$type>::multi_scalar_mul(&[s], &[p, p]).is_err());

            // inner_product stops at the shorter input.
            assert_eq!(<$type>::inner_product([p, q], [s]), p * s);
            assert_eq!(<$type>::inner_product([p], [s, s]), p * s);
            assert_eq!(<$type>::inner_product([], [s]), zero);
        }
    };
}

test_msm!(test_g1_msm, G1Element);
test_msm!(test_g2_msm, G2Element);

//
// Pairing and hash-to-curve tests
//

#[test]
fn test_pairing() {
    let g1 = G1Element::generator();
    let g2 = G2Element::generator();
    let gt = g1.pairing(&g2);
    assert_eq!(gt, GTElement::generator());
    assert_ne!(gt, GTElement::zero());
    // e(g1, g2) has order r.
    assert_eq!(gt * minus_one() + gt, GTElement::zero());
    // A pairing with the identity is the identity.
    assert_eq!(G1Element::zero().pairing(&g2), GTElement::zero());
    assert_eq!(g1.pairing(&G2Element::zero()), GTElement::zero());
    assert_eq!(
        G1Element::zero().pairing(&G2Element::zero()),
        GTElement::zero()
    );

    let mut rng = StdRng::from_seed([4; 32]);
    for _ in 0..5 {
        let a = Scalar::rand(&mut rng);
        let b = Scalar::rand(&mut rng);
        let p = G1Element::hash_to_group_element(&a.to_byte_array());
        let q = G2Element::hash_to_group_element(&b.to_byte_array());
        let e = p.pairing(&q);
        assert_eq!((p * a).pairing(&(q * b)), e * (a * b));
        assert_eq!((p * a).pairing(&q), p.pairing(&(q * a)));
        assert_eq!((p + g1).pairing(&q), e + g1.pairing(&q));
        assert_eq!(p.pairing(&(q + g2)), e + p.pairing(&g2));
        assert_eq!((-p).pairing(&q), -e);
        assert_eq!(p.pairing(&(-q)), -e);
        // The output is a valid, canonically encoded element of GT.
        assert_eq!(GTElement::from_byte_array(&e.to_byte_array()).unwrap(), e);
    }
}

#[test]
fn test_multi_pairing() {
    let mut rng = StdRng::from_seed([5; 32]);
    let p = G1Element::generator() * Scalar::rand(&mut rng);
    let q = G2Element::generator() * Scalar::rand(&mut rng);
    let (g1, g2) = (G1Element::generator(), G2Element::generator());
    let (zero1, zero2) = (G1Element::zero(), G2Element::zero());
    let e = p.pairing(&q);

    assert_eq!(
        G1Element::multi_pairing(&[], &[]).unwrap(),
        GTElement::zero()
    );
    assert_eq!(G1Element::multi_pairing(&[p], &[q]).unwrap(), e);
    assert_eq!(G1Element::multi_pairing(&[p, p], &[q, q]).unwrap(), e + e);
    assert_eq!(
        G1Element::multi_pairing(&[p, g1], &[q, g2]).unwrap(),
        e + GTElement::generator()
    );

    // Terms with the identity contribute nothing.
    assert_eq!(
        G1Element::multi_pairing(&[zero1, p, g1], &[q, q, zero2]).unwrap(),
        e
    );
    assert_eq!(
        G1Element::multi_pairing(&[zero1, zero1], &[zero2, zero2]).unwrap(),
        GTElement::zero()
    );

    // Terms that cancel.
    assert_eq!(
        G1Element::multi_pairing(&[p, -p], &[q, q]).unwrap(),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::multi_pairing(&[p, p], &[q, -q]).unwrap(),
        GTElement::zero()
    );

    // Length mismatches are rejected.
    assert!(G1Element::multi_pairing(&[], &[q]).is_err());
    assert!(G1Element::multi_pairing(&[p], &[]).is_err());
    assert!(G1Element::multi_pairing(&[p, p], &[q]).is_err());
    assert!(G1Element::multi_pairing(&[p], &[q, q]).is_err());
}

#[test]
fn test_hash_to_curve() {
    // The outputs are in the subgroup and not the identity, and distinct messages give distinct
    // points, also when they only differ by trailing zeros. The outputs are blst's hash-to-curve with
    // the domain separation tags of the BLS signature schemes, which
    // test_hash_to_curve_rfc9380_vectors checks against the RFC.
    let mut messages: Vec<Vec<u8>> = vec![vec![]];
    for length in [
        1,
        2,
        31,
        32,
        33,
        63,
        64,
        65,
        127,
        128,
        129,
        255,
        256,
        257,
        1 << 16,
    ] {
        messages.push(vec![0; length]);
        messages.push(vec![0xff; length]);
    }
    let mut seen_g1 = HashSet::new();
    let mut seen_g2 = HashSet::new();
    for msg in &messages {
        let p = G1Element::hash_to_group_element(msg);
        assert_ne!(p, G1Element::zero());
        assert_eq!(G1Element::from_byte_array(&p.to_byte_array()).unwrap(), p);
        assert!(seen_g1.insert(p.to_byte_array()));
        assert_eq!(p, hash_to_g1_with_dst(msg, DST_G1));

        let q = G2Element::hash_to_group_element(msg);
        assert_ne!(q, G2Element::zero());
        assert_eq!(G2Element::from_byte_array(&q.to_byte_array()).unwrap(), q);
        assert!(seen_g2.insert(q.to_byte_array()));
        assert_eq!(q, hash_to_g2_with_dst(msg, DST_G2).0);
    }
}

//
// Serialization tests
//

#[test]
fn test_serde_and_regression() {
    let s1 = Scalar::generator();
    let g1 = G1Element::generator();
    let g2 = G2Element::generator();
    let gt = GTElement::generator();
    let id1 = G1Element::zero();
    let id2 = G2Element::zero();
    let id3 = GTElement::zero();
    let id4 = Scalar::zero();

    verify_serialization(
        &s1,
        Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .as_slice(),
        ),
    );
    verify_serialization(&g1, Some(hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap().as_slice()));
    verify_serialization(&g2, Some(hex::decode("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8").unwrap().as_slice()));
    verify_serialization(&gt, Some(hex::decode("1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba5703350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a201b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b604c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631").unwrap().as_slice()));
    verify_serialization(&id1, Some(hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(&id2, Some(hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(&id3, Some(hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(
        &id4,
        Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        ),
    );
}

#[test]
fn test_consistent_bls12381_serialization() {
    // Generate with BLS signature APIs.
    let pair = BLS12381KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let (pk1, sk1) = (pair.public().clone(), pair.private());
    let sig1 = sk1.sign(MSG); // encoded in G2.

    // Convert using serialized byte arrays.
    let sk2: Scalar = bincode::deserialize(sk1.as_ref()).unwrap();
    let pk2: G1Element = bincode::deserialize(pk1.as_ref()).unwrap();
    // Sign using group ops.
    let sig2 = G2Element::hash_to_group_element(MSG) * sk2;
    // Check signature with pk2, sig2.
    assert_eq!(
        pk2.pairing(&G2Element::hash_to_group_element(MSG)),
        G1Element::generator().pairing(&sig2)
    );
    let sig2_from_bytes: G2Element = bincode::deserialize(sig1.as_ref()).unwrap();
    assert_eq!(sig2, sig2_from_bytes);

    // Convert back and check the resulting signature.
    let sig2_as_bytes = bincode::serialize(&sig2).unwrap();
    let sig3 = <BLS12381Signature as ToFromBytes>::from_bytes(sig2_as_bytes.as_slice()).unwrap();
    pk1.verify(MSG, &sig3).unwrap();
    assert_eq!(sig1, sig3);
}

#[test]
fn test_serialization_scalar() {
    let one = Scalar::generator();

    // Scalars are big-endian: the little-endian encoding of one decodes as 2^248.
    let mut little_endian_one = [0u8; SCALAR_LENGTH];
    little_endian_one[0] = 1;
    assert_eq!(
        Scalar::from_byte_array(&little_endian_one).unwrap(),
        Scalar::from(1u128 << 124) * Scalar::from(1u128 << 124)
    );
    let mut big_endian_one = [0u8; SCALAR_LENGTH];
    big_endian_one[SCALAR_LENGTH - 1] = 1;
    assert_eq!(one.to_byte_array(), big_endian_one);

    // Exactly the integers below r decode.
    let order_plus_one: [u8; SCALAR_LENGTH] =
        hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002");
    let twice_order_minus_one: [u8; SCALAR_LENGTH] =
        hex!("e7db4ea6533afa906673b0101343b00aa77b4805fffcb7fdfffffffe00000001");
    let mut two_to_the_255 = [0u8; SCALAR_LENGTH];
    two_to_the_255[0] = 0x80;
    for bytes in [
        GROUP_ORDER,
        order_plus_one,
        twice_order_minus_one,
        two_to_the_255,
        [0xff; SCALAR_LENGTH],
    ] {
        assert!(Scalar::from_byte_array(&bytes).is_err());
    }
    for s in [Scalar::zero(), one, minus_one()] {
        assert_eq!(Scalar::from_byte_array(&s.to_byte_array()).unwrap(), s);
    }

    // FromTrustedByteArray reduces modulo r instead.
    assert_eq!(
        Scalar::from_trusted_byte_array(&GROUP_ORDER).unwrap(),
        Scalar::zero()
    );
    assert_eq!(
        Scalar::from_trusted_byte_array(&order_plus_one).unwrap(),
        one
    );
    assert_eq!(
        Scalar::from_trusted_byte_array(&twice_order_minus_one).unwrap(),
        minus_one()
    );
    assert_eq!(
        Scalar::from_trusted_byte_array(&[0xff; SCALAR_LENGTH])
            .unwrap()
            .to_byte_array(),
        hex!("1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffd")
    );
    for s in [Scalar::zero(), one, minus_one()] {
        assert_eq!(
            Scalar::from_trusted_byte_array(&s.to_byte_array()).unwrap(),
            s
        );
    }
}

#[test]
fn test_reduce_mod_uniform_buffer() {
    // 9920230154395168010467440495232506909487652629574290093191912925556996116934135093887783048487593217824704573634359454220706793741831181736379748807477797
    let bytes = <[u8; 64]>::try_from(hex::decode("bd69132eca59d8eb6b2aeaab1bb0f4128ea2554a2a5fd5ed90cfa341311d63d2bddef3cf93ebbd3781dc09921ca8611e0db756164b297a90cff258c8138a0a25").unwrap()).unwrap();
    // This is the above bytes as a big-endian integer modulo the BLS scalar field size and then written as big-endian bytes.
    let expected =
        hex::decode("42326e5eb98173088355c38dace25686f73f8900c8af2da6480b34e2313c49c2").unwrap();
    assert_eq!(expected, reduce_mod_uniform_buffer(&bytes).to_byte_array());

    // 99202309022396765790443178473142775358161915835492099699231487822465101596204583014819121570129071631157073920534979728799457207703011355835025584728154395168010467440495232506909487652629574290093191912925556996116934135093887783048487593217824704573634359454220706793741831181736379748807477797
    let bytes = <[u8; 59]>::try_from(hex::decode("bd69132eca59d8eb6b2aeaab1bb0f4128ea2554a2a5fd5ed90cfa341311d63d2bddef3cf93ebbd3781dc09921ca8611e0db756164b297a90cff258").unwrap()).unwrap();
    let expected =
        hex::decode("21015212b5c7a44c04c39447bf7d2addc5035a9b118f07a29956bf00fa65bd74").unwrap();
    assert_eq!(expected, reduce_mod_uniform_buffer(&bytes).to_byte_array());
}

/// Every combination of the three flag bits, unreduced coordinates (x + p) and infinity with any
/// other bit set: only canonical encodings decode. Flipping the sort flag of a point other than the
/// identity gives the canonical encoding of its negation.
macro_rules! test_point_encodings {
    ($name:ident, $type:ty, $length:expr) => {
        #[test]
        fn $name() {
            let zero = <$type>::zero();
            let h = <$type>::hash_to_group_element(MSG);
            for p in [zero, <$type>::generator(), h, -h] {
                let canonical = p.to_byte_array();
                assert_eq!(<$type>::from_byte_array(&canonical).unwrap(), p);

                for flags in 0..8u8 {
                    let mut bytes = canonical;
                    bytes[0] = (bytes[0] & !ALL_FLAGS) | (flags << 5);
                    let expected = if bytes == canonical {
                        Some(p)
                    } else if p != zero && bytes == (-p).to_byte_array() {
                        Some(-p)
                    } else {
                        None
                    };
                    assert_eq!(<$type>::from_byte_array(&bytes).ok(), expected);

                    // Adding p to any coordinate gives an unreduced encoding of the same point,
                    // which is rejected even by FromTrustedByteArray.
                    for index in 0..$length / FP_BYTE_LENGTH {
                        if let Some(unreduced) = add_modulus(&bytes, index, true) {
                            let unreduced: [u8; $length] = unreduced.try_into().unwrap();
                            assert!(<$type>::from_byte_array(&unreduced).is_err());
                            assert!(<$type>::from_trusted_byte_array(&unreduced).is_err());
                        }
                    }
                }
            }

            // Infinity with any other bit set is rejected, also by FromTrustedByteArray. Clearing the
            // infinity flag gives x = 0, which blst rejects (for G1, these are the points (0, ±2)
            // of order 3).
            let infinity = zero.to_byte_array();
            for bit in 0..8 * $length {
                let mut bytes = infinity;
                bytes[bit / 8] ^= 0x80 >> (bit % 8);
                assert!(<$type>::from_byte_array(&bytes).is_err());
                assert!(<$type>::from_trusted_byte_array(&bytes).is_err());
            }
        }
    };
}

test_point_encodings!(test_serialization_g1, G1Element, G1_ELEMENT_BYTE_LENGTH);
test_point_encodings!(test_serialization_g2, G2Element, G2_ELEMENT_BYTE_LENGTH);

#[test]
fn test_serialization_non_subgroup_points() {
    // Points on the curve but not in the prime-order subgroup: FromTrustedByteArray accepts them and
    // their encodings are canonical, but from_byte_array and serde reject them. The sort flag gives
    // the negated point, and doubling gives another point outside the subgroup.
    let p = G1Element::from_trusted_byte_array(&NON_SUBGROUP_G1).unwrap();
    assert_eq!(p.to_byte_array(), NON_SUBGROUP_G1);
    let mut negated = NON_SUBGROUP_G1;
    negated[0] |= SORT_FLAG;
    assert_eq!((-p).to_byte_array(), negated);
    for p in [p, -p, p + p] {
        let bytes = p.to_byte_array();
        assert_eq!(G1Element::from_trusted_byte_array(&bytes).unwrap(), p);
        assert!(G1Element::from_byte_array(&bytes).is_err());
        assert!(check_serde_agrees::<G1Element, G1_ELEMENT_BYTE_LENGTH>(&bytes).is_none());
    }

    let q = G2Element::from_trusted_byte_array(&NON_SUBGROUP_G2).unwrap();
    assert_eq!(q.to_byte_array(), NON_SUBGROUP_G2);
    let mut negated = NON_SUBGROUP_G2;
    negated[0] |= SORT_FLAG;
    assert_eq!((-q).to_byte_array(), negated);
    for q in [q, -q, q + q] {
        let bytes = q.to_byte_array();
        assert_eq!(G2Element::from_trusted_byte_array(&bytes).unwrap(), q);
        assert!(G2Element::from_byte_array(&bytes).is_err());
        assert!(check_serde_agrees::<G2Element, G2_ELEMENT_BYTE_LENGTH>(&bytes).is_none());
    }
}

#[test]
fn test_serialization_gt() {
    // Zero is not in GT, and neither is any element with an unreduced coordinate (c + p) at any of the
    // 12 positions, which even FromTrustedByteArray rejects.
    assert!(GTElement::from_byte_array(&[0; GT_ELEMENT_BYTE_LENGTH]).is_err());
    for element in [GTElement::zero(), GTElement::generator()] {
        let bytes = element.to_byte_array();
        assert_eq!(GTElement::from_byte_array(&bytes).unwrap(), element);
        for index in 0..GT_ELEMENT_BYTE_LENGTH / FP_BYTE_LENGTH {
            let unreduced: [u8; GT_ELEMENT_BYTE_LENGTH] = add_modulus(&bytes, index, false)
                .unwrap()
                .try_into()
                .unwrap();
            assert!(GTElement::from_trusted_byte_array(&unreduced).is_err());
            assert!(GTElement::from_byte_array(&unreduced).is_err());
        }
    }

    // -1 has order 2, so it is not in GT.
    let mut minus_one_bytes = GTElement::zero().to_byte_array();
    let mut p_minus_one = FIELD_MODULUS;
    p_minus_one[FP_BYTE_LENGTH - 1] -= 1;
    minus_one_bytes[..FP_BYTE_LENGTH].copy_from_slice(&p_minus_one);
    let minus_one_element = GTElement::from_trusted_byte_array(&minus_one_bytes).unwrap();
    assert_eq!(minus_one_element + minus_one_element, GTElement::zero());
    assert!(GTElement::from_byte_array(&minus_one_bytes).is_err());

    let mut rng = StdRng::from_seed([6; 32]);
    for _ in 0..10 {
        let f = random_fp12(&mut rng);
        // The encoding of GTElement is blst's.
        assert_eq!(
            GTElement::from_trusted_byte_array(&f.to_bendian())
                .unwrap()
                .to_byte_array(),
            f.to_bendian()
        );
        // A random element of F_p^12 is not in GT.
        assert!(GTElement::from_byte_array(&f.to_bendian()).is_err());
        // Neither is an element of the cyclotomic subgroup that is not of order r.
        let cyclotomic = easy_part_of_final_exponentiation(&f);
        assert!(GTElement::from_byte_array(&cyclotomic.to_bendian()).is_err());
        // The full final exponentiation maps to GT.
        let mut g = blst_fp12::default();
        unsafe { blst_final_exp(&mut g, &f) };
        let element = GTElement::from_byte_array(&g.to_bendian()).unwrap();
        assert_eq!(element.to_byte_array(), g.to_bendian());
        assert_eq!(element * minus_one() + element, GTElement::zero());
    }
}

#[test]
fn test_serde_agrees_with_from_byte_array() {
    fn check<T, const N: usize>(valid: [u8; N], invalid: [u8; N])
    where
        T: ToFromByteArray<N> + Serialize + DeserializeOwned + PartialEq + Debug,
    {
        assert!(check_serde_agrees::<T, N>(&valid).is_some());
        assert!(check_serde_agrees::<T, N>(&invalid).is_none());
        // Every other length, with a valid prefix or padded with a valid encoding.
        let padded = [valid, valid].concat();
        for length in 0..=2 * N {
            assert_eq!(
                check_serde_agrees::<T, N>(&padded[..length]).is_some(),
                length == N
            );
        }
        // JSON that is not a base64 string.
        assert!(serde_json::from_str::<T>("\"not base64!\"").is_err());
        assert!(serde_json::from_str::<T>("[1, 2, 3]").is_err());
        assert!(serde_json::from_str::<T>("null").is_err());
    }
    check::<Scalar, SCALAR_LENGTH>(minus_one().to_byte_array(), GROUP_ORDER);
    let mut invalid_g1 = G1Element::generator().to_byte_array();
    invalid_g1[0] ^= COMPRESSION_FLAG;
    check::<G1Element, G1_ELEMENT_BYTE_LENGTH>(G1Element::generator().to_byte_array(), invalid_g1);
    let mut invalid_g2 = G2Element::generator().to_byte_array();
    invalid_g2[0] ^= COMPRESSION_FLAG;
    check::<G2Element, G2_ELEMENT_BYTE_LENGTH>(G2Element::generator().to_byte_array(), invalid_g2);
    check::<GTElement, GT_ELEMENT_BYTE_LENGTH>(
        GTElement::generator().to_byte_array(),
        [0; GT_ELEMENT_BYTE_LENGTH],
    );
}

//
// Uncompressed G1 tests
//

#[test]
fn test_g1_to_uncompressed() {
    let zero = G1Element::zero();
    let h = G1Element::hash_to_group_element(MSG);
    for p in [zero, G1Element::generator(), h, -h] {
        let canonical = G1ElementUncompressed::from(&p).into_byte_array();
        assert_eq!(decode_uncompressed(canonical), Some(p));

        // Only the canonical flags decode: no compression or sort flag, and the infinity flag
        // exactly for the identity.
        for flags in 0..8u8 {
            let mut bytes = canonical;
            bytes[0] = (bytes[0] & !ALL_FLAGS) | (flags << 5);
            assert_eq!(
                decode_uncompressed(bytes),
                (bytes == canonical).then_some(p)
            );

            // Unreduced coordinates (x + p or y + p) are rejected.
            for index in 0..2 {
                if let Some(unreduced) = add_modulus(&bytes, index, true) {
                    assert_eq!(decode_uncompressed(unreduced.try_into().unwrap()), None);
                }
            }
        }

        if p != zero {
            // The x-coordinate is the compressed encoding without its flags.
            let mut compressed = p.to_byte_array();
            compressed[0] &= !ALL_FLAGS;
            assert_eq!(canonical[..G1_ELEMENT_BYTE_LENGTH], compressed);

            // -y gives -p, and any other change to y gives a point off the curve.
            let negated = G1ElementUncompressed::from(&-p).into_byte_array();
            assert_eq!(
                canonical[..G1_ELEMENT_BYTE_LENGTH],
                negated[..G1_ELEMENT_BYTE_LENGTH]
            );
            assert_eq!(decode_uncompressed(negated), Some(-p));
            let mut off_curve = canonical;
            off_curve[2 * G1_ELEMENT_BYTE_LENGTH - 1] ^= 1;
            assert_eq!(decode_uncompressed(off_curve), None);
        }
    }

    // Infinity with any other bit set is rejected.
    let infinity = G1ElementUncompressed::from(&zero).into_byte_array();
    for bit in 0..8 * infinity.len() {
        let mut bytes = infinity;
        bytes[bit / 8] ^= 0x80 >> (bit % 8);
        assert_eq!(decode_uncompressed(bytes), None);
    }

    // A point on the curve but not in the subgroup is rejected.
    let p = G1Element::from_trusted_byte_array(&NON_SUBGROUP_G1).unwrap();
    assert_eq!(
        decode_uncompressed(G1ElementUncompressed::from(&p).into_byte_array()),
        None
    );
}

#[test]
fn test_g1_sum() {
    // blst's bulk addition handles a point added to itself, to its inverse or to the identity as
    // special cases. Hashi sums the public keys of the signers, which may repeat, and uses the
    // identity as a placeholder.
    let mut rng = StdRng::from_seed([7; 32]);
    let zero = G1Element::zero();
    let p = G1Element::generator() * Scalar::rand(&mut rng);
    let q = G1Element::hash_to_group_element(MSG);
    let pool = [zero, p, -p, q, -q, p + q, -(p + q)];
    let sum = |terms: &[G1Element]| {
        let uncompressed: Vec<G1ElementUncompressed> =
            terms.iter().map(G1ElementUncompressed::from).collect();
        G1ElementUncompressed::sum(&uncompressed).unwrap()
    };
    for n in 0..=100 {
        let mixed: Vec<G1Element> = (0..n).map(|i| pool[i % pool.len()]).collect();
        assert_eq!(sum(&mixed), mixed.iter().fold(zero, |acc, t| acc + t));
        let alternating: Vec<G1Element> = (0..n).map(|i| if i % 2 == 0 { p } else { -p }).collect();
        assert_eq!(sum(&alternating), if n % 2 == 1 { p } else { zero });
        assert_eq!(sum(&vec![p; n]), p * Scalar::from(n as u128));
        assert_eq!(sum(&vec![zero; n]), zero);
    }

    // Sui limits the number of terms to 1200.
    let terms: Vec<G1Element> = (0..1200).map(|i| pool[i % pool.len()]).collect();
    assert_eq!(sum(&terms), terms.iter().fold(zero, |acc, t| acc + t));
    let distinct: Vec<G1Element> = (1..=1200u128)
        .map(|i| G1Element::generator() * Scalar::from(i))
        .collect();
    assert_eq!(
        sum(&distinct),
        G1Element::generator() * Scalar::from(1200 * 1201 / 2)
    );

    // The sum fails if a term is all zeros, off the curve, has an unreduced coordinate or the sort
    // flag.
    let valid = G1ElementUncompressed::from(&p).into_byte_array();
    let mut off_curve = valid;
    off_curve[2 * G1_ELEMENT_BYTE_LENGTH - 1] ^= 1;
    let unreduced = add_modulus(&valid, 1, true).unwrap().try_into().unwrap();
    let mut sort_flag = valid;
    sort_flag[0] |= SORT_FLAG;
    for invalid in [
        [0; 2 * G1_ELEMENT_BYTE_LENGTH],
        off_curve,
        unreduced,
        sort_flag,
    ] {
        let terms = [
            G1ElementUncompressed::from(&p),
            G1ElementUncompressed::from_trusted_byte_array(invalid),
        ];
        assert!(G1ElementUncompressed::sum(&terms).is_err());
    }
}

//
// Test vectors
//

/// Test vectors from RFC 9380, appendix J.9.1 (suite BLS12381G1_XMD:SHA-256_SSWU_RO_) and J.10.1
/// (BLS12381G2_XMD:SHA-256_SSWU_RO_). They use the RFC's domain separation tags, so they are checked
/// against blst's hash-to-curve directly; test_hash_to_curve checks that
/// `hash_to_group_element` is the same function with the tags of the BLS signature schemes.
#[test]
fn test_hash_to_curve_rfc9380_vectors() {
    const G1_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    // The output point (x, y).
    const G1_OUTPUTS: [[&str; 2]; 5] = [
        [
            "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
            "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
        ],
        [
            "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
            "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
        ],
        [
            "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
            "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
        ],
        [
            "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
            "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
        ],
        [
            "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
            "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
        ],
    ];
    for (msg, [x, y]) in rfc9380_messages().iter().zip(G1_OUTPUTS) {
        let p = hash_to_g1_with_dst(msg, G1_DST);
        assert_eq!(
            hex::encode(G1ElementUncompressed::from(&p).into_byte_array()),
            format!("{x}{y}")
        );
    }

    const G2_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    // The output point (x.c0 + x.c1 * u, y.c0 + y.c1 * u) as [x.c0, x.c1, y.c0, y.c1].
    const G2_OUTPUTS: [[&str; 4]; 5] = [
        [
            "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
            "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
            "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
            "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
        ],
        [
            "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
            "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
            "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
            "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
        ],
        [
            "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
            "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
            "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
            "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
        ],
        [
            "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
            "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91",
            "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
            "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662",
        ],
        [
            "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
            "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
            "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
            "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
        ],
    ];
    for (msg, [x0, x1, y0, y1]) in rfc9380_messages().iter().zip(G2_OUTPUTS) {
        let (_, uncompressed) = hash_to_g2_with_dst(msg, G2_DST);
        assert_eq!(hex::encode(uncompressed), format!("{x1}{x0}{y1}{y0}"));
    }
}

/// The encodings of 0, g, 2g, ..., 999g match the test vectors of the zkcrypto bls12_381 crate, which
/// arkworks also uses: these are the SHA-256 digests of g1_compressed_valid_test_vectors.dat,
/// g1_uncompressed_valid_test_vectors.dat and g2_compressed_valid_test_vectors.dat. Every encoding
/// also decodes back.
#[test]
fn test_multiples_of_the_generators() {
    let mut g1_compressed = Vec::new();
    let mut g1_uncompressed = Vec::new();
    let mut g2_compressed = Vec::new();
    let mut p = G1Element::zero();
    let mut q = G2Element::zero();
    for _ in 0..1000 {
        let compressed = p.to_byte_array();
        let uncompressed = G1ElementUncompressed::from(&p).into_byte_array();
        assert_eq!(G1Element::from_byte_array(&compressed).unwrap(), p);
        assert_eq!(decode_uncompressed(uncompressed), Some(p));
        g1_compressed.extend_from_slice(&compressed);
        g1_uncompressed.extend_from_slice(&uncompressed);

        let compressed = q.to_byte_array();
        assert_eq!(G2Element::from_byte_array(&compressed).unwrap(), q);
        g2_compressed.extend_from_slice(&compressed);

        p += G1Element::generator();
        q += G2Element::generator();
    }
    assert_eq!(
        Sha256::digest(&g1_compressed).digest,
        hex!("8acaa1d512b4cf96f4740e4c9afc19ba4618d48fe251c452a19382395bcd0929")
    );
    assert_eq!(
        Sha256::digest(&g1_uncompressed).digest,
        hex!("e25aae8e95c9cd39cdb1eec0100c8245e297510fef0091cbf80b91d49de6b685")
    );
    assert_eq!(
        Sha256::digest(&g2_compressed).digest,
        hex!("b75bc2e41289adda41e448e56a1ea39b11009a27b02e8676c8b86defedc05deb")
    );
}

/// Outputs of every operation that Sui's group_ops natives expose, on fixed inputs. Validators must
/// agree on these bytes, and Seal derives keys from the encoding of GT elements. The values were
/// cross-checked against arkworks (ark-bls12-381 0.4); GT elements are pinned by the SHA-256 digest
/// of their encoding.
#[test]
fn test_golden_outputs() {
    let a = Scalar::from_byte_array(&hex!(
        "0e8b5cfc64077d5637d8c34081badc1b4417b39465ad4b82601114275b40bafe"
    ))
    .unwrap();
    let b = Scalar::from_byte_array(&hex!(
        "0f0e6cf18230b963fe8ba4f4bd9d030f6e1532e39780d1550c2d5c8d8c674a2a"
    ))
    .unwrap();
    assert_eq!(
        (a + b).to_byte_array(),
        hex!("1d99c9ede63836ba366468353f57df2ab22ce677fd2e1cd76c3e70b4e7a80528")
    );
    assert_eq!(
        (a - b).to_byte_array(),
        hex!("736a975e0b74413a6c86f653cdbfb11129c024b3ce2ad62c53e3b798ced970d5")
    );
    assert_eq!(
        (a * b).to_byte_array(),
        hex!("5a14a08c9d20e6e57ffd1d7be158530e8cca1f14ef51bbebfde9eb452068d596")
    );
    assert_eq!(
        (a / b).unwrap().to_byte_array(),
        hex!("73363b379fff915dda13f329801c3c85b8b9f44b52e2b2e9ddda91b990107edc")
    );
    assert_eq!(
        (-a).to_byte_array(),
        hex!("65624a56c595fff1fb6114c787e6fbea0fa5f06e9a51107c9feeebd7a4bf4503")
    );
    assert_eq!(
        a.inverse().unwrap().to_byte_array(),
        hex!("11be79bcd8036206d5ba728a85d9a0825284ef198fc4a2558e28393ef30baa4d")
    );

    let p = G1Element::generator() * a;
    let q = G1Element::hash_to_group_element(b"fastcrypto bls12381 golden Q");
    assert_eq!(p.to_byte_array(), hex!("902576ddd5591d6094c28b4a5253190f19ca7a635f62224348fa23e76e5fdb00115bae85741602dc5eb9eaa08e1a7134"));
    assert_eq!(q.to_byte_array(), hex!("8ff6b1ac097daf776a461bfc5ea654a002d151f87cd1a3b88af01e3ae477bd1cdd0b269924b79a47b490a642d8e3ad40"));
    assert_eq!((p + q).to_byte_array(), hex!("a978a6986aa10ab4c7a96241c62187d82ba93af139fb19e30910b0911cdef6d7a16d5cd794190fed6863fdbe5ced4494"));
    assert_eq!((p - q).to_byte_array(), hex!("b03366bc8a23bd14433dd10b6f29ed5ad4ed12379a00aa04aebe3b7e0bd48f2a75ed6beafd7f80d44415a2223eedf22b"));
    assert_eq!((-p).to_byte_array(), hex!("b02576ddd5591d6094c28b4a5253190f19ca7a635f62224348fa23e76e5fdb00115bae85741602dc5eb9eaa08e1a7134"));
    assert_eq!((p * b).to_byte_array(), hex!("8d7a6a0ec74b9b7006832646f99dad5b685bc81ad404cb1e10eec2b6142aca7af70b0f711cbacb9d856490a33db19b7a"));
    assert_eq!((p / b).unwrap().to_byte_array(), hex!("b1a83654b1eeb9663050627005bd51f7750a521afce8ce5db711ff22b5943730c62fdfa993d65291a4331a564098067c"));
    assert_eq!(G1Element::multi_scalar_mul(&[a, b], &[p, q]).unwrap().to_byte_array(), hex!("b090eee186471db5b811d15c4f66bc33602bfc9eb5183c734e16b67341fb0a55feee8c2192ec9c933b61b82be679a329"));
    assert_eq!(G1ElementUncompressed::from(&p).into_byte_array(), hex!("102576ddd5591d6094c28b4a5253190f19ca7a635f62224348fa23e76e5fdb00115bae85741602dc5eb9eaa08e1a7134014a74ef19bc84e173cc1a0fcb0aeee9eec84ccd914051b86e6200b312508489e722656539a176a729a49bfb596536ec"));
    let sum = G1ElementUncompressed::sum(&[(&p).into(), (&q).into()]).unwrap();
    assert_eq!(G1ElementUncompressed::from(&sum).into_byte_array(), hex!("0978a6986aa10ab4c7a96241c62187d82ba93af139fb19e30910b0911cdef6d7a16d5cd794190fed6863fdbe5ced44940ef48b43588a9eb2d0270099755bad0ffabe305fce1adff438d500aecc018f73628e01002c778d6e78b640c4d3b3ac8e"));

    let r = G2Element::generator() * b;
    let s = G2Element::hash_to_group_element(b"fastcrypto bls12381 golden S");
    assert_eq!(r.to_byte_array(), hex!("ae575cdbe322e87867440906800418943e2711fe1aec9b01a5ca7aebe8659ba0329b59a035763f93c3a92ca033ceec3904cfafde88b7d656d6787d3c558cfea96350e72f10fb1f8e691748da41889e221b5a6567e8ca6fe9c22f3b56e3014a62"));
    assert_eq!(s.to_byte_array(), hex!("886964c7afd7822e5d561c17bd46856e2d55e89f663bccf78277e96e8b2425ba94795a8f6af29048c506005ae72ad1a41576069e53c4462ccc303beb0c3218f3528b30b3a155867f8ccc7a18a3854ebf2e3309ba2ce54ebad75c4dd26445cd42"));
    assert_eq!((r + s).to_byte_array(), hex!("a4e1ce22a7c4f959ad7cfd1fd2a13ec98206d11600d74176114349ef40fd69609241a3b48dc69f115f9ea7b434bfa38c09c8f539c0c0773a107d3255e1a6da6549f1a8c88c0ac994674e60b9deb08a760651332b48c512f5af92a19b52790843"));
    assert_eq!((r - s).to_byte_array(), hex!("a4f6ce66048e9ec2833c91e8dc51ec21efa22fce83a22fb88007623520cd55d2bd229f03a78f7d2db4f81f9aeeaa5e1f0fbea523a02cb24d8ead3c45be67557d44f774e1c1ba6e03ce97cd4c161e78278b698a3b5042e4c1baccd87d07c0d317"));
    assert_eq!((-r).to_byte_array(), hex!("8e575cdbe322e87867440906800418943e2711fe1aec9b01a5ca7aebe8659ba0329b59a035763f93c3a92ca033ceec3904cfafde88b7d656d6787d3c558cfea96350e72f10fb1f8e691748da41889e221b5a6567e8ca6fe9c22f3b56e3014a62"));
    assert_eq!((r * a).to_byte_array(), hex!("ab2a9a0e77ceea842feebbe30f115fffc26fb5310b0560c62d5330549306a7a7d466cc5817496dee440f30fd217d9b0a00fe87c7bc888255eb2c133baffc68b6b290647a31b03c7d97e7fef199d461a66decb05c9dd32fa62296a98352d5f4a2"));
    assert_eq!((r / a).unwrap().to_byte_array(), hex!("8ce346f9c178b100a5ae50f2893fb4f9797dbc8b7264f97e62fc6d45517f53969e118d08caeae7c8d4d60fb22b6e1ff2032df38d5d980ba751a9a713ae9f49362af96fbe6012ce44f6cf44ef4d19290e222189e8d2b6bc984343cbcb19ffa065"));
    assert_eq!(G2Element::multi_scalar_mul(&[a, b], &[r, s]).unwrap().to_byte_array(), hex!("86ba21543897f38fe27336d5fed1f25cc31d6ef16447d58824a1d914b61b75e8f4202fa79192797d5064a723954c4f511737e91304835907652ab81b0e809437e6bbb9bc86dee08132751a55672c01a6009462fa3f8a8c1b03048e19752f8ade"));

    let digest = |x: GTElement| Sha256::digest(x.to_byte_array()).digest;
    let x = p.pairing(&r);
    let y = q.pairing(&s);
    assert_eq!(
        digest(x),
        hex!("5250c5223fa3afc3a1399f5a8f435b15999b4480cc6e792a422c16e0273df417")
    );
    assert_eq!(
        digest(x + y),
        hex!("aa5649aa774bca142a3a252fb7a9340aa189192a950e4b4d3afa432a65fc0720")
    );
    assert_eq!(
        digest(G1Element::multi_pairing(&[p, q], &[r, s]).unwrap()),
        hex!("aa5649aa774bca142a3a252fb7a9340aa189192a950e4b4d3afa432a65fc0720")
    );
    assert_eq!(
        digest(x - y),
        hex!("d8cffb7d36ebab8306f163ed347c38d3447ad9d5271175fb2daf65bb01872afa")
    );
    assert_eq!(
        digest(-x),
        hex!("e59d5fb9d195540124b33e06cb73387698d76ec78c010a5c8ca3ea538a80f483")
    );
    assert_eq!(
        digest(x * a),
        hex!("11b0cf71274c49ce71f81cde3f91384bd5da3f664aef1d8969a781cb63b3baaf")
    );
    assert_eq!(
        digest((x / a).unwrap()),
        hex!("739df53cb0e1aaeafadca4214b1f4b25fc8e3d6c98f510c6bad252f4b9d844eb")
    );
}

//
// Proptests
//

fn arb_scalar() -> impl Strategy<Value = Scalar> {
    prop_oneof![
        1 => prop_oneof![Just(Scalar::zero()), Just(Scalar::generator()), Just(minus_one())],
        4 => any::<[u8; 64]>().prop_map(|bytes| reduce_mod_uniform_buffer(&bytes)),
    ]
}

fn arb_g1() -> impl Strategy<Value = G1Element> {
    prop_oneof![
        1 => Just(G1Element::zero()),
        1 => Just(G1Element::generator()),
        3 => arb_scalar().prop_map(|s| G1Element::generator() * s),
        3 => any::<[u8; 8]>().prop_map(|m| G1Element::hash_to_group_element(&m)),
    ]
}

fn arb_g2() -> impl Strategy<Value = G2Element> {
    prop_oneof![
        1 => Just(G2Element::zero()),
        1 => Just(G2Element::generator()),
        3 => arb_scalar().prop_map(|s| G2Element::generator() * s),
        3 => any::<[u8; 8]>().prop_map(|m| G2Element::hash_to_group_element(&m)),
    ]
}

fn arb_gt() -> impl Strategy<Value = GTElement> {
    prop_oneof![
        1 => Just(GTElement::zero()),
        1 => Just(GTElement::generator()),
        3 => arb_scalar().prop_map(|s| GTElement::generator() * s),
    ]
}

/// 32-byte strings near the boundary of the canonical range [0, r), and beyond it.
fn arb_scalar_bytes() -> impl Strategy<Value = [u8; SCALAR_LENGTH]> {
    prop_oneof![
        any::<[u8; SCALAR_LENGTH]>(),
        arb_scalar().prop_map(|s| s.to_byte_array()),
        // s + r, which is below 2^256 when s is below 2^256 - r.
        arb_scalar().prop_map(|s| add_big_endian(&s.to_byte_array(), &GROUP_ORDER)
            .map_or(GROUP_ORDER, |sum| sum.try_into().unwrap())),
        // r - 2, ..., r + 2.
        (0u8..5).prop_map(|d| {
            let mut small = [0u8; SCALAR_LENGTH];
            small[SCALAR_LENGTH - 1] = d;
            let order_minus_two = (minus_one() - Scalar::generator()).to_byte_array();
            add_big_endian(&order_minus_two, &small)
                .unwrap()
                .try_into()
                .unwrap()
        }),
    ]
}

/// A change to a valid encoding, to get past the length check into the checks behind it.
#[derive(Clone, Debug)]
enum Mutation {
    Keep,
    /// Set the three flag bits to the top three bits of the byte.
    Flags(u8),
    /// Add the field modulus to one coordinate (the index is taken modulo the number of
    /// coordinates).
    AddModulus(usize),
    /// Flip one bit (the index is taken modulo the number of bits).
    FlipBit(usize),
    /// Replace the x-coordinate by a small integer, keeping the flags. This is on the curve about
    /// half of the time, but almost never in the subgroup.
    SmallX(u64),
    /// Replace the encoding by random bytes, keeping the flags.
    Random(Vec<u8>),
}

fn arb_mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        2 => Just(Mutation::Keep),
        2 => any::<u8>().prop_map(Mutation::Flags),
        2 => any::<usize>().prop_map(Mutation::AddModulus),
        2 => any::<usize>().prop_map(Mutation::FlipBit),
        1 => any::<u64>().prop_map(Mutation::SmallX),
        1 => collection::vec(any::<u8>(), GT_ELEMENT_BYTE_LENGTH).prop_map(Mutation::Random),
    ]
}

impl Mutation {
    /// Applies the mutation to an encoding whose first `x_length` bytes are the x-coordinate. With
    /// `flags`, the top three bits of the first byte are flags.
    fn apply<const N: usize>(&self, bytes: [u8; N], flags: bool, x_length: usize) -> [u8; N] {
        let mask = if flags { ALL_FLAGS } else { 0 };
        let mut out = bytes;
        match self {
            Mutation::Keep => {}
            Mutation::Flags(f) => out[0] = (out[0] & !mask) | (f & mask),
            Mutation::AddModulus(index) => {
                if let Some(unreduced) = add_modulus(&bytes, index % (N / FP_BYTE_LENGTH), flags) {
                    out.copy_from_slice(&unreduced);
                }
            }
            Mutation::FlipBit(bit) => out[(bit / 8) % N] ^= 1 << (bit % 8),
            Mutation::SmallX(x) => {
                out[..x_length].fill(0);
                out[x_length - 8..x_length].copy_from_slice(&x.to_be_bytes());
                out[0] |= bytes[0] & mask;
            }
            Mutation::Random(random) => {
                out.copy_from_slice(&random[..N]);
                out[0] = (out[0] & !mask) | (bytes[0] & mask);
            }
        }
        out
    }
}

/// Up to `max` terms (scalar, point), with the points drawn from a small pool and negated at random,
/// so that points repeat and cancel.
fn arb_terms<G: GroupElement<ScalarType = Scalar> + 'static>(
    points: impl Strategy<Value = G>,
    max: usize,
) -> impl Strategy<Value = Vec<(Scalar, G)>> {
    (
        collection::vec(points, 1..4),
        collection::vec(
            (arb_scalar(), any::<prop::sample::Index>(), any::<bool>()),
            0..=max,
        ),
    )
        .prop_map(|(pool, picks)| {
            picks
                .into_iter()
                .map(|(s, index, negate)| {
                    let p = *index.get(&pool);
                    (s, if negate { -p } else { p })
                })
                .collect()
        })
}

proptest! {
    #[test]
    fn prop_scalar_decoding_is_canonical(bytes in arb_scalar_bytes()) {
        let decoded = check_decoding::<Scalar, SCALAR_LENGTH>(&bytes);
        prop_assert_eq!(decoded.is_some(), bytes < GROUP_ORDER);
        // FromTrustedByteArray reduces modulo r.
        let trusted = Scalar::from_trusted_byte_array(&bytes).unwrap();
        let mut padded = [0u8; 48];
        padded[16..].copy_from_slice(&bytes);
        prop_assert_eq!(trusted, buffer_to_scalar_mod_r(&padded).unwrap());
        prop_assert_eq!(arkworks::scalar(&trusted), arkworks::reduce(&bytes));
    }

    #[test]
    fn prop_scalar_from_uniform_buffer(bytes in collection::vec(any::<u8>(), 0..=80)) {
        // Buffers of 48 to 64 bytes are reduced modulo r, and other lengths are rejected.
        let result = buffer_to_scalar_mod_r(&bytes);
        prop_assert_eq!(result.is_ok(), (48..=64).contains(&bytes.len()));
        if let Ok(s) = result {
            prop_assert_eq!(arkworks::scalar(&s), arkworks::reduce(&bytes));
            prop_assert_eq!(reduce_mod_uniform_buffer(&bytes), s);
            prop_assert_eq!(Scalar::fiat_shamir_reduction_to_group_element(&bytes), s);
        }
    }

    #[test]
    fn prop_g1_decoding_is_canonical(p in arb_g1(), mutation in arb_mutation()) {
        let bytes = mutation.apply(p.to_byte_array(), true, G1_ELEMENT_BYTE_LENGTH);
        let decoded = check_decoding::<G1Element, G1_ELEMENT_BYTE_LENGTH>(&bytes);
        // arkworks accepts the infinity flag with other bits set.
        compare_with_arkworks(
            decoded.map(|p| arkworks::g1(&p)),
            arkworks::decode_g1(&bytes),
            |q| arkworks::is_zero(q) && bytes[0] & INFINITY_FLAG != 0,
        )?;
    }

    #[test]
    fn prop_g2_decoding_is_canonical(p in arb_g2(), mutation in arb_mutation()) {
        let bytes = mutation.apply(p.to_byte_array(), true, G2_ELEMENT_BYTE_LENGTH);
        let decoded = check_decoding::<G2Element, G2_ELEMENT_BYTE_LENGTH>(&bytes);
        compare_with_arkworks(
            decoded.map(|p| arkworks::g2(&p)),
            arkworks::decode_g2(&bytes),
            |q| arkworks::is_zero(q) && bytes[0] & INFINITY_FLAG != 0,
        )?;
    }

    #[test]
    fn prop_g1_uncompressed_decoding_is_canonical(p in arb_g1(), mutation in arb_mutation()) {
        let bytes = mutation.apply(
            G1ElementUncompressed::from(&p).into_byte_array(),
            true,
            G1_ELEMENT_BYTE_LENGTH,
        );
        let decoded = decode_uncompressed(bytes);
        if let Some(q) = decoded {
            prop_assert_eq!(G1ElementUncompressed::from(&q).into_byte_array(), bytes);
            prop_assert_eq!(G1Element::from_byte_array(&q.to_byte_array()).unwrap(), q);
        }
        // arkworks accepts the infinity flag with other bits set, and ignores the sort flag.
        let mut without_sort_flag = bytes;
        without_sort_flag[0] &= !SORT_FLAG;
        compare_with_arkworks(
            decoded.map(|p| arkworks::g1(&p)),
            arkworks::decode_g1_uncompressed(&bytes),
            |q| {
                (arkworks::is_zero(q) && bytes[0] & INFINITY_FLAG != 0)
                    || (bytes[0] & ALL_FLAGS == SORT_FLAG
                        && decode_uncompressed(without_sort_flag).map(|p| arkworks::g1(&p))
                            == Some(*q))
            },
        )?;
    }

    #[test]
    fn prop_gt_decoding_is_canonical(x in arb_gt(), mutation in arb_mutation()) {
        let bytes = mutation.apply(x.to_byte_array(), false, FP_BYTE_LENGTH);
        if let Some(y) = check_decoding::<GTElement, GT_ELEMENT_BYTE_LENGTH>(&bytes) {
            // Accepted elements have order dividing r.
            prop_assert_eq!(y * minus_one() + y, GTElement::zero());
        }
    }

    #[test]
    fn prop_decoding_arbitrary_bytes_does_not_panic(
        bytes in collection::vec(any::<u8>(), 0..=GT_ELEMENT_BYTE_LENGTH + 1)
    ) {
        check_serde_agrees::<Scalar, SCALAR_LENGTH>(&bytes);
        check_serde_agrees::<G1Element, G1_ELEMENT_BYTE_LENGTH>(&bytes);
        check_serde_agrees::<G2Element, G2_ELEMENT_BYTE_LENGTH>(&bytes);
        check_serde_agrees::<GTElement, GT_ELEMENT_BYTE_LENGTH>(&bytes);
        if let Some(prefix) = bytes.get(..SCALAR_LENGTH) {
            let _ = Scalar::from_trusted_byte_array(prefix.try_into().unwrap());
        }
        if let Some(prefix) = bytes.get(..G1_ELEMENT_BYTE_LENGTH) {
            let _ = G1Element::from_trusted_byte_array(prefix.try_into().unwrap());
        }
        if let Some(prefix) = bytes.get(..2 * G1_ELEMENT_BYTE_LENGTH) {
            let _ = decode_uncompressed(prefix.try_into().unwrap());
            let _ = G2Element::from_trusted_byte_array(prefix.try_into().unwrap());
        }
        if let Some(prefix) = bytes.get(..GT_ELEMENT_BYTE_LENGTH) {
            let _ = GTElement::from_trusted_byte_array(prefix.try_into().unwrap());
        }
    }

    #[test]
    fn prop_g1_uncompressed_sum_matches_naive(terms in arb_terms(arb_g1(), 64)) {
        let points: Vec<G1Element> = terms.into_iter().map(|(_, p)| p).collect();
        let uncompressed: Vec<G1ElementUncompressed> =
            points.iter().map(G1ElementUncompressed::from).collect();
        let sum = G1ElementUncompressed::sum(&uncompressed).unwrap();
        prop_assert_eq!(sum, points.iter().fold(G1Element::zero(), |acc, p| acc + p));
        prop_assert_eq!(
            decode_uncompressed(G1ElementUncompressed::from(&sum).into_byte_array()),
            Some(sum)
        );
    }
}

proptest! {
    // arkworks is slow without optimizations.
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_scalar_arithmetic_matches_arkworks(a in arb_scalar(), b in arb_scalar()) {
        let (x, y) = (arkworks::scalar(&a), arkworks::scalar(&b));
        prop_assert_eq!(arkworks::scalar(&(a + b)), x + y);
        prop_assert_eq!(arkworks::scalar(&(a - b)), x - y);
        prop_assert_eq!(arkworks::scalar(&(a * b)), x * y);
        prop_assert_eq!(arkworks::scalar(&-a), -x);
        prop_assert_eq!(
            (a / b).ok().map(|q| arkworks::scalar(&q)),
            arkworks::inverse(&y).map(|inverse| x * inverse)
        );
        prop_assert_eq!(b.inverse().ok().map(|i| arkworks::scalar(&i)), arkworks::inverse(&y));
    }

    #[test]
    fn prop_hash_to_curve_matches_arkworks(msg in collection::vec(any::<u8>(), 0..300)) {
        prop_assert_eq!(
            arkworks::g1(&G1Element::hash_to_group_element(&msg)),
            arkworks::hash_to_g1(&msg)
        );
        prop_assert_eq!(
            arkworks::g2(&G2Element::hash_to_group_element(&msg)),
            arkworks::hash_to_g2(&msg)
        );
    }

    #[test]
    fn prop_multi_pairing_matches_pairings(
        g1_terms in arb_terms(arb_g1(), 4),
        g2_terms in arb_terms(arb_g2(), 4),
    ) {
        let a: Vec<G1Element> = g1_terms.into_iter().map(|(_, p)| p).collect();
        let b: Vec<G2Element> = g2_terms.into_iter().map(|(_, q)| q).collect();
        prop_assert_eq!(G1Element::multi_pairing(&a, &b).is_ok(), a.len() == b.len());
        let n = a.len().min(b.len());
        prop_assert_eq!(
            G1Element::multi_pairing(&a[..n], &b[..n]).unwrap(),
            a.iter().zip(&b).fold(GTElement::zero(), |acc, (p, q)| acc + p.pairing(q))
        );
    }
}

proptest! {
    // An arkworks pairing takes a while without optimizations.
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_pairing_matches_arkworks(p in arb_g1(), q in arb_g2(), s in arb_scalar()) {
        let e = p.pairing(&q);
        let expected = arkworks::pairing(&arkworks::g1(&p), &arkworks::g2(&q));
        prop_assert_eq!(e, arkworks::gt(&expected));
        prop_assert_eq!(e * s, arkworks::gt(&arkworks::pow(&expected, &arkworks::scalar(&s))));
        prop_assert_eq!((p * s).pairing(&q), e * s);
        prop_assert_eq!(p.pairing(&(q * s)), e * s);
        prop_assert_eq!(GTElement::from_byte_array(&e.to_byte_array()).unwrap(), e);
    }
}

/// Group operations agree with arkworks, and their outputs are valid, canonical encodings.
macro_rules! prop_group_arithmetic_matches_arkworks {
    ($name:ident, $type:ty, $arb:expr, $to_arkworks:path) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            #[test]
            fn $name(p in $arb, q in $arb, s in arb_scalar()) {
                let (x, y, k) = ($to_arkworks(&p), $to_arkworks(&q), arkworks::scalar(&s));
                prop_assert_eq!($to_arkworks(&(p + q)), x + y);
                prop_assert_eq!($to_arkworks(&(p - q)), x - y);
                prop_assert_eq!($to_arkworks(&-p), -x);
                prop_assert_eq!($to_arkworks(&(p * s)), x * k);
                prop_assert_eq!(
                    (p / s).ok().map(|d| $to_arkworks(&d)),
                    arkworks::inverse(&k).map(|inverse| x * inverse)
                );
                for r in [p + q, p - q, -p, p * s] {
                    prop_assert_eq!(<$type>::from_byte_array(&r.to_byte_array()).unwrap(), r);
                }
                // Equal elements have equal encodings, however they were computed: Sui's group_ops
                // compares elements by their bytes.
                prop_assert_eq!(p == q, p.to_byte_array() == q.to_byte_array());
                prop_assert_eq!((p + q - q).to_byte_array(), p.to_byte_array());
            }
        }
    };
}

prop_group_arithmetic_matches_arkworks!(
    prop_g1_arithmetic_matches_arkworks,
    G1Element,
    arb_g1(),
    arkworks::g1
);
prop_group_arithmetic_matches_arkworks!(
    prop_g2_arithmetic_matches_arkworks,
    G2Element,
    arb_g2(),
    arkworks::g2
);

/// MSM agrees with the naive sum and with arkworks on terms that repeat and cancel. It only fails on
/// empty input.
macro_rules! prop_msm_matches_arkworks {
    ($name:ident, $type:ty, $arb:expr, $to_arkworks:path) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            #[test]
            fn $name(terms in arb_terms($arb, 40)) {
                let (scalars, points): (Vec<Scalar>, Vec<$type>) = terms.into_iter().unzip();
                let result = <$type>::multi_scalar_mul(&scalars, &points);
                prop_assert_eq!(result.is_ok(), !scalars.is_empty());
                if let Ok(result) = result {
                    let naive = points
                        .iter()
                        .zip(&scalars)
                        .fold(<$type>::zero(), |acc, (p, s)| acc + *p * *s);
                    prop_assert_eq!(result, naive);
                    let arkworks_points: Vec<_> = points.iter().map($to_arkworks).collect();
                    let arkworks_scalars: Vec<_> = scalars.iter().map(arkworks::scalar).collect();
                    prop_assert_eq!(
                        $to_arkworks(&result),
                        arkworks::msm(&arkworks_points, &arkworks_scalars)
                    );
                }
            }
        }
    };
}

prop_msm_matches_arkworks!(
    prop_g1_msm_matches_arkworks,
    G1Element,
    arb_g1(),
    arkworks::g1
);
prop_msm_matches_arkworks!(
    prop_g2_msm_matches_arkworks,
    G2Element,
    arb_g2(),
    arkworks::g2
);
