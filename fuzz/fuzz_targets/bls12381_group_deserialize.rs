// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Decodes arbitrary bytes as every BLS12-381 group type (scalars, G1, G2, GT and uncompressed G1)
//! through `from_byte_array`, `from_trusted_byte_array` and serde (BCS, bincode and base64 in JSON).
//! Besides raw bytes, an input can mutate the encoding of a valid element, to get past the length
//! and flag checks into the checks behind them.
//!
//! Invariants: nothing panics; an accepted encoding is the canonical encoding of the element;
//! `from_trusted_byte_array` accepts it too and agrees; serde accepts the same encodings; scalars
//! are accepted exactly below r; accepted GT elements have order dividing r; and decoding of G1
//! and G2 agrees with arkworks, except where arkworks is more lenient than the zcash format (it
//! accepts the infinity flag with other bits set, and the sort flag on uncompressed points).

#![no_main]

use arbitrary::Arbitrary;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::groups::bls12381::{
    buffer_to_scalar_mod_r, G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar,
    FP_BYTE_LENGTH, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH,
    SCALAR_LENGTH,
};
use fastcrypto::groups::{FromTrustedByteArray, GroupElement, HashToGroupElement, Pairing};
use fastcrypto::hash::{HashFunction, Sha512};
use fastcrypto::serde_helpers::ToFromByteArray;
use hex_literal::hex;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

const GROUP_ORDER: [u8; SCALAR_LENGTH] =
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
const FIELD_MODULUS: [u8; FP_BYTE_LENGTH] = hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
const INFINITY_FLAG: u8 = 0x40;
const SORT_FLAG: u8 = 0x20;
const ALL_FLAGS: u8 = 0xe0;

#[derive(Arbitrary, Debug)]
enum Input {
    /// Raw bytes, decoded as every type.
    Raw(Vec<u8>),
    /// The encoding of a valid element derived from `seed`, with some bytes XORed and optionally
    /// the field modulus added to one coordinate (or the group order to a scalar).
    Mutated {
        kind: Kind,
        seed: [u8; 8],
        xor: Vec<(u16, u8)>,
        add_modulus: Option<u8>,
    },
}

#[derive(Arbitrary, Debug)]
enum Kind {
    Scalar,
    G1,
    G2,
    Gt,
    G1Uncompressed,
}

/// A few elements of GT, which are slow to compute.
static GT_ELEMENTS: Lazy<Vec<GTElement>> = Lazy::new(|| {
    vec![
        GTElement::zero(),
        GTElement::generator(),
        G1Element::hash_to_group_element(b"fuzz")
            .pairing(&G2Element::hash_to_group_element(b"fuzz")),
    ]
});

/// Checks serde against `from_byte_array` and returns the decoded element. BCS and JSON accept
/// exactly the encodings of length `N` that `from_byte_array` accepts; bincode ignores trailing
/// bytes.
fn check_serde<T, const N: usize>(bytes: &[u8]) -> Option<T>
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
    }
    expected
}

/// Checks the properties every decoder must have, and returns the decoded element.
fn check<T, const N: usize>(bytes: &[u8]) -> Option<T>
where
    T: ToFromByteArray<N>
        + FromTrustedByteArray<N>
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Debug,
{
    let decoded = check_serde::<T, N>(bytes);
    if let Ok(array) = <[u8; N]>::try_from(bytes) {
        let trusted = T::from_trusted_byte_array(&array);
        if let Some(element) = &decoded {
            assert_eq!(element.to_byte_array(), array, "non-canonical encoding");
            assert_eq!(trusted.as_ref().ok(), Some(element));
        }
    }
    decoded
}

fn check_scalar(bytes: &[u8]) {
    let decoded = check::<Scalar, SCALAR_LENGTH>(bytes);
    if let Ok(array) = <[u8; SCALAR_LENGTH]>::try_from(bytes) {
        assert_eq!(decoded.is_some(), array < GROUP_ORDER);
        // FromTrustedByteArray reduces modulo r.
        let mut padded = [0u8; 48];
        padded[16..].copy_from_slice(&array);
        assert_eq!(
            Scalar::from_trusted_byte_array(&array).unwrap(),
            buffer_to_scalar_mod_r(&padded).unwrap()
        );
    }
}

/// Compares a decoding with arkworks', as compressed encodings. arkworks may also accept an
/// encoding that we reject if `lenient` holds for its result.
fn compare_with_arkworks<A: AffineRepr>(
    ours: Option<Vec<u8>>,
    theirs: Option<A>,
    lenient: impl FnOnce(&A) -> bool,
) {
    match (ours, theirs) {
        (Some(p), Some(q)) => assert_eq!(p, compressed(&q)),
        (None, Some(q)) => assert!(lenient(&q), "only arkworks accepts {q:?}"),
        (Some(p), None) => panic!("only fastcrypto accepts {p:?}"),
        (None, None) => {}
    }
}

/// Decodes a compressed G1 (`A` = `G1Affine`) or G2 (`A` = `G2Affine`) point. arkworks also accepts
/// the infinity flag with other bits set.
fn check_point<T, A, const N: usize>(bytes: &[u8])
where
    T: ToFromByteArray<N>
        + FromTrustedByteArray<N>
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Debug,
    A: AffineRepr,
{
    let decoded = check::<T, N>(bytes);
    if bytes.len() == N {
        compare_with_arkworks(
            decoded.map(|p| p.to_byte_array().to_vec()),
            A::deserialize_compressed(bytes).ok(),
            |q| q.is_zero() && bytes[0] & INFINITY_FLAG != 0,
        );
    }
}

fn check_g1(bytes: &[u8]) {
    check_point::<G1Element, ark_bls12_381::G1Affine, G1_ELEMENT_BYTE_LENGTH>(bytes);
}

fn check_g2(bytes: &[u8]) {
    check_point::<G2Element, ark_bls12_381::G2Affine, G2_ELEMENT_BYTE_LENGTH>(bytes);
}

fn check_gt(bytes: &[u8]) {
    if let Some(x) = check::<GTElement, GT_ELEMENT_BYTE_LENGTH>(bytes) {
        let minus_one = -Scalar::generator();
        assert_eq!(x * minus_one + x, GTElement::zero());
    }
}

/// Decodes the way Sui's `uncompressed_g1_to_g1` does.
fn decode_uncompressed(bytes: [u8; 2 * G1_ELEMENT_BYTE_LENGTH]) -> Option<G1Element> {
    G1Element::try_from(&G1ElementUncompressed::from_trusted_byte_array(bytes)).ok()
}

fn check_g1_uncompressed(bytes: &[u8]) {
    let Ok(array) = <[u8; 2 * G1_ELEMENT_BYTE_LENGTH]>::try_from(bytes) else {
        return;
    };
    let decoded = decode_uncompressed(array);
    if let Some(p) = decoded {
        assert_eq!(
            G1ElementUncompressed::from(&p).into_byte_array(),
            array,
            "non-canonical uncompressed encoding"
        );
    }
    // Summing trusted terms must not panic, whatever they are.
    let _ = G1ElementUncompressed::sum(&[G1ElementUncompressed::from_trusted_byte_array(array)]);

    // arkworks also accepts the infinity flag with other bits set, and ignores the sort flag.
    let mut without_sort_flag = array;
    without_sort_flag[0] &= !SORT_FLAG;
    compare_with_arkworks(
        decoded.map(|p| p.to_byte_array().to_vec()),
        ark_bls12_381::G1Affine::deserialize_uncompressed(bytes).ok(),
        |q| {
            (q.is_zero() && bytes[0] & INFINITY_FLAG != 0)
                || (bytes[0] & ALL_FLAGS == SORT_FLAG
                    && decode_uncompressed(without_sort_flag).map(|p| p.to_byte_array().to_vec())
                        == Some(compressed(q)))
        },
    );
}

fn compressed(p: &impl CanonicalSerialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// Adds the big-endian integer `value` to `bytes[offset..offset + value.len()]`, keeping the flags
/// in the top three bits of the first byte if `flags` is set. Leaves `bytes` unchanged if the sum
/// does not fit.
fn add_at(bytes: &mut [u8], offset: usize, value: &[u8], flags: bool) {
    let mask = if flags { ALL_FLAGS } else { 0 };
    let saved_flags = bytes[0] & mask;
    let mut out = bytes.to_vec();
    out[0] &= !mask;
    let mut carry = 0u16;
    for (o, v) in out[offset..offset + value.len()]
        .iter_mut()
        .zip(value)
        .rev()
    {
        let digit = *o as u16 + *v as u16 + carry;
        *o = digit as u8;
        carry = digit >> 8;
    }
    if carry == 0 && out[0] & mask == 0 {
        out[0] |= saved_flags;
        bytes.copy_from_slice(&out);
    }
}

fuzz_target!(|input: Input| {
    match input {
        Input::Raw(data) => {
            check_scalar(&data);
            check_g1(&data);
            check_g2(&data);
            check_gt(&data);
            check_g1_uncompressed(&data);
            // Also decode the prefixes of longer inputs as every type.
            if let Some(prefix) = data.get(..SCALAR_LENGTH) {
                check_scalar(prefix);
            }
            if let Some(prefix) = data.get(..G1_ELEMENT_BYTE_LENGTH) {
                check_g1(prefix);
            }
            if let Some(prefix) = data.get(..G2_ELEMENT_BYTE_LENGTH) {
                check_g2(prefix);
                check_g1_uncompressed(prefix);
            }
            if let Some(prefix) = data.get(..GT_ELEMENT_BYTE_LENGTH) {
                check_gt(prefix);
            }
        }
        Input::Mutated {
            kind,
            seed,
            xor,
            add_modulus: modulus_index,
        } => {
            let digest = Sha512::digest(seed).digest;
            let scalar = buffer_to_scalar_mod_r(&digest).unwrap();
            let (mut bytes, flags) = match kind {
                Kind::Scalar => (scalar.to_byte_array().to_vec(), false),
                Kind::G1 => (
                    (G1Element::hash_to_group_element(&seed) * scalar)
                        .to_byte_array()
                        .to_vec(),
                    true,
                ),
                Kind::G2 => (
                    (G2Element::hash_to_group_element(&seed) * scalar)
                        .to_byte_array()
                        .to_vec(),
                    true,
                ),
                Kind::Gt => (
                    GT_ELEMENTS[seed[0] as usize % GT_ELEMENTS.len()]
                        .to_byte_array()
                        .to_vec(),
                    false,
                ),
                Kind::G1Uncompressed => (
                    G1ElementUncompressed::from(&(G1Element::generator() * scalar))
                        .into_byte_array()
                        .to_vec(),
                    true,
                ),
            };
            for (position, mask) in xor {
                let length = bytes.len();
                bytes[position as usize % length] ^= mask;
            }
            // Adding r to a scalar, or p to a coordinate, gives an unreduced encoding of the same
            // value.
            if let Some(index) = modulus_index {
                if let Kind::Scalar = kind {
                    add_at(&mut bytes, 0, &GROUP_ORDER, false);
                } else {
                    let index = index as usize % (bytes.len() / FP_BYTE_LENGTH);
                    add_at(&mut bytes, index * FP_BYTE_LENGTH, &FIELD_MODULUS, flags);
                }
            }
            match kind {
                Kind::Scalar => check_scalar(&bytes),
                Kind::G1 => check_g1(&bytes),
                Kind::G2 => check_g2(&bytes),
                Kind::Gt => check_gt(&bytes),
                Kind::G1Uncompressed => check_g1_uncompressed(&bytes),
            }
        }
    }
});
