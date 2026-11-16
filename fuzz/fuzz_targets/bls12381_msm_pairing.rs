// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Multi-scalar multiplication in G1 and G2, sums of uncompressed G1 points and multi-pairing on
//! arbitrary inputs. Scalars and points are decoded from bytes when the bytes are valid and derived
//! from them otherwise, mixed with the inputs that blst handles as special cases: the identity, the
//! scalars 0, 1 and r - 1, repeated points and negated points.
//!
//! Invariants: nothing panics; MSM fails exactly on empty inputs and length mismatches, and
//! otherwise equals the naive sum; the uncompressed sum equals the naive sum; multi-pairing fails
//! exactly on a length mismatch, and otherwise equals the sum of the pairings; and the pairing is
//! bilinear.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::groups::bls12381::{
    buffer_to_scalar_mod_r, G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar,
    G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};
use fastcrypto::groups::{GroupElement, HashToGroupElement, MultiScalarMul, Pairing};
use fastcrypto::serde_helpers::ToFromByteArray;
use libfuzzer_sys::fuzz_target;

/// Twice Sui's `group_ops_bls12381_msm_max_len`.
const MAX_TERMS: usize = 64;
/// Pairings are slow, so multi-pairings use only the first few terms.
const MAX_PAIRINGS: usize = 4;

#[derive(Arbitrary, Debug)]
enum ScalarInput {
    Zero,
    One,
    MinusOne,
    /// Decoded if canonical, and otherwise reduced modulo r.
    Bytes([u8; SCALAR_LENGTH]),
}

#[derive(Arbitrary, Debug)]
enum G1Input {
    Identity,
    Generator,
    /// Decoded if valid, and otherwise hashed to the curve.
    Bytes([u8; G1_ELEMENT_BYTE_LENGTH]),
    /// The previous point, or its negation.
    Previous {
        negate: bool,
    },
}

#[derive(Arbitrary, Debug)]
enum G2Input {
    Identity,
    Generator,
    Bytes([u8; G2_ELEMENT_BYTE_LENGTH]),
    Previous { negate: bool },
}

#[derive(Arbitrary, Debug)]
struct Input {
    g1_terms: Vec<(ScalarInput, G1Input)>,
    g2_terms: Vec<(ScalarInput, G2Input)>,
    /// Drop this many scalars (modulo 3) to make the lengths differ.
    drop_scalars: u8,
}

fn scalar(input: &ScalarInput) -> Scalar {
    match input {
        ScalarInput::Zero => Scalar::zero(),
        ScalarInput::One => Scalar::generator(),
        ScalarInput::MinusOne => -Scalar::generator(),
        ScalarInput::Bytes(bytes) => Scalar::from_byte_array(bytes).unwrap_or_else(|_| {
            let mut padded = [0u8; 48];
            padded[16..].copy_from_slice(bytes);
            buffer_to_scalar_mod_r(&padded).unwrap()
        }),
    }
}

fn g1_points(inputs: &[(ScalarInput, G1Input)]) -> Vec<G1Element> {
    let mut points: Vec<G1Element> = Vec::new();
    for (_, input) in inputs {
        let point = match input {
            G1Input::Identity => G1Element::zero(),
            G1Input::Generator => G1Element::generator(),
            G1Input::Bytes(bytes) => G1Element::from_byte_array(bytes)
                .unwrap_or_else(|_| G1Element::hash_to_group_element(bytes)),
            G1Input::Previous { negate } => {
                let previous = points.last().copied().unwrap_or_else(G1Element::generator);
                if *negate {
                    -previous
                } else {
                    previous
                }
            }
        };
        points.push(point);
    }
    points
}

fn g2_points(inputs: &[(ScalarInput, G2Input)]) -> Vec<G2Element> {
    let mut points: Vec<G2Element> = Vec::new();
    for (_, input) in inputs {
        let point = match input {
            G2Input::Identity => G2Element::zero(),
            G2Input::Generator => G2Element::generator(),
            G2Input::Bytes(bytes) => G2Element::from_byte_array(bytes)
                .unwrap_or_else(|_| G2Element::hash_to_group_element(bytes)),
            G2Input::Previous { negate } => {
                let previous = points.last().copied().unwrap_or_else(G2Element::generator);
                if *negate {
                    -previous
                } else {
                    previous
                }
            }
        };
        points.push(point);
    }
    points
}

fn check_msm<G: GroupElement<ScalarType = Scalar> + MultiScalarMul>(
    scalars: &[Scalar],
    points: &[G],
    drop_scalars: usize,
) {
    let result = G::multi_scalar_mul(scalars, points);
    assert_eq!(result.is_err(), scalars.is_empty());
    if let Ok(result) = result {
        let naive = points
            .iter()
            .zip(scalars)
            .fold(G::zero(), |acc, (p, s)| acc + *p * *s);
        assert_eq!(result, naive);
    }
    let truncated = &scalars[..scalars.len().saturating_sub(drop_scalars)];
    if truncated.len() != points.len() {
        assert!(G::multi_scalar_mul(truncated, points).is_err());
    }
}

fuzz_target!(|input: Input| {
    let drop_scalars = input.drop_scalars as usize % 3;
    let g1_terms = &input.g1_terms[..input.g1_terms.len().min(MAX_TERMS)];
    let g2_terms = &input.g2_terms[..input.g2_terms.len().min(MAX_TERMS)];

    let g1_scalars: Vec<Scalar> = g1_terms.iter().map(|(s, _)| scalar(s)).collect();
    let g1 = g1_points(g1_terms);
    check_msm(&g1_scalars, &g1, drop_scalars);

    let g2_scalars: Vec<Scalar> = g2_terms.iter().map(|(s, _)| scalar(s)).collect();
    let g2 = g2_points(g2_terms);
    check_msm(&g2_scalars, &g2, drop_scalars);

    // The sum of the uncompressed points.
    let uncompressed: Vec<G1ElementUncompressed> =
        g1.iter().map(G1ElementUncompressed::from).collect();
    let sum = G1ElementUncompressed::sum(&uncompressed).unwrap();
    assert_eq!(sum, g1.iter().fold(G1Element::zero(), |acc, p| acc + p));

    // Multi-pairing on the first terms.
    let a = &g1[..g1.len().min(MAX_PAIRINGS)];
    let b = &g2[..g2.len().min(MAX_PAIRINGS)];
    let result = G1Element::multi_pairing(a, b);
    assert_eq!(result.is_ok(), a.len() == b.len());
    if let Ok(result) = result {
        let pairings: Vec<GTElement> = a.iter().zip(b).map(|(p, q)| p.pairing(q)).collect();
        assert_eq!(
            result,
            pairings.iter().fold(GTElement::zero(), |acc, e| acc + e)
        );
        // Bilinearity on the first term.
        if let (Some(p), Some(q), Some(e), Some(s)) =
            (a.first(), b.first(), pairings.first(), g1_scalars.first())
        {
            assert_eq!((*p * *s).pairing(q), *e * *s);
            assert_eq!(p.pairing(&(*q * *s)), *e * *s);
        }
    }
});
