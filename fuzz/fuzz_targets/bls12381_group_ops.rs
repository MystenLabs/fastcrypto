// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The BLS12-381 group operations must not panic on any bytes. This follows what Sui's Move
//! natives (`sui::bls12381`, `sui::group_ops`) do with untrusted input: decode elements, then
//! combine them.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::groups::bls12381::{
    G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar, G1_ELEMENT_BYTE_LENGTH,
};
use fastcrypto::groups::{HashToGroupElement, MultiScalarMul, Pairing};
use fastcrypto::serde_helpers::ToFromByteArray;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Scalar([u8; 32], [u8; 32]),
    G1([u8; 48], [u8; 48], [u8; 32]),
    G2([u8; 96], [u8; 96], [u8; 32]),
    Gt(Box<[u8; 576]>, Box<[u8; 576]>, [u8; 32]),
    G1Msm(Vec<([u8; 32], [u8; 48])>),
    G2Msm(Vec<([u8; 32], [u8; 96])>),
    Pairing([u8; 48], [u8; 96]),
    HashToG1(Vec<u8>),
    HashToG2(Vec<u8>),
    G1Uncompressed(Vec<[u8; 2 * G1_ELEMENT_BYTE_LENGTH]>),
}

fuzz_target!(|op: Op| {
    match op {
        Op::Scalar(a, b) => {
            if let (Ok(a), Ok(b)) = (Scalar::from_byte_array(&a), Scalar::from_byte_array(&b)) {
                let _ = (a + b, a - b, a * b, -a, a / b);
            }
        }
        Op::G1(p, q, s) => {
            let (p, q) = (
                G1Element::from_byte_array(&p),
                G1Element::from_byte_array(&q),
            );
            if let (Ok(p), Ok(q), Ok(s)) = (p, q, Scalar::from_byte_array(&s)) {
                let _ = (p + q, p - q, -p, p * s, p / s);
            }
        }
        Op::G2(p, q, s) => {
            let (p, q) = (
                G2Element::from_byte_array(&p),
                G2Element::from_byte_array(&q),
            );
            if let (Ok(p), Ok(q), Ok(s)) = (p, q, Scalar::from_byte_array(&s)) {
                let _ = (p + q, p - q, -p, p * s, p / s);
            }
        }
        Op::Gt(p, q, s) => {
            let (p, q) = (
                GTElement::from_byte_array(&p),
                GTElement::from_byte_array(&q),
            );
            if let (Ok(p), Ok(q), Ok(s)) = (p, q, Scalar::from_byte_array(&s)) {
                let _ = (p + q, p - q, -p, p * s, p / s);
            }
        }
        Op::G1Msm(terms) => {
            let (scalars, points): (Vec<_>, Vec<_>) = terms
                .iter()
                .filter_map(|(s, p)| {
                    Some((
                        Scalar::from_byte_array(s).ok()?,
                        G1Element::from_byte_array(p).ok()?,
                    ))
                })
                .unzip();
            let _ = G1Element::multi_scalar_mul(&scalars, &points);
        }
        Op::G2Msm(terms) => {
            let (scalars, points): (Vec<_>, Vec<_>) = terms
                .iter()
                .filter_map(|(s, p)| {
                    Some((
                        Scalar::from_byte_array(s).ok()?,
                        G2Element::from_byte_array(p).ok()?,
                    ))
                })
                .unzip();
            let _ = G2Element::multi_scalar_mul(&scalars, &points);
        }
        Op::Pairing(p, q) => {
            if let (Ok(p), Ok(q)) = (
                G1Element::from_byte_array(&p),
                G2Element::from_byte_array(&q),
            ) {
                let _ = p.pairing(&q);
            }
        }
        Op::HashToG1(msg) => {
            let _ = G1Element::hash_to_group_element(&msg);
        }
        Op::HashToG2(msg) => {
            let _ = G2Element::hash_to_group_element(&msg);
        }
        Op::G1Uncompressed(terms) => {
            let terms: Vec<_> = terms
                .into_iter()
                .map(G1ElementUncompressed::from_trusted_byte_array)
                .collect();
            for term in &terms {
                let _ = G1Element::try_from(term);
            }
            // `sum` takes trusted input, so only sum terms that decode.
            let valid: Vec<_> = terms
                .into_iter()
                .filter(|t| G1Element::try_from(t).is_ok())
                .collect();
            let _ = G1ElementUncompressed::sum(&valid);
        }
    }
});
