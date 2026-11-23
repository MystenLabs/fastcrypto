// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Hashes inputs with `poseidon_bytes` the way Sui's `poseidon_bn254` Move native does it. The
//! native rejects more than 16 inputs, but not inputs of other lengths than 32 bytes.
//!
//! Invariants: nothing panics; `poseidon_bytes` accepts exactly 1 to 16 inputs that are canonical
//! little-endian encodings of field elements, that is, 32 bytes for an integer smaller than the
//! modulus p; and it returns a canonical encoding.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto_zkp::bn254::poseidon::poseidon_bytes;
use hex_literal::hex;
use libfuzzer_sys::fuzz_target;

/// The modulus p of the BN254 scalar field, little-endian.
const MODULUS: [u8; 32] =
    hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430");

#[derive(Arbitrary, Debug)]
enum Element {
    Raw(Vec<u8>),
    /// 32 bytes with the top three bits cleared, which is smaller than p.
    Small([u8; 32]),
    /// p - 1, p, p + 1 or p + 2.
    NearModulus(u8),
}

impl Element {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Element::Raw(raw) => raw.clone(),
            Element::Small(bytes) => {
                let mut bytes = *bytes;
                bytes[31] &= 0x1f;
                bytes.to_vec()
            }
            Element::NearModulus(k) => {
                // The lowest byte of p is 1, so this doesn't carry or borrow.
                let mut bytes = MODULUS;
                bytes[0] = k % 4;
                bytes.to_vec()
            }
        }
    }
}

/// Whether the bytes are 32 bytes of a little-endian integer smaller than p.
fn is_canonical(bytes: &[u8]) -> bool {
    bytes.len() == 32 && bytes.iter().rev().lt(MODULUS.iter().rev())
}

fuzz_target!(|elements: Vec<Element>| {
    let inputs: Vec<Vec<u8>> = elements.iter().map(Element::bytes).collect();
    let result = poseidon_bytes(&inputs);
    let valid = (1..=16).contains(&inputs.len()) && inputs.iter().all(|i| is_canonical(i));
    assert_eq!(result.is_ok(), valid);
    if let Ok(hash) = result {
        assert!(is_canonical(&hash));
    }
});
