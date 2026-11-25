// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Decodes arbitrary bytes as a public key and a signature in every way that Sui does, or verifies a
//! (public key, message, signature) input. Each of the three is either arbitrary or an edit of a
//! fixed valid one.
//!
//! Invariants: nothing panics; every decoder accepts exactly the byte strings of the right length
//! and keeps them; and the fixed signature is the only one that verifies under the fixed public key,
//! and verifies only under that key and for the fixed message.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::traits::{EncodeDecodeBase64, ToFromBytes, VerifyingKey};
use fastcrypto_pq::mldsa65::{
    MLDSA65PublicKey, MLDSA65PublicKeyAsBytes, MLDSA65Signature, MLDSA65SignatureAsBytes,
    MLDSA65_PUBLIC_KEY_LENGTH, MLDSA65_SIGNATURE_LENGTH,
};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;

/// A valid public key, message and signature.
struct Valid {
    pk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

static VALID: Lazy<Valid> = Lazy::new(|| {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../fastcrypto-pq/src/tests/ts_interop_vectors.json"
    ))
    .unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "digest-msg")
        .unwrap();
    let field = |name: &str| Hex::decode(case[name].as_str().unwrap()).unwrap();
    Valid {
        pk: field("pk"),
        msg: field("msg"),
        sig: field("sig"),
    }
});

/// The start of each part of a signature: the commitment hash, z, the hint positions and the hint
/// counts.
const SIG_PARTS: [usize; 5] = [0, 48, 3248, 3303, MLDSA65_SIGNATURE_LENGTH];

#[derive(Arbitrary, Debug)]
enum Edit {
    FlipBit(u16, u8),
    SetByte(u16, u8),
    Swap(u16, u16),
    Fill(u16, u16, u8),
}

impl Edit {
    fn apply(&self, bytes: &mut [u8]) {
        let index = |i: u16| i as usize % bytes.len();
        match *self {
            Edit::FlipBit(i, bit) => bytes[index(i)] ^= 1 << (bit % 8),
            Edit::SetByte(i, value) => bytes[index(i)] = value,
            Edit::Swap(i, j) => bytes.swap(index(i), index(j)),
            Edit::Fill(i, j, value) => {
                let (i, j) = (index(i), index(j));
                bytes[i.min(j)..=i.max(j)].fill(value)
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
enum BytesInput {
    /// Arbitrary bytes, repeated up to the right length.
    Repeated(Vec<u8>),
    Edited(Vec<Edit>),
}

impl BytesInput {
    fn bytes(&self, valid: &[u8]) -> Vec<u8> {
        let mut bytes = valid.to_vec();
        match self {
            BytesInput::Repeated(raw) => bytes
                .iter_mut()
                .zip(raw.iter().cycle())
                .for_each(|(byte, raw)| *byte = *raw),
            BytesInput::Edited(edits) => edits.iter().for_each(|edit| edit.apply(&mut bytes)),
        }
        bytes
    }
}

#[derive(Arbitrary, Debug)]
enum Input {
    Decode(Vec<u8>),
    DecodeRepeated(u16, Vec<u8>),
    Verify {
        pk: BytesInput,
        msg: BytesInput,
        msg_suffix: Vec<u8>,
        /// One input per part of the signature, so that a part can be edited without the others.
        sig: [BytesInput; SIG_PARTS.len() - 1],
    },
}

/// Decodes a `T`, and the `*AsBytes` type that goes with it, in every way.
fn decode<T, A, const N: usize>(bytes: &[u8])
where
    T: ToFromBytes + EncodeDecodeBase64 + DeserializeOwned + PartialEq,
    A: DeserializeOwned,
    T: for<'a> TryFrom<&'a A>,
{
    let decoded = T::from_bytes(bytes).ok();
    assert_eq!(decoded.is_some(), bytes.len() == N);
    assert!(decoded.as_ref().is_none_or(|t| t.as_ref() == bytes));

    let base64 = Base64::encode(bytes);
    let json = serde_json::Value::String(base64.clone());
    for other in [
        T::decode_base64(&base64).ok(),
        bcs::from_bytes(bytes).ok(),
        serde_json::from_value(json.clone()).ok(),
        bcs::from_bytes::<A>(bytes)
            .ok()
            .and_then(|a| T::try_from(&a).ok()),
        serde_json::from_value::<A>(json)
            .ok()
            .and_then(|a| T::try_from(&a).ok()),
    ] {
        assert!(other == decoded, "decoders disagree");
    }
}

fn decode_all(bytes: &[u8]) {
    decode::<MLDSA65PublicKey, MLDSA65PublicKeyAsBytes, MLDSA65_PUBLIC_KEY_LENGTH>(bytes);
    decode::<MLDSA65Signature, MLDSA65SignatureAsBytes, MLDSA65_SIGNATURE_LENGTH>(bytes);
}

fuzz_target!(|input: Input| {
    match input {
        Input::Decode(bytes) => decode_all(&bytes),
        Input::DecodeRepeated(len, bytes) => {
            let len = len as usize % (2 * MLDSA65_SIGNATURE_LENGTH);
            decode_all(&bytes.iter().cycle().take(len).copied().collect::<Vec<_>>());
        }
        Input::Verify {
            pk,
            msg,
            msg_suffix,
            sig,
        } => {
            let pk = pk.bytes(&VALID.pk);
            let msg = [msg.bytes(&VALID.msg), msg_suffix].concat();
            let sig: Vec<u8> = SIG_PARTS
                .windows(2)
                .zip(&sig)
                .flat_map(|(part, input)| input.bytes(&VALID.sig[part[0]..part[1]]))
                .collect();

            let result = MLDSA65PublicKey::from_bytes(&pk)
                .unwrap()
                .verify(&msg, &MLDSA65Signature::from_bytes(&sig).unwrap());
            match (pk == VALID.pk, msg == VALID.msg, sig == VALID.sig) {
                (true, true, true) => assert_eq!(result, Ok(())),
                // Other keys could have signed another signature.
                (false, _, false) => assert!(matches!(
                    result,
                    Ok(()) | Err(FastCryptoError::InvalidSignature)
                )),
                _ => assert_eq!(
                    result,
                    Err(FastCryptoError::InvalidSignature),
                    "forged a signature"
                ),
            }
        }
    }
});
