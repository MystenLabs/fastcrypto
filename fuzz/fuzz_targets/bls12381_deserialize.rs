// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Decodes arbitrary bytes as every BLS12-381 signature-scheme type, in both modes and through
//! every decoding path (`from_bytes`, BCS, bincode, JSON).
//!
//! Invariants: nothing panics, every accepted point encoding is the canonical compressed or
//! uncompressed encoding of the decoded point, `Eq`, `Hash` and `Ord` agree with the canonical
//! encoding, binary serde accepts exactly the compressed encodings that `from_bytes` accepts, the
//! `*AsBytes` representations accept any bytes of the right length and convert like binary serde,
//! and JSON agrees with `from_bytes`.

#![no_main]

use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::{Authenticator, SigningKey, ToFromBytes, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

macro_rules! check_mode {
    ($mode:ident, $data:expr) => {{
        use fastcrypto::bls12381::$mode::{
            BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
            BLS12381PrivateKey, BLS12381PublicKey, BLS12381PublicKeyAsBytes, BLS12381Signature,
        };
        let data: &[u8] = $data;

        // Public keys.
        let pk = BLS12381PublicKey::from_bytes(data);
        if let Ok(pk) = &pk {
            let canonical = if data.len() == <BLS12381PublicKey as VerifyingKey>::LENGTH {
                pk.as_bytes().to_vec()
            } else {
                pk.pubkey.serialize().to_vec()
            };
            assert_eq!(
                canonical, data,
                "non-canonical public key encoding accepted"
            );
            let canonical = BLS12381PublicKey::from_bytes(pk.as_bytes()).unwrap();
            assert_eq!(&canonical, pk);
            assert_eq!(hash_of(&canonical), hash_of(pk));
            assert_eq!(canonical.cmp(pk), std::cmp::Ordering::Equal);
            let _ = pk.validate();
        }
        let bcs_pk = bcs::from_bytes::<BLS12381PublicKey>(data);
        assert_eq!(
            bcs_pk.is_ok(),
            pk.is_ok() && data.len() == <BLS12381PublicKey as VerifyingKey>::LENGTH
        );
        let _ = bincode::deserialize::<BLS12381PublicKey>(data);
        let pk_bytes = bcs::from_bytes::<BLS12381PublicKeyAsBytes>(data);
        assert_eq!(
            pk_bytes.is_ok(),
            data.len() == <BLS12381PublicKey as VerifyingKey>::LENGTH
        );
        if let Ok(pk_bytes) = &pk_bytes {
            assert_eq!(BLS12381PublicKey::try_from(pk_bytes).ok(), bcs_pk.ok());
        }

        // Signatures and aggregate signatures.
        let sig = <BLS12381Signature as ToFromBytes>::from_bytes(data);
        let aggregate = BLS12381AggregateSignature::from_bytes(data);
        assert_eq!(sig.is_ok(), aggregate.is_ok());
        if let (Ok(sig), Ok(aggregate)) = (&sig, &aggregate) {
            let canonical = if data.len() == <BLS12381Signature as Authenticator>::LENGTH {
                sig.as_bytes().to_vec()
            } else {
                sig.sig.serialize().to_vec()
            };
            assert_eq!(canonical, data, "non-canonical signature encoding accepted");
            assert_eq!(aggregate.as_bytes(), sig.as_bytes());
            let canonical = <BLS12381Signature as ToFromBytes>::from_bytes(sig.as_bytes()).unwrap();
            assert_eq!(&canonical, sig);
            assert_eq!(hash_of(&canonical), hash_of(sig));
        }
        let bcs_sig = bcs::from_bytes::<BLS12381Signature>(data);
        assert_eq!(
            bcs_sig.is_ok(),
            sig.is_ok() && data.len() == <BLS12381Signature as Authenticator>::LENGTH
        );
        let bcs_aggregate = bcs::from_bytes::<BLS12381AggregateSignature>(data);
        let aggregate_bytes = bcs::from_bytes::<BLS12381AggregateSignatureAsBytes>(data);
        assert_eq!(
            aggregate_bytes.is_ok(),
            data.len() == <BLS12381Signature as Authenticator>::LENGTH
        );
        if let Ok(aggregate_bytes) = &aggregate_bytes {
            assert_eq!(
                BLS12381AggregateSignature::try_from(aggregate_bytes).ok(),
                bcs_aggregate.ok()
            );
        }
        let _ = bincode::deserialize::<BLS12381Signature>(data);

        // Private keys and key pairs.
        if let Ok(sk) = BLS12381PrivateKey::from_bytes(data) {
            assert_eq!(sk.as_bytes(), data);
            assert_eq!(data.len(), <BLS12381PrivateKey as SigningKey>::LENGTH);
        }
        let _ = BLS12381KeyPair::from_bytes(data);
        let _ = bcs::from_bytes::<BLS12381KeyPair>(data);

        // Human-readable serde goes through base64 and from_bytes.
        let json = format!("\"{}\"", Base64::encode(data));
        assert_eq!(
            serde_json::from_str::<BLS12381PublicKey>(&json).ok(),
            pk.ok()
        );
        assert_eq!(
            serde_json::from_str::<BLS12381Signature>(&json).ok(),
            sig.ok()
        );
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = serde_json::from_str::<BLS12381PublicKey>(s);
            let _ = serde_json::from_str::<BLS12381AggregateSignature>(s);
        }
    }};
}

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fuzz_target!(|data: &[u8]| {
    check_mode!(min_sig, data);
    check_mode!(min_pk, data);
});
