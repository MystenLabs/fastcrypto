// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verifies arbitrary (public key, signature, message) triples in both BLS12-381 modes, the way
//! Sui's `bls12381_min_sig_verify` / `bls12381_min_pk_verify` Move natives do (`from_bytes` for
//! both, `validate` on the public key, then `verify`).
//!
//! Invariants: nothing panics, and because BLS signatures are unique, the only signature that
//! verifies under a fixed honest key is the honest signature (and its aggregate form).

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::traits::{AggregateAuthenticator, KeyPair, Signer, ToFromBytes, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Arbitrary, Debug)]
struct Input {
    pk: Vec<u8>,
    sig: Vec<u8>,
    msg: Vec<u8>,
}

macro_rules! check_mode {
    ($mode:ident, $input:expr) => {{
        use fastcrypto::bls12381::$mode::{
            BLS12381AggregateSignature, BLS12381KeyPair, BLS12381PublicKey, BLS12381Signature,
        };
        use once_cell::sync::Lazy;
        static KEY: Lazy<BLS12381KeyPair> =
            Lazy::new(|| BLS12381KeyPair::generate(&mut StdRng::from_seed([1; 32])));
        let input: &Input = $input;

        // What the Move native does.
        let native = <BLS12381Signature as ToFromBytes>::from_bytes(&input.sig)
            .ok()
            .and_then(|sig| {
                let pk = BLS12381PublicKey::from_bytes(&input.pk).ok()?;
                pk.validate().ok()?;
                Some(pk.verify(&input.msg, &sig).is_ok())
            })
            .unwrap_or(false);
        if native && input.pk.as_slice() == KEY.public().as_ref() {
            assert_eq!(
                <BLS12381Signature as ToFromBytes>::from_bytes(&input.sig).unwrap(),
                KEY.sign(&input.msg)
            );
        }

        // Arbitrary signatures against the fixed honest key.
        if let Ok(sig) = <BLS12381Signature as ToFromBytes>::from_bytes(&input.sig) {
            let honest = KEY.sign(&input.msg);
            if KEY.public().verify(&input.msg, &sig).is_ok() {
                assert_eq!(sig, honest, "a second valid signature exists");
            }
            let aggregate = BLS12381AggregateSignature::from(sig.clone());
            if aggregate
                .verify(std::slice::from_ref(KEY.public()), &input.msg)
                .is_ok()
            {
                assert_eq!(sig, honest, "a second valid aggregate signature exists");
            }
        }

        // No other public key accepts the fixed key's signature.
        if let Ok(pk) = BLS12381PublicKey::from_bytes(&input.pk) {
            if &pk != KEY.public() {
                assert!(pk.verify(&input.msg, &KEY.sign(&input.msg)).is_err());
            }
        }
    }};
}

fuzz_target!(|input: Input| {
    check_mode!(min_sig, &input);
    check_mode!(min_pk, &input);
});
