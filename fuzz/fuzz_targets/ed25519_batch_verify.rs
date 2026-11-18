// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Batch-verifies 1 to 6 attacker-chosen (public key, signature, message) items, biased towards the
//! ZIP215 edge cases, with every batch API: `verify_batch_empty_fail(_different_msg)` and
//! `Ed25519AggregateSignature`'s `verify`, `verify_different_msg` and `batch_verify`.
//!
//! Invariants: nothing panics, and every batch API accepts iff each item verifies on its own (up to
//! the 2^-128 soundness error of the random linear combination). This is ZIP215's main property.

#![no_main]

#[path = "ed25519_common.rs"]
mod ed25519_common;

use arbitrary::Arbitrary;
use ed25519_common::{reference_verify, verify_bytes, Key, Sig};
use fastcrypto::ed25519::{Ed25519AggregateSignature, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::traits::{AggregateAuthenticator, ToFromBytes, VerifyingKey};
use libfuzzer_sys::fuzz_target;

const MAX_ITEMS: usize = 6;

#[derive(Arbitrary, Debug)]
struct Item {
    key: Key,
    sig: Sig,
    /// The item's own message, or the shared one.
    msg: Option<Vec<u8>>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    items: Vec<Item>,
    shared_msg: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if input.items.is_empty() || input.items.len() > MAX_ITEMS {
        return;
    }
    let mut pks = vec![];
    let mut sigs = vec![];
    let mut msgs: Vec<&[u8]> = vec![];
    let mut individual = true;
    for item in &input.items {
        let msg = item.msg.as_deref().unwrap_or(&input.shared_msg);
        let pk = item.key.bytes();
        let sig = item.sig.bytes(&item.key, msg);
        let verified = verify_bytes(&pk, &sig, msg);
        assert_eq!(verified, reference_verify(&pk, &sig, msg));
        individual &= verified;
        match (
            Ed25519PublicKey::from_bytes(&pk),
            <Ed25519Signature as ToFromBytes>::from_bytes(&sig),
        ) {
            (Ok(pk), Ok(sig)) => {
                pks.push(pk);
                sigs.push(sig);
                msgs.push(msg);
            }
            // An item that does not decode can't be put in a batch.
            _ => return,
        }
    }

    assert_eq!(
        Ed25519PublicKey::verify_batch_empty_fail_different_msg(&msgs, &pks, &sigs).is_ok(),
        individual
    );
    let aggregate = Ed25519AggregateSignature::aggregate(&sigs).unwrap();
    assert_eq!(
        aggregate.verify_different_msg(&pks, &msgs).is_ok(),
        individual
    );
    let singles: Vec<Ed25519AggregateSignature> = sigs
        .iter()
        .map(|sig| Ed25519AggregateSignature::aggregate(std::slice::from_ref(sig)).unwrap())
        .collect();
    assert_eq!(
        Ed25519AggregateSignature::batch_verify(
            &singles.iter().collect::<Vec<_>>(),
            pks.iter()
                .map(|pk| std::slice::from_ref(pk).iter())
                .collect(),
            &msgs
        )
        .is_ok(),
        individual
    );
    if msgs.iter().all(|msg| *msg == msgs[0]) {
        assert_eq!(
            Ed25519PublicKey::verify_batch_empty_fail(msgs[0], &pks, &sigs).is_ok(),
            individual
        );
        assert_eq!(aggregate.verify(&pks, msgs[0]).is_ok(), individual);
        assert_eq!(
            Ed25519AggregateSignature::batch_verify(&[&aggregate], vec![pks.iter()], &[msgs[0]])
                .is_ok(),
            individual
        );
    }
});
