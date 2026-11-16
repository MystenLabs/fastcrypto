// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Builds batches of aggregate signatures the way Sui verifies certificates (start from the
//! default aggregate, add signatures or aggregates, then `batch_verify` against a fixed committee
//! of validated keys), mixing honest signatures with attacker-chosen bytes.
//!
//! Invariants: nothing panics, `batch_verify` accepts exactly when every entry verifies on its own
//! (up to its 2^-96 soundness error), and an accepted entry equals the honest aggregate, since the
//! valid aggregate signature for a given set of keys and message is unique.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::traits::{AggregateAuthenticator, KeyPair, Signer, ToFromBytes};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const COMMITTEE_SIZE: usize = 4;
const MAX_ENTRIES: usize = 4;
const MAX_SIGNERS: usize = 4;

#[derive(Arbitrary, Debug)]
enum Part {
    /// The honest signature of the signer.
    Honest,
    /// The signer's signature on another message.
    WrongMessage(Vec<u8>),
    /// Attacker-chosen signature bytes, added with `add_signature`.
    Signature(Vec<u8>),
    /// Attacker-chosen aggregate bytes, added with `add_aggregate`.
    Aggregate(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Entry {
    msg: Vec<u8>,
    /// Committee indices of the claimed signers, and what each one contributes.
    signers: Vec<(u8, Part)>,
}

macro_rules! check_mode {
    ($mode:ident, $entries:expr) => {{
        use fastcrypto::bls12381::$mode::{
            BLS12381AggregateSignature, BLS12381KeyPair, BLS12381PublicKey, BLS12381Signature,
        };
        use once_cell::sync::Lazy;
        static COMMITTEE: Lazy<Vec<BLS12381KeyPair>> = Lazy::new(|| {
            let mut rng = StdRng::from_seed([2; 32]);
            (0..COMMITTEE_SIZE)
                .map(|_| BLS12381KeyPair::generate(&mut rng))
                .collect()
        });
        let entries: &[Entry] = $entries;

        let mut aggregates = Vec::new();
        let mut key_groups: Vec<Vec<&BLS12381PublicKey>> = Vec::new();
        let mut honest_aggregates = Vec::new();
        for entry in entries {
            let mut aggregate = BLS12381AggregateSignature::default();
            let mut keys = Vec::new();
            let mut honest = Vec::new();
            for (index, part) in entry.signers.iter().take(MAX_SIGNERS) {
                let kp = &COMMITTEE[*index as usize % COMMITTEE_SIZE];
                keys.push(kp.public());
                honest.push(kp.sign(&entry.msg));
                let added = match part {
                    Part::Honest => aggregate.add_signature(kp.sign(&entry.msg)),
                    Part::WrongMessage(other) => aggregate.add_signature(kp.sign(other)),
                    Part::Signature(bytes) => {
                        match <BLS12381Signature as ToFromBytes>::from_bytes(bytes) {
                            Ok(sig) => aggregate.add_signature(sig),
                            Err(_) => continue,
                        }
                    }
                    Part::Aggregate(bytes) => match BLS12381AggregateSignature::from_bytes(bytes) {
                        Ok(sig) => aggregate.add_aggregate(sig),
                        Err(_) => continue,
                    },
                };
                // Adding a decoded point never fails.
                added.unwrap();
            }
            if keys.is_empty() {
                continue;
            }
            honest_aggregates.push(BLS12381AggregateSignature::aggregate(&honest).unwrap());
            aggregates.push(aggregate);
            key_groups.push(keys);
        }

        let messages: Vec<&[u8]> = entries
            .iter()
            .filter(|e| !e.signers.is_empty())
            .map(|e| e.msg.as_slice())
            .collect();
        let individually: Vec<bool> = aggregates
            .iter()
            .zip(&key_groups)
            .zip(&messages)
            .map(|((aggregate, keys), msg)| {
                let keys: Vec<BLS12381PublicKey> = keys.iter().map(|k| (*k).clone()).collect();
                aggregate.verify(&keys, msg).is_ok()
            })
            .collect();
        for ((ok, aggregate), honest) in
            individually.iter().zip(&aggregates).zip(&honest_aggregates)
        {
            if *ok {
                assert_eq!(
                    aggregate, honest,
                    "a second valid aggregate signature exists"
                );
            }
        }

        let batched = BLS12381AggregateSignature::batch_verify(
            &aggregates.iter().collect::<Vec<_>>(),
            key_groups.iter().map(|keys| keys.iter().copied()).collect(),
            &messages,
        );
        assert_eq!(batched.is_ok(), individually.iter().all(|ok| *ok));
    }};
}

fuzz_target!(|entries: Vec<Entry>| {
    let entries = &entries[..entries.len().min(MAX_ENTRIES)];
    check_mode!(min_sig, entries);
    check_mode!(min_pk, entries);
});
