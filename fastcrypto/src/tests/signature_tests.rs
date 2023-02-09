// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use rand::{rngs::StdRng, SeedableRng};

use crate::traits::Signer;
use crate::{
    hash::{HashFunction, Sha256},
    traits::KeyPair,
};

/// Generate `n` random key pairs.
pub fn keys<KP: KeyPair>(n: usize) -> Vec<KP> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..n).map(|_| KeyPair::generate(&mut rng)).collect()
}

pub struct DifferentMsgsSignatures<KP: KeyPair> {
    pub digests: Vec<Vec<u8>>,
    pub pubkeys: Vec<KP::PubKey>,
    pub signatures: Vec<KP::Sig>,
}

/// Generate a tuple of vectors containing messages, public keys and the corresponding signatures to be used in tests.
pub fn signature_test_inputs_different_msg<KP: KeyPair>() -> DifferentMsgsSignatures<KP> {
    // Make signatures.
    let digests: Vec<Vec<u8>> = [b"Hello", b"world", b"!!!!!"]
        .iter()
        .map(|msg| Sha256::digest(*msg).to_vec())
        .collect();
    let (pubkeys, signatures): (Vec<_>, Vec<_>) = keys::<KP>(3)
        .into_iter()
        .take(3)
        .zip(&digests)
        .map(|(kp, digest)| {
            let sig = kp.sign(digest.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();
    DifferentMsgsSignatures {
        digests,
        pubkeys,
        signatures,
    }
}
