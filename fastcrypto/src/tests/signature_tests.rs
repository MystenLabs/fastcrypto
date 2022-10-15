// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use rand::{rngs::StdRng, SeedableRng};

use crate::{
    hash::{HashFunction, Sha256},
    traits::KeyPair,
};

pub fn keys<KP: KeyPair>(n: usize) -> Vec<KP> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..n).map(|_| KeyPair::generate(&mut rng)).collect()
}

pub fn signature_test_inputs_different_msg<KP: KeyPair>(
) -> (Vec<Vec<u8>>, Vec<KP::PubKey>, Vec<KP::Sig>) {
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
    (digests, pubkeys, signatures)
}
