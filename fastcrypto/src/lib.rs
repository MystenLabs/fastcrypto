// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

use hash::Digest;
use rand::thread_rng;

pub use signature::{Signature as _, Verifier};
use tokio::sync::{
    mpsc::{channel, Sender},
    oneshot,
};

#[cfg(test)]
#[path = "tests/signature_tests.rs"]
pub mod signature_tests;

#[cfg(test)]
#[path = "tests/pubkey_bytes_tests.rs"]
pub mod pubkey_bytes_tests;

#[cfg(test)]
#[path = "tests/ed25519_tests.rs"]
pub mod ed25519_tests;

#[cfg(test)]
#[path = "tests/secp256k1_tests.rs"]
pub mod secp256k1_tests;

#[cfg(test)]
#[path = "tests/bls12381_tests.rs"]
pub mod bls12381_tests;

#[cfg(test)]
#[path = "tests/bulletproofs_tests.rs"]
pub mod bulletproofs_tests;

#[cfg(test)]
#[path = "tests/aes_tests.rs"]
pub mod aes_tests;

#[cfg(test)]
#[path = "tests/hash_tests.rs"]
pub mod hash_tests;

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
pub mod hmac_tests;

#[cfg(test)]
#[path = "tests/encoding_tests.rs"]
pub mod encoding_tests;

#[cfg(feature = "experimental")]
#[cfg(test)]
#[path = "tests/mskr_tests.rs"]
pub mod mskr_tests;

#[cfg(test)]
#[path = "tests/ristretto255_tests.rs"]
pub mod ristretto255_tests;
// Signing traits
pub mod traits;
// Key scheme implementations
pub mod aes;
pub mod bls12381;
pub mod bulletproofs;
pub mod ed25519;
pub mod groups;
pub mod hash;
pub mod hmac;
pub mod secp256k1;

// Other tooling
pub mod encoding;
pub mod error;
pub mod private_seed;
pub mod pubkey_bytes;
pub mod serde_helpers;

/// This module contains unsecure cryptographic primitives. The purpose of this library is to allow seamless
/// benchmarking of systems without taking into account the cost of cryptographic primitives - and hence
/// providing a theoretical maximal throughput that a system could achieve if the cost of crypto is optimized
/// away.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
#[cfg(all(
    feature = "unsecure_schemes",
    not(feature = "secure"),
    debug_assertions
))]
pub mod unsecure;

////////////////////////////////////////////////////////////////
// Generic Keypair
////////////////////////////////////////////////////////////////

pub fn generate_production_keypair<K: traits::KeyPair>() -> K {
    generate_keypair::<K, _>(&mut thread_rng())
}

pub fn generate_keypair<K: traits::KeyPair, R>(csprng: &mut R) -> K
where
    R: traits::AllowedRng,
{
    K::generate(csprng)
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a one-shot channel).
#[derive(Clone)]
pub struct SignatureService<Signature: traits::Authenticator, const DIGEST_LEN: usize> {
    channel: Sender<(Digest<DIGEST_LEN>, oneshot::Sender<Signature>)>,
}

impl<Signature: traits::Authenticator, const DIGEST_LEN: usize>
    SignatureService<Signature, DIGEST_LEN>
{
    pub fn new<S>(signer: S) -> Self
    where
        S: signature::Signer<Signature> + Send + 'static,
    {
        let (tx, mut rx): (Sender<(Digest<DIGEST_LEN>, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = signer.sign(digest.as_ref());
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&self, digest: Digest<DIGEST_LEN>) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {e}");
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}
