// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::min_sig::BLS12381KeyPair;
use crate::hash::{HashFunction, Sha256};
use crate::signature_service::SignatureService;
use crate::traits::{KeyPair, VerifyingKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[tokio::test]
async fn signature_service() {
    let mut rng = StdRng::from_seed([0; 32]);
    let kp = BLS12381KeyPair::generate(&mut rng);
    let pk = kp.public().clone();

    // Spawn the signature service.
    let service = SignatureService::new(kp);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let signature = service.request_signature(digest).await;

    // Verify the signature we received.
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
}
