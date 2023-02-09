// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::Digest;
use crate::traits;
use crate::traits::Signer;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;

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
        S: Signer<Signature> + Send + 'static,
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
