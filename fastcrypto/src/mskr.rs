// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12377::{
    BLS12377KeyPair, BLS12377PrivateKey, BLS12377PublicKey, CELO_BLS_PUBLIC_KEY_LENGTH,
};
use crate::error::FastCryptoError;
use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::traits::{KeyPair, ToFromBytes};
use ark_bls12_377::{Fr, G2Projective};
use ark_ec::group::Group;
use celo_bls::{PrivateKey, PublicKey};
use once_cell::sync::OnceCell;
use rand::thread_rng;
use signature::Signer;
use std::ops::Mul;

pub trait Randomize<PubKey> {
    fn randomize(&self, pks: &[PubKey]) -> Self;
}

pub trait MSKRVerifier<KP: KeyPair> {
    fn verify(
        &self,
        msg: &[u8],
        pks: &[KP::PubKey],
        signature: &MSKRSignature<KP>,
    ) -> Result<(), FastCryptoError>;
}

pub trait MSKRSigner<KP: KeyPair> {
    fn sign(&self, msg: &[u8], pks: &[KP::PubKey]) -> MSKRSignature<KP>;
}

impl<KP: KeyPair> MSKRVerifier<KP> for KP::PubKey
where
    KP::PubKey: Randomize<KP::PubKey>,
{
    fn verify(
        &self,
        msg: &[u8],
        pks: &[KP::PubKey],
        signature: &MSKRSignature<KP>,
    ) -> Result<(), FastCryptoError> {
        let randomized_pk = self.randomize(pks);
        return signature::Verifier::verify(&randomized_pk, msg, &signature.0)
            .map_err(|_| FastCryptoError::GeneralError);
    }
}

impl<KP: KeyPair + Randomize<KP::PubKey>> MSKRSigner<KP> for KP {
    fn sign(&self, msg: &[u8], pks: &[KP::PubKey]) -> MSKRSignature<KP> {
        let randomized_kp = self.randomize(pks);
        return MSKRSignature(randomized_kp.sign(msg));
    }
}

pub struct MSKRSignature<KP: KeyPair>(KP::Sig);


// Implement randomization for BLS12377

fn randomization_scalar(pk: &BLS12377PublicKey, pks: &[BLS12377PublicKey]) -> Fr {
    let mut seed: Vec<u8> = Vec::with_capacity(CELO_BLS_PUBLIC_KEY_LENGTH * (pks.len() + 1));
    seed.extend_from_slice(pk.as_bytes());
    for pki in pks {
        seed.extend_from_slice(&pki.as_bytes());
    }
    hash_to_scalar(seed.as_slice())
}

impl Randomize<BLS12377PublicKey> for BLS12377PublicKey {
    /// Randomize the public key using the input list of public keys.
    fn randomize(&self, pks: &[BLS12377PublicKey]) -> BLS12377PublicKey {
        let pt: &G2Projective = self.pubkey.as_ref();
        let r = randomization_scalar(self, pks);
        let q = pt.mul(&r);
        BLS12377PublicKey {
            pubkey: PublicKey::from(q),
            bytes: OnceCell::new(),
        }
    }
}
impl Randomize<BLS12377PublicKey> for BLS12377KeyPair {
    /// Randomize the secret key using the input list of public keys.
    fn randomize(&self, pks: &[BLS12377PublicKey]) -> BLS12377KeyPair {
        // Randomize public key
        let pt: &G2Projective = self.public().pubkey.as_ref();
        let r = randomization_scalar(self.public(), pks);
        let q = pt.mul(&r);
        let randomized_pk = BLS12377PublicKey {
            pubkey: PublicKey::from(q),
            bytes: OnceCell::new(),
        };

        // Randomize secret key
        let sk = self.private().privkey.as_ref().mul(r);
        let randomized_sk = BLS12377PrivateKey::from(PrivateKey::from(sk));
        BLS12377KeyPair {
            name: randomized_pk,
            secret: randomized_sk,
        }
    }
}

fn hash_to_scalar(bytes: &[u8]) -> Fr {
    let digest = Sha256::digest(bytes);
    let b: [u8; 16] = digest.digest[0..16].try_into().unwrap();
    Fr::from(i128::from_be_bytes(b))
}

#[test]
fn verify_randomized_signature() {
    let kp = BLS12377KeyPair::generate(&mut thread_rng());

    let pks = (0..4)
        .map(|_| {
            let kp = BLS12377KeyPair::generate(&mut thread_rng());
            kp.public().clone()
        })
        .collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sig = MSKRSigner::sign(&kp, msg, &pks);

    assert!(MSKRVerifier::verify(kp.public(), msg, &pks, &sig).is_ok());
}
