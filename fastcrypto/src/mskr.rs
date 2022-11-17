// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12377::{
    BLS12377AggregateSignature, BLS12377KeyPair, BLS12377PrivateKey, BLS12377PublicKey,
    BLS12377Signature, CELO_BLS_PUBLIC_KEY_LENGTH,
};
use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::traits::{AggregateAuthenticator, KeyPair, ToFromBytes};
use ark_bls12_377::{Fr, G1Projective, G2Projective};
use ark_ec::group::Group;
use celo_bls::{PrivateKey, PublicKey};
use once_cell::sync::OnceCell;
use rand::thread_rng;
use signature::{Signer, Verifier};
use std::ops::Mul;

/// Trait impl'd by keys and signatures for signature schemes supporting the MSKR (Multi-Signature with Key Randomization) scheme.
pub trait Randomize<PubKey> {
    fn randomize(&self, pk: &PubKey, pks: &[PubKey]) -> Self;
}

pub trait HashToScalar<Scalar> {
    fn hash_to_scalar(bytes: &[u8]) -> Scalar;
}

//
// Implement MSKR for BLS12377
//

struct BLS12377Hash {}

impl HashToScalar<Fr> for BLS12377Hash {
    fn hash_to_scalar(bytes: &[u8]) -> Fr {
        let digest = Sha256::digest(bytes);
        let b: [u8; 16] = digest.digest[0..16].try_into().unwrap();
        Fr::from(i128::from_be_bytes(b))
    }
}

fn randomization_scalar<
    PubKey: ToFromBytes,
    Scalar,
    H: HashToScalar<Scalar>,
    const PUBLIC_KEY_LENGTH: usize,
>(
    pk: &PubKey,
    pks: &[PubKey],
) -> Scalar {
    let mut seed: Vec<u8> = Vec::with_capacity(PUBLIC_KEY_LENGTH * (pks.len() + 1));
    seed.extend_from_slice(pk.as_bytes());
    for pki in pks {
        seed.extend_from_slice(&pki.as_bytes());
    }
    H::hash_to_scalar(seed.as_slice())
}

impl Randomize<BLS12377PublicKey> for BLS12377PublicKey {
    /// Randomize the public key using the input list of public keys.
    fn randomize(&self, pk: &BLS12377PublicKey, pks: &[BLS12377PublicKey]) -> BLS12377PublicKey {
        let pt: &G2Projective = self.pubkey.as_ref();
        let r = randomization_scalar::<
            BLS12377PublicKey,
            Fr,
            BLS12377Hash,
            CELO_BLS_PUBLIC_KEY_LENGTH,
        >(pk, pks);
        let q = pt.mul(&r);
        BLS12377PublicKey {
            pubkey: PublicKey::from(q),
            bytes: OnceCell::new(),
        }
    }
}

impl Randomize<BLS12377PublicKey> for BLS12377PrivateKey {
    /// Randomize the secret key using the input list of public keys.
    fn randomize(&self, pk: &BLS12377PublicKey, pks: &[BLS12377PublicKey]) -> BLS12377PrivateKey {
        // Randomize secret key
        let r = randomization_scalar::<
            BLS12377PublicKey,
            Fr,
            BLS12377Hash,
            CELO_BLS_PUBLIC_KEY_LENGTH,
        >(pk, pks);
        let sk = self.privkey.as_ref().mul(r);
        BLS12377PrivateKey::from(PrivateKey::from(sk))
    }
}

impl Randomize<BLS12377PublicKey> for BLS12377KeyPair {
    /// Randomize a key pair using the input list of public keys.
    fn randomize(&self, pk: &BLS12377PublicKey, pks: &[BLS12377PublicKey]) -> BLS12377KeyPair {
        //TODO: Scalar computed twice
        BLS12377KeyPair {
            secret: self.secret.randomize(pk, pks),
            name: self.name.randomize(pk, pks),
        }
    }
}

impl Randomize<BLS12377PublicKey> for BLS12377Signature {
    /// Randomize a signature using the input list of public keys.
    fn randomize(&self, pk: &BLS12377PublicKey, pks: &[BLS12377PublicKey]) -> BLS12377Signature {
        let pt: &G1Projective = self.sig.as_ref();
        let r = randomization_scalar::<
            BLS12377PublicKey,
            Fr,
            BLS12377Hash,
            CELO_BLS_PUBLIC_KEY_LENGTH,
        >(pk, pks);
        let q = pt.mul(&r);
        BLS12377Signature::from(celo_bls::Signature::from(q))
    }
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

    let msg = b"Hello world";

    let randomized_kp = kp.randomize(kp.public(), &pks);
    let sig = kp.sign(msg);

    assert!(randomized_kp.public().verify(msg, &sig).is_err());
    assert!(randomized_kp
        .public()
        .verify(msg, &sig.randomize(kp.public(), &pks))
        .is_ok());

    let randomized_sig = randomized_kp.sign(msg);
    assert!(randomized_kp.public().verify(msg, &randomized_sig).is_ok());
}

#[test]
fn verify_aggregate_all() {
    let kps = (0..4)
        .map(|_| BLS12377KeyPair::generate(&mut thread_rng()))
        .collect::<Vec<_>>();

    let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sigs = kps
        .iter()
        .map(|kp| kp.randomize(kp.public(), &pks).sign(msg))
        .collect::<Vec<_>>();

    let randomized_pks = pks
        .iter()
        .map(|pk| pk.randomize(&pk, &pks))
        .collect::<Vec<_>>();

    let aggregate_sig = BLS12377AggregateSignature::aggregate(&sigs).unwrap();

    assert!(aggregate_sig.verify(&randomized_pks, msg).is_ok())
}

#[test]
fn verify_aggregate_subset() {
    let kps = (0..4)
        .map(|_| BLS12377KeyPair::generate(&mut thread_rng()))
        .collect::<Vec<_>>();

    let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sigs = kps
        .iter()
        .skip(1)
        .map(|kp| kp.randomize(kp.public(), &pks).sign(msg))
        .collect::<Vec<_>>();

    let randomized_pks = pks
        .iter()
        .skip(1)
        .map(|pk| pk.randomize(&pk, &pks))
        .collect::<Vec<_>>();
    let aggregate_sig = BLS12377AggregateSignature::aggregate(&sigs).unwrap();

    assert!(aggregate_sig.verify(&randomized_pks, msg).is_ok())
}
