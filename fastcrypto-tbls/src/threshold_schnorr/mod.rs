// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module implements threshold Schnorr signatures.
//! The signatures are compatible with BIP-0340.
//!
//! It provides the following protocols:
//!
//! 1. A Distributed Key Generation (DKG) protocol to generate a shared signing key without a trusted dealer. The protocol also allows resharing of a share from a previous DKG, allowing for key rotation. This is implemented in the [avss] module.
//! 2. A protocol to generate a batch of secret shared nonces for signing. This is implemented in the [batch_avss] module.
//! 3. A presigning protocol to create presigning tuples from the secret shared nonces. This is implemented in the [presigning] module. The presigning tuples can be created in advance of knowing the message to be signed, and one tuple is consumed for each signature.
//! 4. A signing protocol which allows parties to create partial signatures from a presigning tuple and aggregate them into a full signature if there are enough partial signatures. This is implemented in the [signing] module.
//!
//! For both the DKG and nonce generation protocols, it is assumed that each party has an encryption key pair (ECIES) and these public keys are known to all parties. These can be reused for all instances of the protocols.
//!
//! The thresholds are defined as follows:
//! * <i>n</i> = total number of parties
//! * <i>f</i> = maximum number of Byzantine parties
//! * <i>t</i> = threshold for signing
//!
//! The following conditions must hold: <i>t + 2f &leq; n</i> and <i>t > f</i>.

use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::Extensions::{Challenge, Encryption, Recovery};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::GroupElement;
use std::fmt::{Display, Formatter};

pub mod avss;
pub mod batch_avss;
mod bcs;
pub mod complaint;
mod key_derivation;
mod pascal_matrix;
pub mod presigning;
pub mod signing;

/// The group to use for the signing
pub type G = groups::secp256k1::ProjectivePoint;

/// Default scalar
pub type S = <G as GroupElement>::ScalarType;

/// The group used for multi-recipient encryption. Any group that has a secure hash-to-group can be used here.
type EG = RistrettoPoint;

/// Helper function to create a random oracle from a session ID.
fn random_oracle_from_sid(sid: &[u8]) -> RandomOracle {
    RandomOracle::new(&Hex::encode(sid))
}

/// Domain-specific extensions/tags for the random oracle for this module.
enum Extensions {
    Recovery(PartyId),
    Encryption,
    Challenge,
}

impl Display for Extensions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let result = match self {
            Recovery(accuser) => format!("recovery of {accuser}"),
            Encryption => "encryption".to_string(),
            Challenge => "challenge".to_string(),
        };
        write!(f, "{result}")
    }
}

#[cfg(test)]
mod tests {
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::batch_avss::{ReceiverOutput, ShareBatch, SharesForNode};
    use crate::threshold_schnorr::key_derivation::derive_verifying_key;
    use crate::threshold_schnorr::presigning::Presignatures;
    use crate::threshold_schnorr::signing::{aggregate_signatures, generate_partial_signatures};
    use crate::threshold_schnorr::{avss, G, S};
    use crate::types::ShareIndex;
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::array;

    #[test]
    fn test_signing() {
        let f = 2;
        let t = f + 1;
        let n = 3 * f + 1;

        let mut rng = rand::thread_rng();

        // Mock DKG
        // Here, we don't assume anything about the partity of the vk's Y coordinate since we can't do that in a real DKG.
        let sk_element = S::rand(&mut rng);
        let vk_element = G::generator() * sk_element;

        let sk_shares = mock_shares(&mut rng, sk_element, t, n);

        // Mock nonce generation
        const BATCH_SIZE: usize = 10;
        let nonces_for_dealer = (0..n)
            .map(|_| {
                let nonces: [S; BATCH_SIZE] = array::from_fn(|_| S::rand(&mut rng));
                let public_keys = nonces.map(|s| G::generator() * s);
                let nonce_shares: [Vec<S>; BATCH_SIZE] = nonces.map(|nonce| {
                    mock_shares(&mut rng, nonce, t, n)
                        .iter()
                        .map(|s| s.value)
                        .collect_vec()
                });
                (nonces, public_keys, nonce_shares)
            })
            .collect_vec();

        let outputs = (0..n)
            .map(|i| {
                let index = ShareIndex::new(i + 1).unwrap();
                (0..n)
                    .map(|j| {
                        ReceiverOutput {
                            my_shares: SharesForNode {
                                batches: vec![ShareBatch {
                                    index,
                                    shares: array::from_fn(|l| {
                                        nonces_for_dealer[j as usize].2[l][i as usize]
                                    }),
                                    blinding_share: Default::default(), // Not used for this test
                                }],
                            },
                            public_keys: nonces_for_dealer[j as usize].1,
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let mut presigning = outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                Presignatures::new(
                    &[ShareIndex::new((i + 1) as u16).unwrap()],
                    output,
                    f as usize,
                )
                .unwrap()
            })
            .collect_vec();

        let message = b"Hello, world!";

        let beacon_value = S::rand(&mut rng);

        let partial_signatures = presigning
            .iter_mut()
            .enumerate()
            .map(|(i, presigning)| {
                let my_shares = avss::SharesForNode {
                    shares: vec![sk_shares[i].clone()],
                };
                generate_partial_signatures(
                    message,
                    presigning,
                    &my_shares,
                    &vk_element,
                    &beacon_value,
                    None,
                )
                .unwrap()
            })
            .collect_vec();

        assert!(partial_signatures
            .iter()
            .map(|partial_signature| partial_signature.0)
            .all_equal());
        let public = partial_signatures[0].0;

        let signature = aggregate_signatures(
            message,
            &public,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
            &beacon_value,
            t,
            &vk_element,
            None,
        )
        .unwrap();

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&vk_element)
            .unwrap()
            .verify(message, &signature)
            .unwrap();
    }

    fn mock_shares(rng: &mut impl AllowedRng, secret: S, t: u16, n: u16) -> Vec<Eval<S>> {
        let p = Poly::rand_fixed_c0(t - 1, secret, rng);
        (1..=n)
            .map(|i| p.eval(ShareIndex::new(i).unwrap()))
            .collect_vec()
    }

    #[test]
    fn test_derived_signing() {
        let f = 2;
        let t = f + 1;
        let n = 3 * f + 1;

        let mut rng = rand::thread_rng();

        // Mock DKG
        // Here, we don't assume anything about the partity of the vk's Y coordinate since we can't do that in a real DKG.
        let sk_element = S::rand(&mut rng);
        let vk_element = G::generator() * sk_element;

        let sk_shares = mock_shares(&mut rng, sk_element, t, n);

        // Mock nonce generation
        const BATCH_SIZE: usize = 10;
        let nonces_for_dealer = (0..n)
            .map(|_| {
                let nonces: [S; BATCH_SIZE] = array::from_fn(|_| S::rand(&mut rng));
                let public_keys = nonces.map(|s| G::generator() * s);
                let nonce_shares: [Vec<S>; BATCH_SIZE] = nonces.map(|nonce| {
                    mock_shares(&mut rng, nonce, t, n)
                        .iter()
                        .map(|s| s.value)
                        .collect_vec()
                });
                (nonces, public_keys, nonce_shares)
            })
            .collect_vec();

        let outputs = (0..n)
            .map(|i| {
                let index = ShareIndex::new(i + 1).unwrap();
                (0..n)
                    .map(|j| {
                        ReceiverOutput {
                            my_shares: SharesForNode {
                                batches: vec![ShareBatch {
                                    index,
                                    shares: array::from_fn(|l| {
                                        nonces_for_dealer[j as usize].2[l][i as usize]
                                    }),
                                    blinding_share: Default::default(), // Not used for this test
                                }],
                            },
                            public_keys: nonces_for_dealer[j as usize].1,
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let mut presigning = outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                Presignatures::new(
                    &[ShareIndex::new((i + 1) as u16).unwrap()],
                    output,
                    f as usize,
                )
                .unwrap()
            })
            .collect_vec();

        let message = b"Hello, world!";

        let beacon_value = S::rand(&mut rng);

        let partial_signatures = presigning
            .iter_mut()
            .enumerate()
            .map(|(i, presigning)| {
                let my_shares = avss::SharesForNode {
                    shares: vec![sk_shares[i].clone()],
                };
                generate_partial_signatures(
                    message,
                    presigning,
                    &my_shares,
                    &vk_element,
                    &beacon_value,
                    Some(7),
                )
                .unwrap()
            })
            .collect_vec();

        assert!(partial_signatures
            .iter()
            .map(|partial_signature| partial_signature.0)
            .all_equal());
        let public = partial_signatures[0].0;

        let signature = aggregate_signatures(
            message,
            &public,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
            &beacon_value,
            t,
            &vk_element,
            Some(7),
        )
        .unwrap();

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&derive_verifying_key(&vk_element, 7))
            .unwrap()
            .verify(message, &signature)
            .unwrap();
    }
}
