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
pub mod gao;
pub mod key_derivation;
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
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::avss::compute_joint_vk_after_dkg;
    use crate::threshold_schnorr::batch_avss::{ShareBatch, SharesForNode};
    use crate::threshold_schnorr::key_derivation::derive_verifying_key;
    use crate::threshold_schnorr::presigning::Presignatures;
    use crate::threshold_schnorr::signing::{aggregate_signatures, generate_partial_signatures};
    use crate::threshold_schnorr::{avss, batch_avss, EG, G, S};
    use crate::types::{IndexedValue, ShareIndex};
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::array;
    use std::collections::HashMap;
    use std::hash::Hash;

    #[test]
    fn test_e2e() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;

        const BATCH_SIZE: usize = 10;

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(id, sk)| Node {
                    id: id as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        //
        // DKG
        //

        // Map from each party to the outputs it has received
        let mut dkg_outputs = HashMap::<PartyId, HashMap<PartyId, avss::ReceiverOutput>>::new();
        nodes.node_ids_iter().for_each(|id| {
            dkg_outputs.insert(id, HashMap::new());
        });

        let mut messages = Vec::new();
        for dealer_id in nodes.node_ids_iter() {
            let sid = format!("dkg-test-session-{}", dealer_id).into_bytes();
            let dealer: avss::Dealer =
                avss::Dealer::new(None, nodes.clone(), t, f, sid.clone()).unwrap();
            let receivers = sks
                .iter()
                .enumerate()
                .map(|(id, enc_secret_key)| {
                    avss::Receiver::new(
                        nodes.clone(),
                        id as u16,
                        t,
                        sid.clone(),
                        None,
                        enc_secret_key.clone(),
                    )
                })
                .collect::<Vec<_>>();

            // Each dealer creates a message
            let message = dealer.create_message(&mut rng).unwrap();
            messages.push(message.clone());

            // Each receiver processes the message. In this case, we assume all are honest and there are no complaints.
            receivers.iter().for_each(|receiver| {
                let output = assert_valid(receiver.process_message(&message).unwrap());
                dkg_outputs
                    .get_mut(&receiver.id())
                    .unwrap()
                    .insert(dealer_id, output);
            });
        }

        // The first t dealers form the certificate and are the ones whose outputs will be used to create the final shares.
        let dkg_cert = [PartyId::from(1u8), PartyId::from(3u8), PartyId::from(4u8)];

        // Now, each party has collected their outputs from all dealers. We use the first t outputs to create the final shares for signing.
        // Each party should still keep the outputs from all dealers until the end of the epoch to handle complaints.
        let merged_shares = nodes
            .iter()
            .map(|node| {
                (
                    node.id,
                    avss::ReceiverOutput::complete_dkg(
                        t,
                        &image(dkg_outputs.get(&node.id).unwrap(), dkg_cert.iter()),
                    )
                    .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        // We may now compute the joint verification key from the commitments of the first t dealers.
        let vk = compute_joint_vk_after_dkg(f, &sublist(&messages, dkg_cert.iter())).unwrap();

        // For testing, we now recover the secret key from t shares and check that the secret key matches the verification key.
        // In practice, the parties should never do this...
        let shares = merged_shares
            .values()
            .flat_map(|output| output.my_shares.shares.clone())
            .take(t as usize);
        let sk = Poly::recover_c0(t, shares).unwrap();
        assert_eq!(G::generator() * sk, vk);

        //
        // PRESIGNING
        //

        // Generate a batch of nonces for each party
        let mut presigning_outputs =
            HashMap::<PartyId, Vec<batch_avss::ReceiverOutput<BATCH_SIZE>>>::new();
        nodes.node_ids_iter().for_each(|id| {
            presigning_outputs.insert(id, Vec::new());
        });

        for dealer_id in nodes.node_ids_iter() {
            let sid = format!("presig-test-session-{}", dealer_id).into_bytes();
            let dealer: batch_avss::Dealer<BATCH_SIZE> =
                batch_avss::Dealer::new(nodes.clone(), t, f, sid.clone(), &mut rng).unwrap();
            let receivers = sks
                .iter()
                .enumerate()
                .map(|(id, enc_secret_key)| {
                    batch_avss::Receiver::<BATCH_SIZE>::new(
                        nodes.clone(),
                        id as u16,
                        t,
                        sid.clone(),
                        enc_secret_key.clone(),
                    )
                })
                .collect::<Vec<_>>();

            // Each dealer creates a message
            let message = dealer.create_message(&mut rng).unwrap();

            // Each receiver processes the message.
            // In this case, we assume all are honest and there are no complaints.
            receivers.iter().for_each(|receiver| {
                let output = assert_valid_batch(receiver.process_message(&message).unwrap());
                presigning_outputs
                    .get_mut(&receiver.id())
                    .unwrap()
                    .push(output);
            });
        }

        // Each party can process their presigs locally from the secret shared nonces
        let mut presigs = presigning_outputs
            .into_iter()
            .map(|(id, outputs)| {
                (
                    id,
                    Presignatures::<BATCH_SIZE>::new(
                        &nodes.share_ids_of(id).unwrap(),
                        outputs,
                        f as usize,
                    )
                    .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        //
        // SIGNING
        //

        let message = b"Hello, world!";

        // Mock a value from the random beacon
        let beacon_value = S::rand(&mut rng);

        // Each party generates their partial signatures
        let partial_signatures = nodes
            .iter()
            .map(|node| {
                generate_partial_signatures(
                    message,
                    presigs.get_mut(&node.id).unwrap(),
                    &beacon_value,
                    &merged_shares.get(&node.id).unwrap().my_shares,
                    &vk,
                    None,
                )
                .unwrap()
            })
            .collect_vec();

        // The public parts should all be the same
        assert!(partial_signatures
            .iter()
            .map(|partial_signature| partial_signature.0)
            .all_equal());

        // Aggregate partial signatures
        let signature = aggregate_signatures(
            message,
            &partial_signatures[0].0, // All public parts are equal, so we just take the first
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, s)| s.clone())
                .collect_vec(),
            t,
            &vk,
            None,
        )
        .unwrap();

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&vk)
            .unwrap()
            .verify(message, &signature)
            .unwrap();

        //
        // KEY ROTATION
        //

        // Map from each party to the ordered list of outputs it has received.
        // Here, each party will act as dealer multiple times -- once per share they have.
        let mut dkg_outputs_after_rotation =
            HashMap::<(PartyId, ShareIndex), avss::ReceiverOutput>::new();
        let mut messages = HashMap::<(PartyId, ShareIndex), avss::Message>::new();

        for dealer_id in nodes.node_ids_iter() {
            for share_index in nodes.share_ids_of(dealer_id).unwrap() {
                let sid =
                    format!("key-rotation-test-session-{}-{}", dealer_id, share_index).into_bytes();

                // Each dealer uses their existing share as the secret to reshare
                let secret = merged_shares
                    .get(&dealer_id)
                    .unwrap()
                    .my_shares
                    .share_for_index(share_index)
                    .unwrap()
                    .value;
                let dealer: avss::Dealer =
                    avss::Dealer::new(Some(secret), nodes.clone(), t, f, sid.clone()).unwrap();

                let receivers = sks
                    .iter()
                    .enumerate()
                    .map(|(id, enc_secret_key)| {
                        let commitment = merged_shares
                            .get(&(id as u16))
                            .unwrap()
                            .commitments
                            .iter()
                            .find(|c| c.index == share_index)
                            .unwrap()
                            .value;
                        avss::Receiver::new(
                            nodes.clone(),
                            id as u16,
                            t,
                            sid.clone(),
                            Some(commitment),
                            enc_secret_key.clone(),
                        )
                    })
                    .collect::<Vec<_>>();

                // Each dealer creates a message
                let message = dealer.create_message(&mut rng).unwrap();
                messages.insert((dealer_id, share_index), message.clone());

                // Each receiver processes the message. In this case, we assume all are honest and there are no complaints.
                receivers.iter().for_each(|receiver| {
                    let output = assert_valid(receiver.process_message(&message).unwrap());
                    dkg_outputs_after_rotation.insert((receiver.id(), share_index), output);
                });
            }
        }

        // The first t dealers (counted by weight) form the certificate and are the ones whose outputs will be used to create the final shares.
        let key_rotation_cert = [PartyId::from(2u8), PartyId::from(3u8), PartyId::from(5u8)];
        let share_indices_in_cert = key_rotation_cert
            .iter()
            .flat_map(|id| nodes.share_ids_of(*id).unwrap())
            .collect_vec();

        // Now, each party has collected their outputs from all dealers and can form their new shares from the ones in the certificate.
        let merged_shares_after_rotation = nodes
            .node_ids_iter()
            .map(|receiver_id| {
                let my_shares_from_cert = share_indices_in_cert
                    .iter()
                    .map(|&index| IndexedValue {
                        index,
                        value: dkg_outputs_after_rotation
                            .get(&(receiver_id, index))
                            .unwrap()
                            .clone(),
                    })
                    .collect_vec();
                (
                    receiver_id,
                    avss::ReceiverOutput::complete_key_rotation(
                        t,
                        &nodes.share_ids_of(receiver_id).unwrap(),
                        &my_shares_from_cert,
                    )
                    .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        // For testing, we now recover the secret key from t shares and check that the secret key matches the verification key.
        // In practice, the parties should never do this...
        let shares = merged_shares_after_rotation
            .values()
            .flat_map(|output| output.my_shares.shares.clone())
            .take(t as usize);
        let sk = Poly::recover_c0(t, shares).unwrap();
        assert_eq!(G::generator() * sk, vk);

        // Check commitments on the reshared secret from the first dealer
        let commitment_1 = merged_shares.get(&0).unwrap().commitments.first().unwrap();
        let secret_1 = merged_shares
            .get(&0)
            .unwrap()
            .my_shares
            .share_for_index(commitment_1.index)
            .unwrap()
            .value;
        assert_eq!(G::generator() * secret_1, commitment_1.value);

        //
        // SIGNING (again)
        //

        let message_2 = b"Hello again, world!";

        // Mock a value from the random beacon
        let beacon_value = S::rand(&mut rng);

        // Each party generates their partial signatures
        let partial_signatures = nodes
            .iter()
            .map(|node| {
                generate_partial_signatures(
                    message_2,
                    presigs.get_mut(&node.id).unwrap(),
                    &beacon_value,
                    &merged_shares.get(&node.id).unwrap().my_shares,
                    &vk,
                    None,
                )
                .unwrap()
            })
            .collect_vec();

        // The public parts should all be the same
        assert!(partial_signatures
            .iter()
            .map(|partial_signature| partial_signature.0)
            .all_equal());

        // Aggregate partial signatures
        let signature_2 = aggregate_signatures(
            message_2,
            &partial_signatures[0].0, // All public parts are equal, so we just take the first
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, s)| s.clone())
                .collect_vec(),
            t,
            &vk,
            None,
        )
        .unwrap();

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&vk)
            .unwrap()
            .verify(message_2, &signature_2)
            .unwrap();
    }

    fn sublist<'a, T: Clone, I: Clone + 'a>(
        list: &[T],
        indices: impl Iterator<Item = &'a I>,
    ) -> Vec<T>
    where
        usize: From<I>,
    {
        indices
            .map(|i| list[usize::from(i.clone())].clone())
            .collect()
    }

    fn image<'a, T: Clone, I: Eq + Hash + 'a>(
        map: &HashMap<I, T>,
        indices: impl Iterator<Item = &'a I>,
    ) -> Vec<T>
    where
        usize: From<I>,
    {
        indices.map(|i| map.get(i).unwrap().clone()).collect()
    }

    fn assert_valid_batch<const N: usize>(
        processed_message: batch_avss::ProcessedMessage<N>,
    ) -> batch_avss::ReceiverOutput<N> {
        if let batch_avss::ProcessedMessage::Valid(output) = processed_message {
            output
        } else {
            panic!("Expected valid message");
        }
    }

    fn assert_valid(processed_message: avss::ProcessedMessage) -> avss::ReceiverOutput {
        if let avss::ProcessedMessage::Valid(output) = processed_message {
            output
        } else {
            panic!("Expected valid message");
        }
    }

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
                        batch_avss::ReceiverOutput {
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
                    &beacon_value,
                    &my_shares,
                    &vk_element,
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
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
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
                        batch_avss::ReceiverOutput {
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
                    &beacon_value,
                    &my_shares,
                    &vk_element,
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
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
            t,
            &vk_element,
            Some(7),
        )
        .unwrap();

        // Check that this produced a valid signature
        derive_verifying_key(&vk_element, 7)
            .verify(message, &signature)
            .unwrap();
    }
}
