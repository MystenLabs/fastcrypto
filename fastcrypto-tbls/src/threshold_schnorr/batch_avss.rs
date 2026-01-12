// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute secret shares for a batch of random nonces.
//! The size of the batch is proportional to the [Dealer]'s weight.
//!
//! Before the protocol starts, the following setup is needed:
//! * Each receiver has a encryption key pair (ECIES) and these public keys are known to all parties.
//! * The public keys along with the weights of each receiver are known to all parties and defined in the [Nodes] structure.
//! * Define a new [Dealer] with the secrets who begins by calling [Dealer::create_message].

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{create_secret_sharing, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint::{Complaint, ComplaintResponse};
use crate::threshold_schnorr::Extensions::{Challenge, Encryption};
use crate::threshold_schnorr::{random_oracle_from_sid, EG, G, S};
use crate::types::{get_uniform_value, ShareIndex};
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{HashFunction, Sha3_512};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::iter::repeat_with;

/// This represents a Dealer in the AVSS.
/// There is exactly one dealer who creates the shares and broadcasts the encrypted shares.
#[allow(dead_code)]
pub struct Dealer {
    t: u16,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    /// The total number of nonces that this dealer should distribute.
    batch_size: usize,
}

/// This represents a Receiver in the AVSS who receives shares from the [Dealer].
#[allow(dead_code)]
pub struct Receiver {
    pub(crate) id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    t: u16,
    /// The total number of nonces that the receiver expects to receive from the dealer.
    batch_size: usize,
}

/// The message broadcast by the dealer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    ciphertext: MultiRecipientEncryption<EG>,
    response_polynomial: Poly<S>,
}

/// The result of processing a message by a receiver: either valid shares or a complaint.
#[allow(clippy::large_enum_variant)]
pub enum ProcessedMessage {
    Valid(ReceiverOutput),
    Complaint(Complaint),
}

/// The output of a receiver which is a batch of shares and public keys for all nonces.
#[derive(Debug, Clone)]
pub struct ReceiverOutput {
    pub my_shares: SharesForNode,
    pub public_keys: Vec<G>,
}

/// This represents a set of shares for a node. A total of <i>L</i> secrets/nonces are being shared,
/// If we say that node <i>i</i> has a weight `W_i`, we have
/// `indices().len() == shares_for_secret(i).len() == weight() = W_i`
///
/// These can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode {
    pub shares: Vec<ShareBatch>,
}

/// A batch of shares for a single share index, containing shares for each secret and one for the "blinding" polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch {
    /// The index of the share (i.e., the share id).
    pub index: ShareIndex,

    /// The shares for each secret.
    pub batch: Vec<S>,

    /// The share for the blinding polynomial.
    pub blinding_share: S,
}

impl ShareBatch {
    /// Verify a batch of shares using the given challenge.
    fn verify(&self, message: &Message, challenge: &[S]) -> FastCryptoResult<()> {
        if challenge.len() != self.batch_size() {
            return Err(InvalidInput);
        }

        // Verify that r' + sum_l r_l * gamma_l == p''(i)
        if self
            .batch
            .iter()
            .zip_eq(challenge)
            .fold(self.blinding_share, |acc, (r_l, gamma_l)| {
                acc + r_l * gamma_l
            })
            != message.response_polynomial.eval(self.index).value
        {
            return Err(InvalidInput);
        }
        Ok(())
    }

    fn batch_size(&self) -> usize {
        self.batch.len()
    }
}

impl SharesForNode {
    /// Get the weight of this node (number of shares it has).
    pub fn weight(&self) -> u16 {
        self.shares.len() as u16
    }

    /// If all shares have the same batch size, return that.
    /// Otherwise, return an InvalidInput error.
    pub fn try_uniform_batch_size(&self) -> FastCryptoResult<usize> {
        // TODO: Should we cache this? It's called twice per dealer -- once when verifying shares received from a dealer and then again during presigning.
        get_uniform_value(self.shares.iter().map(ShareBatch::batch_size)).ok_or(InvalidInput)
    }

    /// Get all shares this node has for the <i>i</i>-th secret/nonce in the batch.
    /// This panics if `i` is larger than or equal to the batch size.
    pub fn shares_for_secret(&self, i: usize) -> impl Iterator<Item = Eval<S>> + '_ {
        self.shares.iter().map(move |s| Eval {
            index: s.index,
            value: s.batch[i],
        })
    }

    fn verify(&self, message: &Message, challenge: &[S]) -> FastCryptoResult<()> {
        for shares in &self.shares {
            shares.verify(message, challenge)?;
        }
        Ok(())
    }

    /// Recover the shares for this node.
    ///
    /// Fails if `other_shares` is empty or if the batch sizes of all shares in `other_shares` are not equal to the expected batch size.
    fn recover(receiver: &Receiver, other_shares: &[Self]) -> FastCryptoResult<Self> {
        if other_shares.is_empty() {
            return Err(InvalidInput);
        }

        let shares = receiver
            .my_indices()
            .into_iter()
            .map(|index| {
                let batch = (0..receiver.batch_size)
                    .map(|i| {
                        let evaluations = other_shares
                            .iter()
                            .flat_map(|s| s.shares_for_secret(i))
                            .collect_vec();
                        Poly::recover_at(index, &evaluations).unwrap().value
                    })
                    .collect_vec();

                let blinding_share = Poly::recover_at(
                    index,
                    &other_shares
                        .iter()
                        .flat_map(|s| &s.shares)
                        .map(|share| Eval {
                            index: share.index,
                            value: share.blinding_share,
                        })
                        .collect_vec(),
                )?
                .value;

                Ok(ShareBatch {
                    index,
                    batch,
                    blinding_share,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self { shares })
    }
}

impl BCSSerialized for SharesForNode {}

impl Dealer {
    /// Create a new dealer.
    ///
    /// * `nodes` defines the set of receivers and their weights.
    /// * `dealer_id` is the id of this dealer as a node.
    /// * `t` is the number of shares that are needed to reconstruct the full key/signature.
    /// * `f` is the maximum number of Byzantine parties counted by weight.
    /// * `sid` is a session identifier that should be unique for each invocation, but the same for all parties.
    /// * `batch_size_per_weight` is the number of secrets a dealer should deal per weight it has.
    ///
    /// Returns an `InvalidInput` error if
    /// * t <= f or if the total weight of the nodes is smaller than t + 2*f.
    /// * the `dealer_id` is invalid (not part of `nodes`).
    pub fn new(
        nodes: Nodes<EG>,
        dealer_id: PartyId,
        t: u16,
        f: u16,
        sid: Vec<u8>,
        batch_size_per_weight: u16,
    ) -> FastCryptoResult<Self> {
        if t <= f || t + 2 * f > nodes.total_weight() {
            return Err(InvalidInput);
        }

        // Each dealer deals a number of nonces proportional to their weight.
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;
        Ok(Self {
            t,
            nodes,
            sid,
            batch_size,
        })
    }

    /// 1. The Dealer generates shares for the secrets and broadcasts the encrypted shares.
    pub fn create_message(&self, rng: &mut impl AllowedRng) -> FastCryptoResult<Message> {
        let secrets = repeat_with(|| S::rand(rng))
            .take(self.batch_size)
            .collect_vec();

        // Compute the (full) public keys for all secrets
        let full_public_keys = secrets.iter().map(|s| G::generator() * s).collect_vec();

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let total_weight = self.nodes.total_weight();
        let blinding_secret = S::rand(rng);
        let blinding_poly_evaluations =
            create_secret_sharing(rng, blinding_secret, self.t, total_weight);
        let blinding_commit = G::generator() * blinding_secret;

        // Compute all evaluations of all polynomials
        let share_batches = secrets
            .iter()
            .map(|&s| create_secret_sharing(rng, s, self.t, total_weight))
            .collect_vec();

        // Encrypt all shares to the receivers
        let pk_and_msgs = self
            .nodes
            .iter()
            .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
            .map(|(pk, share_ids)| {
                (
                    pk,
                    SharesForNode {
                        shares: share_ids
                            .into_iter()
                            .map(|index| ShareBatch {
                                index,
                                batch: share_batches.iter().map(|shares| shares[index]).collect(),
                                blinding_share: blinding_poly_evaluations[index],
                            })
                            .collect_vec(),
                    }
                    .to_bytes(),
                )
            })
            .collect_vec();

        let ciphertext = MultiRecipientEncryption::encrypt(
            &pk_and_msgs,
            &self.random_oracle().extend(&Encryption.to_string()),
            rng,
        );

        // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
        let challenge = compute_challenge(
            &self.random_oracle(),
            &full_public_keys,
            &blinding_commit,
            &ciphertext,
        );

        // Get the first t evaluations for the response polynomial and use these to compute the coefficients
        let response_polynomial = Poly::interpolate(
            &share_batches
                .into_iter()
                .map(|s| s.take(self.t))
                .zip_eq(&challenge)
                .fold(
                    blinding_poly_evaluations.take(self.t),
                    |acc, (p_l, gamma_l)| acc + p_l * gamma_l,
                )
                .to_vec(),
        )?;

        Ok(Message {
            full_public_keys,
            blinding_commit,
            ciphertext,
            response_polynomial,
        })
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

impl Receiver {
    /// Create a new receiver.
    ///
    /// * `nodes` defines the set of receivers and what shares they should receive.
    /// * `id` is the id of this receiver.
    /// * `dealer_id` is the id of the dealer.
    /// * `t` is the number of shares that are needed to reconstruct the full key/signature.
    /// * `sid` is a session identifier that should be unique for each invocation, but the same for all parties.
    /// * `enc_secret_key` is this Receivers' secret key for the distribution of nonces. The corresponding public key is defined in `nodes`.
    /// * `batch_size_per_weight` is the number of secrets a dealer should deal per weight it has.
    ///
    /// Returns an `InvalidInput` error if the `id` or `dealer_id` is invalid.
    pub fn new(
        nodes: Nodes<EG>,
        id: PartyId,
        dealer_id: PartyId,
        t: u16,
        sid: Vec<u8>,
        enc_secret_key: PrivateKey<EG>,
        batch_size_per_weight: u16,
    ) -> FastCryptoResult<Self> {
        // The dealer is expected to deal a number of nonces proportional to it's weight
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;

        Ok(Self {
            id,
            enc_secret_key,
            nodes,
            sid,
            t,
            batch_size,
        })
    }

    /// 2. Each receiver processes the message, verifies and decrypts its shares.
    ///
    /// If this works, the receiver can store the shares and contribute a signature on the message to a certificate.
    ///
    /// This returns an [InvalidMessage] error if the ciphertext cannot be verified or if the commitments are invalid.
    /// All honest receivers will reject such a message with the same error, and such a message should be ignored.
    ///
    /// If the message is valid but contains invalid shares for this receiver, the call will succeed but will return a [Complaint].
    ///
    /// 3. When f+t signatures have been collected in the certificate, the receivers can now verify the certificate and finish the protocol.
    pub fn process_message(&self, message: &Message) -> FastCryptoResult<ProcessedMessage> {
        let Message {
            full_public_keys,
            blinding_commit,
            ciphertext,
            response_polynomial,
        } = message;

        if full_public_keys.len() != self.batch_size
            || response_polynomial.degree() != self.t as usize - 1
        {
            return Err(InvalidMessage);
        }

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        let challenge = compute_challenge_from_message(&self.random_oracle(), message);
        if G::generator() * response_polynomial.c0()
            != blinding_commit
                + G::multi_scalar_mul(&challenge, full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            return Err(InvalidMessage);
        }

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        ciphertext
            .verify(&random_oracle_encryption)
            .map_err(|_| InvalidMessage)?;

        // Decrypt my shares
        let plaintext = ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        match SharesForNode::from_bytes(&plaintext).and_then(|my_shares| {
            // If there is an error in this scope, we create a complaint instead of returning an error
            verify_shares(
                &my_shares,
                &self.nodes,
                self.id,
                message,
                &challenge,
                self.batch_size,
            )?;
            Ok(my_shares)
        }) {
            Ok(my_shares) => Ok(ProcessedMessage::Valid(ReceiverOutput {
                my_shares,
                public_keys: full_public_keys.clone(),
            })),
            Err(_) => Ok(ProcessedMessage::Complaint(Complaint::create(
                self.id,
                ciphertext,
                &self.enc_secret_key,
                &self.random_oracle(),
                &mut rand::thread_rng(),
            ))),
        }
    }

    /// 4. Upon receiving a complaint, a receiver verifies it and responds with its shares.
    pub fn handle_complaint(
        &self,
        message: &Message,
        complaint: &Complaint,
        my_output: &ReceiverOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        let challenge = compute_challenge_from_message(&self.random_oracle(), message);
        complaint.check(
            &self.nodes.node_id_to_node(complaint.accuser_id)?.pk,
            &message.ciphertext,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                verify_shares(
                    shares,
                    &self.nodes,
                    complaint.accuser_id,
                    message,
                    &challenge,
                    self.batch_size,
                )
            },
        )?;
        Ok(ComplaintResponse {
            responder_id: self.id,
            shares: my_output.my_shares.clone(),
        })
    }

    /// 5. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &Message,
        responses: Vec<ComplaintResponse<SharesForNode>>,
    ) -> FastCryptoResult<ReceiverOutput> {
        // TODO: This fails if one of the responses has an invalid responder_id. We could probably just ignore those instead.

        // Sanity check that we have enough responses (by weight) to recover the shares.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|response| &response.responder_id))?;
        if total_response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let challenge = compute_challenge_from_message(&self.random_oracle(), message);
        let response_shares = responses
            .into_iter()
            .filter_map(|response| {
                response
                    .shares
                    .verify(message, &challenge)
                    .ok()
                    .map(|_| response.shares)
            })
            .collect_vec();

        // Compute the total weight of the valid responses
        let response_weight: u16 = response_shares.iter().map(SharesForNode::weight).sum();
        if response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let my_shares = SharesForNode::recover(self, &response_shares)?;
        my_shares.verify(message, &challenge)?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.full_public_keys.clone(),
        })
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

/// Verify a set of shares receiver from a Dealer
fn verify_shares(
    shares: &SharesForNode,
    nodes: &Nodes<EG>,
    receiver: PartyId,
    message: &Message,
    challenge: &[S],
    expected_batch_size: usize,
) -> FastCryptoResult<()> {
    if shares.weight() != nodes.weight_of(receiver)?
        || shares.try_uniform_batch_size()? != expected_batch_size
    {
        return Err(InvalidMessage);
    }
    shares.verify(message, challenge)
}

fn compute_challenge(
    random_oracle: &RandomOracle,
    c: &[G],
    c_prime: &G,
    e: &MultiRecipientEncryption<EG>,
) -> Vec<S> {
    let random_oracle = random_oracle.extend(&Challenge.to_string());
    let inner_hash = Sha3_512::digest(bcs::to_bytes(&(c.to_vec(), c_prime, e)).unwrap()).digest;
    (0..c.len())
        .map(|l| random_oracle.evaluate_to_group_element(&(l, inner_hash.to_vec())))
        .collect()
}

fn compute_challenge_from_message(random_oracle: &RandomOracle, message: &Message) -> Vec<S> {
    compute_challenge(
        random_oracle,
        &message.full_public_keys,
        &message.blinding_commit,
        &message.ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        compute_challenge, Complaint, Dealer, Message, ProcessedMessage, Receiver, ReceiverOutput,
        ShareBatch, SharesForNode,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::Extensions::Encryption;
    use crate::threshold_schnorr::{EG, G};
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;
    use std::iter::repeat_with;

    #[test]
    fn test_happy_path() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;
        let batch_size_per_weight = 3;

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(i, sk)| Node {
                    id: i as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let sid = b"tbls test".to_vec();
        let dealer_id = 0;
        let dealer: Dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            t,
            f,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    t,
                    sid.clone(),
                    secret_key,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();

        let message = dealer.create_message(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .map(|receiver| {
                (
                    receiver.id,
                    assert_valid(receiver.process_message(&message).unwrap()),
                )
            })
            .collect::<HashMap<_, _>>();

        let secrets = (0..dealer.batch_size)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.shares[0].batch[l], // Each receiver has a single share (weight=1 for all nodes)
                        )
                    })
                    .collect_vec();
                Poly::recover_c0(
                    t,
                    shares.iter().take(t as usize).map(|(id, v)| Eval {
                        index: ShareIndex::try_from(id + 1).unwrap(),
                        value: *v,
                    }),
                )
                .unwrap()
            })
            .collect_vec();

        assert_eq!(secrets, secrets);
    }

    #[test]
    #[allow(clippy::single_match)]
    fn test_happy_path_non_equal_weights() {
        // No complaints, all honest
        let t = 4;
        let f = 3;
        let weights: Vec<u16> = vec![1, 2, 3, 4];
        let batch_size_per_weight = 3;

        let mut rng = rand::thread_rng();
        let sks = weights
            .iter()
            .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            weights
                .into_iter()
                .enumerate()
                .map(|(i, weight)| Node {
                    id: i as u16,
                    pk: PublicKey::from_private_key(&sks[i]),
                    weight,
                })
                .collect_vec(),
        )
        .unwrap();

        let dealer_id = 2;
        let sid = b"tbls test".to_vec();
        let dealer: Dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            t,
            f,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    i as u16,
                    dealer_id,
                    t,
                    sid.clone(),
                    secret_key,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();

        let message = dealer.create_message(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .flat_map(|receiver| {
                assert_valid(receiver.process_message(&message).unwrap())
                    .my_shares
                    .shares
            })
            .collect::<Vec<_>>();

        let secrets = (0..dealer.batch_size)
            .map(|l| {
                Poly::recover_c0(
                    t,
                    all_shares.iter().take(t as usize).map(|s| Eval {
                        index: s.index,
                        value: s.batch[l],
                    }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(secrets, secrets);
    }

    #[test]
    fn test_share_recovery() {
        let t = 3;
        let f = 2;
        let n = 7;
        let batch_size_per_weight: u16 = 3;

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

        let sid = b"tbls test".to_vec();

        let dealer_id = 1;
        let dealer: Dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            t,
            f,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    t,
                    sid.clone(),
                    secret_key,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message_cheating(&mut rng).unwrap();

        let mut all_shares = receivers
            .iter()
            .map(|receiver| (receiver.id, receiver.process_message(&message).unwrap()))
            .collect::<HashMap<_, _>>();

        let complaint = assert_complaint(all_shares.remove(&receivers[0].id).unwrap());
        let mut all_shares = all_shares
            .into_iter()
            .map(|(id, pm)| (id, assert_valid(pm)))
            .collect::<HashMap<_, _>>();

        let responses = receivers
            .iter()
            .skip(1)
            .map(|r| {
                r.handle_complaint(&message, &complaint, all_shares.get(&r.id).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let shares = receivers[0].recover(&message, responses).unwrap();
        all_shares.insert(receivers[0].id, shares);

        // Recover with the first f+1 shares, including the reconstructed
        let secrets = (0..dealer.batch_size)
            .map(|l| {
                let shares = all_shares
                    .iter()
                    .map(|(id, s)| (*id, s.my_shares.shares[0].batch[l]))
                    .collect::<Vec<_>>();
                Poly::recover_c0(
                    t,
                    shares.iter().take(t as usize).map(|(id, v)| Eval {
                        index: ShareIndex::try_from(id + 1).unwrap(),
                        value: *v,
                    }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(secrets, secrets);
    }

    impl Dealer {
        /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
        pub fn create_message_cheating(
            &self,
            rng: &mut impl AllowedRng,
        ) -> FastCryptoResult<Message> {
            let polynomials = repeat_with(|| Poly::rand(self.t - 1, rng))
                .take(self.batch_size)
                .collect_vec();

            // Compute the (full) public keys for all secrets
            let full_public_keys = polynomials
                .iter()
                .map(|p| G::generator() * p.c0())
                .collect_vec();

            // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
            let blinding_poly = Poly::rand(self.t - 1, rng);
            let blinding_commit = G::generator() * blinding_poly.c0();

            // Encrypt all shares to the receivers
            let mut pk_and_msgs = self
                .nodes
                .iter()
                .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
                .map(|(public_key, share_ids)| {
                    (
                        public_key,
                        SharesForNode {
                            shares: share_ids
                                .into_iter()
                                .map(|index| ShareBatch {
                                    index,
                                    batch: polynomials
                                        .iter()
                                        .map(|p_l| p_l.eval(index).value)
                                        .collect_vec(),
                                    blinding_share: blinding_poly.eval(index).value,
                                })
                                .collect_vec(),
                        },
                    )
                })
                .map(|(pk, shares_for_node)| (pk, shares_for_node.to_bytes()))
                .collect_vec();

            // Modify the first share of the first receiver to simulate a cheating dealer
            pk_and_msgs[0].1[7] ^= 1;

            let ciphertext = MultiRecipientEncryption::encrypt(
                &pk_and_msgs,
                &self.random_oracle().extend(&Encryption.to_string()),
                rng,
            );

            // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
            let challenge = compute_challenge(
                &self.random_oracle(),
                &full_public_keys,
                &blinding_commit,
                &ciphertext,
            );
            let mut response_polynomial = blinding_poly;
            for (p_l, gamma_l) in polynomials.into_iter().zip_eq(&challenge) {
                response_polynomial += &(p_l * gamma_l);
            }

            Ok(Message {
                full_public_keys,
                blinding_commit,
                ciphertext,
                response_polynomial,
            })
        }
    }

    fn assert_valid(processed_message: ProcessedMessage) -> ReceiverOutput {
        if let ProcessedMessage::Valid(output) = processed_message {
            output
        } else {
            panic!("Expected valid message");
        }
    }

    fn assert_complaint(processed_message: ProcessedMessage) -> Complaint {
        if let ProcessedMessage::Complaint(complaint) = processed_message {
            complaint
        } else {
            panic!("Expected complaint");
        }
    }
}
