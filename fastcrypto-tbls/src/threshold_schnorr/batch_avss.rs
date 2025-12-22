// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute secret shares for a batch of random nonces.
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
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{HashFunction, Sha3_512};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::array;
use std::fmt::Debug;

/// This represents a Dealer in the AVSS.
/// There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
#[allow(dead_code)]
pub struct Dealer {
    t: u16,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
}

/// This represents a Receiver in the AVSS who receives shares from the [Dealer].
#[allow(dead_code)]
pub struct Receiver {
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    t: u16, // The number of parties that are needed to reconstruct the full key/signature.
}

/// The message broadcast by the dealer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<const BATCH_SIZE: usize> {
    #[serde(with = "BigArray")]
    full_public_keys: [G; BATCH_SIZE],
    blinding_commit: G,
    ciphertext: MultiRecipientEncryption<EG>,
    response_polynomial: Poly<S>,
}

/// The result of processing a message by a receiver: either valid shares or a complaint.
#[allow(clippy::large_enum_variant)] // Clippy complains because ReceiverOutput can be very small if BATCH_SIZE is small.
pub enum ProcessedMessage<const BATCH_SIZE: usize> {
    Valid(ReceiverOutput<BATCH_SIZE>),
    Complaint(Complaint),
}

/// The output of a receiver which is a batch of shares and public keys for all nonces.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<const BATCH_SIZE: usize> {
    pub my_shares: SharesForNode<BATCH_SIZE>,
    pub public_keys: [G; BATCH_SIZE],
}

/// This represents a set of shares for a node. A total of <i>L</i> secrets/nonces are being shared,
/// If we say that node <i>i</i> has a weight `W_i`, we have
/// `indices().len() == shares_for_secret(i).len() == weight() = W_i`
///
/// These can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode<const BATCH_SIZE: usize> {
    pub batches: Vec<ShareBatch<BATCH_SIZE>>,
}

/// A batch of shares for a single share index, containing shares for each secret and one for the "blinding" polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch<const BATCH_SIZE: usize> {
    /// The index of the share (i.e., the share id).
    pub index: ShareIndex,

    /// The shares for each secret.
    #[serde(with = "BigArray")]
    pub shares: [S; BATCH_SIZE],

    /// The share for the blinding polynomial.
    pub blinding_share: S,
}

impl<const BATCH_SIZE: usize> ShareBatch<BATCH_SIZE> {
    /// Verify a batch of shares using the given challenge.
    fn verify(&self, message: &Message<BATCH_SIZE>, challenge: &[S]) -> FastCryptoResult<()> {
        if challenge.len() != self.shares.len() {
            return Err(InvalidInput);
        }

        // Verify that r' + sum_l r_l * gamma_l == p''(i)
        if self
            .shares
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
}

impl<const BATCH_SIZE: usize> SharesForNode<BATCH_SIZE> {
    /// Get the weight of this node (number of shares it has).
    pub fn weight(&self) -> usize {
        self.batches.len()
    }

    /// Get all shares this node has for the <i>i</i>-th secret/nonce in the batch.
    pub fn shares_for_secret(
        &self,
        i: usize,
    ) -> FastCryptoResult<impl Iterator<Item = Eval<S>> + '_> {
        if i >= BATCH_SIZE {
            return Err(InvalidInput);
        }
        Ok(self.batches.iter().map(move |share_batch| Eval {
            index: share_batch.index,
            value: share_batch.shares[i],
        }))
    }

    fn verify(&self, message: &Message<BATCH_SIZE>, challenge: &[S]) -> FastCryptoResult<()> {
        for shares in &self.batches {
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

        let batches = receiver
            .my_indices()
            .into_iter()
            .map(|index| {
                let shares = array::from_fn(|i| {
                    let evaluations: Vec<Eval<S>> = other_shares
                        .iter()
                        .flat_map(|s| s.shares_for_secret(i).expect("Size checked above"))
                        .collect_vec();
                    Poly::recover_at(index, &evaluations).unwrap().value
                });

                let blinding_share = Poly::recover_at(
                    index,
                    &other_shares
                        .iter()
                        .flat_map(|s| &s.batches)
                        .map(|batch| Eval {
                            index: batch.index,
                            value: batch.blinding_share,
                        })
                        .collect_vec(),
                )?
                .value;

                Ok(ShareBatch {
                    index,
                    shares,
                    blinding_share,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self { batches })
    }
}

impl<const BATCH_SIZE: usize> BCSSerialized for SharesForNode<BATCH_SIZE> {}

impl Dealer {
    /// Create a new dealer.
    ///
    /// `nodes` defines the set of receivers and their weights.
    /// `t` is the number of shares that are needed to reconstruct the full key/signature.
    /// `f` is the maximum number of Byzantine parties counted by weight.
    /// `sid` is a session identifier that should be unique for each invocation, but the same for all parties.
    /// `rng` is a random number generator.
    pub fn new(nodes: Nodes<EG>, t: u16, f: u16, sid: Vec<u8>) -> FastCryptoResult<Self> {
        // We need to collect t+f confirmations to make sure that at least t honest parties have confirmed.
        if t <= f || t + 2 * f > nodes.total_weight() {
            return Err(InvalidInput);
        }

        Ok(Self { t, nodes, sid })
    }

    /// 1. The Dealer generates shares for the secrets and broadcasts the encrypted shares.
    pub fn create_message<const BATCH_SIZE: usize>(
        &self,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Message<BATCH_SIZE>> {
        let secrets = array::from_fn(|_| S::rand(rng));

        // Compute the (full) public keys for all secrets
        let full_public_keys = secrets.each_ref().map(|s| G::generator() * s);

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let blinding_secret = S::rand(rng);
        let blinding_poly_evaluations =
            create_secret_sharing(rng, blinding_secret, self.t, self.nodes.total_weight());
        let blinding_commit = G::generator() * blinding_secret;

        // Compute all evaluations of all polynomials
        let shares_for_polynomial =
            secrets.map(|s| create_secret_sharing(rng, s, self.t, self.nodes.total_weight()));

        // Encrypt all shares to the receivers
        let pk_and_msgs = self
            .nodes
            .iter()
            .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
            .map(|(pk, share_ids)| {
                (
                    pk,
                    SharesForNode {
                        batches: share_ids
                            .into_iter()
                            .map(|index| ShareBatch {
                                index,
                                shares: shares_for_polynomial
                                    .each_ref()
                                    .map(|shares| shares[index]),
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
            &shares_for_polynomial
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
    /// `nodes` defines the set of receivers and what shares they should receive.
    /// `id` is the id of this receiver.
    ///
    pub fn new(
        nodes: Nodes<EG>,
        id: PartyId,
        t: u16,
        sid: Vec<u8>,
        enc_secret_key: PrivateKey<EG>,
    ) -> Self {
        Self {
            id,
            enc_secret_key,
            nodes,
            sid,
            t,
        }
    }

    pub fn id(&self) -> PartyId {
        self.id
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
    pub fn process_message<const BATCH_SIZE: usize>(
        &self,
        message: &Message<BATCH_SIZE>,
    ) -> FastCryptoResult<ProcessedMessage<BATCH_SIZE>> {
        let Message {
            full_public_keys,
            blinding_commit,
            ciphertext,
            response_polynomial,
        } = message;

        // The response polynomial should have degree t - 1, but with some negligible probability (if the highest coefficient is zero) it will be smaller.
        if response_polynomial.degree() != self.t as usize - 1 {
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
            if my_shares.weight() != self.my_weight() {
                return Err(InvalidMessage);
            }
            my_shares.verify(message, &challenge)?;
            Ok(my_shares)
        }) {
            Ok(my_shares) => Ok(ProcessedMessage::Valid(ReceiverOutput {
                my_shares,
                public_keys: *full_public_keys,
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
    pub fn handle_complaint<const BATCH_SIZE: usize>(
        &self,
        message: &Message<BATCH_SIZE>,
        complaint: &Complaint,
        my_output: &ReceiverOutput<BATCH_SIZE>,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode<BATCH_SIZE>>> {
        let challenge = compute_challenge_from_message(&self.random_oracle(), message);
        complaint.check(
            &self.nodes.node_id_to_node(complaint.accuser_id)?.pk,
            &message.ciphertext,
            &self.random_oracle(),
            |shares: &SharesForNode<BATCH_SIZE>| shares.verify(message, &challenge),
        )?;
        Ok(ComplaintResponse::create(
            self.id,
            my_output.my_shares.clone(),
        ))
    }

    /// 5. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover<const BATCH_SIZE: usize>(
        &self,
        message: &Message<BATCH_SIZE>,
        responses: Vec<ComplaintResponse<SharesForNode<BATCH_SIZE>>>,
    ) -> FastCryptoResult<ReceiverOutput<BATCH_SIZE>> {
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
        let response_weight = response_shares
            .iter()
            .map(SharesForNode::weight)
            .sum::<usize>();
        if response_weight < self.t as usize {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let my_shares = SharesForNode::recover(self, &response_shares)?;
        my_shares.verify(message, &challenge)?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.full_public_keys,
        })
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    pub fn my_weight(&self) -> usize {
        self.nodes
            .total_weight_of(std::iter::once(&self.id))
            .unwrap() as usize
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

fn compute_challenge<const BATCH_SIZE: usize>(
    random_oracle: &RandomOracle,
    c: &[G; BATCH_SIZE],
    c_prime: &G,
    e: &MultiRecipientEncryption<EG>,
) -> [S; BATCH_SIZE] {
    let random_oracle = random_oracle.extend(&Challenge.to_string());
    let inner_hash = Sha3_512::digest(bcs::to_bytes(&(c.to_vec(), c_prime, e)).unwrap()).digest;
    array::from_fn(|l| random_oracle.evaluate_to_group_element(&(l, inner_hash.to_vec())))
}

fn compute_challenge_from_message<const BATCH_SIZE: usize>(
    random_oracle: &RandomOracle,
    message: &Message<BATCH_SIZE>,
) -> [S; BATCH_SIZE] {
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
    use std::array;
    use std::collections::HashMap;

    #[test]
    fn test_happy_path() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;
        const BATCH_SIZE: usize = 3;

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
        let dealer: Dealer = Dealer::new(nodes.clone(), t, f, sid.clone()).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| {
                Receiver::new(nodes.clone(), i as u16, t, sid.clone(), secret_key)
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message::<BATCH_SIZE>(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .map(|receiver| {
                (
                    receiver.id,
                    assert_valid(receiver.process_message(&message).unwrap()),
                )
            })
            .collect::<HashMap<_, _>>();

        let secrets = (0..BATCH_SIZE)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.batches[0].shares[l], // Each receiver has a single batch (weight 1)
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
        const BATCH_SIZE: usize = 3;

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
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let sid = b"tbls test".to_vec();
        let dealer: Dealer = Dealer::new(nodes.clone(), t, f, sid.clone()).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| {
                Receiver::new(nodes.clone(), i as u16, t, sid.clone(), secret_key)
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message::<BATCH_SIZE>(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .flat_map(|receiver| {
                assert_valid(receiver.process_message(&message).unwrap())
                    .my_shares
                    .batches
            })
            .collect::<Vec<_>>();

        let secrets = (0..BATCH_SIZE)
            .map(|l| {
                Poly::recover_c0(
                    t,
                    all_shares.iter().take(t as usize).map(|s| Eval {
                        index: s.index,
                        value: s.shares[l],
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
        const BATCH_SIZE: usize = 3;

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

        let dealer: Dealer = Dealer::new(nodes.clone(), t, f, sid.clone()).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| {
                Receiver::new(nodes.clone(), i as u16, t, sid.clone(), secret_key)
            })
            .collect::<Vec<_>>();

        let message = dealer
            .create_message_cheating::<BATCH_SIZE>(&mut rng)
            .unwrap();

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
        let secrets = (0..BATCH_SIZE)
            .map(|l| {
                let shares = all_shares
                    .iter()
                    .map(|(id, s)| (*id, s.my_shares.batches[0].shares[l]))
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
        pub fn create_message_cheating<const BATCH_SIZE: usize>(
            &self,
            rng: &mut impl AllowedRng,
        ) -> FastCryptoResult<Message<BATCH_SIZE>> {
            let polynomials = array::from_fn(|_| Poly::rand(self.t - 1, rng));

            // Compute the (full) public keys for all secrets
            let full_public_keys = polynomials.each_ref().map(|p| G::generator() * p.c0());

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
                            batches: share_ids
                                .into_iter()
                                .map(|index| ShareBatch {
                                    index,
                                    shares: polynomials.each_ref().map(|p_l| p_l.eval(index).value),
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

    fn assert_valid<const BATCH_SIZE: usize>(
        processed_message: ProcessedMessage<BATCH_SIZE>,
    ) -> ReceiverOutput<BATCH_SIZE> {
        if let ProcessedMessage::Valid(output) = processed_message {
            output
        } else {
            panic!("Expected valid message");
        }
    }

    fn assert_complaint<const BATCH_SIZE: usize>(
        processed_message: ProcessedMessage<BATCH_SIZE>,
    ) -> Complaint {
        if let ProcessedMessage::Complaint(complaint) = processed_message {
            complaint
        } else {
            panic!("Expected complaint");
        }
    }
}
