// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute secret shares of a batch of random nonces to a set of receivers.
//!
//! Before the protocol starts, the following setup is needed:
//! * Each receiver has a encryption key pair (ECIES) and these public keys are known to all parties.
//! * The public keys along with the weights of each receiver are known to all parties and defined in the [Nodes] structure.
//! * Define a new [Dealer] with the secrets who begins by calling [Dealer::create_message].

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint::{Complaint, ComplaintResponse};
use crate::threshold_schnorr::ro_extension::Extension::{Challenge, Encryption};
use crate::threshold_schnorr::ro_extension::RandomOracleExtensions;
use crate::threshold_schnorr::{EG, G, S};
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::array;
use std::fmt::Debug;
use tap::TapFallible;
use tracing::warn;

/// This represents a Dealer in the AVSS.
/// There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<const BATCH_SIZE: usize> {
    secrets: [S; BATCH_SIZE],
    threshold: u16,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
}

/// This represents a Receiver in the AVSS who receives shares from the [Dealer].
pub struct Receiver<const BATCH_SIZE: usize> {
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
    threshold: u16,
}

/// The output of a receiver which is a batch of shares + the public keys for all nonces.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<const BATCH_SIZE: usize> {
    pub my_shares: SharesForNode<BATCH_SIZE>,
    pub public_keys: [G; BATCH_SIZE],
}

pub enum ProcessedMessage<const BATCH_SIZE: usize> {
    Valid(ReceiverOutput<BATCH_SIZE>),
    Complaint(Complaint),
}

/// The message broadcast by the dealer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<const BATCH_SIZE: usize> {
    #[serde(with = "BigArray")]
    full_public_keys: [G; BATCH_SIZE],
    blinding_commit: G,
    ciphertext: MultiRecipientEncryption<EG>,
    response: Poly<S>,
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
            .zip(challenge)
            .fold(self.blinding_share, |acc, (r_l, gamma_l)| {
                acc + (*r_l * gamma_l)
            })
            != message.response.eval(self.index).value
        {
            return Err(InvalidInput);
        }
        Ok(())
    }
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

impl<const BATCH_SIZE: usize> SharesForNode<BATCH_SIZE> {
    /// Get the weight of this node (number of shares it has).
    pub fn weight(&self) -> usize {
        self.batches.len()
    }

    /// Get all shares this node has for the <i>i</i>-th secret/nonce in the batch.
    pub fn shares_for_secret(&self, i: usize) -> FastCryptoResult<Vec<Eval<S>>> {
        if i >= BATCH_SIZE {
            return Err(InvalidInput);
        }
        Ok(self
            .batches
            .iter()
            .map(|share_batch| Eval {
                index: share_batch.index,
                value: share_batch.shares[i],
            })
            .collect())
    }

    /// Recover the shares for this node.
    ///
    /// Fails if `other_shares` is empty or if the batch sizes of all shares in `other_shares` are not equal to the expected batch size.
    fn recover(receiver: &Receiver<BATCH_SIZE>, other_shares: &[Self]) -> FastCryptoResult<Self> {
        if other_shares.is_empty() {
            return Err(InvalidInput);
        }

        let batches = receiver
            .my_indices()
            .into_iter()
            .map(|index| {
                let shares = std::array::from_fn(|i| {
                    let evaluations: Vec<Eval<S>> = other_shares
                        .iter()
                        .flat_map(|s| s.shares_for_secret(i).expect("Size checked above"))
                        .collect_vec();
                    Poly::interpolate_at_index(index, &evaluations)
                        .unwrap()
                        .value
                });

                let blinding_share = Poly::interpolate_at_index(
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

impl<const BATCH_SIZE: usize> Dealer<BATCH_SIZE> {
    pub fn new(
        nodes: Nodes<EG>,
        threshold: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
        rng: &mut impl AllowedRng,
    ) -> Self {
        let secrets = array::from_fn(|_| S::rand(rng));
        Self {
            secrets,
            threshold,
            nodes,
            random_oracle,
        }
    }

    /// 1. The Dealer generates shares for the secrets and broadcasts the encrypted shares.
    pub fn create_message<Rng: AllowedRng>(
        &self,
        rng: &mut Rng,
    ) -> FastCryptoResult<Message<BATCH_SIZE>> {
        let polynomials = self
            .secrets
            .map(|c0| Poly::rand_fixed_c0(self.threshold - 1, c0, rng));

        // Compute the (full) public keys for all secrets
        let full_public_keys = polynomials.each_ref().map(|p| G::generator() * p.c0());

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let blinding_poly = Poly::rand(self.threshold - 1, rng);
        let blinding_commit = G::generator() * blinding_poly.c0();

        // Encrypt all shares to the receivers
        let pk_and_msgs = self
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

        let ciphertext =
            MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

        // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
        let challenge = self.compute_challenge(&full_public_keys, &blinding_commit, &ciphertext);
        let mut response = blinding_poly;
        for (p_l, gamma_l) in polynomials.into_iter().zip(&challenge) {
            response += &(p_l * gamma_l);
        }

        println!("Response polynomial: {:?}", response);

        Ok(Message {
            full_public_keys,
            blinding_commit,
            ciphertext,
            response,
        })
    }
}

impl<const BATCH_SIZE: usize> Receiver<BATCH_SIZE> {
    /// 2. Each receiver processes the message, verifies and decrypts its shares.
    ///
    /// If this works, the receiver can store the shares and contribute a signature on the message to a certificate.
    ///
    /// This returns an [InvalidMessage] error if the ciphertext cannot be verified or if the commitments are invalid.
    /// All honest receivers will reject such a message with the same error, and such a message should be ignored.
    ///
    /// If the message is valid but contains invalid shares for this receiver, the call will succeed but will return a [Complaint].
    ///
    /// 3. When 2t+1 signatures have been collected in the certificate, the receivers can now verify the certificate and finish the protocol.
    pub fn process_message(
        &self,
        message: &Message<BATCH_SIZE>,
    ) -> FastCryptoResult<ProcessedMessage<BATCH_SIZE>> {
        // The response polynomial should have degree t - 1, but with some negligible probability (if the highest coefficient is zero) it will be smaller.
        if message.response.degree() != self.threshold as usize - 1 {
            return Err(InvalidMessage);
        }

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        let challenge = self.compute_challenge_from_message(message);
        if G::generator() * message.response.c0()
            != message.blinding_commit
                + G::multi_scalar_mul(&challenge, &message.full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            return Err(InvalidMessage);
        }

        let random_oracle_encryption = self.extension(Encryption);
        message
            .ciphertext
            .verify(&random_oracle_encryption)
            .map_err(|_| InvalidMessage)?;

        // Decrypt my shares
        let plaintext = message.ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        match SharesForNode::from_bytes(&plaintext).and_then(|my_shares| {
            if my_shares.weight() != self.my_weight() {
                return Err(InvalidMessage);
            }
            self.verify_shares(message, &my_shares)?;
            Ok(my_shares)
        }) {
            Ok(my_shares) => Ok(ProcessedMessage::Valid(ReceiverOutput {
                my_shares,
                public_keys: message.full_public_keys,
            })),
            Err(_) => Ok(ProcessedMessage::Complaint(Complaint::create(
                self.id,
                &message.ciphertext,
                &self.enc_secret_key,
                self,
                &mut rand::thread_rng(),
            ))),
        }
    }

    /// 4. Upon receiving a complaint, a receiver verifies it and responds with a recovery package for the shares of the accuser.
    pub fn handle_complaint(
        &self,
        message: &Message<BATCH_SIZE>,
        complaint: &Complaint,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse> {
        complaint.check(
            &self.nodes.node_id_to_node(complaint.accuser_id)?.pk,
            &message.ciphertext,
            self,
            |shares| self.verify_shares(message, shares),
        )?;
        Ok(ComplaintResponse::create(
            self.id,
            &message.ciphertext,
            &self.enc_secret_key,
            self,
            rng,
        ))
    }

    /// 5. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &Message<BATCH_SIZE>,
        responses: &[ComplaintResponse],
    ) -> FastCryptoResult<ReceiverOutput<BATCH_SIZE>> {
        // TODO: This fails if one of the responses has an invalid responder_id. We could probably just ignore those instead.

        // Sanity check that we have enough responses (by weight) to recover the shares.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|response| &response.responder_id))?;
        if total_response_weight < self.threshold + 1 {
            return Err(FastCryptoError::InputTooShort(
                (self.threshold + 1) as usize,
            ));
        }

        let response_shares = responses
            .iter()
            .filter_map(|response| {
                self.nodes
                    .node_id_to_node(response.responder_id)
                    .and_then(|node| {
                        response.decrypt_with_response(self, &node.pk, &message.ciphertext)
                    })
                    .tap_err(|_| {
                        warn!(
                            "Ignoring invalid recovery package from {}",
                            response.responder_id
                        )
                    })
                    .ok()
            })
            .collect_vec();

        // Compute the total weight of the valid responses
        let response_weight = response_shares
            .iter()
            .map(SharesForNode::weight)
            .sum::<usize>();
        if response_weight < (self.threshold + 1) as usize {
            return Err(FastCryptoError::InputTooShort(
                (self.threshold + 1) as usize,
            ));
        }

        let my_shares = SharesForNode::recover(self, &response_shares)?;
        self.verify_shares(message, &my_shares)?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.full_public_keys,
        })
    }

    fn verify_shares(
        &self,
        message: &Message<BATCH_SIZE>,
        nonce_shares: &SharesForNode<BATCH_SIZE>,
    ) -> FastCryptoResult<()> {
        let challenge = self.compute_challenge_from_message(message);
        for shares in &nonce_shares.batches {
            shares.verify(message, &challenge)?;
        }
        Ok(())
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    pub fn my_weight(&self) -> usize {
        self.nodes
            .total_weight_of(std::iter::once(&self.id))
            .unwrap() as usize
    }
}

trait FiatShamirImpl<const BATCH_SIZE: usize>: RandomOracleExtensions {
    fn compute_challenge(
        &self,
        c: &[G; BATCH_SIZE],
        c_prime: &G,
        e: &MultiRecipientEncryption<EG>,
    ) -> [S; BATCH_SIZE] {
        let random_oracle = self.extension(Challenge);
        array::from_fn(|l| random_oracle.evaluate_to_group_element(&(l, c.to_vec(), c_prime, e)))
    }

    fn compute_challenge_from_message(&self, message: &Message<BATCH_SIZE>) -> [S; BATCH_SIZE] {
        self.compute_challenge(
            &message.full_public_keys,
            &message.blinding_commit,
            &message.ciphertext,
        )
    }
}

impl<const BATCH_SIZE: usize> RandomOracleExtensions for Dealer<BATCH_SIZE> {
    fn base(&self) -> &RandomOracle {
        &self.random_oracle
    }
}

impl<const BATCH_SIZE: usize> RandomOracleExtensions for Receiver<BATCH_SIZE> {
    fn base(&self) -> &RandomOracle {
        &self.random_oracle
    }
}

impl<const BATCH_SIZE: usize> FiatShamirImpl<BATCH_SIZE> for Dealer<BATCH_SIZE> {}

impl<const BATCH_SIZE: usize> FiatShamirImpl<BATCH_SIZE> for Receiver<BATCH_SIZE> {}

#[cfg(test)]
mod tests {
    use super::{
        Complaint, Dealer, FiatShamirImpl, Message, ProcessedMessage, Receiver, ReceiverOutput,
        ShareBatch, SharesForNode,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::random_oracle::RandomOracle;
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::ro_extension::Extension::Encryption;
    use crate::threshold_schnorr::ro_extension::RandomOracleExtensions;
    use crate::threshold_schnorr::{EG, G};
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::bls12381::G1Element;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;

    #[test]
    fn test_happy_path() {
        // No complaints, all honest. All have weight 1
        let threshold = 2;
        let n = 3 * threshold + 1;
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

        let random_oracle = RandomOracle::new("tbls test");
        let dealer: Dealer<BATCH_SIZE> =
            Dealer::new(nodes.clone(), threshold, random_oracle.clone(), &mut rng);

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                nodes: nodes.clone(),
            })
            .collect::<Vec<_>>();

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
                    threshold,
                    shares
                        .iter()
                        .take((threshold) as usize)
                        .map(|(id, v)| Eval {
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
        let threshold = 2;
        let weights: Vec<u16> = vec![1, 2, 3, 4];
        const BATCH_SIZE: usize = 3;

        let mut rng = rand::thread_rng();
        let sks = weights
            .iter()
            .map(|_| ecies_v1::PrivateKey::<G1Element>::new(&mut rng))
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

        let random_oracle = RandomOracle::new("tbls test");
        let dealer: Dealer<BATCH_SIZE> =
            Dealer::new(nodes.clone(), threshold, random_oracle.clone(), &mut rng);

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                nodes: nodes.clone(),
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

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
                    threshold,
                    all_shares.iter().take((threshold) as usize).map(|s| Eval {
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
        let threshold = 2;
        let n = 3 * threshold + 1;
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

        let dealer: Dealer<BATCH_SIZE> = Dealer::new(
            nodes.clone(),
            threshold,
            RandomOracle::new("batch avss test"),
            &mut rng,
        );

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                random_oracle: RandomOracle::new("batch avss test"),
                threshold,
                nodes: nodes.clone(),
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
            .map(|r| r.handle_complaint(&message, &complaint, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let shares = receivers[0].recover(&message, &responses).unwrap();
        all_shares.insert(receivers[0].id, shares);

        // Recover with the first f+1 shares, including the reconstructed
        let secrets = (0..BATCH_SIZE)
            .map(|l| {
                let shares = all_shares
                    .iter()
                    .map(|(id, s)| (*id, s.my_shares.batches[0].shares[l]))
                    .collect::<Vec<_>>();
                Poly::recover_c0(
                    threshold,
                    shares
                        .iter()
                        .take((threshold) as usize)
                        .map(|(id, v)| Eval {
                            index: ShareIndex::try_from(id + 1).unwrap(),
                            value: *v,
                        }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(secrets, secrets);
    }

    impl<const BATCH_SIZE: usize> Dealer<BATCH_SIZE> {
        /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
        pub fn create_message_cheating<Rng: AllowedRng>(
            &self,
            rng: &mut Rng,
        ) -> FastCryptoResult<Message<BATCH_SIZE>> {
            let polynomials = self
                .secrets
                .map(|c0| Poly::rand_fixed_c0(self.threshold - 1, c0, rng));

            // Compute the (full) public keys for all secrets
            let full_public_keys = polynomials.each_ref().map(|p| G::generator() * p.c0());

            // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
            let blinding_poly = Poly::rand(self.threshold - 1, rng);
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
            pk_and_msgs[0].1[7] += 1;

            let ciphertext =
                MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

            // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
            let challenge =
                self.compute_challenge(&full_public_keys, &blinding_commit, &ciphertext);
            let mut response = blinding_poly;
            for (p_l, gamma_l) in polynomials.into_iter().zip(&challenge) {
                response += &(p_l * gamma_l);
            }

            Ok(Message {
                full_public_keys,
                blinding_commit,
                ciphertext,
                response,
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
