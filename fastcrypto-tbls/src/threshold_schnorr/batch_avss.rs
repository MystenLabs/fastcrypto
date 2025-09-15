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
use crate::polynomial::{interpolate_at_index, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint::{Complaint, ComplaintResponse};
use crate::threshold_schnorr::ro_extension::Extension::{Challenge, Encryption};
use crate::threshold_schnorr::ro_extension::RandomOracleExtensions;
use crate::threshold_schnorr::EG;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use tap::TapFallible;
use tracing::warn;

/// This represents a Dealer in the AVSS.
/// There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<G: GroupElement> {
    secrets: Vec<G::ScalarType>,
    threshold: u16,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
    _group: PhantomData<G>,
}

/// This represents a Receiver in the AVSS who receives shares from the [Dealer].
pub struct Receiver<G> {
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    batch_size: u16,
    random_oracle: RandomOracle,
    threshold: u16,
    _group: PhantomData<G>,
}

/// The output of a receiver which is a batch of shares + the public keys for all nonces.
/// This can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<G: GroupElement> {
    pub my_shares: SharesForNode<G::ScalarType>,
    pub public_keys: Vec<G>,
}

/// The message broadcast by the dealer.
#[derive(Clone, Debug)]
pub struct Message<G: GroupElement> {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    ciphertext: MultiRecipientEncryption<EG>,
    response: Poly<G::ScalarType>,
}

/// A batch of shares for a single share index, containing shares for each secret and one for the "blinding" polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch<C> {
    /// The index of the share (i.e., the share id).
    pub index: ShareIndex,

    /// The shares for each secret.
    pub shares: Vec<C>,

    /// The share for the blinding polynomial.
    pub blinding_share: C,
}

impl<C: Scalar> ShareBatch<C> {
    /// Verify a batch of shares using the given challenge.
    fn verify<G: GroupElement<ScalarType = C>>(
        &self,
        message: &Message<G>,
        challenge: &[C],
    ) -> FastCryptoResult<()> {
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode<C> {
    pub batches: Vec<ShareBatch<C>>,
}

impl<C: Scalar> SharesForNode<C> {
    /// Get the weight of this node (number of shares it has).
    pub fn weight(&self) -> usize {
        self.batches.len()
    }

    /// Get all shares this node has for the <i>i</i>-th secret/nonce in the batch.
    pub fn shares_for_secret(&self, i: usize) -> FastCryptoResult<Vec<Eval<C>>> {
        if i >= self.batch_size() {
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

    /// Assuming that enough shares are given, recover the shares for this node.
    fn recover(indices: Vec<ShareIndex>, other_shares: &[Self]) -> FastCryptoResult<Self> {
        if other_shares.is_empty() || !other_shares.iter().map(|s| s.batch_size()).all_equal() {
            return Err(InvalidInput);
        }
        let batch_size = other_shares[0].batch_size();

        let batches = indices
            .into_iter()
            .map(|index| {
                let shares = (0..batch_size)
                    .map(|i| {
                        let evaluations: Vec<Eval<C>> = other_shares
                            .iter()
                            .flat_map(|s| s.shares_for_secret(i).expect("Size checked above"))
                            .collect_vec();
                        interpolate_at_index(index, &evaluations).unwrap().value
                    })
                    .collect_vec();

                let blinding_share = interpolate_at_index(
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

    /// The size of the batch, <i>L</i>.
    fn batch_size(&self) -> usize {
        assert!(!self.batches.is_empty());
        self.batches[0].shares.len()
    }
}

impl<C: Scalar + Serialize> BCSSerialized for SharesForNode<C> {}

impl<G: GroupElement + Serialize> Dealer<G>
where
    G::ScalarType: FiatShamirChallenge,
{
    pub fn new(
        batch_size: u16,
        nodes: Nodes<EG>,
        threshold: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
        rng: &mut impl AllowedRng,
    ) -> Self {
        let secrets = (0..batch_size)
            .map(|_| G::ScalarType::rand(rng))
            .collect_vec();
        Self {
            secrets,
            threshold,
            nodes,
            random_oracle,
            _group: PhantomData,
        }
    }

    /// 1. The Dealer generates shares for the secrets and broadcasts the encrypted shares.
    pub fn create_message<Rng: AllowedRng>(&self, rng: &mut Rng) -> FastCryptoResult<Message<G>> {
        let polynomials = self
            .secrets
            .iter()
            .map(|c0| Poly::rand_fixed_c0(self.threshold, *c0, rng))
            .collect_vec();

        // Compute the (full) public keys for all secrets
        let full_public_keys = polynomials
            .iter()
            .map(|p| G::generator() * p.c0())
            .collect_vec();

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let blinding_poly = Poly::rand(self.threshold, rng);
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
                                shares: polynomials
                                    .iter()
                                    .map(|p_l| p_l.eval(index).value)
                                    .collect(),
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

        Ok(Message {
            full_public_keys,
            blinding_commit,
            ciphertext,
            response,
        })
    }
}

impl<G: GroupElement + Serialize + MultiScalarMul> Receiver<G>
where
    G::ScalarType: FiatShamirChallenge,
{
    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    pub fn my_weight(&self) -> usize {
        self.nodes
            .total_weight_of(std::iter::once(&self.id))
            .unwrap() as usize
    }

    /// 2. Each receiver processes the message, verifies and decrypts its shares. If this works, the shares are stored and the receiver can contribute a signature on the message to a certificate.
    pub fn process_message(&self, message: &Message<G>) -> FastCryptoResult<ReceiverOutput<G>> {
        if message.response.degree() > self.threshold as usize {
            return Err(InvalidInput);
        }

        let random_oracle_encryption = self.extension(Encryption);

        message.ciphertext.verify(&random_oracle_encryption)?;
        let plaintext = message.ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        let my_shares = SharesForNode::from_bytes(&plaintext)?;

        // Check that we received the correct number of shares.
        if my_shares.weight() != self.my_weight() {
            return Err(InvalidInput);
        }

        self.verify_shares(message, &my_shares)?;

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        let challenge = self.compute_challenge_from_message(message);
        if G::generator() * message.response.c0()
            != message.blinding_commit + G::multi_scalar_mul(&challenge, &message.full_public_keys)?
        {
            return Err(InvalidInput);
        }

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.full_public_keys.clone(),
        })
    }

    /// 3. When 2t+1 signatures have been collected in the certificate, the receivers can now verify it.
    ///    If a receiver is not in the certificate, because it could not decrypt or verify its shares, it should broadcast a [Complaint].
    /// 4. Upon receiving a complaint, a receiver verifies it and responds with a recovery package for the shares of the accuser.
    pub fn handle_complaint(
        &self,
        message: &Message<G>,
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
        message: &Message<G>,
        responses: &[ComplaintResponse],
    ) -> FastCryptoResult<ReceiverOutput<G>> {
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

        let my_shares = SharesForNode::recover(self.my_indices(), &response_shares)?;
        self.verify_shares(message, &my_shares)?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.full_public_keys.clone(),
        })
    }

    fn verify_shares(
        &self,
        message: &Message<G>,
        nonce_shares: &SharesForNode<G::ScalarType>,
    ) -> FastCryptoResult<()> {
        let challenge = self.compute_challenge_from_message(message);
        for shares in &nonce_shares.batches {
            if shares.shares.len() != self.batch_size as usize {
                return Err(InvalidInput);
            }
            shares.verify(message, &challenge)?;
        }
        Ok(())
    }
}

trait FiatShamirImpl<G: GroupElement + Serialize>: RandomOracleExtensions
where
    G::ScalarType: FiatShamirChallenge,
{
    fn compute_challenge(
        &self,
        c: &[G],
        c_prime: &G,
        e: &MultiRecipientEncryption<EG>,
    ) -> Vec<G::ScalarType> {
        let random_oracle = self.extension(Challenge);
        c.iter()
            .enumerate()
            .map(|(l, c_l)| random_oracle.evaluate(&(l, c_l, c_prime, e)))
            .map(|bytes| G::ScalarType::fiat_shamir_reduction_to_group_element(&bytes))
            .collect_vec()
    }

    fn compute_challenge_from_message(&self, message: &Message<G>) -> Vec<G::ScalarType> {
        self.compute_challenge(
            message.full_public_keys.as_slice(),
            &message.blinding_commit,
            &message.ciphertext,
        )
    }
}

impl<G: GroupElement> RandomOracleExtensions for Dealer<G> {
    fn base(&self) -> &RandomOracle {
        &self.random_oracle
    }
}

impl<G: GroupElement> RandomOracleExtensions for Receiver<G> {
    fn base(&self) -> &RandomOracle {
        &self.random_oracle
    }
}

impl<G: GroupElement + Serialize> FiatShamirImpl<G> for Dealer<G> where
    G::ScalarType: FiatShamirChallenge
{
}

impl<G: GroupElement + Serialize> FiatShamirImpl<G> for Receiver<G> where
    G::ScalarType: FiatShamirChallenge
{
}

#[cfg(test)]
mod tests {
    use super::{Complaint, Dealer, FiatShamirImpl, Message, Receiver, ShareBatch, SharesForNode};
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::random_oracle::RandomOracle;
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::ro_extension::Extension::Encryption;
    use crate::threshold_schnorr::ro_extension::RandomOracleExtensions;
    use crate::threshold_schnorr::EG;
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::bls12381::G1Element;
    use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::marker::PhantomData;

    #[test]
    fn test_happy_path() {
        // No complaints, all honest. All have weight 1
        let threshold = 2;
        let n = 3 * threshold + 1;
        let batch_size = 3;

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
        let dealer: Dealer<G1Element> = Dealer::new(
            batch_size,
            nodes.clone(),
            threshold,
            random_oracle.clone(),
            &mut rng,
        );

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                batch_size,
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                nodes: nodes.clone(),
                _group: PhantomData,
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .map(|receiver| (receiver.id, receiver.process_message(&message).unwrap()))
            .collect::<HashMap<_, _>>();

        let secrets = (0..batch_size)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.batches[0].shares[l as usize], // Each receiver has a single batch (weight 1)
                        )
                    })
                    .collect::<Vec<_>>();
                Poly::recover_c0(
                    threshold + 1,
                    shares
                        .iter()
                        .take((threshold + 1) as usize)
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

    #[test]
    #[allow(clippy::single_match)]
    fn test_happy_path_non_equal_weights() {
        // No complaints, all honest
        let threshold = 2;
        let weights: Vec<u16> = vec![1, 2, 3, 4];
        let batch_size = 3;

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
        let dealer: Dealer<G1Element> = Dealer::new(
            batch_size,
            nodes.clone(),
            threshold,
            random_oracle.clone(),
            &mut rng,
        );

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                batch_size,
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                nodes: nodes.clone(),
                _group: PhantomData,
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .flat_map(|receiver| {
                receiver
                    .process_message(&message)
                    .unwrap()
                    .my_shares
                    .batches
            })
            .collect::<Vec<_>>();

        let secrets = (0..batch_size)
            .map(|l| {
                Poly::recover_c0(
                    threshold + 1,
                    all_shares
                        .iter()
                        .take((threshold + 1) as usize)
                        .map(|s| Eval {
                            index: s.index,
                            value: s.shares[l as usize],
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
        let batch_size = 3;

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

        let dealer: Dealer<G1Element> = Dealer::new(
            batch_size,
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
                batch_size,
                random_oracle: RandomOracle::new("batch avss test"),
                threshold,
                _group: PhantomData,
                nodes: nodes.clone(),
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message_cheating(&mut rng).unwrap();

        let mut all_shares = receivers
            .iter()
            .map(|receiver| receiver.process_message(&message).map(|s| (receiver.id, s)))
            .filter_map(Result::ok)
            .collect::<HashMap<_, _>>();
        assert!(all_shares.get(&0).is_none());

        let complaint = Complaint::create(
            receivers[0].id,
            &message.ciphertext,
            &receivers[0].enc_secret_key,
            &receivers[0],
            &mut rng,
        )
        .unwrap();
        let responses = receivers
            .iter()
            .skip(1)
            .map(|r| r.handle_complaint(&message, &complaint, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let shares = receivers[0].recover(&message, &responses).unwrap();
        all_shares.insert(0, shares);

        // Recover with the first f+1 shares, including the reconstructed
        let secrets = (0..batch_size)
            .map(|l| {
                let shares = all_shares
                    .iter()
                    .map(|(id, s)| (*id, s.my_shares.batches[0].shares[l as usize]))
                    .collect::<Vec<_>>();
                Poly::recover_c0(
                    threshold + 1,
                    shares
                        .iter()
                        .take((threshold + 1) as usize)
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

    impl<G: GroupElement + Serialize> Dealer<G>
    where
        G::ScalarType: FiatShamirChallenge,
    {
        /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
        pub fn create_message_cheating<Rng: AllowedRng>(
            &self,
            rng: &mut Rng,
        ) -> FastCryptoResult<Message<G>> {
            let polynomials = self
                .secrets
                .iter()
                .map(|c0| Poly::rand_fixed_c0(self.threshold, *c0, rng))
                .collect_vec();

            // Compute the (full) public keys for all secrets
            let full_public_keys = polynomials
                .iter()
                .map(|p| G::generator() * p.c0())
                .collect_vec();

            // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
            let blinding_poly = Poly::rand(self.threshold, rng);
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
                                    shares: polynomials
                                        .iter()
                                        .map(|p_l| p_l.eval(index).value)
                                        .collect(),
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
}
