// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute secret shares to a set of receivers.
//! A receiver can verify that the secret being shared is the same as a share from a previous round (e.g., the secret key share of a threshold signature).
//!
//! Before the protocol starts, the following setup is needed:
//! * Each receiver has a encryption key pair (ECIES) and these public keys are known to all parties.
//! * The public keys along with the weights of each receiver are known to all parties and defined in the [Nodes] structure.
//! * Define a new [crate::threshold_schnorr::batch_avss::Dealer] with the secrets who begins by calling [crate::threshold_schnorr::batch_avss::Dealer::create_message].

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint::{Complaint, ComplaintResponse};
use crate::threshold_schnorr::ro_extension::Extension::Encryption;
use crate::threshold_schnorr::ro_extension::RandomOracleExtensions;
use crate::threshold_schnorr::{EG, G, S};
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::array;
use std::collections::HashMap;
use tap::TapFallible;
use tracing::warn;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<const BATCH_SIZE: usize> {
    t: u16,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
    secrets: [S; BATCH_SIZE],
}

pub struct Receiver<const BATCH_SIZE: usize> {
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    commitments: [G; BATCH_SIZE], // Commitments to the polynomials of the previous round, used to verify the shares
    random_oracle: RandomOracle,
    t: u16,
}

/// The output of a receiver: The shares for each nonce.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<const BATCH_SIZE: usize> {
    pub my_shares: SharesForNode<BATCH_SIZE>,

    /// The commitments to the polynomials for the next round.
    pub commitments: HashMap<ShareIndex, [G; BATCH_SIZE]>,
}

/// The message broadcast by the dealer, containing the encrypted shares and the public keys of the nonces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<const BATCH_SIZE: usize> {
    ciphertext: MultiRecipientEncryption<EG>,

    #[serde(with = "BigArray")]
    feldman_commitments: [Poly<G>; BATCH_SIZE], // Commitments to the polynomials for each nonce
}

pub enum ProcessedMessage<const BATCH_SIZE: usize> {
    Valid(ReceiverOutput<BATCH_SIZE>),
    Complaint(Complaint),
}

/// The shares for a receiver, containing shares for each nonce and one for the combined polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch<const BATCH_SIZE: usize> {
    /// The index of the share (i.e., the share id).
    pub index: ShareIndex,

    /// The shares for each secret.
    #[serde(with = "BigArray")]
    pub shares: [S; BATCH_SIZE],
}

impl<const BATCH_SIZE: usize> ShareBatch<BATCH_SIZE> {
    fn verify(&self, message: &Message<BATCH_SIZE>) -> FastCryptoResult<()> {
        for (share, c) in self.shares.iter().zip(message.feldman_commitments.iter()) {
            c.verify_share(self.index, share)?;
        }
        Ok(())
    }
}

/// All the shares given to a node -- one batch per share index/weight.
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

    /// Assuming that enough shares are given, recover the shares for this node.
    fn recover(
        indices: Vec<ShareIndex>,
        threshold: u16,
        other_shares: &[Self],
    ) -> FastCryptoResult<Self> {
        if other_shares.is_empty() {
            return Err(InvalidInput);
        }

        // Compute the total weight of the valid responses
        let response_weight = other_shares
            .iter()
            .map(SharesForNode::weight)
            .sum::<usize>();
        if response_weight < threshold as usize {
            return Err(FastCryptoError::GeneralError(
                "Not enough valid responses".to_string(),
            ));
        }

        let batches = indices
            .into_iter()
            .map(|index| {
                let shares = array::from_fn(|i| {
                    let evaluations: Vec<Eval<S>> = other_shares
                        .iter()
                        .flat_map(|s| s.shares_for_secret(i).unwrap())
                        .collect_vec();
                    Poly::interpolate_at_index(index, &evaluations)
                        .unwrap()
                        .value
                });
                Ok(ShareBatch { index, shares })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self { batches })
    }
}

impl<const BATCH_SIZE: usize> BCSSerialized for SharesForNode<BATCH_SIZE> {}

impl<const BATCH_SIZE: usize> Dealer<BATCH_SIZE> {
    pub fn new(
        secrets: [S; BATCH_SIZE],
        nodes: Nodes<EG>,
        t: u16, // The number of parties that are needed to reconstruct the full key/signature
        f: u16, // Upper bound for the number of Byzantine parties
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
    ) -> FastCryptoResult<Self> {
        // We need to collect t+f confirmations to make sure that at least t honest parties have confirmed.
        if t <= f || t + 2 * f > nodes.total_weight() {
            return Err(InvalidInput);
        }

        Ok(Self {
            secrets,
            t,
            nodes,
            random_oracle,
        })
    }

    /// 1. The Dealer samples nonces, generates shares and broadcasts the encrypted shares.
    pub fn create_message<Rng: AllowedRng>(
        &self,
        rng: &mut Rng,
    ) -> FastCryptoResult<Message<BATCH_SIZE>> {
        let polynomials = self
            .secrets
            .map(|c0| Poly::rand_fixed_c0(self.t - 1, c0, rng));

        let commitments = polynomials.each_ref().map(Poly::commit);

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
                            })
                            .collect_vec(),
                    },
                )
            })
            .map(|(pk, shares)| (pk, shares.to_bytes()))
            .collect_vec();

        let ciphertext =
            MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

        Ok(Message {
            ciphertext,
            feldman_commitments: commitments,
        })
    }
}

impl<const BATCH_SIZE: usize> Receiver<BATCH_SIZE> {
    /// 2. Each receiver processes the message, verifies and decrypts its shares.
    ///
    /// If this works, the receiver can store the shares and contribute a signature on the message to a certificate.
    ///
    /// This returns an [InvalidMessage] error if the ciphertext cannot be verified, if the commitments are invalid or do not match the commitments from a previous round.
    /// All honest receivers will reject such a message with the same error, and such a message should be ignored.
    ///
    /// If the message is valid but contains invalid shares for this receiver, the call will succeed but will return a [Complaint].
    ///
    /// 3. When t+f signatures have been collected in the certificate, the receivers can now verify the certificate and finish the protocol.
    pub fn process_message(
        &self,
        message: &Message<BATCH_SIZE>,
    ) -> FastCryptoResult<ProcessedMessage<BATCH_SIZE>> {
        if message
            .feldman_commitments
            .iter()
            .any(|c| c.degree() != self.t as usize - 1)
        {
            return Err(InvalidMessage);
        }

        // Verify that the secrets the dealer is distributing are consistent with the commitments.
        for (commitment, previous) in message.feldman_commitments.iter().zip(&self.commitments) {
            if commitment.c0() != previous {
                return Err(InvalidMessage);
            }
        }

        let random_oracle_encryption = self.extension(Encryption);
        message
            .ciphertext
            .verify(&random_oracle_encryption)
            .map_err(|_| InvalidMessage)?;

        let plaintext = message.ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        match SharesForNode::from_bytes(&plaintext).and_then(|my_shares| {
            if my_shares.weight() != self.my_weight() {
                return Err(InvalidInput);
            }
            self.verify_shares(message, &my_shares)?;
            Ok(my_shares)
        }) {
            Ok(my_shares) => Ok(ProcessedMessage::Valid(ReceiverOutput {
                my_shares,
                commitments: self.compute_commitments(&message),
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

    /// 5. Upon receiving f+1 valid responses to a complaint, the accuser can recover its shares.
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
        if total_response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
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

        let my_shares = SharesForNode::recover(self.my_indices(), self.t, &response_shares)?;
        self.verify_shares(message, &my_shares)?;

        Ok(ReceiverOutput {
            my_shares,
            commitments: self.compute_commitments(&message),
        })
    }

    /// Helper function to verify the consistency of the shares, e.g., that <i>r' + &Sigma;<sub>l</sub> &gamma;<sub>l</sub> r<sub>li</sub> = p''(i)<i>.
    fn verify_shares(
        &self,
        message: &Message<BATCH_SIZE>,
        shares: &SharesForNode<BATCH_SIZE>,
    ) -> FastCryptoResult<()> {
        // Verify shares against commitments.
        // TODO: Use MSM for this
        for batch in shares.batches.iter() {
            batch.verify(message)?;
        }
        Ok(())
    }

    fn compute_commitments(
        &self,
        message: &Message<BATCH_SIZE>,
    ) -> HashMap<ShareIndex, [G; BATCH_SIZE]> {
        self.nodes
            .share_ids_iter()
            .map(|index| {
                let commitments = message
                    .feldman_commitments
                    .iter()
                    .map(|c| c.eval(index).value)
                    .collect_vec();
                (index, commitments.try_into().expect("correct length"))
            })
            .collect()
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

#[cfg(test)]
mod tests {
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::random_oracle::RandomOracle;
    use crate::threshold_schnorr::avss::{Dealer, Message, RandomOracleExtensions, Receiver};
    use crate::threshold_schnorr::avss::{ProcessedMessage, ReceiverOutput};
    use crate::threshold_schnorr::avss::{ShareBatch, SharesForNode};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::complaint::Complaint;
    use crate::threshold_schnorr::ro_extension::Extension::Encryption;
    use crate::threshold_schnorr::{EG, G};
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::array;
    use std::collections::HashMap;

    #[test]
    fn test_sharing() {
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

        let random_oracle = RandomOracle::new("tbls test");

        let secrets = array::from_fn(|_| Scalar::rand(&mut rng));

        // TODO: Add test with multiple rounds. For now mock a commitment to the previous round's secret.
        let previous_round_commitments = secrets.map(|nonce| G::generator() * nonce);

        let dealer: Dealer<BATCH_SIZE> = Dealer {
            secrets,
            t,
            nodes: nodes.clone(),
            random_oracle,
        };

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, enc_secret_key)| Receiver {
                id: id as u16,
                enc_secret_key,
                commitments: previous_round_commitments,
                random_oracle: RandomOracle::new("tbls test"),
                t,
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
                            all_shares.get(&r.id).unwrap().my_shares.batches[0].shares[l],
                        )
                    })
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

    #[test]
    fn test_sharing_two_rounds() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;
        const BATCH_SIZE: usize = 7;

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

        let secrets = array::from_fn(|_| Scalar::rand(&mut rng));

        // Mock a commitment to the previous round's secret.
        let previous_round_commitments = secrets.map(|nonce| G::generator() * nonce);
        let dealer: Dealer<BATCH_SIZE> = Dealer {
            secrets,
            t,
            nodes: nodes.clone(),
            random_oracle,
        };

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, enc_secret_key)| Receiver {
                id: id as u16,
                enc_secret_key,
                commitments: previous_round_commitments,
                random_oracle: RandomOracle::new("tbls test"),
                t,
                nodes: nodes.clone(),
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

        // Get shares for all receivers
        let all_shares = receivers
            .iter()
            .map(|receiver| {
                (
                    receiver.id,
                    assert_valid(receiver.process_message(&message).unwrap()),
                )
            })
            .collect::<HashMap<_, _>>();

        // Now, receiver 0 will be the dealer for the next round and will redistribute its shares as the new secrets.
        let shares_for_dealer = all_shares.get(&receivers[0].id).unwrap();
        let secrets = shares_for_dealer.my_shares.batches[0].shares;
        let share_index = ShareIndex::new(1).unwrap(); // The index of the shares from the previous round

        let dealer: Dealer<BATCH_SIZE> = Dealer {
            secrets,
            t,
            nodes: nodes.clone(),
            random_oracle: RandomOracle::new("tbls test 2"),
        };

        let receivers = receivers
            .into_iter()
            .map(
                |Receiver {
                     id,
                     enc_secret_key,
                     t,
                     nodes,
                     ..
                 }| Receiver {
                    id,
                    enc_secret_key,
                    commitments: all_shares
                        .get(&id)
                        .unwrap()
                        .commitments
                        .get(&share_index)
                        .unwrap()
                        .clone(),
                    random_oracle: RandomOracle::new("tbls test 2"),
                    t,
                    nodes,
                },
            )
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

        // Shares for all receivers
        let all_shares = receivers
            .iter()
            .map(|receiver| {
                (
                    receiver.id,
                    assert_valid(receiver.process_message(&message).unwrap()),
                )
            })
            .collect::<HashMap<_, _>>();

        // Recover secrets
        let recovered = (0..BATCH_SIZE)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.batches[0].shares[l],
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

        assert_eq!(secrets.to_vec(), recovered);
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

        let random_oracle = RandomOracle::new("tbls test");
        let secrets = array::from_fn(|_| Scalar::rand(&mut rng));

        let dealer: Dealer<BATCH_SIZE> = Dealer {
            secrets,
            t,
            nodes: nodes.clone(),
            random_oracle,
        };

        let commitments = secrets.map(|nonce| G::generator() * nonce);

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, enc_secret_key)| Receiver {
                id: i as u16,
                enc_secret_key,
                commitments,
                random_oracle: RandomOracle::new("tbls test"),
                t,
                nodes: nodes.clone(),
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message_cheating(&mut rng).unwrap();

        let mut all_shares = receivers
            .iter()
            .map(|receiver| {
                receiver
                    .process_message(&message)
                    .map(|s| (receiver.id, s))
                    .unwrap()
            })
            .collect::<HashMap<_, _>>();

        // The first receiver complains
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
        let recovered = (0..BATCH_SIZE)
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

        assert_eq!(recovered, secrets);
    }

    impl<const BATCH_SIZE: usize> Dealer<BATCH_SIZE> {
        pub fn create_message_cheating<Rng: AllowedRng>(
            &self,
            rng: &mut Rng,
        ) -> FastCryptoResult<Message<BATCH_SIZE>> {
            let polynomials = self
                .secrets
                .map(|c0| Poly::rand_fixed_c0(self.t - 1, c0, rng));

            let commitments = polynomials.each_ref().map(Poly::commit);

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
                                })
                                .collect_vec(),
                        },
                    )
                })
                .map(|(pk, shares)| (pk, shares.to_bytes()))
                .collect_vec();

            // Modify the first share of the first receiver to simulate a cheating dealer
            pk_and_msgs[0].1[7] += 1;

            let ciphertext =
                MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

            Ok(Message {
                ciphertext,
                feldman_commitments: commitments,
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
