// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute shares for a secret to a set of receivers.
//! A receiver can verify that the secret being shared is the same as a share from a previous round (e.g., the secret key share of a threshold signature).
//!
//! Before the protocol starts, the following setup is needed:
//! * Each receiver has a encryption key pair (ECIES) and these public keys are known to all parties.
//! * The public keys along with the weights of each receiver are known to all parties and defined in the [Nodes] structure.
//! * Define a new [crate::threshold_schnorr::Dealer] with the secrets who begins by calling [crate::threshold_schnorr::Dealer::create_message].

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint::{Complaint, ComplaintResponse};
use crate::threshold_schnorr::Extensions::Encryption;
use crate::threshold_schnorr::{random_oracle_from_sid, EG, G, S};
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::Scalar;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tap::TapFallible;
use tracing::warn;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
#[allow(dead_code)]
pub struct Dealer {
    t: u16,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    secret: Option<S>,
}

#[allow(dead_code)]
pub struct Receiver {
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    commitment: Option<G>,
    sid: Vec<u8>,
    t: u16,
}

/// The message broadcast by the dealer, containing the encrypted shares and the public keys of the nonces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    ciphertext: MultiRecipientEncryption<EG>,
    feldman_commitment: Poly<G>,
}

/// The result of a [Receiver] processing a [Message]: Either valid shares or a complaint.
#[allow(clippy::large_enum_variant)] // Clippy complains because ReceiverOutput can be very small if BATCH_SIZE is small.
pub enum ProcessedMessage {
    Valid(ReceiverOutput),
    Complaint(Complaint),
}

/// The output of a receiver: The shares for each nonce + commitments for the next round.
#[derive(Debug, Clone)]
pub struct ReceiverOutput {
    pub my_shares: SharesForNode,

    /// The commitments to the polynomials will be used for key rotation.
    pub commitments: Vec<Eval<G>>,
}

/// All the shares given to a node. One share per the node's weight.
/// These can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode {
    pub shares: Vec<Eval<S>>,
}

impl SharesForNode {
    /// Get the weight of this node (number of shares it has).
    pub fn weight(&self) -> usize {
        self.shares.len()
    }

    fn verify(&self, message: &Message) -> FastCryptoResult<()> {
        for share in &self.shares {
            message
                .feldman_commitment
                .verify_share(share.index, &share.value)?
        }
        Ok(())
    }

    /// Assuming that enough shares are given, recover the shares for this node.
    fn recover(
        indices: Vec<ShareIndex>,
        threshold: u16,
        other_shares: &[Self],
    ) -> FastCryptoResult<Self> {
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

        let shares = indices
            .into_iter()
            .map(|index| {
                let evaluations = other_shares
                    .iter()
                    .flat_map(|share| share.shares.clone())
                    .collect_vec();
                Poly::interpolate_at_index(index, &evaluations).unwrap()
            })
            .collect_vec();

        Ok(Self { shares })
    }
}

impl BCSSerialized for SharesForNode {}

impl Dealer {
    /// Create a new dealer.
    ///
    /// * `secret`: The secret to share.
    /// * `nodes`: The set of nodes (parties) participating in the protocol, including their public keys and weights.
    /// * `t`: The threshold number of shares required to reconstruct the secret. One party can have multiple shares according to its weight.
    /// * `f`: An upper bound on the number of Byzantine parties counted by weight.
    /// * `sid`: A session identifier that should be unique for each invocation of the protocol but the same for all parties in a single invocation.
    pub fn new(
        secret: Option<S>,
        nodes: Nodes<EG>,
        t: u16,
        f: u16,
        sid: Vec<u8>,
    ) -> FastCryptoResult<Self> {
        // We need to collect t+f confirmations to make sure that at least t honest parties have confirmed.
        if t <= f || t + 2 * f > nodes.total_weight() {
            return Err(InvalidInput);
        }

        Ok(Self {
            secret,
            t,
            nodes,
            sid,
        })
    }

    /// 1. The Dealer samples nonces, generates shares and broadcasts the encrypted shares.
    pub fn create_message<Rng: AllowedRng>(&self, rng: &mut Rng) -> FastCryptoResult<Message> {
        let secret = self.secret.unwrap_or(S::rand(rng));
        let polynomial = Poly::rand_fixed_c0(self.t - 1, secret, rng);

        // Encrypt all shares to the receivers
        let pk_and_msgs = self
            .nodes
            .iter()
            .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
            .map(|(public_key, share_ids)| {
                (
                    public_key,
                    SharesForNode {
                        shares: share_ids
                            .into_iter()
                            .map(|index| polynomial.eval(index))
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

        Ok(Message {
            ciphertext,
            feldman_commitment: polynomial.commit(),
        })
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

impl Receiver {
    /// Create a new receiver.
    ///
    /// * `nodes`: The set of nodes (parties) participating in the protocol, including their public keys and weights.
    /// * `id`: The unique identifier of this receiver. Should match one of the party ids in `nodes`.
    /// * `t`: The threshold number of shares required to reconstruct the secret. One party can have multiple shares according to its weight.
    /// * `sid`: A session identifier that should be unique for each invocation of the protocol but the same for all parties in a single invocation.
    /// * `commitment`: A commitment to the secret being shared. This should be equal to `secret * G` and is typically found as the commitment from a previous round (see [ReceiverOutput]).
    /// * `enc_secret_key`: The private key used to decrypt the shares sent to this receiver.
    pub fn new(
        nodes: Nodes<EG>,
        id: PartyId,
        t: u16,
        sid: Vec<u8>,
        commitment: Option<G>,
        enc_secret_key: PrivateKey<EG>,
    ) -> Self {
        Self {
            id,
            enc_secret_key,
            commitment,
            sid,
            t,
            nodes,
        }
    }

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
    pub fn process_message(&self, message: &Message) -> FastCryptoResult<ProcessedMessage> {
        if message.feldman_commitment.degree() != self.t as usize - 1 {
            return Err(InvalidMessage);
        }

        // If a commitment is given, verify that the secret the dealer is distributing is consistent
        if let Some(c) = &self.commitment {
            if message.feldman_commitment.c0() != c {
                return Err(InvalidMessage);
            }
        }

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
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
            my_shares.verify(message)?;
            Ok(my_shares)
        }) {
            Ok(my_shares) => Ok(ProcessedMessage::Valid(ReceiverOutput {
                my_shares,
                commitments: self.compute_commitments(message),
            })),
            Err(_) => Ok(ProcessedMessage::Complaint(Complaint::create(
                self.id,
                &message.ciphertext,
                &self.enc_secret_key,
                &self.random_oracle(),
                &mut rand::thread_rng(),
            ))),
        }
    }

    /// 4. Upon receiving a complaint, a receiver verifies it and responds with a recovery package for the shares of the accuser.
    pub fn handle_complaint(
        &self,
        message: &Message,
        complaint: &Complaint,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse> {
        complaint.check(
            &self.nodes.node_id_to_node(complaint.accuser_id)?.pk,
            &message.ciphertext,
            &self.random_oracle(),
            |shares: &SharesForNode| shares.verify(message),
        )?;
        Ok(ComplaintResponse::create(
            self.id,
            &message.ciphertext,
            &self.enc_secret_key,
            &self.random_oracle(),
            rng,
        ))
    }

    /// 5. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &Message,
        responses: &[ComplaintResponse],
    ) -> FastCryptoResult<ReceiverOutput> {
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
                        response.decrypt_with_response(
                            &self.random_oracle(),
                            &node.pk,
                            &message.ciphertext,
                        )
                    })
                    .and_then(|shares: SharesForNode| {
                        // Verify the shares are valid
                        shares.verify(message).map(|_| shares)
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
        my_shares.verify(message)?;

        Ok(ReceiverOutput {
            my_shares,
            commitments: self.compute_commitments(message),
        })
    }

    fn compute_commitments(&self, message: &Message) -> Vec<Eval<G>> {
        self.nodes
            .share_ids_iter()
            .map(|index| message.feldman_commitment.eval(index))
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

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

#[cfg(test)]
mod tests {
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::Poly;
    use crate::threshold_schnorr::avss::SharesForNode;
    use crate::threshold_schnorr::avss::{Dealer, Message, Receiver};
    use crate::threshold_schnorr::avss::{ProcessedMessage, ReceiverOutput};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::complaint::Complaint;
    use crate::threshold_schnorr::Extensions::Encryption;
    use crate::threshold_schnorr::{EG, G, S};
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;

    #[test]
    fn test_sharing() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;

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

        let secret = Scalar::rand(&mut rng);
        let previous_round_commitment = G::generator() * secret;

        let dealer: Dealer = Dealer::new(Some(secret), nodes.clone(), t, f, sid.clone()).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, enc_secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    t,
                    sid.clone(),
                    Some(previous_round_commitment),
                    enc_secret_key,
                )
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

        let shares = receivers
            .iter()
            .flat_map(|r| all_shares.get(&r.id).unwrap().my_shares.shares.clone())
            .collect::<Vec<_>>();
        let recovered = Poly::recover_c0(t, shares.iter().take(t as usize)).unwrap();

        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_sharing_two_rounds() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;

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

        let dealer: Dealer = Dealer::new(None, nodes.clone(), t, f, sid.clone()).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, enc_secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    t,
                    sid.clone(),
                    None,
                    enc_secret_key,
                )
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

        // Now, receiver 0 will be the dealer for the next round and will redistribute its first shares as the new secret.
        let shares_for_dealer = all_shares.get(&receivers[0].id).unwrap();
        let secret = shares_for_dealer.my_shares.shares[0].clone();

        let sid2 = b"tbls test 2".to_vec();
        let dealer: Dealer =
            Dealer::new(Some(secret.value), nodes.clone(), t, f, sid2.clone()).unwrap();
        let receivers = receivers
            .into_iter()
            .map(
                |Receiver {
                     id,
                     enc_secret_key,
                     t,
                     nodes,
                     ..
                 }| {
                    let commitment = all_shares.get(&id).unwrap().commitments[0].clone();
                    assert_eq!(commitment.index, secret.index);
                    Receiver::new(
                        nodes,
                        id,
                        t,
                        sid2.clone(),
                        Some(commitment.value),
                        enc_secret_key,
                    )
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
        let shares = receivers
            .iter()
            .flat_map(|r| all_shares.get(&r.id).unwrap().my_shares.shares.clone())
            .collect_vec();
        let recovered = Poly::recover_c0(t, shares.iter().take(t as usize)).unwrap();

        assert_eq!(secret.value, recovered);
    }

    #[test]
    fn test_share_recovery() {
        let t = 3;
        let f = 2;
        let n = 7;

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
        let secret = Scalar::rand(&mut rng);

        let dealer: Dealer = Dealer::new(Some(secret), nodes.clone(), t, f, sid.clone()).unwrap();

        let commitment = G::generator() * secret;

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, enc_secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    i as u16,
                    t,
                    sid.clone(),
                    Some(commitment),
                    enc_secret_key,
                )
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
        let shares = all_shares
            .iter()
            .flat_map(|(_id, s)| s.my_shares.shares.clone())
            .collect_vec();
        let recovered = Poly::recover_c0(t, shares.iter().take(t as usize)).unwrap();

        assert_eq!(recovered, secret);
    }

    impl Dealer {
        pub fn create_message_cheating<Rng: AllowedRng>(
            &self,
            rng: &mut Rng,
        ) -> FastCryptoResult<Message> {
            let secret = self.secret.unwrap_or(S::rand(rng));
            let polynomial = Poly::rand_fixed_c0(self.t - 1, secret, rng);
            let commitment = polynomial.commit();

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
                                .map(|index| polynomial.eval(index))
                                .collect_vec(),
                        }
                        .to_bytes(),
                    )
                })
                .collect_vec();

            // Modify the first share of the first receiver to simulate a cheating dealer
            pk_and_msgs[0].1[7] += 1;

            let ciphertext = MultiRecipientEncryption::encrypt(
                &pk_and_msgs,
                &self.random_oracle().extend(&Encryption.to_string()),
                rng,
            );

            Ok(Message {
                ciphertext,
                feldman_commitment: commitment,
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
