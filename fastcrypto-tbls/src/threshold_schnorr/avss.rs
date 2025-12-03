// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute shares for a secret to a set of receivers.
//! A receiver can verify that the secret being shared is the same as a share from a previous round (e.g., the secret key share of a threshold signature).
//!
//! Before the protocol starts, the following setup is needed:
//! * Each receiver has an encryption key pair (ECIES) and these public keys are known to all parties.
//! * The public keys along with the weights of each receiver are known to all parties and defined in the [Nodes] structure.
//! * Define a new [crate::threshold_schnorr::Dealer] with the secrets, who begins by calling [crate::threshold_schnorr::Dealer::create_message].

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint::{Complaint, ComplaintResponse};
use crate::threshold_schnorr::Extensions::Encryption;
use crate::threshold_schnorr::{random_oracle_from_sid, EG, G, S};
use crate::types;
use crate::types::{IndexedValue, ShareIndex};
use fastcrypto::error::FastCryptoError::{
    InputLengthWrong, InvalidInput, InvalidMessage, NotEnoughWeight,
};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Add;

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
    Valid(PartialOutput),
    Complaint(Complaint),
}

/// The output of a receiver after a single instance of AVSS: The shares for each nonce + commitments for the next round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialOutput {
    pub my_shares: SharesForNode,

    /// The commitments to the polynomials will be used for key rotation.
    pub feldman_commitment: Poly<G>,
}

/// The output after combining multiple `PartialOutputs`,
/// either using [PartialOutput::complete_dkg] or [PartialOutput::complete_key_rotation].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverOutput {
    pub my_shares: SharesForNode,

    /// The commitments to the polynomials will be used for key rotation.
    pub commitments: Vec<Eval<G>>,

    /// The public key corresponding to the secret the dealer is sharing.
    pub vk: G,
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
                Poly::recover_at(index, &evaluations).unwrap()
            })
            .collect_vec();

        Ok(Self { shares })
    }
}

impl BCSSerialized for SharesForNode {}

impl Dealer {
    /// Create a new dealer.
    ///
    /// * `secret`: The secret to share. If None, a random secret will be generated.
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

        // Evaluate all shares
        let all_shares = polynomial.eval_range(self.nodes.total_weight())?;

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
                            .map(|index| all_shares[index].clone())
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
    /// * `commitment`: A commitment to the secret being shared. This should be equal to `secret * G` and is typically found as the commitment from a previous round (see [ReceiverOutput]). If None, no consistency check will be performed.
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

    pub fn id(&self) -> PartyId {
        self.id
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
            Ok(my_shares) => Ok(ProcessedMessage::Valid(PartialOutput {
                my_shares,
                feldman_commitment: message.feldman_commitment.clone(),
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

    /// 4. Upon receiving a complaint, a receiver verifies it and responds with its shares.
    pub fn handle_complaint(
        &self,
        message: &Message,
        complaint: &Complaint,
        my_output: &PartialOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        complaint.check(
            &self.nodes.node_id_to_node(complaint.accuser_id)?.pk,
            &message.ciphertext,
            &self.random_oracle(),
            |shares: &SharesForNode| shares.verify(message),
        )?;
        Ok(ComplaintResponse::create(
            self.id,
            my_output.my_shares.clone(),
        ))
    }

    /// 5. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &Message,
        responses: Vec<ComplaintResponse<SharesForNode>>,
    ) -> FastCryptoResult<PartialOutput> {
        // Sanity check that we have enough responses (by weight) to recover the shares.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|response| &response.responder_id))?;
        if total_response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        // Filter responses with invalid shares
        let valid_responses = responses
            .into_iter()
            .filter(|response| response.shares.verify(message).is_ok())
            .collect_vec();

        // Compute the total weight of the valid responses
        let valid_response_weight = self.nodes.total_weight_of(
            valid_responses
                .iter()
                .map(|response| &response.responder_id),
        )?;
        if valid_response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let valid_shares = valid_responses
            .into_iter()
            .map(|response| response.shares)
            .collect_vec();

        let my_shares = SharesForNode::recover(self.my_indices(), self.t, &valid_shares)?;
        my_shares.verify(message)?;

        Ok(PartialOutput {
            my_shares,
            feldman_commitment: message.feldman_commitment.clone(),
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

impl ReceiverOutput {
    pub fn share_for_index(&self, index: ShareIndex) -> Option<&Eval<S>> {
        self.my_shares.shares.iter().find(|s| s.index == index)
    }

    pub fn commitment_for_index(&self, index: ShareIndex) -> Option<&Eval<G>> {
        self.commitments.iter().find(|c| c.index == index)
    }

    /// Combine multiple outputs from different dealers into a single output by summing.
    /// This is used after a successful AVSS used for DKG to combine the shares from multiple dealers into a single share for each party.
    /// Panics if the given `ReceiverOutput`s are not compatible (same weight, same indices, same number of commitments)
    /// Returns the combined output, including the joint verifying key
    pub fn complete_dkg(
        t: u16,
        nodes: &Nodes<EG>,
        outputs: HashMap<PartyId, PartialOutput>,
    ) -> FastCryptoResult<Self> {
        if nodes.total_weight_of(outputs.keys())? < t {
            return Err(NotEnoughWeight(t as usize));
        }

        let outputs = outputs.into_values().collect_vec();

        // Sanity check: Outputs cannot be empty and all outputs must have the same weight.
        if !outputs.iter().map(|output| output.weight()).all_equal() {
            return Err(InvalidInput);
        }

        outputs
            .into_iter()
            .reduce(|acc, output| acc + output)
            .ok_or(InvalidInput)
            .map(|o| o.into_receiver_output(nodes))
    }

    /// Interpolate shares from multiple outputs to create new shares for the given indices.
    /// This is used after key rotation where each party shares their shares from the previous round as the new secret.
    /// After collecting t such shares from different parties, new shares for the given indices can be created using this function.
    ///
    /// The `outputs` parameter is a list of `IndexedValue`, where each `value` is the output of an
    /// AVSS instance and the corresponding `index` indicates which share from the previous round
    /// the AVSS instance was sharing.
    pub fn complete_key_rotation(
        t: u16,
        my_id: PartyId,
        nodes: &Nodes<EG>,
        outputs: &[IndexedValue<PartialOutput>],
    ) -> FastCryptoResult<Self> {
        if outputs.len() != t as usize {
            return Err(InputLengthWrong(t as usize));
        }
        if outputs.is_empty() {
            return Err(InvalidInput);
        }

        let my_indices = nodes.share_ids_of(my_id)?;

        let outputs = outputs
            .iter()
            .map(|output| Eval {
                index: output.index,
                value: output.clone().value.into_receiver_output(nodes),
            })
            .collect_vec();

        let lagrange_coefficients: Vec<Vec<S>> = my_indices
            .iter()
            .map(|&index| {
                let coeffs = Poly::get_lagrange_coefficients_for_c0(
                    t,
                    outputs.iter().map(|output| Eval {
                        index: output.index,
                        value: output.value.share_for_index(index).unwrap().value,
                    }),
                )
                .unwrap();
                coeffs.1.iter().map(|s| s * coeffs.0).collect_vec() // Include denominator here
            })
            .collect_vec();

        let shares = my_indices
            .iter()
            .zip(&lagrange_coefficients)
            .map(|(&index, coeffs)| Eval {
                index,
                value: S::sum(outputs.iter().zip(coeffs).map(|(output, coeff)| {
                    output.value.share_for_index(index).unwrap().clone().value * coeff
                })),
            })
            .collect();

        // TODO: use msm
        let commitments = nodes
            .share_ids_iter()
            .map(|index| Eval {
                index,
                value: G::sum(outputs.iter().enumerate().zip(&lagrange_coefficients).map(
                    |((i, output), coeffs)| {
                        output.value.commitment_for_index(index).unwrap().value * coeffs[i]
                    },
                )),
            })
            .collect_vec();

        let vk = G::multi_scalar_mul(
            &lagrange_coefficients[0],
            outputs
                .iter()
                .map(|o| o.value.vk)
                .collect_vec().as_slice(),
        )?;

        Ok(Self {
            my_shares: SharesForNode { shares },
            commitments,
            vk,
        })
    }
}

impl PartialOutput {
    fn into_receiver_output(self, nodes: &Nodes<EG>) -> ReceiverOutput {
        ReceiverOutput {
            commitments: self.compute_all_commitments(
                ShareIndex::new(nodes.total_weight()).expect("Weight is non-zero"),
            ),
            vk: self.feldman_commitment.into_c0(),
            my_shares: self.my_shares,
        }
    }

    fn compute_all_commitments(&self, to: ShareIndex) -> Vec<Eval<G>> {
        self.feldman_commitment
            .eval_range(to.get())
            .unwrap()
            .to_vec()
    }

    #[cfg(test)]
    fn commitment_for_index(&self, index: ShareIndex) -> Eval<G> {
        self.feldman_commitment.eval(index)
    }

    fn weight(&self) -> usize {
        self.my_shares.weight()
    }
}

impl Add<Self> for PartialOutput {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let shares = self
            .my_shares
            .shares
            .iter()
            .zip_eq(&rhs.my_shares.shares)
            .map(types::sum)
            .collect_vec();
        Self {
            my_shares: SharesForNode { shares },
            feldman_commitment: self.feldman_commitment + &rhs.feldman_commitment,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::Poly;
    use crate::threshold_schnorr::avss::{Dealer, Message, Receiver};
    use crate::threshold_schnorr::avss::{PartialOutput, ProcessedMessage};
    use crate::threshold_schnorr::avss::{ReceiverOutput, SharesForNode};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::complaint::Complaint;
    use crate::threshold_schnorr::tests::restrict;
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
                    let commitment = all_shares
                        .get(&id)
                        .unwrap()
                        .commitment_for_index(secret.index);
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
            .map(|r| {
                r.handle_complaint(&message, &complaint, all_shares.get(&r.id).unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let shares = receivers[0].recover(&message, responses).unwrap();
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
            pk_and_msgs[0].1[7] ^= 1;

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

    #[test]
    fn test_dkg_simple() {
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
                .map(|(id, sk)| Node {
                    id: id as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        // Map from each party to the list of outputs it has received
        let mut outputs = HashMap::<PartyId, HashMap<PartyId, PartialOutput>>::new();
        for node in nodes.iter() {
            outputs.insert(node.id, HashMap::new());
        }

        let mut messages = Vec::new();

        // Each node acts as dealer in the DKG
        for node in nodes.iter() {
            let sid = format!("dkg-test-session-{}", node.id).into_bytes();
            let dealer: Dealer = Dealer::new(None, nodes.clone(), t, f, sid.clone()).unwrap();
            let receivers = sks
                .iter()
                .enumerate()
                .map(|(id, enc_secret_key)| {
                    Receiver::new(
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
                outputs
                    .get_mut(&receiver.id())
                    .unwrap()
                    .insert(node.id, output);
            });

            // TODO: Create certificate and post it on TOB
        }

        // Now, each party has collected their outputs from all dealers.
        // We use the first t outputs seen on-chain (because all dealers have weight 1) to create the final shares.
        let mut final_shares = HashMap::<PartyId, ReceiverOutput>::new();
        let cert = vec![0, 1, 2];
        for node in nodes.iter() {
            let my_outputs = outputs.get(&node.id).unwrap();
            let final_share = ReceiverOutput::complete_dkg(
                t,
                &nodes,
                restrict(my_outputs, cert.clone().into_iter()),
            )
            .unwrap();
            final_shares.insert(node.id, final_share.clone());
        }

        // We may now compute the joint verification key from the commitments of the first t dealers.
        let vk = final_shares.get(&0).unwrap().vk;

        // For testing, we can recover the secret key from t shares and check that the secret key matches the verification key.
        let shares = final_shares
            .values()
            .flat_map(|output| output.my_shares.shares.clone())
            .collect_vec();
        let sk = Poly::recover_c0(t, shares[..t as usize].iter()).unwrap();
        assert_eq!(G::generator() * sk, vk);
    }

    fn assert_valid(processed_message: ProcessedMessage) -> PartialOutput {
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
