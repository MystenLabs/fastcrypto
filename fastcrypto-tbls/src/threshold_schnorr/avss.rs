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
use crate::threshold_schnorr::recovery_proof::RecoveryProof;
use crate::threshold_schnorr::Extensions::Encryption;
use crate::threshold_schnorr::{random_oracle_from_sid, Parameters, EG, G, S};
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
use tap::TapFallible;
use tracing::warn;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
#[allow(dead_code)]
pub struct Dealer {
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    params: Parameters, // `f` is currently unused by the (non-batch) AVSS.
    secret: S, // For key rotation this is set to the previous round's share; otherwise sampled in `new`.
}

#[allow(dead_code)]
pub struct Receiver {
    // Protocol-dependent fields first, then private fields, then state fields.
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    params: Parameters,
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    commitment: Option<G>,
}

/// An upper bound on the BCS-serialized size of a [Message], to be enforced when deserializing
/// untrusted messages.
pub const AVSS_MESSAGE_MAX_SIZE: usize = 250_000; // 250 KB. A total weight of 2500 measures ~170 KB.

/// The message broadcast by the dealer, containing the encrypted shares and the public keys of the nonces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    feldman_commitment: Poly<G>,
    ciphertext: MultiRecipientEncryption<EG>,
}

/// The result of a [Receiver] processing a [Message]: Either valid shares or a complaint.
#[allow(clippy::large_enum_variant)] // Clippy complains because DkOutput can be very small if BATCH_SIZE is small.
pub enum ProcessedMessage {
    Valid(AvssOutput),
    Complaint(Complaint),
}

/// A complaint by a receiver who could not decrypt or verify its shares from the dealer's
/// broadcast. Given enough responses, the accuser can recover its shares.
///
/// The accuser's id is not carried here; the higher-level protocol tracks which party a complaint
/// came from and passes it to [Receiver::handle_complaint].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Complaint {
    pub proof: RecoveryProof,
}

/// A response to a [Complaint], containing the responder's shares so the accuser can
/// Lagrange-interpolate their own.
///
/// The responder's id is not carried here; the higher-level protocol tracks which party a response
/// came from and passes it to [Receiver::verify_complaint_response].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintResponse {
    pub shares: SharesForNode,
}

/// A [ComplaintResponse] whose shares have been verified against the dealer's [Message] and bound
/// to the responder that sent it. Created only by [Receiver::verify_complaint_response] and
/// consumed by [Receiver::recover], which can therefore trust its contents.
#[derive(Debug, Clone)]
pub struct VerifiedComplaintResponse {
    responder_id: PartyId,
    shares: SharesForNode,
}

/// The output of a receiver after a single instance of AVSS: The shares for each nonce + commitments for the next round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvssOutput {
    /// The commitments to the polynomials will be used for key rotation.
    pub feldman_commitment: Poly<G>,
    pub my_shares: SharesForNode,
}

/// The output after combining multiple `AvssOutputs`,
/// either using [AvssOutput::complete_dkg] or [AvssOutput::complete_key_rotation].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkOutput {
    /// The public key corresponding to the secret the dealer is sharing.
    pub vk: G,

    /// The commitments to the polynomials will be used for key rotation.
    pub commitments: Vec<Eval<G>>,

    pub my_shares: SharesForNode,
}

/// A single share: an evaluation of the secret-sharing polynomial at a share index.
pub type Share = Eval<S>;

/// All the shares given to a node. One share per the node's weight.
/// These can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode {
    pub shares: Vec<Share>,
}

impl SharesForNode {
    /// Get the weight of this node (number of shares it has).
    pub fn weight(&self) -> usize {
        self.shares.len()
    }

    fn verify(&self, message: &Message) -> FastCryptoResult<()> {
        for share in &self.shares {
            // TODO: possible optimization - all shares get be verified at once
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
        if !indices.iter().all_unique() {
            return Err(InvalidInput);
        }

        let evaluations = other_shares
            .iter()
            .flat_map(|share| share.shares.iter().cloned())
            .collect_vec();
        if !evaluations.iter().map(|e| e.index).all_unique() {
            return Err(InvalidInput);
        }
        if evaluations.len() < threshold as usize {
            return Err(FastCryptoError::GeneralError(
                "Not enough valid responses".to_string(),
            ));
        }
        let evaluations = evaluations
            .into_iter()
            .take(threshold as usize)
            .collect_vec();

        let shares = indices
            .into_iter()
            .map(|index| Poly::recover_at(threshold, index, &evaluations))
            .collect::<FastCryptoResult<Vec<_>>>()?;

        Ok(Self { shares })
    }
}

impl BCSSerialized for SharesForNode {}

impl Dealer {
    /// Create a new dealer.
    ///
    /// * `secret`: The secret to share. If None, a random secret is sampled from `rng`.
    /// * `nodes`: The set of nodes (parties) participating in the protocol, including their public keys and weights.
    /// * `params`: The threshold parameters.
    /// * `sid`: A session identifier that should be unique for each invocation of the protocol but the same for all parties in a single invocation.
    /// * `rng`: Used to sample the secret when `secret` is None.
    ///
    /// Returns an error if `t` is zero or larger than the total weight of the nodes.
    pub fn new<R: AllowedRng>(
        secret: Option<S>,
        nodes: Nodes<EG>,
        params: Parameters,
        sid: Vec<u8>, // TODO: what exactly is the req - unique per dkg or per avss? currently it is unique per avss.
        rng: &mut R,
    ) -> FastCryptoResult<Self> {
        if params.t == 0 || params.t > nodes.total_weight() {
            return Err(InvalidInput);
        }
        Ok(Self {
            secret: secret.unwrap_or_else(|| S::rand(rng)),
            params,
            nodes,
            sid,
        })
    }

    /// 1. The Dealer samples nonces, generates shares and broadcasts the encrypted shares.
    pub fn create_message<Rng: AllowedRng>(&self, rng: &mut Rng) -> Message {
        let polynomial = Poly::rand_fixed_c0(self.params.t - 1, self.secret, rng);

        // Compute all shares
        let all_shares = polynomial.eval_range(self.nodes.total_weight());

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
                            .map(|index| all_shares.get_eval(index))
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

        Message {
            ciphertext,
            feldman_commitment: polynomial.commit(),
        }
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
    /// * `params`: The threshold parameters. Only `params.t` is used by the AVSS; `params.f` is carried for consistency with the other protocols.
    /// * `sid`: A session identifier that should be unique for each invocation of the protocol but the same for all parties in a single invocation.
    /// * `commitment`: A commitment to the secret being shared. This should be equal to `secret * G` and is typically found as the commitment from a previous round (see [DkOutput]). If None, no consistency check will be performed.
    /// * `enc_secret_key`: The private key used to decrypt the shares sent to this receiver.
    pub fn new(
        nodes: Nodes<EG>,
        id: PartyId,
        params: Parameters,
        sid: Vec<u8>,
        commitment: Option<G>,
        enc_secret_key: PrivateKey<EG>,
    ) -> FastCryptoResult<Self> {
        // Validate that `id` is one of the parties in `nodes`.
        nodes.node_id_to_node(id)?;
        Ok(Self {
            id,
            enc_secret_key,
            commitment,
            sid,
            params,
            nodes,
        })
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
        if message.feldman_commitment.degree() + 1 != self.params.t as usize {
            warn!(
                "AVSS process_message: invalid feldman commitment degree {} (expected {})",
                message.feldman_commitment.degree(),
                self.params.t as usize - 1,
            );
            return Err(InvalidMessage);
        }

        // If a commitment is given, verify that the secret the dealer is distributing is consistent
        if let Some(c) = &self.commitment {
            if message.feldman_commitment.c0() != *c {
                warn!(
                    "AVSS process_message: feldman commitment c0 does not match the expected commitment from a previous round"
                );
                return Err(InvalidMessage);
            }
        }

        if message.ciphertext.len() != self.nodes.num_nodes() {
            warn!("AVSS process_message: ciphertext has the wrong number of recipients");
            return Err(InvalidMessage);
        }

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        message
            .ciphertext
            .verify(&random_oracle_encryption)
            .map_err(|e| {
                warn!("AVSS process_message: ciphertext verification failed: {e:?}");
                InvalidMessage
            })?;

        let plaintext = message.ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        match SharesForNode::from_bytes(&plaintext).and_then(|my_shares| {
            verify_shares(
                &my_shares,
                &self.nodes.share_ids_of(self.id)?,
                self.id,
                message,
            )?;
            Ok(my_shares)
        }) {
            Ok(my_shares) => Ok(ProcessedMessage::Valid(AvssOutput {
                my_shares,
                feldman_commitment: message.feldman_commitment.clone(),
            })),
            Err(_) => Ok(ProcessedMessage::Complaint(Complaint {
                proof: RecoveryProof::create(
                    self.id,
                    &message.ciphertext.shared(),
                    &self.enc_secret_key,
                    &self.random_oracle(),
                    &mut rand::thread_rng(), // TODO: pass rng from higher level protocol
                ),
            })),
        }
    }

    /// 4. Upon receiving a complaint, a receiver verifies it and responds with its shares.
    ///
    /// `accuser_id` is the party that raised the complaint (tracked by the caller, see [Complaint]).
    /// Assumes the dealer's `message` has already been validated via [Receiver::process_message].
    pub fn handle_complaint(
        &self,
        message: &Message,
        accuser_id: PartyId,
        complaint: &Complaint,
        my_output: &AvssOutput,
    ) -> FastCryptoResult<ComplaintResponse> {
        let accuser_share_ids = self.nodes.share_ids_of(accuser_id)?;
        complaint.proof.check(
            accuser_id,
            &self.nodes.node_id_to_node(accuser_id)?.pk,
            message
                .ciphertext
                .encs
                .get(accuser_id as usize)
                .ok_or(InvalidInput)?,
            &message.ciphertext.shared(),
            &self.random_oracle(),
            |shares: &SharesForNode| verify_shares(shares, &accuser_share_ids, accuser_id, message),
        )?;
        Ok(ComplaintResponse {
            shares: my_output.my_shares.clone(),
        })
    }

    /// Verify a [ComplaintResponse] received from `responder_id` against the dealer's `message`,
    /// binding the verified shares to the responder. The resulting [VerifiedComplaintResponse]s are
    /// the input to [Receiver::recover].
    pub fn verify_complaint_response(
        &self,
        message: &Message,
        responder_id: PartyId,
        response: ComplaintResponse,
    ) -> FastCryptoResult<VerifiedComplaintResponse> {
        verify_shares(
            &response.shares,
            &self.nodes.share_ids_of(responder_id)?,
            responder_id,
            message,
        )?;
        Ok(VerifiedComplaintResponse {
            responder_id,
            shares: response.shares,
        })
    }

    /// 5. Upon receiving enough verified responses (by weight) to a complaint, the accuser can
    ///    recover its shares. Each response must first be verified with
    ///    [Receiver::verify_complaint_response].
    ///
    ///    Fails if the responses do not come from distinct parties or if their combined weight is
    ///    below the threshold `t`.
    pub fn recover(
        &self,
        message: &Message,
        responses: Vec<VerifiedComplaintResponse>,
    ) -> FastCryptoResult<AvssOutput> {
        // Responses must come from distinct parties, otherwise a single responder could be counted
        // multiple times towards the threshold.
        if !responses.iter().map(|r| r.responder_id).all_unique() {
            return Err(InvalidInput);
        }

        // The responses are already verified, so we only need enough weight to interpolate.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|r| &r.responder_id))?;
        if total_response_weight < self.params.t {
            return Err(FastCryptoError::InputTooShort(self.params.t as usize));
        }

        let valid_shares = responses.into_iter().map(|r| r.shares).collect_vec();
        let my_shares = SharesForNode::recover(self.my_indices(), self.params.t, &valid_shares)?;

        // The recovered shares are interpolated from already-verified shares, so this should never
        // fail; if it does, something is seriously wrong.
        my_shares.verify(message).tap_err(|e| {
            warn!(
                "AVSS recover: recovered shares failed verification, this should never happen: {e:?}"
            );
        })?;

        Ok(AvssOutput {
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

/// Verify a set of shares received from a Dealer: that the share indices are exactly
/// `expected_share_ids` and that each share is consistent with the dealer's commitment.
fn verify_shares(
    shares: &SharesForNode,
    expected_share_ids: &[ShareIndex],
    receiver: PartyId,
    message: &Message,
) -> FastCryptoResult<()> {
    // TODO: this function returs err both in case verify failed and in case there is a bug in the impl.
    // We should decide on a consistent error handling strategy here

    if !shares
        .shares
        .iter()
        .map(|s| s.index)
        .eq(expected_share_ids.iter().copied())
    {
        warn!(
            "AVSS verify_shares: share indices do not match the receiver's assigned indices for receiver {}",
            receiver,
        );
        return Err(InvalidMessage);
    }
    shares.verify(message).tap_err(|e| {
        warn!(
            "AVSS verify_shares: cryptographic share verification failed for receiver {}: {e:?}",
            receiver,
        );
    })
}

impl DkOutput {
    pub fn share_for_index(&self, index: ShareIndex) -> Option<&Eval<S>> {
        self.my_shares.shares.iter().find(|s| s.index == index)
    }

    pub fn commitment_for_index(&self, index: ShareIndex) -> Option<&Eval<G>> {
        self.commitments.iter().find(|c| c.index == index)
    }

    /// Combine multiple outputs from different dealers into a single output by summing.
    /// This is used after a successful AVSS used for DKG to combine the shares from multiple dealers into a single share for each party.
    /// Panics if the given `DkOutput`s are not compatible (same weight, same indices, same number of commitments)
    /// Returns the combined output, including the joint verifying key
    pub fn complete_dkg(
        t: u16,
        nodes: &Nodes<EG>,
        outputs: HashMap<PartyId, AvssOutput>,
    ) -> FastCryptoResult<Self> {
        if nodes.total_weight_of(outputs.keys())? < t {
            return Err(NotEnoughWeight(t as usize));
        }

        let outputs = outputs.into_values().collect_vec();

        // Sanity check: Outputs cannot be empty and all outputs must have the same weight.
        if outputs.is_empty() || !outputs.iter().map(|output| output.weight()).all_equal() {
            return Err(InvalidInput);
        }

        let mut outputs = outputs.into_iter();
        let first = outputs.next().ok_or(InvalidInput)?;
        outputs
            .try_fold(first, |acc, output| acc.try_add(output))
            .map(|o| o.into_dk_output(nodes))
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
        outputs: &[IndexedValue<AvssOutput>],
    ) -> FastCryptoResult<Self> {
        if outputs.len() != t as usize {
            return Err(InputLengthWrong(t as usize));
        }
        if outputs.is_empty() {
            return Err(InvalidInput);
        }

        let my_indices = nodes.share_ids_of(my_id)?;

        let lagrange_coefficients: Vec<S> = Poly::<G>::get_lagrange_coefficients_for_c0(
            t,
            outputs.iter().map(|output| output.index),
        )
        .map(|c| c.1.iter().map(|s| s * c.0).collect_vec())?;

        let feldman_commitment = Poly::multi_scalar_mul(
            &outputs
                .iter()
                .map(|output| output.value.feldman_commitment.clone())
                .collect_vec(),
            &lagrange_coefficients,
        )?;

        let commitments = feldman_commitment.eval_range(nodes.total_weight()).to_vec();

        let shares = my_indices
            .iter()
            .map(|&index| {
                let terms = outputs
                    .iter()
                    .zip(&lagrange_coefficients)
                    .map(|(output, coeff)| {
                        Ok(output
                            .value
                            .share_for_index(index)
                            .ok_or(InvalidInput)?
                            .value
                            * coeff)
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()?;
                Ok(Eval {
                    index,
                    value: S::sum(terms.into_iter()),
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        let vk = G::multi_scalar_mul(
            &lagrange_coefficients,
            outputs
                .iter()
                .map(|o| o.value.feldman_commitment.c0())
                .collect_vec()
                .as_slice(),
        )?;

        Ok(Self {
            my_shares: SharesForNode { shares },
            commitments,
            vk,
        })
    }
}

impl AvssOutput {
    fn into_dk_output(self, nodes: &Nodes<EG>) -> DkOutput {
        DkOutput {
            commitments: self.compute_all_commitments(
                ShareIndex::new(nodes.total_weight()).expect("Weight is non-zero"),
            ),
            vk: self.feldman_commitment.c0(),
            my_shares: self.my_shares,
        }
    }

    // TODO: move inline into the function that calls it
    fn compute_all_commitments(&self, to: ShareIndex) -> Vec<Eval<G>> {
        self.feldman_commitment.eval_range(to.get()).to_vec()
    }

    #[cfg(test)]
    fn commitment_for_index(&self, index: ShareIndex) -> Eval<G> {
        self.feldman_commitment.eval(index)
    }

    fn share_for_index(&self, index: ShareIndex) -> Option<&Eval<S>> {
        self.my_shares.shares.iter().find(|s| s.index == index)
    }

    fn weight(&self) -> usize {
        self.my_shares.weight()
    }

    /// Combine this output with another by summing shares that share the same index.
    /// Returns [InvalidInput] if the two outputs hold a different number of shares or if their
    /// indices do not line up positionally.
    fn try_add(self, rhs: Self) -> FastCryptoResult<Self> {
        if self.my_shares.shares.len() != rhs.my_shares.shares.len() {
            return Err(InvalidInput);
        }
        let shares = self
            .my_shares
            .shares
            .iter()
            .zip(&rhs.my_shares.shares)
            .map(|(a, b)| {
                if a.index != b.index {
                    return Err(InvalidInput);
                }
                Ok(Eval {
                    index: a.index,
                    value: a.value + b.value,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self {
            my_shares: SharesForNode { shares },
            feldman_commitment: self.feldman_commitment + &rhs.feldman_commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::Poly;
    use crate::threshold_schnorr::avss::Complaint;
    use crate::threshold_schnorr::avss::{AvssOutput, ProcessedMessage};
    use crate::threshold_schnorr::avss::{Dealer, Message, Receiver};
    use crate::threshold_schnorr::avss::{DkOutput, SharesForNode};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::tests::restrict;
    use crate::threshold_schnorr::Extensions::Encryption;
    use crate::threshold_schnorr::{Parameters, EG, G};
    use crate::types::{IndexedValue, ShareIndex};
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;

    #[test]
    fn test_size_limits() {
        // Worst case for total weight <= 2500: the maximum number of nodes (Nodes::MAX_NODES = 1000,
        // which maximizes the per-recipient encryption overhead) summing to the maximum total weight
        // 2500, with t = total_weight (which maximizes the feldman commitment of t group elements).
        let num_nodes = 1000usize;
        let total_weight = 2500u16;
        let params = Parameters {
            t: total_weight,
            f: 1,
        };

        let mut rng = rand::thread_rng();
        let sks = (0..num_nodes)
            .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
            .collect::<Vec<_>>();
        // 500 nodes of weight 3 and 500 of weight 2 sum to 2500.
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(i, sk)| Node {
                    id: i as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight: if i < 500 { 3 } else { 2 },
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(nodes.total_weight(), total_weight);

        let dealer =
            Dealer::new(None, nodes, params, b"size-limit-test".to_vec(), &mut rng).unwrap();
        let message = dealer.create_message(&mut rng);
        let size = bcs::to_bytes(&message).unwrap().len();
        assert!(
            size <= super::AVSS_MESSAGE_MAX_SIZE,
            "AVSS message size {size} exceeds limit {}",
            super::AVSS_MESSAGE_MAX_SIZE
        );
    }

    #[test]
    fn test_sharing() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let n = 7;
        let params = Parameters { t, f: 1 }; // avss does not use f

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

        let dealer: Dealer =
            Dealer::new(Some(secret), nodes.clone(), params, sid.clone(), &mut rng).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, enc_secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    params,
                    sid.clone(),
                    Some(previous_round_commitment),
                    enc_secret_key,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng);

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
        let n = 7;
        let params = Parameters { t, f: 1 }; // avss does not use f

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

        let dealer: Dealer =
            Dealer::new(None, nodes.clone(), params, sid.clone(), &mut rng).unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, enc_secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    params,
                    sid.clone(),
                    None,
                    enc_secret_key,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng);

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
        let dealer: Dealer = Dealer::new(
            Some(secret.value),
            nodes.clone(),
            params,
            sid2.clone(),
            &mut rng,
        )
        .unwrap();
        let receivers = receivers
            .into_iter()
            .map(
                |Receiver {
                     id,
                     enc_secret_key,
                     params,
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
                        params,
                        sid2.clone(),
                        Some(commitment.value),
                        enc_secret_key,
                    )
                    .unwrap()
                },
            )
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng);

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
        let n = 7;
        let params = Parameters { t, f: 1 }; // avss does not use f

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

        let dealer: Dealer =
            Dealer::new(Some(secret), nodes.clone(), params, sid.clone(), &mut rng).unwrap();

        let commitment = G::generator() * secret;

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, enc_secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    i as u16,
                    params,
                    sid.clone(),
                    Some(commitment),
                    enc_secret_key,
                )
                .unwrap()
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

        let accuser_id = receivers[0].id;
        let responses = receivers
            .iter()
            .skip(1)
            .map(|r| {
                let response = r
                    .handle_complaint(
                        &message,
                        accuser_id,
                        &complaint,
                        all_shares.get(&r.id).unwrap(),
                    )
                    .unwrap();
                receivers[0]
                    .verify_complaint_response(&message, r.id, response)
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
            let polynomial = Poly::rand_fixed_c0(self.params.t - 1, self.secret, rng);
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
        let n = 7;
        let params = Parameters { t, f: 1 }; // avss does not use f

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
        let mut outputs = HashMap::<PartyId, HashMap<PartyId, AvssOutput>>::new();
        for node in nodes.iter() {
            outputs.insert(node.id, HashMap::new());
        }

        let mut messages = Vec::new();

        // Each node acts as dealer in the DKG
        for node in nodes.iter() {
            let sid = format!("dkg-test-session-{}", node.id).into_bytes();
            let dealer: Dealer =
                Dealer::new(None, nodes.clone(), params, sid.clone(), &mut rng).unwrap();
            let receivers = sks
                .iter()
                .enumerate()
                .map(|(id, enc_secret_key)| {
                    Receiver::new(
                        nodes.clone(),
                        id as u16,
                        params,
                        sid.clone(),
                        None,
                        enc_secret_key.clone(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            // Each dealer creates a message
            let message = dealer.create_message(&mut rng);
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
        let mut final_shares = HashMap::<PartyId, DkOutput>::new();
        let cert = vec![0, 1, 2];
        for node in nodes.iter() {
            let my_outputs = outputs.get(&node.id).unwrap();
            let final_share =
                DkOutput::complete_dkg(t, &nodes, restrict(my_outputs, cert.clone().into_iter()))
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

    #[test]
    fn test_key_rotation_with_zero_weight_node() {
        // Node 0 has weight 0: it holds no shares but must still complete key rotation.
        let t = 3;
        let weights = [0u16, 2, 1, 1];
        let n = weights.len();
        let params = Parameters { t, f: 1 }; // avss does not use f

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            sks.iter()
                .zip(weights)
                .enumerate()
                .map(|(id, (sk, weight))| Node {
                    id: id as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let make_receivers = |sid: &[u8], commitment: Option<G>| {
            sks.iter()
                .enumerate()
                .map(|(id, sk)| {
                    Receiver::new(
                        nodes.clone(),
                        id as u16,
                        params,
                        sid.to_vec(),
                        commitment,
                        sk.clone(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };

        // Round 0: a single dealer shares a random secret.
        let secret = Scalar::rand(&mut rng);
        let vk = G::generator() * secret;
        let sid0 = b"key-rotation-zero-weight-round0".to_vec();
        let message = Dealer::new(Some(secret), nodes.clone(), params, sid0.clone(), &mut rng)
            .unwrap()
            .create_message(&mut rng);
        let round0: HashMap<PartyId, DkOutput> = make_receivers(&sid0, Some(vk))
            .iter()
            .map(|r| {
                (
                    r.id(),
                    assert_valid(r.process_message(&message).unwrap()).into_dk_output(&nodes),
                )
            })
            .collect();

        // Key rotation: each existing share index is reshared by the node holding it.
        let mut rotated = HashMap::<(PartyId, ShareIndex), AvssOutput>::new();
        for share_index in nodes.share_ids_iter() {
            let holder = nodes.share_id_to_node(&share_index).unwrap().id;
            let reshared_secret = round0
                .get(&holder)
                .unwrap()
                .share_for_index(share_index)
                .unwrap()
                .value;
            let commitment = round0
                .get(&0)
                .unwrap()
                .commitment_for_index(share_index)
                .unwrap()
                .value;
            let sid = format!("key-rotation-zero-weight-{}", share_index.get()).into_bytes();
            let message = Dealer::new(
                Some(reshared_secret),
                nodes.clone(),
                params,
                sid.clone(),
                &mut rng,
            )
            .unwrap()
            .create_message(&mut rng);
            for r in make_receivers(&sid, Some(commitment)) {
                rotated.insert(
                    (r.id(), share_index),
                    assert_valid(r.process_message(&message).unwrap()),
                );
            }
        }

        // The first t share indices form the certificate.
        let cert = nodes.share_ids_iter().take(t as usize).collect_vec();
        let new_outputs: HashMap<PartyId, DkOutput> = nodes
            .node_ids_iter()
            .map(|id| {
                let outputs = cert
                    .iter()
                    .map(|&index| IndexedValue {
                        index,
                        value: rotated.get(&(id, index)).unwrap().clone(),
                    })
                    .collect_vec();
                (
                    id,
                    DkOutput::complete_key_rotation(t, id, &nodes, &outputs).unwrap(),
                )
            })
            .collect();

        // The verifying key is preserved; each node holds one share per unit of weight.
        for (id, output) in &new_outputs {
            assert_eq!(output.vk, vk);
            assert_eq!(
                output.my_shares.weight(),
                nodes.weight_of(*id).unwrap() as usize
            );
        }
        assert_eq!(new_outputs.get(&0).unwrap().my_shares.weight(), 0);

        // The rotated shares still reconstruct the original secret.
        let shares = new_outputs
            .values()
            .flat_map(|output| output.my_shares.shares.clone())
            .collect_vec();
        let recovered = Poly::recover_c0(t, shares[..t as usize].iter()).unwrap();
        assert_eq!(secret, recovered);
    }

    fn assert_valid(processed_message: ProcessedMessage) -> AvssOutput {
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
