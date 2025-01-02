// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::dl_verification::verify_poly_evals;
use crate::ecies_v1::{self, RecoveryPackage};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly, PrivatePoly, PublicPoly};
use crate::random_oracle::RandomOracle;
use crate::tbls::Share;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tap::prelude::*;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

/// Generics below use `G: GroupElement' for the group of the VSS public key, and `EG: GroupElement'
/// for the group of the ECIES public key.

/// Party in the DKG protocol.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party<G: GroupElement, EG: GroupElement>
where
    EG::ScalarType: Zeroize,
{
    pub id: PartyId,
    pub(crate) nodes: Nodes<EG>,
    pub t: u16,
    pub random_oracle: RandomOracle,
    pub(crate) enc_sk: ecies_v1::PrivateKey<EG>,
    pub(crate) vss_sk: PrivatePoly<G>,
}

/// Assumptions:
/// - The high-level protocol is responsible for verifying that the 'sender' is correct in the
///   following messages (based on the chain's authentication).
/// - The high-level protocol is responsible that all parties see the same order of messages.
///
/// A complaint/fraud claim against a dealer that created invalid encrypted share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Complaint<EG: GroupElement> {
    pub(crate) accused_sender: PartyId,
    pub(crate) proof: RecoveryPackage<EG>,
}

/// A [Confirmation] is sent during the second phase of the protocol. It includes complaints
/// created by receiver of invalid encrypted shares (if any).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation<EG: GroupElement> {
    pub sender: PartyId,
    /// List of complaints against other parties. Empty if there are none.
    pub complaints: Vec<Complaint<EG>>,
}

// Upper bound on the size of binary serialized incoming messages assuming <=3333 shares, <=400
// parties, and using G2Element for encryption. This is a safe upper bound since:
// - Message is O(96*t + 32*n) bytes.
// - Confirmation is O((96*3 + 32) * k) bytes.
// Could be used as a sanity safety check before deserializing an incoming message.
pub const DKG_MESSAGES_MAX_SIZE: usize = 400_000; // 400 KB

/// [Output] is the final output of the DKG protocol in case it runs
/// successfully. It can be used later with [ThresholdBls], see examples in tests.
///
/// If shares is None, the object can only be used for verifying (partial and full) signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output<G: GroupElement, EG: GroupElement> {
    pub nodes: Nodes<EG>,
    pub vss_pk: Poly<G>,
    pub shares: Option<Vec<Share<G::ScalarType>>>, // None if some shares are missing or weight is zero.
}

/// [Message] holds all encrypted shares a dealer sends during the first phase of the
/// protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    pub sender: PartyId,
    /// The commitment of the secret polynomial created by the sender.
    pub vss_pk: PublicPoly<G>,
    /// The encrypted shares created by the sender. Sorted according to the receivers.
    pub encrypted_shares: ecies_v1::MultiRecipientEncryption<EG>,
}

/// Wrapper for collecting everything related to a processed message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessedMessage<G: GroupElement, EG: GroupElement> {
    pub message: Message<G, EG>,
    /// Possibly empty
    pub shares: Vec<Share<G::ScalarType>>,
    pub complaint: Option<Complaint<EG>>,
}

/// Unique processed messages that are being used in the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsedProcessedMessages<G: GroupElement, EG: GroupElement>(
    pub Vec<ProcessedMessage<G, EG>>,
);

impl<G: GroupElement, EG: GroupElement> From<&[ProcessedMessage<G, EG>]>
    for UsedProcessedMessages<G, EG>
{
    // Assumes all parties see the same order of messages.
    fn from(msgs: &[ProcessedMessage<G, EG>]) -> Self {
        let filtered = msgs
            .iter()
            .unique_by(|&m| m.message.sender) // stable
            .cloned()
            .collect::<Vec<_>>();
        Self(filtered)
    }
}

/// Processed messages that were not excluded after the third phase of the protocol.
pub struct VerifiedProcessedMessages<G: GroupElement, EG: GroupElement>(
    Vec<ProcessedMessage<G, EG>>,
);

impl<G: GroupElement, EG: GroupElement> VerifiedProcessedMessages<G, EG> {
    fn filter_from(msgs: &UsedProcessedMessages<G, EG>, to_exclude: &[PartyId]) -> Self {
        let filtered = msgs
            .0
            .iter()
            .filter(|m| !to_exclude.contains(&m.message.sender))
            .cloned()
            .collect::<Vec<_>>();
        Self(filtered)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub fn data(&self) -> &[ProcessedMessage<G, EG>] {
        &self.0
    }
}

/// A dealer in the DKG ceremony.
///
/// Can be instantiated with G1Curve or G2Curve.
impl<G, EG> Party<G, EG>
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + HashToGroupElement + DeserializeOwned,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
    /// 1. Create a new ECIES private key and send the public key to all parties.
    /// 2. After *all* parties have sent their ECIES public keys, create the (same) set of nodes.

    /// 3. Create a new Party instance with the ECIES private key and the set of nodes.
    pub fn new<R: AllowedRng>(
        enc_sk: ecies_v1::PrivateKey<EG>,
        nodes: Nodes<EG>,
        t: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
        rng: &mut R,
    ) -> FastCryptoResult<Self> {
        // Confirm that my ecies pk is in the nodes.
        let enc_pk = ecies_v1::PublicKey::<EG>::from_private_key(&enc_sk);
        let my_node = nodes
            .iter()
            .find(|n| n.pk == enc_pk)
            .ok_or(FastCryptoError::InvalidInput)?;
        // Sanity check that the threshold makes sense (t <= n/2 since we later wait for 2t-1).
        if t > (nodes.total_weight() / 2) || t == 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        // TODO: [comm opt] Instead of generating the polynomial at random, use PRF generated values
        // to reduce communication.
        let vss_sk = PrivatePoly::<G>::rand(t - 1, rng);

        // TODO: remove once the protocol is stable since it's a non negligible computation.
        let vss_pk = vss_sk.commit::<G>();
        info!(
            "DKG: Creating party {} with weight {}, nodes hash {:?}, t {}, n {}, ro {:?}, enc pk {:?}, vss pk c0 {:?}",
            my_node.id,
            my_node.weight,
            nodes.hash(),
            t,
            nodes.total_weight(),
            random_oracle,
            enc_pk,
            vss_pk.c0(),
        );

        Ok(Self {
            id: my_node.id,
            nodes,
            t,
            random_oracle,
            enc_sk,
            vss_sk,
        })
    }

    /// The threshold needed to reconstruct the full key/signature.
    pub fn t(&self) -> u16 {
        self.t
    }

    /// 4. Create the first message to be broadcasted.
    ///
    ///    Returns IgnoredMessage if the party has zero weight (so no need to create a message).
    pub fn create_message<R: AllowedRng>(&self, rng: &mut R) -> FastCryptoResult<Message<G, EG>> {
        let node = self.nodes.node_id_to_node(self.id).expect("my id is valid");
        if node.weight == 0 {
            return Err(FastCryptoError::IgnoredMessage);
        }

        let vss_pk = self.vss_sk.commit();
        let encryption_ro = self.encryption_random_oracle(self.id);
        info!(
            "DKG: Creating message for party {} with vss pk c0 {:?}, ro {:?}",
            self.id,
            vss_pk.c0(),
            encryption_ro,
        );
        // Create a vector of a public key and shares per receiver.
        let pk_and_shares = self
            .nodes
            .iter()
            .map(|node| {
                let share_ids = self
                    .nodes
                    .share_ids_of(node.id)
                    .expect("iterating on valid nodes");
                let shares = share_ids
                    .iter()
                    .map(|share_id| self.vss_sk.eval(*share_id).value)
                    .collect::<Vec<_>>();
                // Works even with empty shares_ids (will result in [0]).
                let buff = bcs::to_bytes(&shares).expect("serialize of shares should never fail");
                (node.pk.clone(), buff)
            })
            .collect::<Vec<_>>();
        // Encrypt everything.
        let encrypted_shares =
            ecies_v1::MultiRecipientEncryption::encrypt(&pk_and_shares, &encryption_ro, rng);

        debug!(
            "DKG: Created message using {:?}, with eph key {:?} nizk {:?}",
            encryption_ro,
            encrypted_shares.ephemeral_key(),
            encrypted_shares.proof(),
        );

        Ok(Message {
            sender: self.id,
            vss_pk,
            encrypted_shares,
        })
    }

    // Sanity checks that can be done by any party on a received message.
    fn sanity_check_message(&self, msg: &Message<G, EG>) -> FastCryptoResult<()> {
        let node = self
            .nodes
            .node_id_to_node(msg.sender)
            .tap_err(|_| {
                warn!(
                    "DKG: Message sanity check failed, invalid id {}",
                    msg.sender
                )
            })
            .map_err(|_| FastCryptoError::InvalidMessage)?;
        if node.weight == 0 {
            warn!(
                "DKG: Message sanity check failed for id {}, zero weight",
                msg.sender
            );
            return Err(FastCryptoError::InvalidMessage);
        };

        if self.t as usize != msg.vss_pk.degree() + 1 {
            warn!(
                "DKG: Message sanity check failed for id {}, expected degree={}, got {}",
                msg.sender,
                self.t - 1,
                msg.vss_pk.degree()
            );
            return Err(FastCryptoError::InvalidMessage);
        }

        if *msg.vss_pk.c0() == G::zero() {
            warn!(
                "DKG: Message sanity check failed for id {}, zero c0",
                msg.sender,
            );
            return Err(FastCryptoError::InvalidMessage);
        }

        if self.nodes.num_nodes() != msg.encrypted_shares.len() {
            warn!(
                "DKG: Message sanity check failed for id {}, expected encrypted_shares.len={}, got {}",
                msg.sender,
                self.nodes.num_nodes(),
                msg.encrypted_shares.len()
            );
            return Err(FastCryptoError::InvalidMessage);
        }

        let encryption_ro = self.encryption_random_oracle(msg.sender);
        msg.encrypted_shares
            .verify(&encryption_ro)
            .tap_err(|e| {
                warn!("DKG: Message sanity check failed for id {}, verify with RO {:?}, eph key {:?} and proof {:?}, returned err: {:?}",
                    msg.sender,
                    encryption_ro,
                    msg.encrypted_shares.ephemeral_key(),
                    msg.encrypted_shares.proof(),
                    e)
            })
            .map_err(|_| FastCryptoError::InvalidMessage)
    }

    /// 5. Process a message and create the second message to be broadcasted.
    ///    The second message contains the list of complaints on invalid shares. In addition, it
    ///    returns a set of valid shares (so far).
    ///
    ///    We split this function into two parts: process_message and merge, so that the caller can
    ///    process messages concurrently and then merge the results.

    ///    [process_message] processes a message and returns an intermediate object ProcessedMessage.
    ///
    ///    Returns error InvalidMessage if the message is invalid and should be ignored (note that we
    ///    could count it as part of the f+1 messages we wait for, but it's also safe to ignore it
    ///    and just wait for f+1 valid messages).
    ///
    ///    Assumptions: Called only once per sender (the high level protocol is responsible for deduplication).
    pub fn process_message<R: AllowedRng>(
        &self,
        message: Message<G, EG>,
        rng: &mut R,
    ) -> FastCryptoResult<ProcessedMessage<G, EG>> {
        debug!(
            "DKG: Processing message from party {} with vss pk c0 {:?}",
            message.sender,
            message.vss_pk.c0()
        );
        // Ignore if invalid (and other honest parties will ignore as well).
        self.sanity_check_message(&message)?;

        let my_share_ids = self.nodes.share_ids_of(self.id).expect("my id is valid");
        let encryption_ro = self.encryption_random_oracle(message.sender);
        let buffer =
            message
                .encrypted_shares
                .decrypt(&self.enc_sk, &encryption_ro, self.id as usize);
        let decrypted_shares: Option<Vec<G::ScalarType>> = bcs::from_bytes(buffer.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .ok();

        if decrypted_shares.is_none()
            || decrypted_shares.as_ref().unwrap().len() != my_share_ids.len()
        {
            warn!(
                "DKG: Processing message from party {} failed, invalid number of decrypted shares",
                message.sender
            );
            let complaint = Complaint {
                accused_sender: message.sender,
                proof: message.encrypted_shares.create_recovery_package(
                    &self.enc_sk,
                    &self.recovery_random_oracle(self.id, message.sender),
                    rng,
                ),
            };
            return Ok(ProcessedMessage {
                message,
                shares: vec![],
                complaint: Some(complaint),
            });
        }

        let decrypted_shares = decrypted_shares
            .expect("checked above")
            .iter()
            .zip(my_share_ids)
            .map(|(s, i)| Eval {
                index: i,
                value: *s,
            })
            .collect::<Vec<_>>();
        debug!(
            "DKG: Successfully decrypted shares from party {}",
            message.sender
        );
        // Verify all shares in a batch.
        if verify_poly_evals(&decrypted_shares, &message.vss_pk, rng).is_err() {
            warn!(
                "DKG: Processing message from party {} failed, invalid shares",
                message.sender
            );
            let complaint = Complaint {
                accused_sender: message.sender,
                proof: message.encrypted_shares.create_recovery_package(
                    &self.enc_sk,
                    &self.recovery_random_oracle(self.id, message.sender),
                    rng,
                ),
            };
            return Ok(ProcessedMessage {
                message,
                shares: vec![],
                complaint: Some(complaint),
            });
        }

        info!(
            "DKG: Successfully processed message from party {}",
            message.sender
        );
        Ok(ProcessedMessage {
            message,
            shares: decrypted_shares,
            complaint: None,
        })
    }

    /// 6. Merge results from multiple ProcessedMessages so only one message needs to be sent.
    ///
    ///    Returns NotEnoughInputs if the threshold t is not met.
    ///
    ///    Assumptions: processed_messages is the result of process_message on the same set of messages
    ///    on all parties.
    pub fn merge(
        &self,
        processed_messages: &[ProcessedMessage<G, EG>],
    ) -> FastCryptoResult<(Confirmation<EG>, UsedProcessedMessages<G, EG>)> {
        debug!("DKG: Trying to merge {} messages", processed_messages.len());
        let filtered_messages = UsedProcessedMessages::from(processed_messages);
        // Verify we have enough messages
        let total_weight = filtered_messages
            .0
            .iter()
            .map(|m| {
                self.nodes
                    .node_id_to_node(m.message.sender)
                    .expect("checked in process_message")
                    .weight as u32
            })
            .sum::<u32>();
        if total_weight < (self.t as u32) {
            debug!("Merge failed with total weight {total_weight}");
            return Err(FastCryptoError::NotEnoughInputs);
        }

        info!("DKG: Merging messages with total weight {total_weight}");

        // Log used parties.
        let used_parties = filtered_messages
            .0
            .iter()
            .map(|m| m.message.sender.to_string())
            .collect::<Vec<String>>()
            .join(",");
        debug!("DKG: Using messages from parties: {}", used_parties);

        let mut conf = Confirmation {
            sender: self.id,
            complaints: Vec::new(),
        };
        for m in &filtered_messages.0 {
            if let Some(complaint) = &m.complaint {
                info!("DKG: Including a complaint on party {}", m.message.sender);
                conf.complaints.push(complaint.clone());
            }
        }

        if filtered_messages.0.iter().all(|m| m.complaint.is_some()) {
            error!("DKG: All processed messages resulted in complaints, this should never happen");
            return Err(FastCryptoError::GeneralError(
                "All processed messages resulted in complaints".to_string(),
            ));
        }

        Ok((conf, filtered_messages))
    }

    /// 7. Process all confirmations, check all complaints, and update the local set of
    ///    valid shares accordingly.
    ///
    ///    Returns NotEnoughInputs if the threshold minimal_threshold is not met.
    ///
    ///    Assumptions: All parties use the same set of confirmations (and outputs from merge).
    pub(crate) fn process_confirmations<R: AllowedRng>(
        &self,
        messages: &UsedProcessedMessages<G, EG>,
        confirmations: &[Confirmation<EG>],
        rng: &mut R,
    ) -> FastCryptoResult<VerifiedProcessedMessages<G, EG>> {
        debug!("Processing {} confirmations", confirmations.len());
        let required_threshold = 2 * (self.t as u32) - 1; // guarantee that at least t honest nodes have valid shares.

        // Ignore confirmations with invalid sender or zero weights
        let confirmations = confirmations
            .iter()
            .filter(|c| {
                self.nodes
                    .node_id_to_node(c.sender)
                    .is_ok_and(|n| n.weight > 0)
            })
            .unique_by(|m| m.sender)
            .collect::<Vec<_>>();
        // Verify we have enough confirmations
        let total_weight = confirmations
            .iter()
            .map(|c| {
                self.nodes
                    .node_id_to_node(c.sender)
                    .expect("checked above")
                    .weight as u32
            })
            .sum::<u32>();
        if total_weight < required_threshold {
            debug!("Processing confirmations failed with total weight {total_weight}");
            return Err(FastCryptoError::NotEnoughInputs);
        }

        info!("DKG: Processing confirmations with total weight {total_weight}, expected {required_threshold}");

        // Two hash maps for faster access in the main loop below.
        let id_to_pk = self
            .nodes
            .iter()
            .map(|n| (n.id, &n.pk))
            .collect::<HashMap<_, _>>();
        let id_to_m1 = messages
            .0
            .iter()
            .map(|m| (m.message.sender, &m.message))
            .collect::<HashMap<_, _>>();

        let mut to_exclude = HashSet::new();
        'outer: for m2 in confirmations {
            'inner: for complaint in &m2.complaints {
                let accused = complaint.accused_sender;
                let accuser = m2.sender;
                debug!("DKG: Checking complaint from {accuser} on {accused}");
                let accuser_pk = id_to_pk
                    .get(&accuser)
                    .expect("checked above that accuser is valid id");
                // If the claim refers to a non existing message, it's an invalid complaint.
                let valid_complaint = match id_to_m1.get(&accused) {
                    Some(related_m1) => Self::check_complaint_proof(
                        &complaint.proof,
                        accuser_pk,
                        accuser,
                        &self
                            .nodes
                            .share_ids_of(accuser)
                            .expect("checked above the accuser is valid id"),
                        &related_m1.vss_pk,
                        &related_m1.encrypted_shares,
                        &self.recovery_random_oracle(accuser, accused),
                        &self.encryption_random_oracle(accused),
                        rng,
                    )
                    .is_ok(),
                    None => false,
                };
                match valid_complaint {
                    // Ignore accused from now on, and continue processing complaints from the
                    // current accuser.
                    true => {
                        warn!("DKG: Processing confirmations excluded accused party {accused}");
                        to_exclude.insert(accused);
                        continue 'inner;
                    }
                    // Ignore the accuser from now on, including its other complaints (not critical
                    // for security, just saves some work).
                    false => {
                        warn!("DKG: Processing confirmations excluded accuser {accuser}");
                        to_exclude.insert(accuser);
                        continue 'outer;
                    }
                }
            }
        }

        let verified_messages = VerifiedProcessedMessages::filter_from(
            messages,
            &to_exclude.into_iter().collect::<Vec<_>>(),
        );

        if verified_messages.is_empty() {
            error!(
                "DKG: No verified messages after processing complaints, this should never happen"
            );
            return Err(FastCryptoError::GeneralError(
                "No verified messages after processing complaints".to_string(),
            ));
        }

        // Log verified messages parties.
        let used_parties = verified_messages
            .0
            .iter()
            .map(|m| m.message.sender.to_string())
            .collect::<Vec<String>>()
            .join(",");
        debug!(
            "DKG: Using verified messages from parties: {}",
            used_parties
        );

        Ok(verified_messages)
    }

    /// 8. Aggregate the valid shares (as returned from the previous step) and the public key.
    pub(crate) fn aggregate(&self, messages: &VerifiedProcessedMessages<G, EG>) -> Output<G, EG> {
        debug!(
            "Aggregating shares from {} verified messages",
            messages.0.len()
        );
        let id_to_m1 = messages
            .0
            .iter()
            .map(|m| (m.message.sender, &m.message))
            .collect::<HashMap<_, _>>();
        let mut vss_pk = PublicPoly::<G>::zero();
        let my_share_ids = self.nodes.share_ids_of(self.id).expect("my id is valid");

        let mut final_shares = my_share_ids
            .iter()
            .map(|share_id| {
                (
                    share_id,
                    Share {
                        index: *share_id,
                        value: G::ScalarType::zero(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        for m in &messages.0 {
            vss_pk += &id_to_m1
                .get(&m.message.sender)
                .expect("shares only includes shares from valid first messages")
                .vss_pk;
            for share in &m.shares {
                final_shares
                    .get_mut(&share.index)
                    .expect("created above")
                    .value += share.value;
            }
        }

        // If I didn't receive a valid share for one of the verified messages (i.e., my complaint
        // was not processed), then I don't have a valid share for the final key.
        let has_invalid_share = messages.0.iter().any(|m| m.complaint.is_some());
        let has_zero_shares = final_shares.is_empty(); // if my weight is zero
        info!(
            "DKG: Aggregating my shares completed with has_invalid_share={}, has_zero_shares={}",
            has_invalid_share, has_zero_shares
        );
        if has_invalid_share {
            warn!("DKG: Aggregating my shares failed");
        }

        let shares = if !has_invalid_share && !has_zero_shares {
            Some(
                final_shares
                    .values()
                    .cloned()
                    .sorted_by_key(|s| s.index)
                    .collect(),
            )
        } else {
            None
        };

        Output {
            nodes: self.nodes.clone(),
            vss_pk,
            shares,
        }
    }

    /// Execute the previous two steps together.
    pub fn complete<R: AllowedRng>(
        &self,
        messages: &UsedProcessedMessages<G, EG>,
        confirmations: &[Confirmation<EG>],
        rng: &mut R,
    ) -> FastCryptoResult<Output<G, EG>> {
        let verified_messages = self.process_confirmations(messages, confirmations, rng)?;
        Ok(self.aggregate(&verified_messages))
    }

    // Returns an error if the *complaint* is invalid (counterintuitive).
    #[allow(clippy::too_many_arguments)]
    fn check_complaint_proof<R: AllowedRng>(
        recovery_pkg: &ecies_v1::RecoveryPackage<EG>,
        receiver_pk: &ecies_v1::PublicKey<EG>,
        receiver_id: PartyId,
        share_ids: &[ShareIndex],
        vss_pk: &PublicPoly<G>,
        encryption: &ecies_v1::MultiRecipientEncryption<EG>,
        recovery_random_oracle: &RandomOracle,
        encryption_random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> FastCryptoResult<()> {
        // Check that the recovery package is valid, and if not, return an error since the complaint
        // is invalid.
        let buffer = encryption.decrypt_with_recovery_package(
            recovery_pkg,
            recovery_random_oracle,
            encryption_random_oracle,
            receiver_pk,
            receiver_id as usize,
        )?;

        let decrypted_shares: Vec<G::ScalarType> = match bcs::from_bytes(buffer.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                debug!("DKG: check_complaint_proof failed to deserialize shares");
                return Ok(());
            }
        };

        if decrypted_shares.len() != share_ids.len() {
            debug!("DKG: check_complaint_proof recovered invalid number of shares");
            return Ok(());
        }

        let decrypted_shares = decrypted_shares
            .into_iter()
            .zip(share_ids)
            .map(|(s, i)| Eval {
                index: *i,
                value: s,
            })
            .collect::<Vec<_>>();

        match verify_poly_evals(&decrypted_shares, vss_pk, rng) {
            Ok(()) => Err(FastCryptoError::InvalidProof),
            Err(_) => {
                debug!("DKG: check_complaint_proof failed to verify shares");
                Ok(())
            }
        }
    }

    fn encryption_random_oracle(&self, sender: PartyId) -> RandomOracle {
        self.random_oracle.extend(&format!("encs {}", sender))
    }

    fn recovery_random_oracle(&self, accuser: PartyId, accused: PartyId) -> RandomOracle {
        self.random_oracle.extend(&format!(
            "recovery of {} received from {}",
            accuser, accused
        ))
    }
}

#[cfg(test)]
pub fn create_fake_complaint<EG>() -> Complaint<EG>
where
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    <EG as GroupElement>::ScalarType: FiatShamirChallenge + Zeroize,
{
    let sk = ecies_v1::PrivateKey::<EG>::new(&mut rand::thread_rng());
    let pk = ecies_v1::PublicKey::<EG>::from_private_key(&sk);
    let mr_enc = ecies_v1::MultiRecipientEncryption::encrypt(
        &[(pk.clone(), b"test".to_vec())],
        &RandomOracle::new("test"),
        &mut rand::thread_rng(),
    );
    let pkg = mr_enc.create_recovery_package(
        &sk,
        &RandomOracle::new("does not matter"),
        &mut rand::thread_rng(),
    );
    Complaint {
        accused_sender: 1,
        proof: pkg,
    }
}
