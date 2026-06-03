// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous verifiable secret sharing (AVSS) for a batch of random nonces.
//!
//! A dealer shares `L = w_dealer · BATCH_SIZE` nonces among `n` weighted receivers with total
//! weight `W` under a threshold `t`. The numbered steps below, starting at
//! [Dealer::create_optimistic_messages], walk through the protocol.

use crate::ecies_v1::{
    Ciphertext, MultiRecipientEncryption, PrivateKey, RecoveryPackage, SharedComponents,
};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{create_secret_sharing, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::recovery_proof;
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::Extensions::{Challenge, Encryption, Recovery};
use crate::threshold_schnorr::{random_oracle_from_sid, EG, G, S};
use crate::types::{get_uniform_value, ShareIndex};
use fastcrypto::error::FastCryptoError::{
    InvalidInput, InvalidMessage, InvalidProof, NotEnoughWeight,
};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::secp256k1::SCALAR_SIZE_IN_BYTES;
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::merkle;
use fastcrypto::merkle::MerkleTree;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::iter::repeat_with;
use tracing::warn;

pub type Digest = fastcrypto::hash::Digest<{ Blake2b256::OUTPUT_SIZE }>;

/// Threshold parameters for the AVSS protocol.
#[derive(Copy, Clone, Debug)]
pub struct Parameters {
    /// Reconstruction threshold: `≥ t` valid shares (by weight) reconstruct a secret.
    pub t: u16,
    /// Byzantine bound by share-weight.
    pub f: u16,
}

/// The AVSS dealer. Exactly one per session; creates the shares and broadcasts the encrypted
/// shares to every receiver.
#[allow(dead_code)]
pub struct Dealer {
    params: Parameters,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    /// The total number of nonces that this dealer should distribute.
    batch_size: usize,
}

/// An AVSS receiver, holding the shares the [Dealer] dealt to it.
#[allow(dead_code)]
pub struct Receiver {
    pub id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    params: Parameters,
    /// The total number of nonces that the receiver expects to receive from the dealer.
    batch_size: usize,
}

/// The dealer's per-recipient optimistic-phase message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptimisticMessage {
    pub avss_common: AvssCommonMessage,
    pub ciphertext: Ciphertext,
}

/// A receiver's optimistic-phase acknowledgement that it successfully decrypted and verified its
/// shares. The caller signs it over `H(v)` (the [AvssCommonMessage] hash) out-of-band and
/// aggregates `≥ t + f` weight of these into the optimistic certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Confirm {
    pub avss_common_message_hash: Digest,
}

/// Dealer state carried from the optimistic to the pessimistic phase.
#[derive(Clone, Debug)]
pub struct DealerState {
    avss_common: AvssCommonMessage,
    ciphertexts: Vec<Ciphertext>,
}

/// The dealer's per-recipient message for the AVID (pessimistic) phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PessimisticMessage {
    /// One entry per pending recipient `i ∈ I`.
    pub dispersal: BTreeMap<PartyId, DispersalEntry>,
    pub dispersal_hash: Digest,
}

/// One pending recipient's slice of the AVID dispersal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispersalEntry {
    /// Merkle root over the receiver's ciphertext shards (the per-recipient `r_i`).
    pub recipient_root: merkle::Node,
    /// This receiver's shards for the recipient's ciphertext
    pub authenticated_shards: AuthenticatedShards,
}

/// The shared part of the dealer's broadcast (`v`) — identical for every receiver in both
/// phases.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssCommonMessage {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    ciphertext_shared: SharedComponents<EG>,
    response_polynomial: Poly<S>,
    ciphertext_hashes: Vec<Digest>,
}

/// A [AvssCommonMessage] that has been validated against the dealer's commitments by a receiver.
#[derive(Clone, Debug)]
pub struct VerifiedAvssCommonMessage(AvssCommonMessage);

/// A verified dispersal message from the pessimistic phase.
#[derive(Clone, Debug)]
pub struct VerifiedPessimisticMessage {
    pub message: PessimisticMessage,
    pub verified_common: VerifiedAvssCommonMessage,
}

/// The set of confirmers from the optimistic phase (parties not in `pending_recipients`), together
/// with the common message `H(v)` they attested to.
///
/// The caller constructs this directly and asserts that it has verified the confirmers' signed
/// [Confirm]s over `avss_common_message_hash`.
#[derive(Clone, Debug)]
pub struct VerifiedConfirmers {
    /// The confirmer party ids.
    pub confirmers: BTreeSet<PartyId>,
    /// `H(v)` — the common message the confirmers attested to.
    pub avss_common_message_hash: Digest,
}

/// A sender's shards for one recipient's ciphertext, with a Merkle proof against the
/// corresponding `recipient_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    shards: Vec<Shard>,
    proof: merkle::MerkleProof,
}

/// One sender's echo to a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Echo {
    sender: PartyId,
    authenticated_shards: AuthenticatedShards,
    pub dispersal_hash: Digest,
}

/// An [Echo] that has been verified by [Receiver::verify_echo] against a specific [AvssCommonMessage].
#[derive(Clone, Debug)]
pub struct VerifiedEcho(Echo);

/// The result of [Receiver::decode_ciphertext]: either a successfully reconstructed ciphertext
/// whose AVID dispersal is consistent, or a [BlameComplaint] when the collected shards either fail
/// to RS-decode or decode to a ciphertext whose re-encoding disagrees with the dealer's `r_i`.
#[allow(clippy::large_enum_variant)]
pub enum DecodeOutcome {
    Decoded(Ciphertext),
    InvalidDispersal(BlameComplaint),
}

/// The result of [Receiver::verify_and_decrypt].
#[allow(clippy::large_enum_variant)]
pub enum DecryptionOutcome {
    Valid(ReceiverOutput),
    Invalid(RevealComplaint),
}

/// An endorsement of the dealer's pessimistic broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub dispersal_hash: Digest,
}

/// A complaint by a receiver who could not decrypt or verify its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealComplaint {
    /// This is unforgeable since the recovery package in `proof` only decrypts under the accuser's key.
    pub accuser_id: PartyId,
    pub proof: recovery_proof::RecoveryProof,
    pub ciphertext: Ciphertext,
    pub dispersal_hash: Digest,
}

/// A complaint by a receiver who found the AVID dispersal inconsistent.
///
/// `accuser_id` is unauthenticated at this layer. The caller is responsible for attributing
/// the complaint to a specific sender.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlameComplaint {
    pub accuser_id: PartyId,
    pub shards: BTreeMap<PartyId, AuthenticatedShards>,
    pub dispersal_hash: Digest,
}

/// A responder's reply to a [RevealComplaint] / [BlameComplaint]: their dealer-encrypted
/// ciphertext plus a recovery package, so the accuser can authenticate and decrypt the
/// responder's shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplaintResponse {
    pub responder_id: PartyId,
    pub ciphertext: Ciphertext,
    pub recovery_package: RecoveryPackage<EG>,
}

/// A [ComplaintResponse] that has been verified by [Receiver::verify_complaint_response]: the
/// carried ciphertext is AVID-bound to the dealer's broadcast, decryption via the recovery
/// package yielded shares satisfying the dealer's response polynomial.
#[derive(Clone, Debug)]
pub struct VerifiedComplaintResponse {
    responder_id: PartyId,
    shares: SharesForNode,
}

/// The output of a receiver which is a batch of shares and public keys for all nonces.
#[derive(Debug, Clone)]
pub struct ReceiverOutput {
    pub my_shares: SharesForNode,
    pub public_keys: Vec<G>,
}

/// This represents a set of shares for a node. A total of <i>L</i> secrets/nonces are being
/// shared. If we say that node <i>i</i> has a weight `W_i`, we have
/// `indices().len() == shares_for_secret(i).len() == weight() = W_i`.
///
/// Produced by [Receiver::verify_and_decrypt] on the happy path, or by [Receiver::recover] from
/// complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode {
    pub shares: Vec<ShareBatch>,
}

/// A batch of shares for a single share index, containing shares for each secret and one for the
/// "blinding" polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch {
    /// The index of the share (i.e., the share id).
    pub index: ShareIndex,

    /// The shares for each secret.
    pub batch: Vec<S>,

    /// The share for the blinding polynomial.
    pub blinding_share: S,
}

impl Dealer {
    /// Create a new dealer.
    ///
    /// * `nodes` defines the set of receivers and their weights.
    /// * `dealer_id` is the id of this dealer as a node.
    /// * `params` carries the reconstruction threshold `t` and Byzantine bound `f`.
    /// * `sid` is a session identifier that should be unique for each invocation, but the same
    ///   for all parties.
    /// * `batch_size_per_weight` is the number of secrets a dealer should deal per weight it has.
    ///
    /// Returns an `InvalidInput` error if
    /// * t is larger than the total weight of the nodes.
    /// * the `dealer_id` is invalid (not part of `nodes`).
    pub fn new(
        nodes: Nodes<EG>,
        dealer_id: PartyId,
        params: Parameters,
        sid: Vec<u8>,
        batch_size_per_weight: u16,
    ) -> FastCryptoResult<Self> {
        params.validate(nodes.total_weight())?;
        // Each dealer deals a number of nonces proportional to their weight.
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;
        Ok(Self {
            params,
            nodes,
            sid,
            batch_size,
        })
    }

    /// 1. Build the optimistic-phase messages: encrypt shares for every receiver and bundle each
    ///    receiver's ciphertext with `v`. Returns a [DealerState] that can be used to produce the
    ///    pessimistic-phase messages later, after the dealer has collected a certificate.
    pub fn create_optimistic_messages(
        &self,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(DealerState, BTreeMap<PartyId, OptimisticMessage>)> {
        let state = self.create_encrypted_shares_with_mutation(rng, |_| {})?;
        let messages = state
            .ciphertexts
            .iter()
            .zip(self.nodes.node_ids_iter())
            .map(|(ct, i)| {
                (
                    i,
                    OptimisticMessage {
                        avss_common: state.avss_common.clone(),
                        ciphertext: ct.clone(),
                    },
                )
            })
            .collect();
        Ok((state, messages))
    }

    /// Encrypt shares, build `v`, and return the dealer state. Test mutation hook runs after the
    /// plaintexts are constructed and before encryption.
    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    fn create_encrypted_shares_with_mutation(
        &self,
        rng: &mut impl AllowedRng,
        mutate_plaintexts: impl FnOnce(&mut [(crate::ecies_v1::PublicKey<EG>, Vec<u8>)]),
    ) -> FastCryptoResult<DealerState> {
        let secrets = repeat_with(|| S::rand(rng))
            .take(self.batch_size)
            .collect_vec();

        // Compute the (full) public keys for all secrets
        let full_public_keys = secrets.iter().map(|s| G::generator() * s).collect_vec();

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let total_weight = self.nodes.total_weight();
        let blinding_secret = S::rand(rng);
        let blinding_poly_evaluations =
            create_secret_sharing(rng, blinding_secret, self.params.t, total_weight);
        let blinding_commit = G::generator() * blinding_secret;

        // Compute all evaluations of all polynomials
        let share_batches = secrets
            .iter()
            .map(|&s| create_secret_sharing(rng, s, self.params.t, total_weight))
            .collect_vec();

        // Encrypt all shares to the receivers
        let mut pk_and_msgs = self
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

        #[cfg(test)]
        mutate_plaintexts(&mut pk_and_msgs);

        let random_oracle = self.random_oracle();

        let encryption = MultiRecipientEncryption::encrypt(
            &pk_and_msgs,
            &random_oracle.extend(&Encryption.to_string()),
            rng,
        );
        let (ciphertext_shared, ciphertexts) = encryption.into_parts();

        let ciphertext_hashes = ciphertexts.iter().map(hash_ciphertext).collect_vec();

        // "response" polynomial from https://eprint.iacr.org/2023/536.pdf
        let challenge = compute_challenge(
            &random_oracle,
            &full_public_keys,
            &blinding_commit,
            &ciphertext_shared,
            &ciphertext_hashes,
        );

        // Get the first t evaluations for the response polynomial and use these to compute the coefficients.
        let response_polynomial = Poly::interpolate(
            &share_batches
                .into_iter()
                .map(|s| s.take(self.params.t))
                .zip_eq(&challenge)
                .fold(
                    blinding_poly_evaluations.take(self.params.t),
                    |acc, (p_l, gamma_l)| acc + p_l * gamma_l,
                )
                .to_vec(),
        )?;

        let common = AvssCommonMessage {
            full_public_keys,
            blinding_commit,
            ciphertext_shared,
            response_polynomial,
            ciphertext_hashes,
        };

        Ok(DealerState {
            avss_common: common,
            ciphertexts,
        })
    }

    /// 3. Build a [PessimisticMessage] per receiver dispersing the existing `E_i` for
    ///    `i ∈ pending_recipients` (those that didn't confirm) via AVID. Every message pins the
    ///    same [dispersal_hash], returned so the caller knows the signing target for the
    ///    confirmer/voter quorum.
    ///
    ///    Only needed for the stragglers: if every receiver confirmed in the optimistic phase, the
    ///    pessimistic phase is skipped entirely.
    pub fn create_pessimistic_messages(
        &self,
        state: &DealerState,
        pending_recipients: BTreeSet<PartyId>,
    ) -> FastCryptoResult<(Digest, Vec<PessimisticMessage>)> {
        self.create_pessimistic_messages_with_mutation(state, pending_recipients, |_| {})
    }

    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    fn create_pessimistic_messages_with_mutation(
        &self,
        state: &DealerState,
        pending_recipients: BTreeSet<PartyId>,
        mutate_shards: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<(Digest, Vec<PessimisticMessage>)> {
        // Validate pending_recipients ⊆ all_ids.
        let all_ids: BTreeSet<PartyId> = self.nodes.node_ids_iter().collect();
        if !pending_recipients.is_subset(&all_ids) {
            return Err(InvalidInput);
        }
        let avss_common_message_hash = state.avss_common.hash();

        let code = get_coder(&self.nodes, self.params.f);

        // RS-encode each pending recipient's ciphertext and bucket shards by sender.
        let mut shards_by_recipient: BTreeMap<PartyId, Vec<Vec<Shard>>> = pending_recipients
            .iter()
            .map(|&i| {
                let shards = code
                    .encode(&state.ciphertexts[i as usize].0)
                    .expect("non-empty ciphertext");
                let by_sender = self.nodes.collect_to_nodes(shards.into_iter())?;
                Ok((i, by_sender))
            })
            .collect::<FastCryptoResult<_>>()?;

        #[cfg(test)]
        mutate_shards(&mut shards_by_recipient);

        let recipient_trees: BTreeMap<PartyId, MerkleTree<Blake2b256>> = shards_by_recipient
            .iter()
            .map(|(&i, shards)| Ok((i, recipient_tree(shards)?)))
            .collect::<FastCryptoResult<_>>()?;

        let dispersal_hash = dispersal_hash(
            &avss_common_message_hash,
            recipient_trees.iter().map(|(&i, tree)| (i, tree.root())),
        );

        let messages = self
            .nodes
            .node_ids_iter()
            .map(|j| {
                let dispersal: BTreeMap<PartyId, DispersalEntry> = pending_recipients
                    .iter()
                    .map(|&i| {
                        let tree = recipient_trees.get(&i).expect("populated above");
                        let shards = shards_by_recipient.get(&i).expect("populated above")
                            [j as usize]
                            .clone();
                        Ok((
                            i,
                            DispersalEntry {
                                recipient_root: tree.root(),
                                authenticated_shards: AuthenticatedShards {
                                    shards,
                                    proof: tree.get_proof(j as usize)?,
                                },
                            },
                        ))
                    })
                    .collect::<FastCryptoResult<_>>()?;
                Ok(PessimisticMessage {
                    dispersal,
                    dispersal_hash,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        Ok((dispersal_hash, messages))
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
    /// * `params` carries the reconstruction threshold `t` and Byzantine bound `f`.
    /// * `sid` is a session identifier that should be unique for each invocation, but the same
    ///   for all parties.
    /// * `enc_secret_key` is this Receivers' secret key for the distribution of nonces. The
    ///   corresponding public key is defined in `nodes`.
    /// * `batch_size_per_weight` is the number of secrets a dealer should deal per weight it has.
    ///
    /// Returns an `InvalidInput` error if the `id` or `dealer_id` is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nodes: Nodes<EG>,
        id: PartyId,
        dealer_id: PartyId,
        params: Parameters,
        sid: Vec<u8>,
        enc_secret_key: PrivateKey<EG>,
        batch_size_per_weight: u16,
    ) -> FastCryptoResult<Self> {
        // Check that the id is valid
        let _ = nodes.node_id_to_node(id)?;

        // The dealer is expected to deal a number of nonces proportional to it's weight
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;

        params.validate(nodes.total_weight())?;

        Ok(Self {
            id,
            enc_secret_key,
            nodes,
            sid,
            params,
            batch_size,
        })
    }

    /// 2. Process a message from the dealer in the optimistic phase. On success returns the
    ///    [ReceiverOutput], a [Confirm] for the dealer, and the [VerifiedAvssCommonMessage] (retain
    ///    for the session). On any failure the receiver silently ignores the message and falls
    ///    through to the pessimistic phase.
    ///
    ///    A confirmer should also retain its own ciphertext `E_j` (`message.ciphertext`) so it can
    ///    answer complaints later via [Self::handle_reveal] / [Self::handle_blame].
    pub fn process_optimistic(
        &self,
        message: &OptimisticMessage,
    ) -> FastCryptoResult<(ReceiverOutput, Confirm, VerifiedAvssCommonMessage)> {
        let verified_common = self.verify_common_message(message.avss_common.clone())?;
        self.check_ciphertext_hash(&message.ciphertext, &verified_common)?;
        let output = self.decrypt_and_verify_shares(&message.ciphertext, &verified_common)?;
        Ok((
            output,
            Confirm {
                avss_common_message_hash: verified_common.common().hash(),
            },
            verified_common,
        ))
    }

    /// Verify a [AvssCommonMessage] (see [AvssCommonMessage::verify]) and return the resulting
    /// [VerifiedAvssCommonMessage].
    pub fn verify_common_message(
        &self,
        common_message: AvssCommonMessage,
    ) -> FastCryptoResult<VerifiedAvssCommonMessage> {
        common_message.verify(
            self.params.t,
            self.batch_size,
            self.nodes.num_nodes(),
            &self.random_oracle(),
        )
    }

    /// 4. Verify the AVID-phase [PessimisticMessage] against a [VerifiedAvssCommonMessage] and emit
    ///    one [Echo] per pending recipient. The receiver is expected to already hold the
    ///    [VerifiedAvssCommonMessage] from the optimistic phase or to have fetched it from a confirming party.
    ///    Returns also a [VerifiedPessimisticMessage] for the AVID-layer calls and a [Vote] over the
    ///    `dispersal_hash`.
    ///
    /// The [Vote] only attests to the **dispersal layer** — `H(v)` and the Merkle roots — not
    /// to share validity. Pending recipients can therefore publish the Vote immediately, before
    /// they've run [Self::verify_and_decrypt] on their own ciphertext.
    pub fn echo(
        &self,
        message: PessimisticMessage,
        verified_common: VerifiedAvssCommonMessage,
        verified_confirmers: &VerifiedConfirmers,
    ) -> FastCryptoResult<(VerifiedPessimisticMessage, BTreeMap<PartyId, Echo>, Vote)> {
        if self
            .nodes
            .total_weight_of(verified_confirmers.confirmers.iter())?
            < self.params.t + self.params.f
        {
            warn!("batch_avss echo: not enough confirmers");
            return Err(NotEnoughWeight((self.params.t + self.params.f) as usize));
        }
        let expected_avss_common_message_hash = verified_common.common().hash();
        if verified_confirmers.avss_common_message_hash != expected_avss_common_message_hash {
            warn!("batch_avss echo: confirmers attested to a different common message");
            return Err(InvalidMessage);
        }
        message.verify(
            &self.nodes,
            &expected_avss_common_message_hash,
            self.id,
            verified_confirmers,
        )?;

        let dispersal_hash = message.dispersal_hash;
        let echoes = message
            .dispersal
            .iter()
            .map(|(&i, entry)| {
                (
                    i,
                    Echo {
                        sender: self.id,
                        authenticated_shards: entry.authenticated_shards.clone(),
                        dispersal_hash,
                    },
                )
            })
            .collect();
        Ok((
            VerifiedPessimisticMessage {
                message,
                verified_common,
            },
            echoes,
            Vote { dispersal_hash },
        ))
    }

    /// Verify an [Echo] addressed to this receiver against a [VerifiedPessimisticMessage]. Returns a
    /// [VerifiedEcho] suitable for [Self::decode_ciphertext].
    ///
    /// Precondition: `self.id` is one of the message's dispersal recipients. Echoes are only
    /// meaningful for pending recipients; confirmers calling this for themselves get
    /// [InvalidInput].
    pub fn verify_echo(
        &self,
        echo: Echo,
        verified_message: &VerifiedPessimisticMessage,
    ) -> FastCryptoResult<VerifiedEcho> {
        if !verified_message.message.dispersal.contains_key(&self.id) {
            return Err(InvalidInput);
        }
        let weight = self.nodes.weight_of(echo.sender)?;
        let expected_dispersal_hash = &verified_message.message.dispersal_hash;
        let recipient_root = verified_message.recipient_root(self.id)?;
        echo.verify(weight, expected_dispersal_hash, recipient_root)
    }

    /// 5. Reconstruct this receiver's ciphertext from a quorum of [VerifiedEcho]s (`≥ W − 2f`
    ///    weight). Returns [DecodeOutcome::Decoded] when the dispersal is consistent, or
    ///    [DecodeOutcome::InvalidDispersal] (a [BlameComplaint]) otherwise.
    ///
    ///    The [BlameComplaint] is a dispersal-layer fault: hold it until the matching `H(v)` is
    ///    certified on the TOB, or discard it if a different `v` wins.
    ///
    ///    A pending recipient should retain its echoes and the decoded ciphertext for the session,
    ///    to decode and to answer complaints.
    pub fn decode_ciphertext(
        &self,
        echos: &[VerifiedEcho],
        verified_message: &VerifiedPessimisticMessage,
    ) -> FastCryptoResult<DecodeOutcome> {
        if !echos.iter().map(|e| e.0.sender).all_unique() {
            return Err(InvalidInput);
        }

        let required_weight = self.nodes.total_weight() - 2 * self.params.f;
        if self
            .nodes
            .total_weight_of(echos.iter().map(|e| &e.0.sender))?
            < required_weight
        {
            return Err(NotEnoughWeight(required_weight as usize));
        }

        let shards: BTreeMap<PartyId, AuthenticatedShards> = echos
            .iter()
            .cloned()
            .map(|e| (e.0.sender, e.0.authenticated_shards))
            .collect();

        let common = verified_message.verified_common.common();
        let recipient_root = verified_message.recipient_root(self.id)?;
        let expected_hash = common.ciphertext_hash(self.id).ok_or(InvalidProof)?;
        Ok(self
            .reconstruct_ciphertext(self.id, &shards)
            .and_then(|ct| {
                self.check_avid_consistency(&ct, recipient_root)?;
                if hash_ciphertext(&ct) != *expected_hash {
                    return Err(InvalidMessage);
                }
                Ok(DecodeOutcome::Decoded(ct))
            })
            .unwrap_or_else(|e| {
                warn!(
                    "batch_avss decode_ciphertext: receiver {} raising BlameComplaint after RS-decode / AVID-consistency / ciphertext-hash check failed: {e:?}",
                    self.id,
                );
                DecodeOutcome::InvalidDispersal(BlameComplaint {
                    accuser_id: self.id,
                    shards,
                    dispersal_hash: verified_message.message.dispersal_hash,
                })
            }))
    }

    /// 6. Decrypt and verify the receiver's own shares from a successfully decoded ciphertext.
    ///    Rejects with [InvalidMessage] if the ciphertext doesn't match the hash pinned in `v`.
    ///    Otherwise yields [DecryptionOutcome::Valid] when shares verify, or
    ///    [DecryptionOutcome::Invalid] (a [RevealComplaint] bound to `dispersal_hash`) when they
    ///    don't.
    ///
    ///    The [RevealComplaint] is an encryption-layer fault carrying the accuser's ciphertext and
    ///    an ECIES recovery package; broadcast it only after the TOB certificate pins `H(v)`.
    pub fn verify_and_decrypt(
        &self,
        ciphertext: &Ciphertext,
        common_message: &VerifiedAvssCommonMessage,
        dispersal_hash: Digest,
    ) -> FastCryptoResult<DecryptionOutcome> {
        self.check_ciphertext_hash(ciphertext, common_message)?;
        match self.decrypt_and_verify_shares(ciphertext, common_message) {
            Ok(output) => Ok(DecryptionOutcome::Valid(output)),
            Err(e) => {
                warn!(
                    "batch_avss verify_and_decrypt: receiver {} raising RevealComplaint after share decode/verify failed: {e:?}",
                    self.id,
                );
                Ok(DecryptionOutcome::Invalid(RevealComplaint {
                    accuser_id: self.id,
                    proof: recovery_proof::RecoveryProof::create(
                        self.id,
                        &common_message.common().ciphertext_shared,
                        &self.enc_secret_key,
                        &self.random_oracle(),
                        &mut rand::thread_rng(),
                    ),
                    ciphertext: ciphertext.clone(),
                    dispersal_hash,
                }))
            }
        }
    }

    /// Reject a ciphertext whose hash doesn't match the one pinned for this receiver in `v`. This
    /// stops a dealer from dispersing a different ciphertext via AVID.
    fn check_ciphertext_hash(
        &self,
        ciphertext: &Ciphertext,
        common_message: &VerifiedAvssCommonMessage,
    ) -> FastCryptoResult<()> {
        let expected_hash = common_message
            .common()
            .ciphertext_hashes
            .get(self.id as usize)
            .ok_or(InvalidMessage)?;
        if hash_ciphertext(ciphertext) != *expected_hash {
            warn!(
                "batch_avss check_ciphertext_hash: ciphertext hash does not match ciphertext_hashes[{}]",
                self.id,
            );
            return Err(InvalidMessage);
        }
        Ok(())
    }

    /// Decrypt and verify this receiver's own shares against the common message, returning the
    /// [ReceiverOutput] on success or the underlying error.
    fn decrypt_and_verify_shares(
        &self,
        ciphertext: &Ciphertext,
        common_message: &VerifiedAvssCommonMessage,
    ) -> FastCryptoResult<ReceiverOutput> {
        let common_message = common_message.common();
        let AvssCommonMessage {
            full_public_keys,
            ciphertext_shared,
            ..
        } = &common_message;
        let random_oracle = self.random_oracle();

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        let plaintext = ciphertext_shared.decrypt(
            ciphertext,
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        let challenge = compute_challenge_from_common_message(&random_oracle, common_message);
        let my_shares = SharesForNode::from_bytes(plaintext)?;
        my_shares.verify(
            common_message,
            &challenge,
            &self.nodes.share_ids_of(self.id)?,
            self.batch_size,
        )?;
        Ok(ReceiverOutput {
            my_shares,
            public_keys: full_public_keys.clone(),
        })
    }

    /// 7a. Validate a [RevealComplaint] complaint and respond with this party's own shares so
    ///     the accuser can recover. Accepts iff the ciphertext is bound to the dealer's broadcast
    ///     and the recovery package decrypts it to invalid shares.
    pub fn handle_reveal(
        &self,
        reveal: &RevealComplaint,
        verified_message: &VerifiedPessimisticMessage,
        own_ciphertext: Ciphertext,
    ) -> FastCryptoResult<ComplaintResponse> {
        let common_message = verified_message.common();
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);

        let RevealComplaint {
            accuser_id,
            proof,
            ciphertext: reveal_ciphertext,
            dispersal_hash,
        } = reveal;

        if *dispersal_hash != verified_message.message.dispersal_hash {
            return Err(InvalidProof);
        }
        let recipient_root = verified_message.recipient_root(*accuser_id)?;
        self.check_avid_consistency(reveal_ciphertext, recipient_root)
            .map_err(|_| InvalidProof)?;
        let accuser = self.nodes.node_id_to_node(*accuser_id)?;
        let accuser_indices = self.nodes.share_ids_of(*accuser_id)?;
        proof.check(
            *accuser_id,
            &accuser.pk,
            reveal_ciphertext,
            &common_message.ciphertext_shared,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                shares.verify(
                    common_message,
                    &challenge,
                    &accuser_indices,
                    self.batch_size,
                )
            },
        )?;

        Ok(self.build_complaint_response(common_message, own_ciphertext))
    }

    /// 7b. Validate a [BlameComplaint] and respond with this party's shares.
    pub fn handle_blame(
        &self,
        blame: &BlameComplaint,
        verified_message: &VerifiedPessimisticMessage,
        own_ciphertext: Ciphertext,
    ) -> FastCryptoResult<ComplaintResponse> {
        let common_message = verified_message.common();

        let BlameComplaint {
            accuser_id,
            shards,
            dispersal_hash,
        } = blame;

        if *dispersal_hash != verified_message.message.dispersal_hash {
            return Err(InvalidProof);
        }
        let recipient_root = verified_message.recipient_root(*accuser_id)?;
        let expected_hash = common_message
            .ciphertext_hash(*accuser_id)
            .ok_or(InvalidProof)?;

        if shards
            .iter()
            .any(|(sender, auth)| auth.verify(*sender as usize, recipient_root).is_err())
        {
            return Err(InvalidProof);
        }

        let weight_of_shards = self.nodes.total_weight_of(shards.keys())?;
        if weight_of_shards < self.nodes.total_weight() - 2 * self.params.f {
            return Err(InvalidProof);
        }

        // The blame is valid iff the contributed shards either fail to RS-decode, decode to a
        // ciphertext whose re-encoding doesn't match the accuser's `r_i`, or decode to a
        // ciphertext whose hash doesn't match `ciphertext_hashes[accuser_id]` in `v`.
        if self
            .reconstruct_ciphertext(*accuser_id, shards)
            .ok()
            .is_some_and(|ct| {
                self.check_avid_consistency(&ct, recipient_root).is_ok()
                    && hash_ciphertext(&ct) == *expected_hash
            })
        {
            return Err(InvalidProof);
        }

        Ok(self.build_complaint_response(common_message, own_ciphertext))
    }

    /// Build a [ComplaintResponse] for an answered [RevealComplaint] / [BlameComplaint]: package
    /// this party's own dealer-encrypted ciphertext together with an ECIES recovery package, so
    /// the accuser can decrypt and authenticate the responder's shares.
    fn build_complaint_response(
        &self,
        common_message: &AvssCommonMessage,
        ciphertext: Ciphertext,
    ) -> ComplaintResponse {
        let recovery_package = common_message.ciphertext_shared.create_recovery_package(
            &self.enc_secret_key,
            &self.random_oracle().extend(&Recovery(self.id).to_string()),
            &mut rand::thread_rng(),
        );
        ComplaintResponse {
            responder_id: self.id,
            ciphertext,
            recovery_package,
        }
    }

    /// Verify a [ComplaintResponse] against `common_message`: confirm that the responder's
    /// ciphertext is the one the dealer broadcast to them, that the recovery package decrypts
    /// it, and that the recovered shares are the ones the dealer dealt. Returns a
    /// [VerifiedComplaintResponse] suitable for [Self::recover].
    pub fn verify_complaint_response(
        &self,
        response: ComplaintResponse,
        verified_message: &VerifiedPessimisticMessage,
    ) -> FastCryptoResult<VerifiedComplaintResponse> {
        let common_message = verified_message.common();
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);

        let ComplaintResponse {
            responder_id,
            ciphertext,
            recovery_package,
        } = response;

        // The responder may be a confirmer (not in `pending_recipients`), so their dispersal
        // entries — and hence their `recipient_root` — aren't in the [PessimisticMessage].
        // Instead, verify the responder's ciphertext against `v`'s `ciphertext_hashes`, which
        // pin every receiver's ciphertext in `v`.
        let expected_hash = common_message
            .ciphertext_hash(responder_id)
            .ok_or(InvalidProof)?;
        if hash_ciphertext(&ciphertext) != *expected_hash {
            return Err(InvalidProof);
        }
        let responder = self.nodes.node_id_to_node(responder_id)?;
        let shares = common_message
            .ciphertext_shared
            .decrypt_with_recovery_package(
                &ciphertext,
                &recovery_package,
                &self
                    .random_oracle()
                    .extend(&Recovery(responder_id).to_string()),
                &self.random_oracle().extend(&Encryption.to_string()),
                &responder.pk,
                responder_id as usize,
            )
            .and_then(SharesForNode::from_bytes)?;

        shares.verify(
            common_message,
            &challenge,
            &self.nodes.share_ids_of(responder_id)?,
            self.batch_size,
        )?;

        Ok(VerifiedComplaintResponse {
            responder_id,
            shares,
        })
    }

    /// 8. Recover the accuser's own shares from a quorum of [VerifiedComplaintResponse]s.
    ///    Responses must already be validated via [Self::verify_complaint_response]. Fails if
    ///    `common_message` is malformed, the responses contribute `< t` weight, or the
    ///    interpolated shares fail final verification.
    pub fn recover(
        &self,
        verified_message: &VerifiedPessimisticMessage,
        responses: Vec<VerifiedComplaintResponse>,
    ) -> FastCryptoResult<ReceiverOutput> {
        // Reject duplicate responders before summing weight, so an attacker can't inflate the
        // weight tally by replaying one party's response.
        if !responses.iter().map(|r| r.responder_id).all_unique() {
            return Err(InvalidInput);
        }
        let response_shares = responses.into_iter().map(|v| v.shares).collect_vec();
        let response_weight: u16 = response_shares.iter().map(SharesForNode::weight).sum();
        if response_weight < self.params.t {
            return Err(FastCryptoError::InputTooShort(self.params.t as usize));
        }

        let common_message = verified_message.common();
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);
        let my_shares = SharesForNode::recover(self, &response_shares)?;
        my_shares.verify(
            common_message,
            &challenge,
            &self.nodes.share_ids_of(self.id)?,
            self.batch_size,
        )?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: common_message.full_public_keys.clone(),
        })
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }

    /// Reed-Solomon decode the ciphertext for `accuser_id` from a set of authenticated shard
    /// contributions, keyed by sender id. Missing senders and senders whose shard count
    /// doesn't match their weight are treated as erasures, so RS decoding fails if those
    /// account for more than `2f` of the total weight. The caller is responsible for having
    /// authenticated the shards via their Merkle proofs.
    fn reconstruct_ciphertext(
        &self,
        accuser_id: PartyId,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
    ) -> FastCryptoResult<Ciphertext> {
        let shards_matrix = self
            .nodes
            .node_ids_iter()
            .flat_map(|id| -> Vec<Option<Shard>> {
                let weight = self.nodes.weight_of(id).expect("valid party id") as usize;
                match shards.get(&id) {
                    // If the shards exist and are consistent with the weight, put them in the
                    // matrix. Otherwise, add a None, corresponding to an erasure.
                    Some(auth) if auth.shards.len() == weight => {
                        auth.shards.iter().cloned().map(Some).collect_vec()
                    }
                    _ => vec![None; weight],
                }
            })
            .collect_vec();

        // The encryption used, counter-mode, is length-preserving, so the length of the
        // ciphertext is equal to the length of the plaintext.
        let expected_length = SharesForNode::bcs_serialized_size(
            self.nodes.weight_of(accuser_id)? as usize,
            self.batch_size,
        );
        get_coder(&self.nodes, self.params.f)
            .decode(shards_matrix, expected_length)
            .map(Ciphertext)
    }

    /// RS-encode `ciphertext`, rebuild the per-recipient Merkle tree, and check its root matches
    /// the dealer's `expected_root`. Errors with [InvalidMessage] on mismatch.
    fn check_avid_consistency(
        &self,
        ciphertext: &Ciphertext,
        expected_root: &merkle::Node,
    ) -> FastCryptoResult<()> {
        let new_shards = self.nodes.collect_to_nodes(
            get_coder(&self.nodes, self.params.f)
                .encode(&ciphertext.0)?
                .into_iter(),
        )?;
        if recipient_tree(&new_shards)?.root() != *expected_root {
            return Err(InvalidMessage);
        }
        Ok(())
    }
}

impl DealerState {
    /// The shared `v` ([AvssCommonMessage]) committed in the optimistic phase.
    pub fn common(&self) -> &AvssCommonMessage {
        &self.avss_common
    }

    /// Test-only: per-recipient ciphertext for the given party.
    #[cfg(test)]
    fn ciphertext_for(&self, id: PartyId) -> &Ciphertext {
        &self.ciphertexts[id as usize]
    }
}

impl PessimisticMessage {
    /// Verify the structural shape of this [PessimisticMessage] and the receiver's own
    /// dispersal proofs. Checks that:
    ///   * dispersal recipients and confirmers partition the node set
    ///   * `dispersal_hash` matches the combined hash of `expected_avss_common_message_hash` and
    ///     the actual roots in `dispersal`,
    ///   * every dispersal entry Merkle-authenticates against its root at leaf `receiver_id`.
    ///
    /// The confirmers are taken on trust from the [VerifiedConfirmers] the caller constructed.
    fn verify(
        &self,
        nodes: &Nodes<EG>,
        expected_avss_common_message_hash: &Digest,
        receiver_id: PartyId,
        confirmers: &VerifiedConfirmers,
    ) -> FastCryptoResult<()> {
        // Dispersal recipients and confirmers must partition the node set.
        if !self
            .dispersal
            .keys()
            .chain(confirmers.confirmers.iter())
            .copied()
            .sorted()
            .eq(nodes.node_ids_iter().sorted())
        {
            warn!(
                "batch_avss PessimisticMessage::verify: dispersal recipients and confirmers do not partition the node set (dispersal.len() = {}, confirmers.len() = {}, num_nodes = {})",
                self.dispersal.len(),
                confirmers.confirmers.len(),
                nodes.num_nodes(),
            );
            return Err(InvalidMessage);
        }

        let expected_dispersal_hash = dispersal_hash(
            expected_avss_common_message_hash,
            self.dispersal
                .iter()
                .map(|(&i, e)| (i, e.recipient_root.clone())),
        );
        if self.dispersal_hash != expected_dispersal_hash {
            warn!(
                "batch_avss PessimisticMessage::verify: dispersal_hash does not match expected (computed from v and dispersal roots)"
            );
            return Err(InvalidMessage);
        }

        for entry in self.dispersal.values() {
            entry
                .authenticated_shards
                .verify(receiver_id as usize, &entry.recipient_root)
                .map_err(|e| {
                    warn!(
                        "batch_avss PessimisticMessage::verify: dispersal entry Merkle proof failed at receiver {}: {e:?}",
                        receiver_id,
                    );
                    e
                })?;
        }

        Ok(())
    }
}

impl Parameters {
    /// Validate `(t, f)` against the given total weight `W`.
    ///   * It is possible to create a Reed-Solomon `(W, W − 2f)` coder.
    ///   * `1 ≤ t ≤ W` — recovery threshold is well-defined and reachable by the total weight.
    pub fn validate(&self, total_weight: u16) -> FastCryptoResult<()> {
        let Parameters { t, f } = *self;
        if f == 0 || total_weight <= 2 * f || t == 0 || t > total_weight {
            return Err(InvalidInput);
        }
        ErasureCoder::check_parameters(total_weight as usize, (total_weight - 2 * f) as usize)?;
        Ok(())
    }
}

impl VerifiedPessimisticMessage {
    fn common(&self) -> &AvssCommonMessage {
        self.verified_common.common()
    }

    fn recipient_root(&self, party: PartyId) -> FastCryptoResult<&merkle::Node> {
        self.message
            .dispersal
            .get(&party)
            .map(|d| &d.recipient_root)
            .ok_or(InvalidProof)
    }
}

impl VerifiedAvssCommonMessage {
    /// The validated [AvssCommonMessage].
    pub fn common(&self) -> &AvssCommonMessage {
        &self.0
    }
}

impl AvssCommonMessage {
    /// Verify the dealer's commitments: lengths/degree are well-formed, the encryption NIZK in
    /// `ciphertext_shared` checks, and `g^{p''(0)} = c' · ∏ c_l^{γ_l}`. Consumes `self` and
    /// returns a [VerifiedAvssCommonMessage] on success.
    fn verify(
        self,
        t: u16,
        batch_size: usize,
        num_nodes: usize,
        random_oracle: &RandomOracle,
    ) -> FastCryptoResult<VerifiedAvssCommonMessage> {
        if t == 0
            || self.full_public_keys.len() != batch_size
            || self.response_polynomial.degree() != t as usize - 1
            || self.ciphertext_hashes.len() != num_nodes
        {
            warn!(
                "batch_avss AvssCommonMessage::verify: invalid sizes (t = {}, full_public_keys.len() = {}, expected {}; response_polynomial.degree() = {}, expected {}; ciphertext_hashes.len() = {}, expected {})",
                t,
                self.full_public_keys.len(),
                batch_size,
                self.response_polynomial.degree(),
                t as usize - 1,
                self.ciphertext_hashes.len(),
                num_nodes,
            );
            return Err(InvalidMessage);
        }
        self.ciphertext_shared
            .verify(&random_oracle.extend(&Encryption.to_string()))
            .map_err(|e| {
                warn!("batch_avss AvssCommonMessage::verify: ciphertext_shared NIZK verification failed: {e:?}");
                InvalidMessage
            })?;
        let challenge = compute_challenge_from_common_message(random_oracle, &self);
        if G::generator() * self.response_polynomial.c0()
            != self.blinding_commit
                + G::multi_scalar_mul(&challenge, &self.full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            warn!(
                "batch_avss AvssCommonMessage::verify: response polynomial does not match the blinding commitment and public keys"
            );
            return Err(InvalidMessage);
        }
        Ok(VerifiedAvssCommonMessage(self))
    }

    /// Canonical Blake2b-256 hash of this [AvssCommonMessage]. Used to bind echoes and complaints
    /// to a specific dealer broadcast.
    pub fn hash(&self) -> Digest {
        let mut hasher = Blake2b256::new();
        hasher.update(bcs::to_bytes(self).expect("serialize should never fail"));
        hasher.finalize()
    }

    pub fn ciphertext_hash(&self, id: PartyId) -> Option<&Digest> {
        self.ciphertext_hashes.get(id as usize)
    }
}

impl ShareBatch {
    /// Verify a batch of shares using the given challenge.
    fn verify(&self, message: &AvssCommonMessage, challenge: &[S]) -> FastCryptoResult<()> {
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

    fn verify(
        &self,
        message: &AvssCommonMessage,
        challenge: &[S],
        expected_indices: &[ShareIndex],
        expected_batch_size: usize,
    ) -> FastCryptoResult<()> {
        let actual_batch_size = self.try_uniform_batch_size()?;
        if actual_batch_size != expected_batch_size {
            warn!(
                "batch_avss SharesForNode::verify: batch_size {} does not match expected {}",
                actual_batch_size, expected_batch_size,
            );
            return Err(InvalidMessage);
        }
        let actual: BTreeSet<ShareIndex> = self.shares.iter().map(|s| s.index).collect();
        let expected: BTreeSet<ShareIndex> = expected_indices.iter().copied().collect();
        if actual != expected {
            warn!("batch_avss SharesForNode::verify: share index set does not match expected");
            return Err(InvalidMessage);
        }
        for shares in &self.shares {
            shares.verify(message, challenge).map_err(|e| {
                warn!(
                    "batch_avss SharesForNode::verify: cryptographic share verification failed at index {:?}: {e:?}",
                    shares.index,
                );
                e
            })?;
        }
        Ok(())
    }

    /// Recover the shares for this node.
    ///
    /// Fails if `other_shares` is empty or if the batch sizes of all shares in `other_shares`
    /// are not equal to the expected batch size.
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
                        Ok(Poly::recover_at(index, &evaluations)?.value)
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()?;

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

    /// BCS-serialized length of a `SharesForNode` for a node of the given weight at the given
    /// batch size.
    fn bcs_serialized_size(weight: usize, batch_size: usize) -> usize {
        // Layout:
        // SharesForNode = Vec<ShareBatch>
        //   = ULEB128(weight) + weight × ShareBatch
        // ShareBatch
        //   = NonZeroU16 (= 2 bytes) + Vec<S> + S
        //   = 2 + ULEB128(batch_size) + (batch_size + 1) × SCALAR_SIZE_IN_BYTES

        // TODO: A bit of a hack — this hardcodes the BCS layout of `SharesForNode`
        uleb128_len(weight)
            + weight * (2 + uleb128_len(batch_size) + (batch_size + 1) * SCALAR_SIZE_IN_BYTES)
    }
}

impl BCSSerialized for SharesForNode {}

impl AuthenticatedShards {
    /// Verify that `shards` are the leaf at `leaf_index` under `recipient_root`.
    fn verify(&self, leaf_index: usize, recipient_root: &merkle::Node) -> FastCryptoResult<()> {
        self.proof
            .verify_proof_with_unserialized_leaf(recipient_root, &self.shards, leaf_index)
    }
}

impl Echo {
    /// Verify this echo for the recipient: the sender's shard count matches `sender_weight`,
    /// the carried `dispersal_hash` matches the verifier's expected value, and the Merkle
    /// proof checks against `recipient_root`.
    fn verify(
        self,
        sender_weight: u16,
        expected_dispersal_hash: &Digest,
        recipient_root: &merkle::Node,
    ) -> FastCryptoResult<VerifiedEcho> {
        if self.authenticated_shards.shards.len() != sender_weight as usize {
            return Err(InvalidMessage);
        }
        if &self.dispersal_hash != expected_dispersal_hash {
            return Err(InvalidMessage);
        }
        self.authenticated_shards
            .verify(self.sender as usize, recipient_root)?;
        Ok(VerifiedEcho(self))
    }
}

/// Reed-Solomon `(W, W − 2f)` coder over the per-receiver ciphertexts. Requires the parameters
/// to have been validated via [Parameters::validate].
fn get_coder(nodes: &Nodes<EG>, f: u16) -> ErasureCoder {
    ErasureCoder::new(
        nodes.total_weight() as usize,
        (nodes.total_weight() - 2 * f) as usize,
    )
    .expect("parameters were validated by Parameters::validate")
}

/// Blake2b-256 hash of a per-recipient ciphertext.
fn hash_ciphertext(ciphertext: &Ciphertext) -> Digest {
    let mut hasher = Blake2b256::new();
    hasher.update(&ciphertext.0);
    hasher.finalize()
}

/// Combined binding for a pessimistic-phase broadcast: `H(H(v), roots)`.
fn dispersal_hash(
    avss_common_message_hash: &Digest,
    recipient_roots: impl Iterator<Item = (PartyId, merkle::Node)>,
) -> Digest {
    let mut hasher = Blake2b256::new();
    hasher.update(avss_common_message_hash);
    for (id, root) in recipient_roots {
        hasher.update(id.to_le_bytes());
        hasher.update(root.bytes());
    }
    hasher.finalize()
}

/// Build the per-recipient Merkle tree over `shards` (per-node grouped shard chunks of one
/// ciphertext). The root of this tree is the per-recipient `recipient_root`.
fn recipient_tree(shards: &[Vec<Shard>]) -> FastCryptoResult<MerkleTree<Blake2b256>> {
    MerkleTree::<Blake2b256>::build_from_unserialized(shards.iter())
}

/// Number of bytes BCS uses to encode `x` as an unsigned LEB128 length prefix.
fn uleb128_len(x: usize) -> usize {
    let mut len = 1;
    let mut v = x >> 7;
    while v != 0 {
        len += 1;
        v >>= 7;
    }
    len
}

fn compute_challenge(
    random_oracle: &RandomOracle,
    c: &[G],
    c_prime: &G,
    shared: &SharedComponents<EG>,
    ciphertext_hashes: &[Digest],
) -> Vec<S> {
    let random_oracle = random_oracle.extend(&Challenge.to_string());
    let inner_hash = Blake2b256::digest(
        bcs::to_bytes(&(c.to_vec(), c_prime, shared, ciphertext_hashes)).unwrap(),
    )
    .digest;
    (0..c.len())
        .map(|l| random_oracle.evaluate_to_group_element(&(l, inner_hash.to_vec())))
        .collect()
}

fn compute_challenge_from_common_message(
    random_oracle: &RandomOracle,
    message: &AvssCommonMessage,
) -> Vec<S> {
    compute_challenge(
        random_oracle,
        &message.full_public_keys,
        &message.blinding_commit,
        &message.ciphertext_shared,
        &message.ciphertext_hashes,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Confirm, Dealer, DealerState, DecodeOutcome, DecryptionOutcome, OptimisticMessage,
        Parameters, PessimisticMessage, Receiver, ReceiverOutput, ShareBatch, SharesForNode,
        VerifiedConfirmers, VerifiedEcho,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::{Ciphertext, PublicKey};
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::{batch_avss, EG};
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    #[test]
    fn test_bcs_serialized_size_matches_serialization() {
        // For every (weight, batch_size) in the matrix, build a real `SharesForNode` and BCS-
        // serialize it; the byte length must agree with `SharesForNode::bcs_serialized_size`. Cases
        // straddle the ULEB128 single-byte/two-byte boundary at 128 in both dimensions.
        use crate::threshold_schnorr::S;
        use fastcrypto::groups::GroupElement;

        let dummy_index = ShareIndex::try_from(1u16).unwrap();
        let zero_scalar = S::zero();
        for &weight in &[1usize, 2, 5, 10, 100, 127, 128, 200] {
            for &batch_size in &[1usize, 2, 3, 7, 50, 127, 128, 200] {
                let shares_for_node = SharesForNode {
                    shares: (0..weight)
                        .map(|_| ShareBatch {
                            index: dummy_index,
                            batch: vec![zero_scalar; batch_size],
                            blinding_share: zero_scalar,
                        })
                        .collect(),
                };
                let actual = shares_for_node.to_bytes().len();
                let formula = SharesForNode::bcs_serialized_size(weight, batch_size);
                assert_eq!(actual, formula, "weight={weight}, batch_size={batch_size}");
            }
        }
    }

    #[test]
    fn test_optimistic_then_pessimistic() {
        // 5 of 7 parties confirm in the optimistic phase; the remaining 2 receive their shares
        // via the pessimistic AVID phase, gated on the optimistic certificate.
        let t = 3;
        let f = 2;
        let n = 7u16;
        let batch_size_per_weight = 3;

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

        let sid = b"opt test".to_vec();
        let dealer_id = 0;
        let params = Parameters { t, f };
        let dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            params,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, sk)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    params,
                    sid.clone(),
                    sk,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();

        // Optimistic phase: only parties 0..=4 confirm; 5 and 6 are stragglers.
        let (state, optimistic_messages) = dealer.create_optimistic_messages(&mut rng).unwrap();
        let confirmers: Vec<PartyId> = (0u16..=4).collect();
        let pending: BTreeSet<PartyId> = [5u16, 6].into_iter().collect();
        let mut confirms = BTreeMap::new();
        for id in &confirmers {
            let (_output, confirm, _verified_common) = receivers[*id as usize]
                .process_optimistic(&optimistic_messages[id])
                .unwrap();
            confirms.insert(*id, confirm);
        }
        // weight check: 5 confirmers @ weight 1 = 5 >= t + f = 5 (caller-side sanity).
        assert!(confirms.len() as u16 >= t + f);

        // Pessimistic phase: dispersal for parties in I = {5, 6}.
        let (_dispersal_hash, messages) = dealer
            .create_pessimistic_messages(&state, pending.clone())
            .unwrap();
        // The confirmers are the parties we collected Confirms from (the complement of the
        // dispersal recipients). The caller verifies their signed Confirms; here we just wrap the
        // collected ids and the common message they attested to.
        let confirmers = VerifiedConfirmers {
            confirmers: confirms.keys().copied().collect(),
            avss_common_message_hash: state.avss_common.hash(),
        };

        // All receivers verify v (which they already have from the optimistic phase) and echo
        // for I. Every receiver also emits a `Vote` over `dispersal_hash` at this point —
        // pending recipients still need to decode and verify their shares before relying on
        // them, but the Vote attests to the dispersal layer (Merkle roots), not the
        // decryption, so it's safe to publish immediately.
        let mut verified_messages = Vec::with_capacity(receivers.len());
        let mut echos = Vec::with_capacity(receivers.len());
        for r in &receivers {
            let vcm = r.verify_common_message(state.avss_common.clone()).unwrap();
            let (vm, echoes, _vote) = r
                .echo(messages[r.id as usize].clone(), vcm.clone(), &confirmers)
                .unwrap();
            verified_messages.push(vm);
            echos.push(echoes);
        }

        // Each receiver j sends echoes only for recipients in pending_recipients (= 2 echoes).
        for echo_set in &echos {
            assert_eq!(echo_set.len(), pending.len());
        }

        // For each i in pending, gather all echoes addressed to i and decode.
        for &i in &pending {
            let echoes_for_i: Vec<batch_avss::Echo> =
                echos.iter().map(|em| em[&i].clone()).collect();
            let r = &receivers[i as usize];
            let vm = &verified_messages[i as usize];
            let verified_echos = echoes_for_i
                .into_iter()
                .map(|e| r.verify_echo(e, vm).unwrap())
                .collect_vec();
            let pem = assert_decoded(r.decode_ciphertext(&verified_echos, vm).unwrap());
            assert_valid(
                r.verify_and_decrypt(&pem, &vm.verified_common, vm.message.dispersal_hash)
                    .unwrap(),
            );
        }
    }

    #[test]
    fn test_share_recovery() {
        // Cheating dealer flips a byte in receiver 0's plaintext. Receivers 1..n succeed in the
        // optimistic phase and confirm; receiver 0 fails to confirm and lands in the pessimistic
        // phase, where their AVID-recovered ciphertext decrypts to bad shares — triggering an
        // Invalid complaint. Confirmers respond and receiver 0 recovers.
        let t = 3u16;
        let f = 2u16;
        let n = 7u16;
        let batch_size_per_weight: u16 = 3;
        let victim_id = 0u16;
        let (dealer, receivers) = uniform_session(n, t, f, batch_size_per_weight);

        let mut rng = rand::thread_rng();
        let state = dealer.create_encrypted_shares_cheating(&mut rng).unwrap();
        let common = state.common().clone();
        let opt_messages: Vec<OptimisticMessage> = (0..n)
            .map(|i| OptimisticMessage {
                avss_common: common.clone(),
                ciphertext: state.ciphertext_for(i).clone(),
            })
            .collect();

        // Optimistic: receivers 1..n confirm; receiver 0's decryption fails.
        let mut outputs: HashMap<u16, ReceiverOutput> = HashMap::new();
        let mut confirms: BTreeMap<PartyId, Confirm> = BTreeMap::new();
        for r in receivers.iter().filter(|r| r.id != victim_id) {
            let (out, c, _) = r.process_optimistic(&opt_messages[r.id as usize]).unwrap();
            outputs.insert(r.id, out);
            confirms.insert(r.id, c);
        }
        assert!(receivers[victim_id as usize]
            .process_optimistic(&opt_messages[victim_id as usize])
            .is_err());

        let pending: BTreeSet<PartyId> = std::iter::once(victim_id).collect();
        let (_dispersal_hash, messages) =
            dealer.create_pessimistic_messages(&state, pending).unwrap();
        // The confirmers are the parties we collected Confirms from (the complement of the
        // dispersal recipients). The caller verifies their signed Confirms; we wrap the ids and
        // the common message they attested to.
        let confirmers = VerifiedConfirmers {
            confirmers: confirms.keys().copied().collect(),
            avss_common_message_hash: common.hash(),
        };

        // Receiver 0 verifies their PessimisticMessage and produces their own echo (the only
        // entry, for themselves). Other receivers each emit one echo addressed to receiver 0.
        let vcm0 = receivers[victim_id as usize]
            .verify_common_message(common.clone())
            .unwrap();
        let (vm0, _, _vote0) = receivers[victim_id as usize]
            .echo(
                messages[victim_id as usize].clone(),
                vcm0.clone(),
                &confirmers,
            )
            .unwrap();
        let echoes_for_victim: Vec<VerifiedEcho> = receivers
            .iter()
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (_, echoes, _) = r
                    .echo(messages[r.id as usize].clone(), vcm.clone(), &confirmers)
                    .unwrap();
                receivers[victim_id as usize]
                    .verify_echo(echoes[&victim_id].clone(), &vm0)
                    .unwrap()
            })
            .collect();
        let pem = assert_decoded(
            receivers[victim_id as usize]
                .decode_ciphertext(&echoes_for_victim, &vm0)
                .unwrap(),
        );
        let reveal = match receivers[victim_id as usize]
            .verify_and_decrypt(&pem, &vm0.verified_common, vm0.message.dispersal_hash)
            .unwrap()
        {
            DecryptionOutcome::Invalid(r) => r,
            other => panic!("expected Invalid, got {:?}", outcome_kind(&other)),
        };

        // Confirmers handle the Reveal using their own ciphertexts from the optimistic phase.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (vm, _, _vote) = r
                    .echo(messages[r.id as usize].clone(), vcm.clone(), &confirmers)
                    .unwrap();
                r.handle_reveal(&reveal, &vm, state.ciphertext_for(r.id).clone())
                    .unwrap()
            })
            .collect_vec();

        let verified_responses = responses
            .into_iter()
            .map(|r| {
                receivers[victim_id as usize]
                    .verify_complaint_response(r, &vm0)
                    .unwrap()
            })
            .collect_vec();
        let recovered = receivers[victim_id as usize]
            .recover(&vm0, verified_responses)
            .unwrap();
        outputs.insert(victim_id, recovered);

        // Sanity: t shares (taken from any t receivers) recover the secret.
        for l in 0..dealer.batch_size {
            let shares = receivers
                .iter()
                .take(t as usize)
                .map(|r| Eval {
                    index: ShareIndex::try_from(r.id + 1).unwrap(),
                    value: outputs.get(&r.id).unwrap().my_shares.shares[0].batch[l],
                })
                .collect_vec();
            Poly::recover_c0(t, shares.into_iter()).unwrap();
        }
    }

    #[test]
    fn test_share_recovery_blame() {
        // Receivers 1..n confirm in the optimistic phase. Receiver 0 is treated as a straggler
        // (no optimistic confirm) and goes through the pessimistic phase. The dealer corrupts
        // the AVID shards for receiver 0's ciphertext, so receiver 0's decode_ciphertext yields
        // an InvalidDispersal complaint. Confirmers respond and receiver 0 recovers.
        let t = 3u16;
        let f = 2u16;
        let n = 7u16;
        let batch_size_per_weight: u16 = 3;
        let victim_id = 0u16;
        let (dealer, receivers) = uniform_session(n, t, f, batch_size_per_weight);

        let mut rng = rand::thread_rng();
        let (state, opt_messages) = dealer.create_optimistic_messages(&mut rng).unwrap();
        let common = state.common().clone();

        // Optimistic: receivers 1..n confirm; receiver 0 is simulated as not having received
        // the optimistic message.
        let mut outputs: HashMap<u16, ReceiverOutput> = HashMap::new();
        let mut confirms: BTreeMap<PartyId, Confirm> = BTreeMap::new();
        for r in receivers.iter().filter(|r| r.id != victim_id) {
            let (out, c, _) = r.process_optimistic(&opt_messages[&r.id]).unwrap();
            outputs.insert(r.id, out);
            confirms.insert(r.id, c);
        }

        let pending: BTreeSet<PartyId> = std::iter::once(victim_id).collect();
        let (_dispersal_hash, messages) = dealer
            .pessimistic_with_corrupted_dispersal(&state, pending)
            .unwrap();
        // The confirmers are the parties we collected Confirms from (the complement of the
        // dispersal recipients). The caller verifies their signed Confirms; we wrap the ids and
        // the common message they attested to.
        let confirmers = VerifiedConfirmers {
            confirmers: confirms.keys().copied().collect(),
            avss_common_message_hash: common.hash(),
        };

        // Receiver 0 collects echoes for their own ciphertext. With f senders' shards corrupted,
        // the W − f remaining honest echoes still fall short of the (W − 2f) RS-decode quorum
        // when combined with the corrupted ones — so we simulate the last `f` senders being
        // silent (their corrupted shards would otherwise short-circuit the decoder).
        let vcm0 = receivers[victim_id as usize]
            .verify_common_message(common.clone())
            .unwrap();
        let (vm0, _, _) = receivers[victim_id as usize]
            .echo(
                messages[victim_id as usize].clone(),
                vcm0.clone(),
                &confirmers,
            )
            .unwrap();
        let echoes_for_victim: Vec<VerifiedEcho> = receivers
            .iter()
            .take((n - f) as usize)
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (_, echoes, _) = r
                    .echo(messages[r.id as usize].clone(), vcm.clone(), &confirmers)
                    .unwrap();
                receivers[victim_id as usize]
                    .verify_echo(echoes[&victim_id].clone(), &vm0)
                    .unwrap()
            })
            .collect();

        let blame = match receivers[victim_id as usize]
            .decode_ciphertext(&echoes_for_victim, &vm0)
            .unwrap()
        {
            DecodeOutcome::InvalidDispersal(blame) => blame,
            DecodeOutcome::Decoded(_) => panic!("expected InvalidDispersal from victim"),
        };

        // Confirmers handle the Blame using their own ciphertexts.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (vm, _, _) = r
                    .echo(messages[r.id as usize].clone(), vcm.clone(), &confirmers)
                    .unwrap();
                r.handle_blame(&blame, &vm, state.ciphertext_for(r.id).clone())
                    .unwrap()
            })
            .collect_vec();

        let verified_responses = responses
            .into_iter()
            .map(|r| {
                receivers[victim_id as usize]
                    .verify_complaint_response(r, &vm0)
                    .unwrap()
            })
            .collect_vec();
        let recovered = receivers[victim_id as usize]
            .recover(&vm0, verified_responses)
            .unwrap();
        outputs.insert(victim_id, recovered);

        for l in 0..dealer.batch_size {
            let shares = receivers
                .iter()
                .take(t as usize)
                .map(|r| Eval {
                    index: ShareIndex::try_from(r.id + 1).unwrap(),
                    value: outputs.get(&r.id).unwrap().my_shares.shares[0].batch[l],
                })
                .collect_vec();
            Poly::recover_c0(t, shares.into_iter()).unwrap();
        }
    }

    /// Build a uniform-weight Dealer and matching set of Receivers for tests.
    fn uniform_session(
        n: u16,
        t: u16,
        f: u16,
        batch_size_per_weight: u16,
    ) -> (Dealer, Vec<Receiver>) {
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
        let sid = b"avss test".to_vec();
        let dealer_id = 1;
        let params = Parameters { t, f };
        let dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            params,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();
        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, sk)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    params,
                    sid.clone(),
                    sk,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();
        (dealer, receivers)
    }

    fn assert_valid(outcome: DecryptionOutcome) -> ReceiverOutput {
        match outcome {
            DecryptionOutcome::Valid(output) => output,
            ref other => panic!("expected valid outcome, got {:?}", outcome_kind(other)),
        }
    }

    fn assert_decoded(outcome: DecodeOutcome) -> Ciphertext {
        match outcome {
            DecodeOutcome::Decoded(c) => c,
            DecodeOutcome::InvalidDispersal { .. } => {
                panic!("expected Decoded outcome, got InvalidDispersal")
            }
        }
    }

    fn outcome_kind(outcome: &DecryptionOutcome) -> &'static str {
        match outcome {
            DecryptionOutcome::Valid(_) => "Valid",
            DecryptionOutcome::Invalid(_) => "Invalid",
        }
    }

    impl Dealer {
        /// Test-only: build a dealer state in which receiver 0's plaintext has one byte flipped
        /// before encryption. AVID dispersal stays consistent with `v` (the ciphertext is still
        /// pinned in `ciphertext_hashes`), but a receiver who decrypts E_0 sees shares that fail
        /// verification.
        fn create_encrypted_shares_cheating(
            &self,
            rng: &mut impl AllowedRng,
        ) -> FastCryptoResult<DealerState> {
            self.create_encrypted_shares_with_mutation(rng, |pk_and_msgs| {
                pk_and_msgs[0].1[7] ^= 1;
            })
        }

        fn pessimistic_with_corrupted_dispersal(
            &self,
            state: &DealerState,
            pending: BTreeSet<PartyId>,
        ) -> FastCryptoResult<(super::Digest, Vec<PessimisticMessage>)> {
            let f = self.params.f as usize;
            let n = self.nodes.total_weight() as usize;
            self.create_pessimistic_messages_with_mutation(state, pending, |shards_by_recipient| {
                // Flip a byte in the shards held by the last `f` senders for receiver 0's
                // ciphertext.
                if let Some(shards) = shards_by_recipient.get_mut(&0) {
                    for sender_shards in shards.iter_mut().skip(n - f) {
                        sender_shards[0].0[0] ^= 1;
                    }
                }
            })
        }
    }
}
