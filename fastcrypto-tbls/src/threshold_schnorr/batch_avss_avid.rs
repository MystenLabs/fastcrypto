// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous verifiable secret sharing (AVSS) for a batch of random nonces.
//!
//! A dealer shares `L = w_dealer · BATCH_SIZE` nonces among `n` weighted receivers with total
//! weight `W` under a threshold `t`. The numbered steps below, starting at
//! [Dealer::create_avss_messages], walk through the protocol.

use crate::ecies_v1::{
    Ciphertext, MultiRecipientEncryption, PrivateKey, RecoveryPackage, SharedComponents,
};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{create_secret_sharing, Eval, Poly};
use crate::random_oracle::RandomOracle;
pub use crate::threshold_schnorr::avid::{Echo, EchoBuilder, VerifiedEcho};
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::recovery_proof;
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::Extensions::{Challenge, Encryption, Recovery};
use crate::threshold_schnorr::{avid, Certificate, VerifiedCertificate};
use crate::threshold_schnorr::{random_oracle_from_sid, EG, G, S};
use crate::types::{get_uniform_value, ShareIndex};
use fastcrypto::error::FastCryptoError::{
    InvalidInput, InvalidMessage, InvalidProof, NotEnoughWeight,
};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::iter::repeat_with;
use std::sync::Arc;
use tap::TapFallible;
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

/// The Dealer for the protocol. Exactly one per instance.
#[allow(dead_code)]
pub struct Dealer {
    params: Parameters,
    nodes: Arc<Nodes<EG>>,
    sid: Vec<u8>,
    batch_size: usize,
    avid: avid::Avid,
}

/// One of the receivers for the protocol. One per node in `nodes`.
#[allow(dead_code)]
pub struct Receiver {
    pub id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Arc<Nodes<EG>>,
    sid: Vec<u8>,
    params: Parameters,
    batch_size: usize,
    avid: avid::Avid,
}

/// The dealer's per-recipient optimistic-phase message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessage {
    pub common: AvssCommonMessage,
    pub ciphertext: Ciphertext,
}

/// The shared part of the dealer's optimistic phase broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssCommonMessage {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    ciphertext_shared: SharedComponents<EG>,
    response_polynomial: Poly<S>,
    ciphertext_hashes: Vec<Digest>,
}

/// A [AvssCommonMessage] that has been validated against the dealer's commitments by a receiver.
///
/// This is purely a statement about the dealer's *common* broadcast (public keys, commitments,
/// ciphertext hashes). It carries no claim about whether this receiver's own shares were
/// decrypted or verified.
#[derive(Clone, Debug)]
pub struct VerifiedAvssCommonMessage(AvssCommonMessage);

/// A receiver's acknowledgement that it successfully decrypted and verified its
/// shares from the [AvssMessage].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssVote {
    pub common_message_hash: Digest,
}

/// Dealer state carried from the optimistic to the pessimistic phase.
#[derive(Clone, Debug)]
pub struct DealerState {
    pub common: AvssCommonMessage,
    ciphertexts: Vec<Ciphertext>,
}

/// Dealer-side cache that can create individual [AvidMessage]s on demand.
pub struct AvidMessageBuilder<C: Certificate<Payload = AvssVote>> {
    inner: avid::DispersalBuilder,
    avss_cert: C,
}

/// The dealer's per-receiver pessimistic-phase message. Generic over the concrete cert type
/// `C: Certificate<Payload = AvssVote>` so different deployments can plug in their own cert.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvidMessage<C: Certificate<Payload = AvssVote>> {
    pub dispersal: avid::Dispersal,
    pub avss_cert: C,
}

/// An endorsement of the dealer's pessimistic dispersal: the AVID-layer [avid::Vote]
/// (`top_root` + `pending_recipients`) bundled with the `common_message_hash` of the AVSS
/// instance it ratifies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvidVote {
    pub vote: avid::Vote,
    pub common_message_hash: Digest,
}

/// The result of [Receiver::decode_ciphertext]: either a successfully reconstructed ciphertext
/// whose AVID dispersal is consistent, or an [AvidComplaint] when the collected shards either
/// fail to RS-decode or decode to a ciphertext whose re-encoding disagrees with the ciphertext
/// hashes.
#[allow(clippy::large_enum_variant)]
pub enum DecodeOutcome {
    Decoded(Ciphertext),
    InvalidDispersal(AvidComplaint),
}

/// The result of [Receiver::decrypt_and_verify].
#[allow(clippy::large_enum_variant)]
pub enum DecryptionOutcome {
    Valid(ReceiverOutput),
    Invalid(AvssComplaint),
}

/// A complaint by a receiver who could not decrypt or verify its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssComplaint {
    pub proof: recovery_proof::RecoveryProof,
    pub ciphertext: Ciphertext,
}

/// A complaint by a receiver who found the AVID dispersal inconsistent — a generic AVID
/// [avid::Complaint].
pub use avid::Complaint as AvidComplaint;

/// A responder's reply to a [AvssComplaint] / [AvidComplaint]: their ciphertext and a recovery
/// package, so the accuser can try to authenticate and decrypt the responder's shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplaintResponse {
    pub ciphertext: Ciphertext,
    pub recovery_package: RecoveryPackage<EG>,
}

/// A [ComplaintResponse] that has been verified by [Receiver::verify_complaint_response].
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
/// Produced by [Receiver::decrypt_and_verify] on the happy path, or by [Receiver::recover] from
/// complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode {
    pub shares: Vec<ShareBatch>,
}

/// A batch of shares for a single share index, containing shares for each secret and one for the
/// "blinding" polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch {
    /// The shares for each secret.
    pub batch: Vec<S>,

    /// The share for the blinding polynomial.
    pub blinding_share: S,
}

// TODO: This can be removed when batch_avss is removed.
impl ReceiverOutput {
    /// Convert to the legacy [`crate::threshold_schnorr::batch_avss::ReceiverOutput`].
    pub fn into_legacy(
        self,
        indices: &[ShareIndex],
    ) -> crate::threshold_schnorr::batch_avss::ReceiverOutput {
        use crate::threshold_schnorr::batch_avss as legacy;
        legacy::ReceiverOutput {
            my_shares: legacy::SharesForNode {
                shares: self
                    .my_shares
                    .shares
                    .into_iter()
                    .zip(indices)
                    .map(|(s, &index)| legacy::ShareBatch {
                        index,
                        batch: s.batch,
                        blinding_share: s.blinding_share,
                    })
                    .collect(),
            },
            public_keys: self.public_keys,
        }
    }
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
        let nodes = Arc::new(nodes);
        let avid = avid::Avid::new(Arc::clone(&nodes), params.f)?;
        // Each dealer deals a number of nonces proportional to their weight.
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;
        Ok(Self {
            params,
            nodes,
            sid,
            batch_size,
            avid,
        })
    }

    /// 1. Build the optimistic-phase messages. Encrypt shares for every receiver and bundle each
    ///    receiver's ciphertext with the [AvssCommonMessage] as an [AvssMessage] per receiver.
    ///    Returns also a [DealerState] that can be used to produce the pessimistic-phase messages
    ///    later, after the dealer has collected an AVSS certificate.
    pub fn create_avss_messages(
        &self,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(DealerState, BTreeMap<PartyId, AvssMessage>)> {
        let state = self.create_encrypted_shares_with_mutation(rng, |_| {})?;
        let messages = state
            .ciphertexts
            .iter()
            .zip(self.nodes.node_ids_iter())
            .map(|(ct, i)| {
                (
                    i,
                    AvssMessage {
                        common: state.common.clone(),
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

        let ciphertext_hashes = ciphertexts
            .iter()
            .map(|c| {
                let bytes: &[u8] = &c.0;
                Blake2b256::digest(bytes)
            })
            .collect_vec();

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
            common,
            ciphertexts,
        })
    }

    /// 3. RS-encode and commit the pending recipients' ciphertexts via AVID, returning an
    ///    [AvidMessageBuilder] that can create per-receiver [AvidMessage]s on demand via
    ///    [AvidMessageBuilder::message_for]. The pending recipients are derived as the relative
    ///    complement of `avss_cert.signers()` within the node set.
    ///
    ///    All receivers that sent an [AvssVote] in the optimistic phase — including late voters
    ///    not in `avss_cert` — should get an [AvidMessage] from the dealer.
    ///
    ///    Once `≥ W − f` weight of [AvidVote]s has been collected, the dealer can form and
    ///    publish a certificate over those votes on the TOB.
    ///
    ///    This phase is only needed if any receiver failed to confirm in the optimistic phase.
    ///    If every receiver confirmed, the pessimistic phase can be skipped entirely.
    pub fn create_avid_messages<C: Certificate<Payload = AvssVote>>(
        &self,
        state: &DealerState,
        avss_cert: C,
    ) -> FastCryptoResult<AvidMessageBuilder<C>> {
        self.create_avid_messages_with_mutation(state, avss_cert, |_| {})
    }

    fn create_avid_messages_with_mutation<C: Certificate<Payload = AvssVote>>(
        &self,
        state: &DealerState,
        avss_cert: C,
        mutate_shards: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<AvidMessageBuilder<C>> {
        let pending_recipients: BTreeSet<PartyId> = self
            .nodes
            .node_ids_iter()
            .filter(|id| !avss_cert.signers().contains(id))
            .collect();
        if self.nodes.total_weight_of(pending_recipients.iter())? >= self.params.f {
            warn!("batch_avss create_avid_messages_with_mutation: too many pending recipients");
            return Err(InvalidInput);
        }
        let payloads: BTreeMap<PartyId, Vec<u8>> = pending_recipients
            .iter()
            .map(|&i| (i, state.ciphertexts[i as usize].0.clone()))
            .collect();
        self.avid
            .disperse_with_mutation(&payloads, mutate_shards)
            .map(|inner| AvidMessageBuilder { inner, avss_cert })
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
        let nodes = Arc::new(nodes);
        let avid = avid::Avid::new(nodes.clone(), params.f)?;

        Ok(Self {
            id,
            enc_secret_key,
            nodes,
            sid,
            params,
            batch_size,
            avid,
        })
    }

    /// 2. Process an [AvssMessage] sent by the dealer in the optimistic phase.
    ///
    ///    The receiver should provide a `verified_avss_common_message` if it has already received
    ///    and verified the [AvssCommonMessage] from a prior delivery of this AVSS round.
    ///
    ///    On success, returns
    ///     * a [ReceiverOutput],
    ///     * an [AvssVote] to be returned to the dealer,
    ///     * a [VerifiedAvssCommonMessage] to be retained for the rest of the session.
    ///
    ///    On any failure the receiver silently ignores the message and falls through to the
    ///    pessimistic phase.
    ///
    ///    A voter should also retain its own ciphertext (`message.ciphertext`) so it can answer
    ///    complaints later via [Self::handle_avss_complaint] / [Self::handle_avid_complaint].
    pub fn process_avss_message(
        &self,
        message: &AvssMessage,
        verified_avss_common_message: Option<&VerifiedAvssCommonMessage>,
    ) -> FastCryptoResult<(ReceiverOutput, AvssVote, VerifiedAvssCommonMessage)> {
        if verified_avss_common_message
            .is_some_and(|verified| verified.0.hash() != message.common.hash())
        {
            warn!("batch_avss process_avss_message: provided verified common message does not match the message's common message");
            return Err(InvalidInput);
        }
        let verified_common = self.verify_common_message(message.common.clone())?;
        self.check_ciphertext_hash(&message.ciphertext, &verified_common)?;
        let output = self.decrypt_and_verify_shares(&message.ciphertext, &verified_common)?;
        Ok((
            output,
            AvssVote {
                common_message_hash: verified_common.0.hash(),
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

    /// 4. Verify a pessimistic-phase [AvidMessage] and emit an [EchoBuilder] which can build
    ///    [Echo]es on demand. Returns also an [AvidVote] to be signed and returned to the dealer.
    ///
    ///    The receiver should provide a `verified_avss_common_message` whenever it holds one for
    ///    this AVSS round — whether it obtained it by verifying its shares in the optimistic phase
    ///    ([Self::process_avss_message]) or by verifying just the common on its own
    ///    ([Self::verify_common_message]). Only the common-level guarantee is needed here; the
    ///    receiver's shares need not have been verified. If the receiver has no verified common (or
    ///    it doesn't match), the AVID message should be ignored and this function returns `Ok(None)`.
    ///
    ///    Receivers who did not receive their shares through an [AvssMessage] should wait for a
    ///    published [Certificate] over [AvidVote]s that confirms they are a pending recipient and
    ///    then get the [AvssCommonMessage] and [Echo]es from the signers.
    pub fn process_avid_message<C: Certificate<Payload = AvssVote>>(
        &self,
        verified_avss_common_message: Option<&VerifiedAvssCommonMessage>,
        message: AvidMessage<C>,
    ) -> FastCryptoResult<Option<(EchoBuilder, AvidVote)>> {
        let AvidMessage {
            dispersal,
            avss_cert,
        } = message;

        if let Some(verified_common) = verified_avss_common_message {
            if avss_cert.payload().common_message_hash != verified_common.0.hash() {
                warn!(
                    "batch_avss process_avid_message: AVSS Cert binds a different common message"
                );
                return Ok(None);
            }
        } else {
            warn!("batch_avss process_avid_message: no verified common message available");
            return Ok(None);
        }

        let required_weight_of_voters = self.params.t + self.params.f;
        if self.nodes.total_weight_of(avss_cert.signers().iter())? < required_weight_of_voters {
            warn!("batch_avss echo: not enough voters");
            return Err(NotEnoughWeight(required_weight_of_voters as usize));
        }
        avss_cert.verify()?;
        // Dispersal recipients and voters must partition the node set (AVSS policy).
        if !dispersal
            .keys()
            .eq(self.nodes.relative_complement(avss_cert.signers()).iter())
        {
            warn!("batch_avss echo: dispersal recipients and voters do not partition the node set");
            return Err(InvalidMessage);
        }
        let (builder, vote) = self.avid.process_dispersal(self.id, dispersal)?;
        let avid_vote = AvidVote {
            vote,
            common_message_hash: avss_cert.payload().common_message_hash,
        };
        Ok(Some((builder, avid_vote)))
    }

    /// Verify an [Echo] addressed to this receiver. Returns a [VerifiedEcho] suitable for
    /// [Self::decode_ciphertext].
    ///
    /// Precondition: `self.id` is one of the pending recipients. Echoes are only
    /// meaningful for pending recipients, so voters calling this for themselves get
    /// [InvalidInput].
    pub fn verify_avid_echo_message<C: Certificate<Payload = AvidVote>>(
        &self,
        echo: Echo,
        sender: PartyId,
        avid_cert: &VerifiedCertificate<C>,
    ) -> FastCryptoResult<VerifiedEcho> {
        self.avid
            .verify_echo(echo, sender, &avid_cert.payload().vote, self.id)
    }

    /// 5. Reconstruct this receiver's ciphertext from at least `W − 2f` weight of
    ///    [VerifiedEcho]s. Returns [DecodeOutcome::Decoded] if the dispersal is consistent and
    ///    the reconstructed ciphertext matches [VerifiedAvssCommonMessage], or
    ///    [DecodeOutcome::InvalidDispersal] (an [AvidComplaint]) otherwise.
    ///
    ///    The caller should get an [AvssCommonMessage] from one of the signers of the cert and
    ///    verify it before calling this method.
    ///
    ///    An [AvidComplaint] is a dispersal-layer fault. Hold it until the matching cert on
    ///    [AvidVote]s is certified on the TOB, or discard it if a different one wins.
    ///
    ///    The caller should retain its decoded ciphertext for the session to answer complaints.
    pub fn decode_ciphertext<C: Certificate<Payload = AvidVote>>(
        &self,
        echoes: &[VerifiedEcho],
        verified_common: &VerifiedAvssCommonMessage,
        avid_cert: &VerifiedCertificate<C>,
    ) -> FastCryptoResult<DecodeOutcome> {
        if avid_cert.payload().common_message_hash != verified_common.0.hash() {
            warn!("batch_avss decode_ciphertext: AvidCert binds a different common message");
            return Err(InvalidMessage);
        }
        let expected_hash = verified_common
            .0
            .ciphertext_hashes
            .get(self.id as usize)
            .ok_or(InvalidProof)?;
        Ok(
            match self.avid.decode_or_complain(echoes, |payload| {
                Blake2b256::digest(payload) == *expected_hash
            })? {
                Ok(bytes) => DecodeOutcome::Decoded(Ciphertext(bytes)),
                Err(complaint) => {
                    warn!(
                        "batch_avss decode_ciphertext: receiver {} raising AvidComplaint",
                        self.id,
                    );
                    DecodeOutcome::InvalidDispersal(complaint)
                }
            },
        )
    }

    /// 6. Decrypt and verify the receiver's own shares from a successfully decoded ciphertext.
    ///    Rejects with [InvalidMessage] if the ciphertext doesn't match the hash pinned in
    ///    [VerifiedAvssCommonMessage] or if `avid_cert` is for a different [AvssCommonMessage].
    ///
    ///    Otherwise, yields [DecryptionOutcome::Valid] when shares verify, or
    ///    [DecryptionOutcome::Invalid] (an [AvssComplaint]) when they don't.
    ///
    ///    The [AvssComplaint] is an encryption-layer fault carrying the accuser's ciphertext
    ///    and an ECIES recovery package. Broadcast it only after seeing a TOB certificate for
    ///    the corresponding `common_message_hash`.
    pub fn decrypt_and_verify<C: Certificate<Payload = AvidVote>>(
        &self,
        ciphertext: &Ciphertext,
        verified_common: &VerifiedAvssCommonMessage,
        avid_cert: &VerifiedCertificate<C>,
    ) -> FastCryptoResult<DecryptionOutcome> {
        if avid_cert.payload().common_message_hash != verified_common.0.hash() {
            warn!("batch_avss decrypt_and_verify: AvidCert binds a different common message");
            return Err(InvalidMessage);
        }
        self.check_ciphertext_hash(ciphertext, verified_common)?;
        match self.decrypt_and_verify_shares(ciphertext, verified_common) {
            Ok(output) => Ok(DecryptionOutcome::Valid(output)),
            Err(e) => {
                warn!(
                    "batch_avss verify_and_decrypt: receiver {} raising AvssComplaint after share decode/verify failed: {e:?}",
                    self.id,
                );
                Ok(DecryptionOutcome::Invalid(AvssComplaint {
                    proof: recovery_proof::RecoveryProof::create(
                        self.id,
                        &verified_common.0.ciphertext_shared,
                        &self.enc_secret_key,
                        &self.random_oracle(),
                        &mut rand::thread_rng(),
                    ),
                    ciphertext: ciphertext.clone(),
                }))
            }
        }
    }

    /// Reject a ciphertext whose hash doesn't match the one pinned for this receiver in
    /// [VerifiedAvssCommonMessage]. This stops a dealer from dispersing a different ciphertext
    /// via AVID.
    fn check_ciphertext_hash(
        &self,
        ciphertext: &Ciphertext,
        verified_common: &VerifiedAvssCommonMessage,
    ) -> FastCryptoResult<()> {
        if Blake2b256::digest(&ciphertext.0)
            != *verified_common
                .0
                .ciphertext_hashes
                .get(self.id as usize)
                .ok_or(InvalidMessage)?
        {
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
        let AvssCommonMessage {
            full_public_keys,
            ciphertext_shared,
            ..
        } = &&common_message.0;
        let random_oracle = self.random_oracle();

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        let plaintext = ciphertext_shared.decrypt(
            ciphertext,
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        let challenge = compute_challenge_from_common_message(&random_oracle, &common_message.0);
        let my_shares = SharesForNode::from_bytes(plaintext)?;
        my_shares.verify(
            &common_message.0,
            &challenge,
            &self.nodes.share_ids_of(self.id)?,
            self.batch_size,
        )?;
        Ok(ReceiverOutput {
            my_shares,
            public_keys: full_public_keys.clone(),
        })
    }

    /// 7a. Validate a [AvssComplaint] and respond with this party's own shares.
    pub fn handle_avss_complaint(
        &self,
        reveal: &AvssComplaint,
        accuser_id: PartyId,
        verified_common: &VerifiedAvssCommonMessage,
        own_ciphertext: Ciphertext,
    ) -> FastCryptoResult<ComplaintResponse> {
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), &verified_common.0);

        let AvssComplaint { proof, ciphertext } = reveal;

        if Blake2b256::digest(&ciphertext.0)
            != *verified_common
                .0
                .ciphertext_hashes
                .get(accuser_id as usize)
                .ok_or(InvalidProof)?
        {
            return Err(InvalidProof);
        }
        let accuser = self.nodes.node_id_to_node(accuser_id)?;
        let accuser_indices = self.nodes.share_ids_of(accuser_id)?;
        proof.check(
            accuser_id,
            &accuser.pk,
            ciphertext,
            &verified_common.0.ciphertext_shared,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                shares.verify(
                    &verified_common.0,
                    &challenge,
                    &accuser_indices,
                    self.batch_size,
                )
            },
        )?;

        Ok(self.build_complaint_response(&verified_common.0, own_ciphertext))
    }

    /// 7b. Validate a [AvidComplaint] and respond with this party's own shares.
    pub fn handle_avid_complaint<C: Certificate<Payload = AvidVote>>(
        &self,
        blame: &AvidComplaint,
        accuser_id: PartyId,
        verified_common: &VerifiedAvssCommonMessage,
        avid_cert: &VerifiedCertificate<C>,
        own_ciphertext: Ciphertext,
    ) -> FastCryptoResult<ComplaintResponse> {
        let expected_hash = verified_common
            .0
            .ciphertext_hashes
            .get(accuser_id as usize)
            .ok_or(InvalidProof)?;

        let vote = &avid_cert.payload().vote;
        if !self.avid.complaint_is_valid(
            blame,
            accuser_id,
            &vote.top_root,
            &vote.recipients,
            |payload| Blake2b256::digest(payload) == *expected_hash,
        )? {
            return Err(InvalidProof);
        }

        Ok(self.build_complaint_response(&verified_common.0, own_ciphertext))
    }

    /// Build a [ComplaintResponse] for a validated [AvssComplaint] / [AvidComplaint].
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
            ciphertext,
            recovery_package,
        }
    }

    /// Verify a [ComplaintResponse] against a [VerifiedAvssCommonMessage].
    pub fn verify_complaint_response(
        &self,
        responder_id: PartyId,
        response: ComplaintResponse,
        verified_common: &VerifiedAvssCommonMessage,
    ) -> FastCryptoResult<VerifiedComplaintResponse> {
        let ComplaintResponse {
            ciphertext,
            recovery_package,
        } = response;
        if Blake2b256::digest(&ciphertext.0)
            != *verified_common
                .0
                .ciphertext_hashes
                .get(responder_id as usize)
                .ok_or(InvalidProof)?
        {
            return Err(InvalidProof);
        }
        let shares = verified_common
            .0
            .ciphertext_shared
            .decrypt_with_recovery_package(
                &ciphertext,
                &recovery_package,
                &self
                    .random_oracle()
                    .extend(&Recovery(responder_id).to_string()),
                &self.random_oracle().extend(&Encryption.to_string()),
                &self.nodes.node_id_to_node(responder_id)?.pk,
                responder_id as usize,
            )
            .and_then(SharesForNode::from_bytes)?;

        shares.verify(
            &verified_common.0,
            &compute_challenge_from_common_message(&self.random_oracle(), &verified_common.0),
            &self.nodes.share_ids_of(responder_id)?,
            self.batch_size,
        )?;

        Ok(VerifiedComplaintResponse {
            responder_id,
            shares,
        })
    }

    /// 8. Recover the accuser's own shares from a quorum (`≥ t`) of [VerifiedComplaintResponse]s.
    ///    Responses must already be validated via [Self::verify_complaint_response]. Fails if the
    ///    responses contribute `< t` weight, or the interpolated shares fail final verification.
    pub fn recover(
        &self,
        verified_common: &VerifiedAvssCommonMessage,
        responses: Vec<VerifiedComplaintResponse>,
    ) -> FastCryptoResult<ReceiverOutput> {
        if !responses.iter().map(|r| r.responder_id).all_unique() {
            return Err(InvalidInput);
        }

        if responses.iter().any(|r| {
            self.nodes
                .weight_of(r.responder_id)
                .ok()
                .is_none_or(|w| w != r.shares.weight())
        }) {
            return Err(InvalidInput);
        }

        if self
            .nodes
            .total_weight_of(responses.iter().map(|r| &r.responder_id))?
            < self.params.t
        {
            return Err(NotEnoughWeight(self.params.t as usize));
        }

        let response_shares: Vec<(PartyId, SharesForNode)> = responses
            .into_iter()
            .map(|v| (v.responder_id, v.shares))
            .collect();

        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), &verified_common.0);
        let my_shares = SharesForNode::recover(self, &response_shares)?;
        my_shares.verify(
            &verified_common.0,
            &challenge,
            &self.nodes.share_ids_of(self.id)?,
            self.batch_size,
        )?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: verified_common.0.full_public_keys.clone(),
        })
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

impl Parameters {
    /// Validate `(t, f)` against the given total weight `W`.
    ///   * It is possible to create a Reed-Solomon `(W, t)` coder.
    ///   * `1 ≤ t ≤ W` — recovery threshold is well-defined and reachable by the total
    ///     weight.
    pub fn validate(&self, total_weight: u16) -> FastCryptoResult<()> {
        let Parameters { t, f } = *self;
        if f == 0 || total_weight <= 2 * f || t == 0 || t > total_weight {
            return Err(InvalidInput);
        }
        ErasureCoder::check_parameters(total_weight as usize, t as usize)?;
        Ok(())
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
            .tap_err(|e| warn!("batch_avss AvssCommonMessage::verify: ciphertext_shared NIZK verification failed: {e:?}"))
            .map_err(|_| InvalidMessage)?;
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
        Blake2b256::digest(bcs::to_bytes(self).expect("serialize should never fail"))
    }
}

impl<C: Certificate<Payload = AvssVote> + Clone> AvidMessageBuilder<C> {
    /// Build the [AvidMessage] addressed to `receiver`.
    pub fn message_for(&self, receiver: PartyId) -> FastCryptoResult<AvidMessage<C>> {
        Ok(AvidMessage {
            dispersal: self.inner.dispersal_for(receiver)?,
            avss_cert: self.avss_cert.clone(),
        })
    }
}

impl ShareBatch {
    /// Verify a batch of shares at share index `index` using the given challenge.
    fn verify(
        &self,
        index: ShareIndex,
        message: &AvssCommonMessage,
        challenge: &[S],
    ) -> FastCryptoResult<()> {
        if challenge.len() != self.batch.len() {
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
            != message.response_polynomial.eval(index).value
        {
            return Err(InvalidInput);
        }
        Ok(())
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
        get_uniform_value(self.shares.iter().map(|b| b.batch.len())).ok_or(InvalidInput)
    }

    /// Get all shares this node has for the <i>i</i>-th secret/nonce in the batch, paired with
    /// the share indices the node was assigned (`indices.len()` must equal the number of share
    /// batches). Panics if `i` is larger than or equal to the batch size.
    pub fn shares_for_secret<'a>(
        &'a self,
        indices: &'a [ShareIndex],
        i: usize,
    ) -> impl Iterator<Item = Eval<S>> + 'a {
        self.shares
            .iter()
            .zip(indices)
            .map(move |(s, &index)| Eval {
                index,
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
        if self.shares.len() != expected_indices.len() {
            warn!(
                "batch_avss SharesForNode::verify: share count {} does not match expected weight {}",
                self.shares.len(),
                expected_indices.len(),
            );
            return Err(InvalidMessage);
        }
        for (shares, &index) in self.shares.iter().zip(expected_indices) {
            shares.verify(index, message, challenge).map_err(|e| {
                warn!(
                    "batch_avss SharesForNode::verify: cryptographic share verification failed at index {:?}: {e:?}",
                    index,
                );
                e
            })?;
        }
        Ok(())
    }

    /// Recover the shares for this node.
    ///
    /// Fails if `other_shares` is empty.
    fn recover(
        receiver: &Receiver,
        other_shares: &[(PartyId, SharesForNode)],
    ) -> FastCryptoResult<Self> {
        if other_shares.is_empty() {
            return Err(InvalidInput);
        }

        // Pre-compute each responder's share indices once.
        let responders: Vec<(Vec<ShareIndex>, &SharesForNode)> = other_shares
            .iter()
            .map(|(id, s)| Ok((receiver.nodes.share_ids_of(*id)?, s)))
            .collect::<FastCryptoResult<_>>()?;

        let shares = receiver
            .my_indices()
            .into_iter()
            .map(|index| {
                let batch = (0..receiver.batch_size)
                    .map(|i| {
                        let evaluations = responders
                            .iter()
                            .flat_map(|(ids, s)| s.shares_for_secret(ids, i))
                            .collect_vec();
                        Ok(Poly::recover_at(index, &evaluations)?.value)
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()?;

                let blinding_share = Poly::recover_at(
                    index,
                    &responders
                        .iter()
                        .flat_map(|(ids, s)| ids.iter().copied().zip(s.shares.iter()))
                        .map(|(index, share)| Eval {
                            index,
                            value: share.blinding_share,
                        })
                        .collect_vec(),
                )?
                .value;

                Ok(ShareBatch {
                    batch,
                    blinding_share,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self { shares })
    }
}

impl BCSSerialized for SharesForNode {}

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
        AvidMessageBuilder, AvidVote, AvssMessage, AvssVote, Dealer, DealerState, DecodeOutcome,
        DecryptionOutcome, Parameters, Receiver, ReceiverOutput, VerifiedEcho,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::{Ciphertext, PublicKey};
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::{avid, batch_avss_avid as batch_avss, Certificate, EG};
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    /// Concrete [AvssCert](super::AvssCert) implementation used by these tests.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct AvssCert {
        voters: BTreeSet<PartyId>,
        vote: AvssVote,
    }

    impl Certificate for AvssCert {
        type Payload = AvssVote;
        fn signers(&self) -> &BTreeSet<PartyId> {
            &self.voters
        }
        fn payload(&self) -> &AvssVote {
            &self.vote
        }
        fn verify(&self) -> FastCryptoResult<()> {
            Ok(())
        }
    }

    /// Concrete [AvidCert](super::AvidCert) implementation used by these tests.
    #[derive(Clone, Debug)]
    struct AvidCert {
        signers: BTreeSet<PartyId>,
        vote: AvidVote,
    }

    impl Certificate for AvidCert {
        type Payload = AvidVote;
        fn signers(&self) -> &BTreeSet<PartyId> {
            &self.signers
        }
        fn payload(&self) -> &AvidVote {
            &self.vote
        }
        fn verify(&self) -> FastCryptoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn test_optimistic_then_pessimistic() {
        // 8 of 10 parties confirm in the optimistic phase; the remaining 2 receive their shares
        // via the pessimistic AVID phase, gated on the optimistic certificate. Pending weight
        // (= 2) must be strictly less than `f` so the dealer-side precheck in
        // `create_avid_messages_with_mutation` accepts the cert.
        let t = 3;
        let f = 3;
        let n = 10u16;
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

        // Optimistic phase: only parties 0..=7 confirm; 8 and 9 are stragglers.
        let (state, optimistic_messages) = dealer.create_avss_messages(&mut rng).unwrap();
        let voters: Vec<PartyId> = (0u16..=7).collect();
        let pending: BTreeSet<PartyId> = [8u16, 9].into_iter().collect();
        let votes: BTreeMap<PartyId, AvssVote> = voters
            .iter()
            .map(|id| {
                (
                    *id,
                    receivers[*id as usize]
                        .process_avss_message(&optimistic_messages[id], None)
                        .unwrap()
                        .1,
                )
            })
            .collect();
        assert!(votes.len() as u16 >= t + f);

        // The voters are the parties we collected AvssVotes from (the complement of the
        // dispersal recipients). The caller verifies their signed AvssVotes; here we just wrap the
        // collected ids and the common message they attested to.
        let cert = AvssCert {
            voters: votes.keys().copied().collect(),
            vote: AvssVote {
                common_message_hash: state.common.hash(),
            },
        };
        // Pessimistic phase: dispersal for the complement of voters (I = {5, 6}). The dealer
        // bundles each dispersal with the cert into an [AvidMessage].
        let messages = dealer.create_avid_messages(&state, cert.clone()).unwrap();

        // All receivers verify v (which they already have from the optimistic phase) and echo
        // for I. Every receiver also emits an `AvidVote` over `top_root` at this point —
        // pending recipients still need to decode and verify their shares before relying on
        // them, but the AvidVote attests to the dispersal layer (Merkle root), not the
        // decryption, so it's safe to publish immediately.
        let mut avid_votes: Vec<AvidVote> = Vec::with_capacity(receivers.len());
        let mut verified_commons = Vec::with_capacity(receivers.len());
        let mut echo_sets = Vec::with_capacity(receivers.len());
        for r in &receivers {
            let vcm = r.verify_common_message(state.common.clone()).unwrap();
            let (builder, avid_vote) = r
                .process_avid_message(Some(&vcm), messages.message_for(r.id).unwrap())
                .unwrap()
                .unwrap();
            let echoes: BTreeMap<PartyId, avid::Echo> = builder
                .recipients()
                .iter()
                .map(|&rcpt| (rcpt, builder.create_echo(rcpt).unwrap()))
                .collect();
            avid_votes.push(avid_vote);
            verified_commons.push(vcm);
            echo_sets.push(echoes);
        }

        // Each receiver j sends echoes only for recipients in pending_recipients (= 2 echoes).
        for echo_set in &echo_sets {
            assert_eq!(echo_set.len(), pending.len());
        }

        // For each i in pending, gather all echoes addressed to i and decode.
        for &i in &pending {
            let echoes_for_i: Vec<(PartyId, batch_avss::Echo)> = echo_sets
                .iter()
                .enumerate()
                .map(|(sender, em)| (sender as PartyId, em[&i].clone()))
                .collect();
            let r = &receivers[i as usize];
            let avid_cert = AvidCert {
                signers: receivers.iter().map(|r| r.id).collect(),
                vote: avid_votes[i as usize].clone(),
            }
            .into_verified()
            .unwrap();
            let vcm = &verified_commons[i as usize];
            let verified_echoes = echoes_for_i
                .into_iter()
                .map(|(sender, e)| r.verify_avid_echo_message(e, sender, &avid_cert).unwrap())
                .collect_vec();
            let outcome = r
                .decode_ciphertext(&verified_echoes, vcm, &avid_cert)
                .unwrap();
            let decoded = assert_decoded(outcome);
            assert_valid(r.decrypt_and_verify(&decoded, vcm, &avid_cert).unwrap());
        }
    }

    #[test]
    fn test_share_recovery() {
        // Cheating dealer flips a byte in receiver 0's plaintext. Receivers 1..n succeed in the
        // optimistic phase and confirm; receiver 0 fails to confirm and lands in the pessimistic
        // phase, where their AVID-recovered ciphertext decrypts to bad shares — triggering an
        // Invalid complaint. Voters respond and receiver 0 recovers.
        let t = 3u16;
        let f = 2u16;
        let n = 7u16;
        let batch_size_per_weight: u16 = 3;
        let victim_id = 0u16;
        let (dealer, receivers) = uniform_session(n, t, f, batch_size_per_weight);

        let mut rng = rand::thread_rng();
        let state = dealer.create_encrypted_shares_cheating(&mut rng).unwrap();
        let common = state.common.clone();
        let opt_messages: Vec<AvssMessage> = (0..n)
            .map(|i| AvssMessage {
                common: common.clone(),
                ciphertext: state.ciphertexts[i as usize].clone(),
            })
            .collect();

        // Optimistic: receivers 1..n confirm; receiver 0's decryption fails.
        let mut outputs: HashMap<u16, ReceiverOutput> = HashMap::new();
        let mut votes: BTreeMap<PartyId, AvssVote> = BTreeMap::new();
        for r in receivers.iter().filter(|r| r.id != victim_id) {
            let (out, c, _) = r
                .process_avss_message(&opt_messages[r.id as usize], None)
                .unwrap();
            outputs.insert(r.id, out);
            votes.insert(r.id, c);
        }
        assert!(receivers[victim_id as usize]
            .process_avss_message(&opt_messages[victim_id as usize], None)
            .is_err());

        // The voters are the parties we collected AvssVotes from (the complement of the
        // dispersal recipients). The caller verifies their signed AvssVotes; we wrap the ids and
        // the common message they attested to.
        let cert = AvssCert {
            voters: votes.keys().copied().collect(),
            vote: AvssVote {
                common_message_hash: common.hash(),
            },
        };
        let messages = dealer.create_avid_messages(&state, cert.clone()).unwrap();

        // Receiver 0 verifies their AvidMessage and produces their own echo (the only
        // entry, for themselves). Other receivers each emit one echo addressed to receiver 0.
        let vcm0 = receivers[victim_id as usize]
            .verify_common_message(common.clone())
            .unwrap();
        let (_, vote0) = receivers[victim_id as usize]
            .process_avid_message(Some(&vcm0), messages.message_for(victim_id).unwrap())
            .unwrap()
            .unwrap();
        let avid_cert0 = AvidCert {
            signers: receivers.iter().map(|r| r.id).collect(),
            vote: vote0,
        }
        .into_verified()
        .unwrap();
        let echoes_for_victim: Vec<VerifiedEcho> = receivers
            .iter()
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (builder, _) = r
                    .process_avid_message(Some(&vcm), messages.message_for(r.id).unwrap())
                    .unwrap()
                    .unwrap();
                let echo = builder.create_echo(victim_id).unwrap();
                receivers[victim_id as usize]
                    .verify_avid_echo_message(echo, r.id, &avid_cert0)
                    .unwrap()
            })
            .collect();
        let outcome = receivers[victim_id as usize]
            .decode_ciphertext(&echoes_for_victim, &vcm0, &avid_cert0)
            .unwrap();
        let decoded = assert_decoded(outcome);
        let reveal = match receivers[victim_id as usize]
            .decrypt_and_verify(&decoded, &vcm0, &avid_cert0)
            .unwrap()
        {
            DecryptionOutcome::Invalid(r) => r,
            other => panic!("expected Invalid, got {:?}", outcome_kind(&other)),
        };

        // Voters handle the AvssComplaint using their own ciphertexts from the optimistic phase.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let resp = r
                    .handle_avss_complaint(
                        &reveal,
                        victim_id,
                        &vcm,
                        state.ciphertexts[r.id as usize].clone(),
                    )
                    .unwrap();
                (r.id, resp)
            })
            .collect_vec();

        let verified_responses = responses
            .into_iter()
            .map(|(id, resp)| {
                receivers[victim_id as usize]
                    .verify_complaint_response(id, resp, &vcm0)
                    .unwrap()
            })
            .collect_vec();
        let recovered = receivers[victim_id as usize]
            .recover(&vcm0, verified_responses)
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
        // an InvalidDispersal complaint. Voters respond and receiver 0 recovers.
        let t = 3u16;
        let f = 2u16;
        let n = 7u16;
        let batch_size_per_weight: u16 = 3;
        let victim_id = 0u16;
        let (dealer, receivers) = uniform_session(n, t, f, batch_size_per_weight);

        let mut rng = rand::thread_rng();
        let (state, opt_messages) = dealer.create_avss_messages(&mut rng).unwrap();
        let common = state.common.clone();

        // Optimistic: receivers 1..n confirm; receiver 0 is simulated as not having received
        // the optimistic message.
        let mut outputs: HashMap<u16, ReceiverOutput> = HashMap::new();
        let mut votes: BTreeMap<PartyId, AvssVote> = BTreeMap::new();
        for r in receivers.iter().filter(|r| r.id != victim_id) {
            let (out, c, _) = r.process_avss_message(&opt_messages[&r.id], None).unwrap();
            outputs.insert(r.id, out);
            votes.insert(r.id, c);
        }

        // The voters are the parties we collected AvssVotes from (the complement of the
        // dispersal recipients). The caller verifies their signed AvssVotes; we wrap the ids and
        // the common message they attested to.
        let cert = AvssCert {
            voters: votes.keys().copied().collect(),
            vote: AvssVote {
                common_message_hash: common.hash(),
            },
        };
        let messages = dealer
            .pessimistic_with_corrupted_dispersal(&state, cert.clone())
            .unwrap();

        // Receiver 0 collects echoes for their own ciphertext from the first W − f honest
        // dispersers. The last `f` dispersers (whose shards the dealer corrupted) are simulated
        // as silent — their
        // corrupted-but-proof-valid shards would otherwise be accepted into the RS decode and lead
        // straight to a consistent (but wrong) payload, masking the dealer's misbehavior. With
        // them dropped, the W − f echoes still meet the AVID reconstruction quorum, decode to a
        // payload that fails the dealer's `ciphertext_hashes[victim_id]` check, and yield the
        // blame complaint the test verifies.
        let vcm0 = receivers[victim_id as usize]
            .verify_common_message(common.clone())
            .unwrap();
        let (_, vote0) = receivers[victim_id as usize]
            .process_avid_message(Some(&vcm0), messages.message_for(victim_id).unwrap())
            .unwrap()
            .unwrap();
        let avid_cert0 = AvidCert {
            signers: receivers.iter().map(|r| r.id).collect(),
            vote: vote0,
        }
        .into_verified()
        .unwrap();
        let echoes_for_victim: Vec<VerifiedEcho> = receivers
            .iter()
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (builder, _) = r
                    .process_avid_message(Some(&vcm), messages.message_for(r.id).unwrap())
                    .unwrap()
                    .unwrap();
                let echo = builder.create_echo(victim_id).unwrap();
                receivers[victim_id as usize]
                    .verify_avid_echo_message(echo, r.id, &avid_cert0)
                    .unwrap()
            })
            .collect();

        let outcome = receivers[victim_id as usize]
            .decode_ciphertext(&echoes_for_victim, &vcm0, &avid_cert0)
            .unwrap();
        let blame = match outcome {
            DecodeOutcome::InvalidDispersal(blame) => blame,
            DecodeOutcome::Decoded { .. } => panic!("expected InvalidDispersal from victim"),
        };

        // Voters handle the Blame using their own ciphertexts.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (_, vote) = r
                    .process_avid_message(Some(&vcm), messages.message_for(r.id).unwrap())
                    .unwrap()
                    .unwrap();
                let avid_cert = AvidCert {
                    signers: receivers.iter().map(|r| r.id).collect(),
                    vote,
                }
                .into_verified()
                .unwrap();
                let resp = r
                    .handle_avid_complaint(
                        &blame,
                        victim_id,
                        &vcm,
                        &avid_cert,
                        state.ciphertexts[r.id as usize].clone(),
                    )
                    .unwrap();
                (r.id, resp)
            })
            .collect_vec();

        let verified_responses = responses
            .into_iter()
            .map(|(id, resp)| {
                receivers[victim_id as usize]
                    .verify_complaint_response(id, resp, &vcm0)
                    .unwrap()
            })
            .collect_vec();
        let recovered = receivers[victim_id as usize]
            .recover(&vcm0, verified_responses)
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
            cert: AvssCert,
        ) -> FastCryptoResult<AvidMessageBuilder<AvssCert>> {
            let f = self.params.f as usize;
            let n = self.nodes.total_weight() as usize;
            self.create_avid_messages_with_mutation(state, cert, |shards_by_recipient| {
                // Flip a byte in the shards held by the last `f` dispersers for receiver 0's
                // ciphertext.
                if let Some(shards) = shards_by_recipient.get_mut(&0) {
                    for disperser_shards in shards.iter_mut().skip(n - f) {
                        disperser_shards[0].0[0] ^= 1;
                    }
                }
            })
        }
    }
}
