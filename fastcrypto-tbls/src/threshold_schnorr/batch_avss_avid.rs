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
pub use crate::threshold_schnorr::avid::{
    AuthenticatedShards, Dispersal, Echo, EchoBuilder, VerifiedEcho,
};
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::recovery_proof;
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::Extensions::{Challenge, Encryption, Recovery};
use crate::threshold_schnorr::{avid, Certificate, VerifiedCertificate};
use crate::threshold_schnorr::{random_oracle_from_sid, Parameters, EG, G, S};
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

/// The Dealer for the protocol. Exactly one per instance.
#[allow(dead_code)]
pub struct Dealer {
    nodes: Arc<Nodes<EG>>,
    params: Parameters,
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
    params: Parameters,
    sid: Vec<u8>,
    batch_size: usize,
    avid: avid::Avid,
}

/// An upper bound on the BCS-serialized size of an [AvssMessage], to be enforced when
/// deserializing untrusted messages.
pub const AVSS_MESSAGE_MAX_SIZE: usize = 500_000; // 500 KB.

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
    ciphertext_hashes: Vec<Digest>,
    response_polynomial: Poly<S>,
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

/// Dealer-side state carried from the optimistic to the pessimistic phase. Builds the per-receiver
/// [AvssMessage]s on demand and carries the ciphertexts into the pessimistic AVID phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessageBuilder {
    pub common: AvssCommonMessage,
    ciphertexts: Vec<Ciphertext>,
}

/// Dealer-side cache that can create individual [AvidMessage]s on demand.
pub struct AvidMessageBuilder<C: Certificate<Payload = AvssVote>> {
    inner: avid::DispersalBuilder,
    avss_cert: C,
}

/// An upper bound on the BCS-serialized size of an [AvidMessage] (excluding the cert `C`), to be
/// enforced when deserializing untrusted messages.
pub const AVID_MESSAGE_MAX_SIZE: usize = 500_000; // 500 KB, plus the cert.

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

/// The result of [Receiver::decode_and_decrypt].
#[allow(clippy::large_enum_variant)]
pub enum DecodeAndDecryptOutcome {
    InvalidDispersal(AvidComplaint),
    InvalidDecryption(AvssComplaint),
    Valid(Ciphertext, ReceiverOutput),
}

/// A complaint by a receiver who could not decrypt or verify its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssComplaint {
    pub ciphertext: Ciphertext,
    pub proof: recovery_proof::RecoveryProof,
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
/// Produced by [Receiver::decode_and_decrypt] on the happy path, or by [Receiver::recover] from
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
        let total_weight = nodes.total_weight();
        params.validate(total_weight)?;
        params.check_erasure_code_params(total_weight)?;
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

    /// 1. Build the [AvssMessageBuilder]. This encrypts the shares for every receiver and holds
    ///    everything the dealer needs to create the per-receiver [AvssMessage]s.
    ///
    ///    The dealer must send all [AvssMessage]s until it has collected an AVID certificate, even
    ///    after an AVSS certificate has been created.
    ///
    ///    To survive a crash, the caller should persist the returned [AvssMessageBuilder] before
    ///    sending any messages, so that even after a restart it can reproduce both the optimistic
    ///    [AvssMessage]s and use the same ciphertexts in the pessimistic AVID dispersal.
    pub fn create_avss_messages(
        &self,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<AvssMessageBuilder> {
        self.create_avss_messages_with_mutation(rng, |_| {})
    }

    /// Encrypt shares, build `v`, and return the dealer state. Test mutation hook runs after the
    /// plaintexts are constructed and before encryption.
    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    fn create_avss_messages_with_mutation(
        &self,
        rng: &mut impl AllowedRng,
        mutate_plaintexts: impl FnOnce(&mut [(crate::ecies_v1::PublicKey<EG>, Vec<u8>)]),
    ) -> FastCryptoResult<AvssMessageBuilder> {
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
            ciphertext_hashes,
            response_polynomial,
        };

        Ok(AvssMessageBuilder {
            common,
            ciphertexts,
        })
    }

    /// 3. RS-encode and commit the pending recipients' ciphertexts via AVID, returning an
    ///    [AvidMessageBuilder] that can create per-receiver [AvidMessage]s on demand via
    ///    [AvidMessageBuilder::message_for]. The pending recipients are derived as the relative
    ///    complement of `avss_cert.signers()` within the node set.
    ///
    ///    Every receiver that sent an [AvssVote] (including late voters not in `avss_cert`) should
    ///    get an [AvidMessage] until the dealer has collected an AVID certificate.
    ///
    ///    Forming the input `avss_cert`: the dealer should collect `≥ t + f` weight of [AvssVote]s,
    ///    then wait a short grace period to pick up any additional votes, and only then form the
    ///    certificate. This keeps the pending-recipient set (and hence the dispersal) as small as
    ///    possible.
    ///
    ///    Once `≥ W − f` weight of [AvidVote]s has been collected, the dealer can form and
    ///    publish a certificate over those votes on the TOB.
    ///
    ///    This phase is only needed if any receiver failed to confirm in the optimistic phase.
    ///    If every receiver confirmed, the pessimistic phase can be skipped entirely.
    ///
    ///    The pending recipients (the non-confirmers) may carry at most `f` weight: the confirmers
    ///    then hold `≥ W − f` weight, so `≥ W − 2f` of them are honest — exactly the AVID decode
    ///    quorum needed to reconstruct each pending recipient's ciphertext. This returns
    ///    [InvalidInput] if the pending weight exceeds `f`.
    pub fn create_avid_messages<C: Certificate<Payload = AvssVote>>(
        &self,
        avss_message_builder: &AvssMessageBuilder,
        avss_cert: C,
    ) -> FastCryptoResult<AvidMessageBuilder<C>> {
        self.create_avid_messages_with_mutation(avss_message_builder, avss_cert, |_| {})
    }

    /// Test-only variant of [Self::create_avid_messages] that runs `mutate_shards` over the
    /// per-recipient, per-disperser shards before they are committed, to simulate a cheating dealer.
    #[cfg(test)]
    fn create_avid_messages_for_testing<C: Certificate<Payload = AvssVote>>(
        &self,
        avss_message_builder: &AvssMessageBuilder,
        avss_cert: C,
        mutate_shards: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<AvidMessageBuilder<C>> {
        self.create_avid_messages_with_mutation(avss_message_builder, avss_cert, mutate_shards)
    }

    fn create_avid_messages_with_mutation<C: Certificate<Payload = AvssVote>>(
        &self,
        avss_message_builder: &AvssMessageBuilder,
        avss_cert: C,
        mutate_shards: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<AvidMessageBuilder<C>> {
        if avss_message_builder.common.hash() != avss_cert.payload().common_message_hash {
            warn!("batch_avss create_avid_messages_with_mutation: AVSS Cert binds a different common message");
            return Err(InvalidInput);
        }
        let pending_recipients: BTreeSet<PartyId> = self
            .nodes
            .node_ids_iter()
            .filter(|id| !avss_cert.signers().contains(id))
            .collect();
        if self.nodes.total_weight_of(pending_recipients.iter())? > self.params.f {
            warn!("batch_avss create_avid_messages_with_mutation: too many pending recipients");
            return Err(InvalidInput);
        }
        let payloads: BTreeMap<PartyId, Vec<u8>> = pending_recipients
            .iter()
            .map(|&i| (i, avss_message_builder.ciphertexts[i as usize].0.clone()))
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
        let _ = nodes.node_id_to_node(id)?;

        // The dealer is expected to deal a number of nonces proportional to it's weight
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;

        let total_weight = nodes.total_weight();
        params.validate(total_weight)?;
        params.check_erasure_code_params(total_weight)?;
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
    ///    and verified the [AvssCommonMessage] for this AVSS round. If the common provided here
    ///    disagrees with the one in `message`, e.g. an equivocating dealer sent a different common
    ///    after the receiver already committed to one, the message is rejected with [InvalidInput].
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
    ///    complaints later via [Self::handle_avss_complaint] / [Self::handle_avid_complaint], and
    ///    should persist the returned outputs before sending its [AvssVote].
    pub fn process_avss_message(
        &self,
        message: &AvssMessage,
        verified_avss_common_message: Option<&VerifiedAvssCommonMessage>,
    ) -> FastCryptoResult<(ReceiverOutput, AvssVote, VerifiedAvssCommonMessage)> {
        let verified_common = match verified_avss_common_message {
            Some(verified) if verified.0.hash() == message.common.hash() => verified.clone(),
            Some(_) => {
                warn!("batch_avss process_avss_message: provided verified common message does not match the message's common message");
                return Err(InvalidInput);
            }
            None => self.verify_common_message(message.common.clone())?,
        };
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
    ///
    /// Called in the pessimistic phase by a receiver that needs a [VerifiedAvssCommonMessage] but
    /// did not obtain one from its own [AvssMessage] since the result is required by
    /// [Self::process_avid_message] and [Self::decode_and_decrypt].
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
    ///    The caller must already hold a `verified_avss_common_message` for this AVSS round before
    ///    processing the [AvidMessage], obtained either when verifying its shares in the AVSS
    ///    phase ([Self::process_avss_message]) or by fetching the [AvssCommonMessage] from a peer
    ///    and verify it using [Self::verify_common_message].
    ///
    ///    Receivers who did not receive their shares through an [AvssMessage] should wait for a
    ///    published [Certificate] over [AvidVote]s that confirms they are a pending recipient and
    ///    then get the [AvssCommonMessage] and [Echo]es from the signers.
    ///
    ///    The caller should persist the outputs before sending its [AvidVote]. Returns
    ///    [InvalidMessage] if the `avss_cert` binds a different common than the one provided.
    pub fn process_avid_message<C: Certificate<Payload = AvssVote>>(
        &self,
        verified_avss_common_message: &VerifiedAvssCommonMessage,
        message: AvidMessage<C>,
    ) -> FastCryptoResult<(EchoBuilder, AvidVote)> {
        let AvidMessage {
            dispersal,
            avss_cert,
        } = message;

        if avss_cert.payload().common_message_hash != verified_avss_common_message.0.hash() {
            warn!("batch_avss process_avid_message: AVSS Cert binds a different common message");
            return Err(InvalidMessage);
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
        Ok((builder, avid_vote))
    }

    /// Verify an [Echo] addressed to this receiver. Returns a [VerifiedEcho] suitable for
    /// [Self::decode_and_decrypt].
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
    ///    [VerifiedEcho]s and, when the dispersal is consistent, decrypt and verify its shares.
    ///
    ///    A pending recipient should only pull echoes from the signers after the [AvidVote]
    ///    certificate is published and the cert confirms it is a pending recipient.
    ///
    ///    The caller should get an [AvssCommonMessage] from one of the signers of the cert and
    ///    verify it before calling this method.
    ///
    ///    Returns [DecodeAndDecryptOutcome::InvalidDispersal] (an [AvidComplaint]) when the collected
    ///    shards fail to RS-decode, or decode to a ciphertext whose re-encoding disagrees with the
    ///    hash pinned in [VerifiedAvssCommonMessage] — a dispersal-layer fault, after which
    ///    decryption is skipped. Otherwise the ciphertext decoded and this receiver's shares are
    ///    verified: [DecodeAndDecryptOutcome::Valid] with the decoded [Ciphertext] and [ReceiverOutput]
    ///    when they verify, or [DecodeAndDecryptOutcome::InvalidDecryption] (an [AvssComplaint]) when they
    ///    don't.
    ///
    ///    An [AvidComplaint] is a dispersal-layer fault. Hold it until the matching cert on
    ///    [AvidVote]s is certified on the TOB, or discard it if a different one wins. An
    ///    [AvssComplaint] is an encryption-layer fault carrying the accuser's ciphertext and an
    ///    ECIES recovery package. Broadcast it only after seeing a TOB certificate for the
    ///    corresponding `common_message_hash`.
    ///
    ///    The caller should persist its decoded ciphertext for the session to answer complaints.
    pub fn decode_and_decrypt<C: Certificate<Payload = AvidVote>>(
        &self,
        echoes: &[VerifiedEcho],
        verified_common: &VerifiedAvssCommonMessage,
        avid_cert: &VerifiedCertificate<C>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<DecodeAndDecryptOutcome> {
        if avid_cert.payload().common_message_hash != verified_common.0.hash() {
            warn!("batch_avss decode_and_decrypt: AvidCert binds a different common message");
            return Err(InvalidMessage);
        }
        let expected_hash = verified_common
            .0
            .ciphertext_hashes
            .get(self.id as usize)
            .ok_or(InvalidProof)?;

        let ciphertext = match self.avid.decode_or_complain(echoes, |payload| {
            Blake2b256::digest(payload) == *expected_hash
        })? {
            Ok(bytes) => Ciphertext(bytes),
            Err(complaint) => {
                warn!(
                    "batch_avss decode_and_decrypt: receiver {} raising AvidComplaint",
                    self.id,
                );
                return Ok(DecodeAndDecryptOutcome::InvalidDispersal(complaint));
            }
        };

        Ok(
            match self.decrypt_and_verify_shares(&ciphertext, verified_common) {
                Ok(output) => DecodeAndDecryptOutcome::Valid(ciphertext, output),
                Err(e) => {
                    warn!(
                    "batch_avss decode_and_decrypt: receiver {} raising AvssComplaint after share decode/verify failed: {e:?}",
                    self.id,
                );
                    DecodeAndDecryptOutcome::InvalidDecryption(AvssComplaint {
                        ciphertext,
                        proof: recovery_proof::RecoveryProof::create(
                            self.id,
                            &verified_common.0.ciphertext_shared,
                            &self.enc_secret_key,
                            &self.random_oracle(),
                            rng,
                        ),
                    })
                }
            },
        )
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

    /// 6a. Validate a [AvssComplaint] and respond with this party's own shares.
    pub fn handle_avss_complaint(
        &self,
        reveal: &AvssComplaint,
        accuser_id: PartyId,
        verified_common: &VerifiedAvssCommonMessage,
        own_ciphertext: Ciphertext,
        rng: &mut impl AllowedRng,
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

        Ok(self.build_complaint_response(&verified_common.0, own_ciphertext, rng))
    }

    /// 6b. Validate a [AvidComplaint] and respond with this party's own shares.
    pub fn handle_avid_complaint<C: Certificate<Payload = AvidVote>>(
        &self,
        blame: &AvidComplaint,
        accuser_id: PartyId,
        verified_common: &VerifiedAvssCommonMessage,
        avid_cert: &VerifiedCertificate<C>,
        own_ciphertext: Ciphertext,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse> {
        let expected_hash = verified_common
            .0
            .ciphertext_hashes
            .get(accuser_id as usize)
            .ok_or(InvalidProof)?;

        let vote = &avid_cert.payload().vote;
        self.avid
            .complaint_is_valid(blame, accuser_id, vote, |payload| {
                Blake2b256::digest(payload) == *expected_hash
            })?;

        Ok(self.build_complaint_response(&verified_common.0, own_ciphertext, rng))
    }

    /// Build a [ComplaintResponse] for a validated [AvssComplaint] / [AvidComplaint].
    fn build_complaint_response(
        &self,
        common_message: &AvssCommonMessage,
        ciphertext: Ciphertext,
        rng: &mut impl AllowedRng,
    ) -> ComplaintResponse {
        let recovery_package = common_message.ciphertext_shared.create_recovery_package(
            &self.enc_secret_key,
            &self.random_oracle().extend(&Recovery(self.id).to_string()),
            rng,
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

    /// 7. Recover the accuser's own shares from a quorum (`≥ t`) of [VerifiedComplaintResponse]s.
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

        let my_shares = SharesForNode::recover(self, &response_shares)?;

        // Each response was already checked by verify_complaint_response, and interpolating valid
        // shares yields valid shares, so this final verification is defense-in-depth and should be
        // unreachable as a failure. Warn loudly if it ever does fail, since that signals a logic
        // error rather than a malicious input.
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), &verified_common.0);
        my_shares
            .verify(
                &verified_common.0,
                &challenge,
                &self.nodes.share_ids_of(self.id)?,
                self.batch_size,
            )
            .tap_err(|e| {
                warn!("batch_avss recover: recovered shares failed final verification, which should be unreachable with verified responses: {e:?}")
            })?;

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

impl AvssMessageBuilder {
    /// The optimistic-phase [AvssMessage] for every receiver.
    pub fn messages(&self) -> impl Iterator<Item = (PartyId, AvssMessage)> + '_ {
        self.ciphertexts
            .iter()
            .enumerate()
            .map(|(i, ciphertext)| (i as PartyId, self.message_from_ciphertext(ciphertext)))
    }

    /// The optimistic-phase [AvssMessage] for a given `receiver`, or `None` if `receiver` is not a
    /// valid id.
    pub fn message_for(&self, receiver: PartyId) -> Option<AvssMessage> {
        self.ciphertexts
            .get(receiver as usize)
            .map(|ciphertext| self.message_from_ciphertext(ciphertext))
    }

    fn message_from_ciphertext(&self, ciphertext: &Ciphertext) -> AvssMessage {
        AvssMessage {
            common: self.common.clone(),
            ciphertext: ciphertext.clone(),
        }
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
                            .take(receiver.params.t as usize)
                            .collect_vec();
                        Ok(Poly::recover_at(receiver.params.t, index, &evaluations)?.value)
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()?;

                let blinding_share = Poly::recover_at(
                    receiver.params.t,
                    index,
                    &responders
                        .iter()
                        .flat_map(|(ids, s)| ids.iter().copied().zip(s.shares.iter()))
                        .map(|(index, share)| Eval {
                            index,
                            value: share.blinding_share,
                        })
                        .take(receiver.params.t as usize)
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

impl Parameters {
    fn check_erasure_code_params(&self, total_weight: u16) -> FastCryptoResult<()> {
        ErasureCoder::check_parameters(total_weight as usize, self.t as usize)
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
        AvidMessageBuilder, AvidVote, AvssMessage, AvssMessageBuilder, AvssVote, Dealer,
        DecodeAndDecryptOutcome, Parameters, Receiver, ReceiverOutput, VerifiedEcho,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
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
        // 7 of 10 parties confirm in the optimistic phase; the remaining 3 receive their shares
        // via the pessimistic AVID phase, gated on the optimistic certificate. Pending weight
        // (= 3) must be at most `f` so the dealer-side precheck in
        // `create_avid_messages_with_mutation` accepts the cert; here it sits exactly at the
        // `f = 3` boundary.
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

        // Optimistic phase: only parties 0..=6 confirm; 7, 8 and 9 are stragglers.
        let state = dealer.create_avss_messages(&mut rng).unwrap();
        let voters: Vec<PartyId> = (0u16..=6).collect();
        let pending: BTreeSet<PartyId> = [7u16, 8, 9].into_iter().collect();
        let votes: BTreeMap<PartyId, AvssVote> = voters
            .iter()
            .map(|id| {
                (
                    *id,
                    receivers[*id as usize]
                        .process_avss_message(&state.message_for(*id).unwrap(), None)
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
        // Pessimistic phase: dispersal for the complement of voters (I = {7, 8, 9}). The dealer
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
                .process_avid_message(&vcm, messages.message_for(r.id).unwrap())
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

        // Each receiver j sends echoes only for recipients in pending_recipients (= 3 echoes).
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
                .decode_and_decrypt(&verified_echoes, vcm, &avid_cert, &mut rng)
                .unwrap();
            assert_valid(outcome);
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
        let opt_messages: Vec<AvssMessage> = state.messages().map(|(_, m)| m).collect();

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
            .process_avid_message(&vcm0, messages.message_for(victim_id).unwrap())
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
                    .process_avid_message(&vcm, messages.message_for(r.id).unwrap())
                    .unwrap();
                let echo = builder.create_echo(victim_id).unwrap();
                receivers[victim_id as usize]
                    .verify_avid_echo_message(echo, r.id, &avid_cert0)
                    .unwrap()
            })
            .collect();
        let outcome = receivers[victim_id as usize]
            .decode_and_decrypt(&echoes_for_victim, &vcm0, &avid_cert0, &mut rng)
            .unwrap();
        let reveal = match outcome {
            DecodeAndDecryptOutcome::InvalidDecryption(r) => r,
            _ => panic!("expected InvalidDecryption outcome"),
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
                        &mut rand::thread_rng(),
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
        // the AVID shards for receiver 0's ciphertext, so receiver 0's decode_and_decrypt yields
        // an InvalidDispersal complaint. Voters respond and receiver 0 recovers.
        let t = 3u16;
        let f = 2u16;
        let n = 7u16;
        let batch_size_per_weight: u16 = 3;
        let victim_id = 0u16;
        let (dealer, receivers) = uniform_session(n, t, f, batch_size_per_weight);

        let mut rng = rand::thread_rng();
        let state = dealer.create_avss_messages(&mut rng).unwrap();
        let common = state.common.clone();

        // Optimistic: receivers 1..n confirm; receiver 0 is simulated as not having received
        // the optimistic message.
        let mut outputs: HashMap<u16, ReceiverOutput> = HashMap::new();
        let mut votes: BTreeMap<PartyId, AvssVote> = BTreeMap::new();
        for r in receivers.iter().filter(|r| r.id != victim_id) {
            let (out, c, _) = r
                .process_avss_message(&state.message_for(r.id).unwrap(), None)
                .unwrap();
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
            .process_avid_message(&vcm0, messages.message_for(victim_id).unwrap())
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
                    .process_avid_message(&vcm, messages.message_for(r.id).unwrap())
                    .unwrap();
                let echo = builder.create_echo(victim_id).unwrap();
                receivers[victim_id as usize]
                    .verify_avid_echo_message(echo, r.id, &avid_cert0)
                    .unwrap()
            })
            .collect();

        let outcome = receivers[victim_id as usize]
            .decode_and_decrypt(&echoes_for_victim, &vcm0, &avid_cert0, &mut rng)
            .unwrap();
        let blame = match outcome {
            DecodeAndDecryptOutcome::InvalidDispersal(blame) => blame,
            _ => panic!("expected InvalidDispersal from victim"),
        };

        // Voters handle the Blame using their own ciphertexts.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                let vcm = r.verify_common_message(common.clone()).unwrap();
                let (_, vote) = r
                    .process_avid_message(&vcm, messages.message_for(r.id).unwrap())
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
                        &mut rand::thread_rng(),
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

    fn assert_valid(outcome: DecodeAndDecryptOutcome) -> ReceiverOutput {
        match outcome {
            DecodeAndDecryptOutcome::Valid(_, output) => output,
            ref other => panic!("expected valid outcome, got {:?}", outcome_kind(other)),
        }
    }

    fn outcome_kind(outcome: &DecodeAndDecryptOutcome) -> &'static str {
        match outcome {
            DecodeAndDecryptOutcome::InvalidDispersal(_) => "InvalidDispersal",
            DecodeAndDecryptOutcome::InvalidDecryption(_) => "InvalidDecryption",
            DecodeAndDecryptOutcome::Valid(..) => "Valid",
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
        ) -> FastCryptoResult<AvssMessageBuilder> {
            self.create_avss_messages_with_mutation(rng, |pk_and_msgs| {
                pk_and_msgs[0].1[7] ^= 1;
            })
        }

        fn pessimistic_with_corrupted_dispersal(
            &self,
            state: &AvssMessageBuilder,
            cert: AvssCert,
        ) -> FastCryptoResult<AvidMessageBuilder<AvssCert>> {
            let f = self.params.f as usize;
            let n = self.nodes.total_weight() as usize;
            self.create_avid_messages_for_testing(state, cert, |shards_by_recipient| {
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
