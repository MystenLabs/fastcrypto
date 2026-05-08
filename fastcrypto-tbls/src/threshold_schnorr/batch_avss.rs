// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous verifiable secret sharing (AVSS) for a batch of random nonces.
//!
//! # What it does
//!
//! A single dealer commits to a batch of `L` random nonces `r_1, …, r_L` and distributes
//! shares to `n` weighted receivers forming a `t`-of-`W` threshold (with `W = Σ_j w_j` total
//! weight, `f` the Byzantine bound by weight, and `L = w_dealer · BATCH_SIZE`). Every honest
//! receiver `j` ends up with `p_l(i_{j,1}), …, p_l(i_{j,w_j})` for every secret `r_l`, where
//! `p_l` is a degree-`(t−1)` polynomial with `p_l(0) = r_l`. Any `≥ t` valid shares reconstruct
//! `r_l`.
//!
//! # Two layers
//!
//! The dealer's broadcast (the [CommonMessage]) carries the public commitments
//! `c_l = g^{r_l}`, the blinding commitment `c' = g^{r'}`, the *response polynomial* `p''(X)`,
//! and the per-recipient Merkle roots `r_1, …, r_n`.
//!
//! **AVID layer.** The dealer encrypts each receiver's shares under multi-recipient ECIES,
//! RS-encodes the per-recipient ciphertexts under a `(W, W−2f)` code, and Merkle-commits each
//! ciphertext's shards into the root `r_i`. Receivers exchange small [Echo]s so any quorum can
//! reconstruct a ciphertext even if the dealer didn't reach them directly.
//!
//! **AVSS layer.** Each receiver decrypts their own ciphertext to get their shares. The
//! response polynomial `p''(X) = p'(X) + Σ_l γ_l · p_l(X)` — a degree-`(t−1)` linear
//! combination of all `L` sharing polynomials plus a blinding `p'`, where `γ_l` is a
//! Fiat-Shamir challenge over *all* dealer commitments — lets the receiver verify their shares
//! with one polynomial identity (construction from [eprint/2023/536](https://eprint.iacr.org/2023/536)).
//! Because `γ` binds to every public root, the dealer can't equivocate later.
//!
//! # Happy path
//!
//! 1. **Dealer.** Build a [Message] per receiver and send it point-to-point.
//! 2. **Echo.** Each receiver verifies their dispersal entry and sends an [Echo] to every other
//!    recipient with their shard for that recipient's ciphertext.
//! 3. **Decode.** Collect `≥ W−2f` valid echoes for the same [CommonMessage] and run
//!    [Receiver::decode_ciphertext].
//! 4. **Verify-and-decrypt.** Run the polynomial commitment check
//!    `g^{p''(0)} = c' · ∏ c_l^{γ_l}`, decrypt the ciphertext, and verify each share pointwise
//!    against `p''`.
//! 5. **Vote.** Once enough valid echoes have been collected in step 2 and step 4 succeeds, the
//!    receiver sends a [Vote] to the dealer.
//! 6. The dealer collects `≥ W−f` votes (by weight) into a certificate posted on the TOB. The
//!    broadcast is now *certified* — every party agrees on `common_message_hash`.
//! 7. A receiver that saw the certificate but missed the original [Message] or enough echoes
//!    fetches [CommonMessage] / echoes from a voter, then runs steps 3–4 (without sending a
//!    [Vote]).
//!
//! Receivers should retain the [VerifiedCommonMessage] for the lifetime of the session — it is
//! required to validate complaints and build a [ComplaintResponse]. The [Echo]s and the decoded
//! ciphertext should also be kept so laggards (step 7) can fetch them.
//!
//! # Complaint paths
//!
//! Complaints are broadcast only after the certificate is in place; the certificate is what
//! pins down the [CommonMessage] every validation hinges on.
//!
//! - **[RevealComplaint]** (encryption-layer fault, raised in step 4). Decryption fails or the shares
//!   don't satisfy `p''`. The accuser publishes a `RevealComplaint` with their ciphertext and an ECIES
//!   recovery package; verifiers re-bind the ciphertext to the dealer's broadcast and use the
//!   recovery package to confirm decryption yields invalid shares.
//! - **[BlameComplaint]** (dispersal-layer fault, raised in step 3). When [Receiver::decode_ciphertext]
//!   returns [DecodeOutcome::InvalidDispersal], **hold** the [BlameComplaint] — do not broadcast yet.
//!   If a certificate for the same `common_message_hash` later lands on the TOB, publish it; if
//!   a different [CommonMessage] gets certified instead, discard the held [BlameComplaint] and re-decode
//!   against echoes for the certified common. Verifiers re-run the same decode-and-re-encode
//!   check on the carried shards.
//!
//! Verifiers respond to a valid complaint with a [ComplaintResponse] carrying their own
//! ciphertext plus a recovery package. The accuser AVID-binds each responder's ciphertext,
//! decrypts via the recovery package, verifies the shares against `p''`, and
//! Lagrange-interpolates once `≥ t` weight of valid responses has accrued
//! (see [Receiver::recover]).

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey, RecoveryPackage, SharedComponents};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{create_secret_sharing, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint;
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
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::iter::repeat_with;

/// Blake2b digest used to bind echoes/complaints to a specific [CommonMessage].
pub type Digest = fastcrypto::hash::Digest<{ Blake2b256::OUTPUT_SIZE }>;

/// This represents a Dealer in the AVSS.
/// There is exactly one dealer who creates the shares and broadcasts the encrypted shares.
#[allow(dead_code)]
pub struct Dealer {
    f: u16,
    t: u16,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    /// The total number of nonces that this dealer should distribute.
    batch_size: usize,
}

/// This represents a Receiver in the AVSS who receives shares from the [Dealer].
#[allow(dead_code)]
pub struct Receiver {
    pub id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    sid: Vec<u8>,
    f: u16,
    t: u16,
    /// The total number of nonces that the receiver expects to receive from the dealer.
    batch_size: usize,
    /// Reed-Solomon `(W, W - 2f)` coder over the dealer's per-receiver ciphertexts.
    code: ErasureCoder,
}

/// The dealer's per-recipient message: the shared [CommonMessage] plus the receiver's own
/// [AuthenticatedShards] entries (one per ciphertext, indexed by recipient id).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub common: CommonMessage,
    dispersal: Vec<AuthenticatedShards>,
}

/// The shared part of the dealer's broadcast — identical for every receiver. Receivers must run
/// it through [Receiver::verify_common_message] before any further step; the resulting
/// [VerifiedCommonMessage] is what every later API consumes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonMessage {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    ciphertext_shared: SharedComponents<EG>,
    response_polynomial: Poly<S>,
    recipient_roots: Vec<merkle::Node>,
}

/// A [CommonMessage] that has been validated against the dealer's commitments. Receivers
/// should keep it around for the lifetime of the session.
// TODO: We can cache the hash and challenge here if it makes sense.
#[derive(Clone, Debug)]
pub struct VerifiedCommonMessage(pub CommonMessage);

/// One recipient's shards for one ciphertext, with a Merkle proof verifying against the
/// corresponding `recipient_root` from [CommonMessage].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    shards: Vec<Shard>,
    proof: merkle::MerkleProof,
}

/// One sender's echo to a single recipient: their shard for the recipient's ciphertext, with a
/// proof that verifies against the recipient's [CommonMessage::recipient_roots] entry, plus a
/// hash binding the echo to a specific [CommonMessage].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Echo {
    sender: PartyId,
    authenticated_shards: AuthenticatedShards,
    pub common_message_hash: Digest,
}

/// An [Echo] that has been verified by [Receiver::verify_echo] against a specific
/// [CommonMessage]: the sender's shard count matches their weight, the Merkle proof checks out
/// against the receiver's `recipient_root`, and the echo's `common_message_hash` matches.
#[derive(Clone, Debug)]
pub struct VerifiedEcho(Echo);

/// The result of [Receiver::decode_ciphertext]: either a successfully reconstructed
/// ciphertext whose AVID dispersal is consistent, or a [BlameComplaint] when the collected shards either
/// fail to RS-decode or decode to a ciphertext whose re-encoding disagrees with the dealer's
/// `r_i`.
///
/// On `InvalidDispersal`, do **not** broadcast the [BlameComplaint] immediately: hold it until the same
/// `common_message_hash` is certified on the TOB, then publish. If a *different* [CommonMessage]
/// gets certified instead, discard the held [BlameComplaint] and re-decode against the echoes for the
/// certified common.
#[allow(clippy::large_enum_variant)]
pub enum DecodeOutcome {
    Decoded(Vec<u8>),
    InvalidDispersal(BlameComplaint),
}

/// The result of [Receiver::verify_and_decrypt].
#[allow(clippy::large_enum_variant)]
pub enum DecryptionOutcome {
    Valid { output: ReceiverOutput, vote: Vote },
    Invalid(RevealComplaint),
}

/// An endorsement of the dealer's broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub common_message_hash: Digest,
}

/// A complaint by a receiver who could not decrypt or verify its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealComplaint {
    pub proof: complaint::Complaint,
    pub ciphertext: Vec<u8>,
    pub common_message_hash: Digest,
}

/// A complaint by a receiver who found the AVID dispersal inconsistent. Self-contained: carries
/// the accuser's collected per-sender [AuthenticatedShards] so verifiers can re-run the AVID
/// check without needing to observe echoes addressed to the accuser. The map keys are sender
/// ids, which both deduplicates contributions and gives O(log n) lookup during reconstruction.
///
/// Do not broadcast a [BlameComplaint] until the matching `common_message_hash` has been certified on the
/// TOB; see [DecodeOutcome::InvalidDispersal].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlameComplaint {
    pub accuser_id: PartyId,
    pub shards: BTreeMap<PartyId, AuthenticatedShards>,
    pub common_message_hash: Digest,
}

/// A responder's reply to a [RevealComplaint] / [BlameComplaint] complaint. Carries the responder's own dealer-
/// encrypted ciphertext together with an ECIES recovery package, so the accuser can
/// independently authenticate the responder's shares against the dealer's broadcast and
/// extract them via decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplaintResponse {
    pub responder_id: PartyId,
    pub ciphertext: Vec<u8>,
    pub recovery_package: RecoveryPackage<EG>,
}

/// A [ComplaintResponse] that has been verified by [Receiver::verify_complaint_response]: the
/// carried ciphertext is AVID-bound to the dealer's broadcast, decryption via the recovery
/// package yielded shares satisfying the dealer's response polynomial.
#[derive(Clone, Debug)]
pub struct VerifiedComplaintResponse(SharesForNode);

/// The output of a receiver which is a batch of shares and public keys for all nonces.
#[derive(Debug, Clone)]
pub struct ReceiverOutput {
    pub my_shares: SharesForNode,
    pub public_keys: Vec<G>,
}

/// This represents a set of shares for a node. A total of <i>L</i> secrets/nonces are being shared,
/// If we say that node <i>i</i> has a weight `W_i`, we have
/// `indices().len() == shares_for_secret(i).len() == weight() = W_i`
///
/// Produced by [Receiver::verify_and_decrypt] on the happy path, or by [Receiver::recover]
/// from complaint responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode {
    pub shares: Vec<ShareBatch>,
}

/// A batch of shares for a single share index, containing shares for each secret and one for the "blinding" polynomial.
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
    /// * `t` is the number of shares that are needed to reconstruct the full key/signature.
    /// * `f` is the maximum number of Byzantine parties counted by weight.
    /// * `sid` is a session identifier that should be unique for each invocation, but the same for all parties.
    /// * `batch_size_per_weight` is the number of secrets a dealer should deal per weight it has.
    ///
    /// Returns an `InvalidInput` error if
    /// * t is larger than the total weight of the nodes.
    /// * the `dealer_id` is invalid (not part of `nodes`).
    pub fn new(
        nodes: Nodes<EG>,
        dealer_id: PartyId,
        f: u16,
        t: u16,
        sid: Vec<u8>,
        batch_size_per_weight: u16,
    ) -> FastCryptoResult<Self> {
        if t > nodes.total_weight() {
            return Err(InvalidInput);
        }
        // Each dealer deals a number of nonces proportional to their weight.
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;
        Ok(Self {
            f,
            t,
            nodes,
            sid,
            batch_size,
        })
    }

    /// 1. Build one [Message] per receiver. Each carries a shared [CommonMessage] (with the
    ///    public commitments and the per-recipient Merkle roots) and the recipient's own
    ///    [AuthenticatedShards] entries. Sent point-to-point to the corresponding receiver.
    pub fn create_message(&self, rng: &mut impl AllowedRng) -> FastCryptoResult<Vec<Message>> {
        self.create_message_with_mutation(rng, |_| {}, |_| {})
    }

    /// Like [Self::create_message] but exposes mutation hooks for tests: `mutate_plaintexts` runs
    /// before encryption, and `mutate_shards` runs after RS-encoding (and before the per-recipient
    /// Merkle trees are built), so tests can simulate a faulty dealer at either layer.
    fn create_message_with_mutation(
        &self,
        rng: &mut impl AllowedRng,
        #[cfg_attr(not(test), allow(unused_variables))] mutate_plaintexts: impl FnOnce(
            &mut [(crate::ecies_v1::PublicKey<EG>, Vec<u8>)],
        ),
        #[cfg_attr(not(test), allow(unused_variables))] mutate_shards: impl FnOnce(
            &mut Vec<Vec<Vec<Shard>>>,
        ),
    ) -> FastCryptoResult<Vec<Message>> {
        let secrets = repeat_with(|| S::rand(rng))
            .take(self.batch_size)
            .collect_vec();

        // Compute the (full) public keys for all secrets
        let full_public_keys = secrets.iter().map(|s| G::generator() * s).collect_vec();

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let total_weight = self.nodes.total_weight();
        let blinding_secret = S::rand(rng);
        let blinding_poly_evaluations =
            create_secret_sharing(rng, blinding_secret, self.t, total_weight);
        let blinding_commit = G::generator() * blinding_secret;

        // Compute all evaluations of all polynomials
        let share_batches = secrets
            .iter()
            .map(|&s| create_secret_sharing(rng, s, self.t, total_weight))
            .collect_vec();

        // Encrypt all shares to the receivers
        #[cfg_attr(not(test), allow(unused_mut))]
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

        let ciphertext = MultiRecipientEncryption::encrypt(
            &pk_and_msgs,
            &self.random_oracle().extend(&Encryption.to_string()),
            rng,
        );

        let (shared, ciphertexts) = ciphertext.clone().into_parts();
        let code = ErasureCoder::new(
            self.nodes.total_weight() as usize,
            (self.nodes.total_weight() - 2 * self.f) as usize, // 2f parity shards
        )?;

        #[cfg_attr(not(test), allow(unused_mut))]
        let mut shards: Vec<Vec<Vec<Shard>>> = ciphertexts
            .iter()
            .map(|c| {
                // Every node has positive weight, so each per-recipient ciphertext is non-empty
                // and `code.encode` cannot return `InvalidInput`.
                let shards = code.encode(c).expect("non-empty ciphertext"); // One shard per weight
                self.nodes.collect_to_nodes(shards.into_iter()) // Grouped to nodes by weight
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        #[cfg(test)]
        mutate_shards(&mut shards);

        let recipient_trees = shards
            .iter()
            .map(recipient_tree)
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let recipient_roots = recipient_trees.iter().map(MerkleTree::root).collect_vec();

        let dispersals: Vec<Vec<AuthenticatedShards>> = self
            .nodes
            .node_ids_iter()
            .map(|id| {
                shards
                    .iter()
                    .zip(&recipient_trees)
                    .map(|(s, tree)| {
                        Ok(AuthenticatedShards {
                            shards: s[id as usize].clone(),
                            proof: tree.get_proof(id as usize)?,
                        })
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
        let challenge = compute_challenge(
            &self.random_oracle(),
            &full_public_keys,
            &blinding_commit,
            &shared,
            &recipient_roots,
        );

        // Get the first t evaluations for the response polynomial and use these to compute the coefficients
        let response_polynomial = Poly::interpolate(
            &share_batches
                .into_iter()
                .map(|s| s.take(self.t))
                .zip_eq(&challenge)
                .fold(
                    blinding_poly_evaluations.take(self.t),
                    |acc, (p_l, gamma_l)| acc + p_l * gamma_l,
                )
                .to_vec(),
        )?;

        let common = CommonMessage {
            full_public_keys,
            ciphertext_shared: shared,
            response_polynomial,
            blinding_commit,
            recipient_roots,
        };

        Ok(dispersals
            .into_iter()
            .map(|dispersal| Message {
                common: common.clone(),
                dispersal,
            })
            .collect_vec())
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
    /// * `f` is the maximum number of Byzantine parties counted by weight.
    /// * `t` is the number of shares that are needed to reconstruct the full key/signature.
    /// * `sid` is a session identifier that should be unique for each invocation, but the same for all parties.
    /// * `enc_secret_key` is this Receivers' secret key for the distribution of nonces. The corresponding public key is defined in `nodes`.
    /// * `batch_size_per_weight` is the number of secrets a dealer should deal per weight it has.
    ///
    /// Returns an `InvalidInput` error if the `id` or `dealer_id` is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nodes: Nodes<EG>,
        id: PartyId,
        dealer_id: PartyId,
        f: u16,
        t: u16,
        sid: Vec<u8>,
        enc_secret_key: PrivateKey<EG>,
        batch_size_per_weight: u16,
    ) -> FastCryptoResult<Self> {
        // Check that the id is valid
        let _ = nodes.node_id_to_node(id)?;

        // The dealer is expected to deal a number of nonces proportional to it's weight
        let batch_size = nodes.weight_of(dealer_id)? as usize * batch_size_per_weight as usize;

        let code = ErasureCoder::new(
            nodes.total_weight() as usize,
            (nodes.total_weight() - 2 * f) as usize, // 2f parity shards
        )?;

        Ok(Self {
            id,
            enc_secret_key,
            nodes,
            sid,
            f,
            t,
            batch_size,
            code,
        })
    }

    /// 2. Verify the dispersal entries against `recipient_roots` and emit one [Echo] per
    ///    recipient (indexed by recipient id) for the receiver to broadcast. Also returns the
    ///    [VerifiedCommonMessage] that the receiver should keep around for the rest of the
    ///    session.
    pub fn echo(&self, message: &Message) -> FastCryptoResult<(VerifiedCommonMessage, Vec<Echo>)> {
        let n = self.nodes.num_nodes();
        if message.dispersal.len() != n || message.common.recipient_roots.len() != n {
            return Err(InvalidMessage);
        }
        if message
            .dispersal
            .iter()
            .zip(&message.common.recipient_roots)
            .any(|(auth, root)| auth.verify(self.id as usize, root).is_err())
        {
            return Err(InvalidMessage);
        }

        let verified_common_message = self.verify_common_message(message.common.clone())?;
        let common_message_hash = verified_common_message.0.hash();
        let echoes = message
            .dispersal
            .iter()
            .cloned()
            .map(|authenticated_shards| Echo {
                sender: self.id,
                authenticated_shards,
                common_message_hash,
            })
            .collect();
        Ok((verified_common_message, echoes))
    }

    /// Run the dealer's commitments through [CommonMessage::verify] using this receiver's `t`,
    /// `batch_size`, and session id. Returns the resulting [VerifiedCommonMessage].
    pub fn verify_common_message(
        &self,
        common_message: CommonMessage,
    ) -> FastCryptoResult<VerifiedCommonMessage> {
        common_message.verify(self.t, self.batch_size, &self.random_oracle())
    }

    /// Verify an [Echo] addressed to this receiver against `common_message`: the sender's shard
    /// count matches their advertised weight, the Merkle proof checks against the receiver's
    /// `recipient_root`, and the echo's `common_message_hash` matches. Returns a [VerifiedEcho]
    /// suitable for [Self::decode_ciphertext].
    pub fn verify_echo(
        &self,
        echo: Echo,
        common_message: &VerifiedCommonMessage,
    ) -> FastCryptoResult<VerifiedEcho> {
        let weight = self.nodes.weight_of(echo.sender)?;
        echo.verify(weight, self.id, &common_message.0)
    }

    /// 3. Reconstruct this receiver's ciphertext from a quorum of [VerifiedEcho]s. Returns
    ///    [DecodeOutcome::Decoded] when the AVID dispersal is consistent with the dealer's
    ///    `r_{self.id}`, or [DecodeOutcome::InvalidDispersal] (a [BlameComplaint]) when it isn't.
    ///
    ///    Echoes must already be validated via [Self::verify_echo] and must come from distinct
    ///    senders — duplicates yield [InvalidInput]. Returns [NotEnoughWeight] if the senders
    ///    contribute `< W − 2f` weight.
    pub fn decode_ciphertext(
        &self,
        echos: &[VerifiedEcho],
        common_message: &VerifiedCommonMessage,
    ) -> FastCryptoResult<DecodeOutcome> {
        if !echos.iter().map(|e| e.0.sender).all_unique() {
            return Err(InvalidInput);
        }

        let required_weight = self.nodes.total_weight() - 2 * self.f;
        if self
            .nodes
            .total_weight_of(echos.iter().map(|e| &e.0.sender))?
            < required_weight
        {
            return Err(NotEnoughWeight(required_weight as usize));
        }

        // Try to RS-decode the ciphertext and re-encode it. The dispersal is consistent iff
        // both succeed and the re-encoded root matches `r_{self.id}`. Otherwise the dealer's
        // dispersal is inconsistent — package the collected shards into a self-contained [BlameComplaint].
        let shards: BTreeMap<PartyId, AuthenticatedShards> = echos
            .iter()
            .cloned()
            .map(|e| (e.0.sender, e.0.authenticated_shards))
            .collect();

        Ok(self
            .reconstruct_ciphertext(self.id, &shards)
            .and_then(|ct| {
                self.check_avid_consistency(&ct, common_message.0.recipient_root(self.id)?)?;
                Ok(DecodeOutcome::Decoded(ct))
            })
            .unwrap_or(DecodeOutcome::InvalidDispersal(BlameComplaint {
                accuser_id: self.id,
                shards,
                common_message_hash: common_message.0.hash(),
            })))
    }

    /// 4. Decrypt and verify the receiver's own shares from a successfully decoded ciphertext.
    ///    Yields [DecryptionOutcome::Valid] (with a [Vote] to broadcast) when shares verify, or
    ///    [DecryptionOutcome::Invalid] (a [RevealComplaint]) otherwise.
    pub fn verify_and_decrypt(
        &self,
        ciphertext: &[u8],
        common_message: &VerifiedCommonMessage,
    ) -> FastCryptoResult<DecryptionOutcome> {
        let common_message = &common_message.0;
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);
        let CommonMessage {
            full_public_keys,
            ciphertext_shared: shared,
            ..
        } = &common_message;

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        shared
            .verify(&random_oracle_encryption)
            .map_err(|_| InvalidMessage)?;
        let plaintext = shared.decrypt(
            ciphertext,
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );

        let common_message_hash = common_message.hash();
        SharesForNode::from_bytes(plaintext)
            .and_then(|my_shares| {
                my_shares.verify(
                    common_message,
                    &challenge,
                    self.nodes.weight_of(self.id)?,
                    self.batch_size,
                )?;
                Ok(my_shares)
            })
            .map(|my_shares| DecryptionOutcome::Valid {
                output: ReceiverOutput {
                    my_shares,
                    public_keys: full_public_keys.clone(),
                },
                vote: Vote {
                    common_message_hash,
                },
            })
            .or_else(|_| {
                Ok(DecryptionOutcome::Invalid(RevealComplaint {
                    proof: complaint::Complaint::create(
                        self.id,
                        shared,
                        &self.enc_secret_key,
                        &self.random_oracle(),
                        &mut rand::thread_rng(),
                    ),
                    ciphertext: ciphertext.to_vec(),
                    common_message_hash,
                }))
            })
    }

    /// 5a. Validate a [RevealComplaint] complaint and respond with this party's own shares so the
    ///     accuser can recover. Accepts iff the ciphertext is bound to the dealer's broadcast
    ///     (re-encodes to `recipient_roots[accuser_id]`) and the recovery package decrypts it
    ///     to invalid shares.
    pub fn handle_reveal(
        &self,
        reveal: &RevealComplaint,
        common_message: &VerifiedCommonMessage,
        ciphertext: Vec<u8>,
    ) -> FastCryptoResult<ComplaintResponse> {
        let common_message = &common_message.0;
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);

        let RevealComplaint {
            proof,
            ciphertext: reveal_ciphertext,
            common_message_hash,
        } = reveal;

        if *common_message_hash != common_message.hash() {
            return Err(InvalidProof);
        }
        let recipient_root = common_message.recipient_root(proof.accuser_id)?;
        self.check_avid_consistency(reveal_ciphertext, recipient_root)
            .map_err(|_| InvalidProof)?;
        let accuser = self.nodes.node_id_to_node(proof.accuser_id)?;
        proof.check(
            &accuser.pk,
            reveal_ciphertext,
            &common_message.ciphertext_shared,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                shares.verify(common_message, &challenge, accuser.weight, self.batch_size)
            },
        )?;

        Ok(self.build_complaint_response(common_message, ciphertext))
    }

    /// 5b. Validate a [BlameComplaint] complaint and respond with this party's own shares. Accepts iff
    ///     each entry in `blame.shards` authenticates under
    ///     `common_message.recipient_roots[accuser_id]` at its sender's leaf, the senders
    ///     contribute `≥ W − 2f` weight, and the resulting set of shards either fails to
    ///     RS-decode or decodes to a ciphertext whose re-encoding doesn't match the accuser's
    ///     `r_i`.
    pub fn handle_blame(
        &self,
        blame: &BlameComplaint,
        common_message: &VerifiedCommonMessage,
        ciphertext: Vec<u8>,
    ) -> FastCryptoResult<ComplaintResponse> {
        let common_message = &common_message.0;

        let BlameComplaint {
            accuser_id,
            shards,
            common_message_hash,
        } = blame;

        if *common_message_hash != common_message.hash() {
            return Err(InvalidProof);
        }
        let recipient_root = common_message.recipient_root(*accuser_id)?;

        if shards
            .iter()
            .any(|(sender, auth)| auth.verify(*sender as usize, recipient_root).is_err())
        {
            return Err(InvalidProof);
        }

        let weight_of_shards = self.nodes.total_weight_of(shards.keys())?;
        if weight_of_shards < self.nodes.total_weight() - 2 * self.f {
            return Err(InvalidProof);
        }

        // The blame is valid iff the contributed shards either fail to RS-decode (they don't
        // lie on a single codeword) or decode to a ciphertext whose re-encoding doesn't match
        // the accuser's `r_i`.
        if self
            .reconstruct_ciphertext(*accuser_id, shards)
            .ok()
            .is_some_and(|ct| self.check_avid_consistency(&ct, recipient_root).is_ok())
        {
            return Err(InvalidProof);
        }

        Ok(self.build_complaint_response(common_message, ciphertext))
    }

    /// Build a [ComplaintResponse] for an answered [RevealComplaint] / [BlameComplaint]: package this party's own
    /// dealer-encrypted ciphertext together with an ECIES recovery package, so the accuser can
    /// decrypt and authenticate the responder's shares.
    fn build_complaint_response(
        &self,
        common_message: &CommonMessage,
        ciphertext: Vec<u8>,
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
        common_message: &VerifiedCommonMessage,
    ) -> FastCryptoResult<VerifiedComplaintResponse> {
        let common_message = &common_message.0;
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);

        let ComplaintResponse {
            responder_id,
            ciphertext,
            recovery_package,
        } = response;

        self.check_avid_consistency(&ciphertext, common_message.recipient_root(responder_id)?)?;
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
            responder.weight,
            self.batch_size,
        )?;

        Ok(VerifiedComplaintResponse(shares))
    }

    /// 6. Recover the accuser's own shares from a quorum of [VerifiedComplaintResponse]s.
    ///    Responses must already be validated via [Self::verify_complaint_response]. Fails if
    ///    `common_message` is malformed, the responses contribute `< t` weight, or the
    ///    interpolated shares fail final verification.
    pub fn recover(
        &self,
        common_message: &VerifiedCommonMessage,
        responses: Vec<VerifiedComplaintResponse>,
    ) -> FastCryptoResult<ReceiverOutput> {
        let response_shares = responses.into_iter().map(|v| v.0).collect_vec();
        let response_weight: u16 = response_shares.iter().map(SharesForNode::weight).sum();
        if response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let common_message = &common_message.0;
        let challenge =
            compute_challenge_from_common_message(&self.random_oracle(), common_message);
        let my_shares = SharesForNode::recover(self, &response_shares)?;
        my_shares.verify(
            common_message,
            &challenge,
            self.nodes.weight_of(self.id)?,
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
    ) -> FastCryptoResult<Vec<u8>> {
        let shards_matrix = self
            .nodes
            .node_ids_iter()
            .flat_map(|id| -> Vec<Option<Shard>> {
                let weight = self.nodes.weight_of(id).expect("valid party id") as usize;
                match shards.get(&id) {
                    // If the shards exist and are consistent with the weight, put them in the matrix. Otherwise, add a None, corresponding to an erasure.
                    Some(auth) if auth.shards.len() == weight => {
                        auth.shards.iter().cloned().map(Some).collect_vec()
                    }
                    _ => vec![None; weight],
                }
            })
            .collect_vec();

        // The encryption used, counter-mode, is length-preserving, so the length of the ciphertext is equal to the length of the plaintext.
        let expected_length = SharesForNode::bcs_serialized_size(
            self.nodes.weight_of(accuser_id)? as usize,
            self.batch_size,
        );
        self.code.decode(shards_matrix, expected_length)
    }

    /// RS-encode `ciphertext`, rebuild the per-recipient Merkle tree, and check its root matches
    /// the dealer's `expected_root`. Errors with [InvalidMessage] on mismatch.
    fn check_avid_consistency(
        &self,
        ciphertext: &[u8],
        expected_root: &merkle::Node,
    ) -> FastCryptoResult<()> {
        let new_shards = self
            .nodes
            .collect_to_nodes(self.code.encode(ciphertext)?.into_iter())?;
        if recipient_tree(&new_shards)?.root() != *expected_root {
            return Err(InvalidMessage);
        }
        Ok(())
    }
}

impl CommonMessage {
    /// Verify the dealer's commitments: the lengths/degree of the published values are
    /// well-formed and `g^{p''(0)} = c' · ∏ c_l^{γ_l}`. Consumes `self` and returns a
    /// [VerifiedCommonMessage] on success.
    fn verify(
        self,
        t: u16,
        batch_size: usize,
        random_oracle: &RandomOracle,
    ) -> FastCryptoResult<VerifiedCommonMessage> {
        if self.full_public_keys.len() != batch_size
            || self.response_polynomial.degree() != t as usize - 1
        {
            return Err(InvalidMessage);
        }
        let challenge = compute_challenge_from_common_message(random_oracle, &self);
        if G::generator() * self.response_polynomial.c0()
            != self.blinding_commit
                + G::multi_scalar_mul(&challenge, &self.full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            return Err(InvalidMessage);
        }
        Ok(VerifiedCommonMessage(self))
    }

    /// Blake2b hash of the BCS-serialized [CommonMessage]. Used to bind echoes and complaints
    /// to a specific dealer broadcast.
    fn hash(&self) -> Digest {
        let mut hasher = Blake2b256::new();
        hasher.update(
            bcs::to_bytes(&(
                &self.ciphertext_shared,
                &self.full_public_keys,
                &self.blinding_commit,
                &self.response_polynomial,
                &self.recipient_roots,
            ))
            .unwrap(),
        );
        hasher.finalize()
    }

    /// The dealer's per-recipient Merkle root for `id`. Returns [InvalidProof] if `id` is
    /// out of range.
    fn recipient_root(&self, id: PartyId) -> FastCryptoResult<&merkle::Node> {
        self.recipient_roots.get(id as usize).ok_or(InvalidProof)
    }
}

impl ShareBatch {
    /// Verify a batch of shares using the given challenge.
    fn verify(&self, message: &CommonMessage, challenge: &[S]) -> FastCryptoResult<()> {
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
        message: &CommonMessage,
        challenge: &[S],
        weight: u16,
        expected_batch_size: usize,
    ) -> FastCryptoResult<()> {
        if self.weight() != weight || self.try_uniform_batch_size()? != expected_batch_size {
            return Err(InvalidMessage);
        }
        for shares in &self.shares {
            shares.verify(message, challenge)?;
        }
        Ok(())
    }

    /// Recover the shares for this node.
    ///
    /// Fails if `other_shares` is empty or if the batch sizes of all shares in `other_shares` are not equal to the expected batch size.
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
                        Poly::recover_at(index, &evaluations).unwrap().value
                    })
                    .collect_vec();

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
    /// Verify this echo against `common_message` for the recipient `receiver_id`: the sender's
    /// shard count matches `sender_weight`, the Merkle proof checks against
    /// `recipient_roots[receiver_id]`, and the echo's `common_message_hash` matches.
    fn verify(
        self,
        sender_weight: u16,
        receiver_id: PartyId,
        common_message: &CommonMessage,
    ) -> FastCryptoResult<VerifiedEcho> {
        if self.authenticated_shards.shards.len() != sender_weight as usize {
            return Err(InvalidMessage);
        }
        self.authenticated_shards.verify(
            self.sender as usize,
            common_message.recipient_root(receiver_id)?,
        )?;
        if self.common_message_hash != common_message.hash() {
            return Err(InvalidMessage);
        }
        Ok(VerifiedEcho(self))
    }
}

/// Build the per-recipient Merkle tree over `shards` (per-node grouped shard chunks of one
/// ciphertext). The root of this tree is the per-recipient `recipient_root`.
#[allow(clippy::ptr_arg)]
fn recipient_tree(shards: &Vec<Vec<Shard>>) -> FastCryptoResult<MerkleTree<Blake2b256>> {
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
    recipient_roots: &[merkle::Node],
) -> Vec<S> {
    let random_oracle = random_oracle.extend(&Challenge.to_string());
    let inner_hash =
        Blake2b256::digest(bcs::to_bytes(&(c.to_vec(), c_prime, shared, recipient_roots)).unwrap())
            .digest;
    (0..c.len())
        .map(|l| random_oracle.evaluate_to_group_element(&(l, inner_hash.to_vec())))
        .collect()
}

fn compute_challenge_from_common_message(
    random_oracle: &RandomOracle,
    message: &CommonMessage,
) -> Vec<S> {
    compute_challenge(
        random_oracle,
        &message.full_public_keys,
        &message.blinding_commit,
        &message.ciphertext_shared,
        &message.recipient_roots,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Dealer, DecodeOutcome, DecryptionOutcome, Message, Receiver, ReceiverOutput, ShareBatch,
        SharesForNode,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::EG;
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;

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
    fn test_happy_path() {
        // No complaints, all honest. All have weight 1
        let t = 3;
        let f = 2;
        let n = 7;
        let batch_size_per_weight = 3;

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
        let dealer_id = 0;
        let dealer: Dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            f,
            t,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    f,
                    t,
                    sid.clone(),
                    secret_key,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();

        let messages = dealer.create_message(&mut rng).unwrap();

        let (verified_commons, echoes_by_sender): (Vec<_>, Vec<_>) = receivers
            .iter()
            .map(|receiver| receiver.echo(&messages[receiver.id as usize]).unwrap())
            .unzip();

        let echoes_by_recipient = receivers
            .iter()
            .enumerate()
            .map(|(i, _)| {
                echoes_by_sender
                    .iter()
                    .map(|em| em[i].clone())
                    .collect_vec()
            })
            .collect_vec();

        let decoded_ciphertext = receivers
            .iter()
            .zip(verified_commons.iter())
            .zip(echoes_by_recipient.iter())
            .map(|((receiver, vcm), echoes)| {
                let verified = echoes
                    .iter()
                    .map(|e| receiver.verify_echo(e.clone(), vcm).unwrap())
                    .collect_vec();
                assert_decoded(receiver.decode_ciphertext(&verified, vcm).unwrap())
            })
            .collect_vec();

        let all_shares = receivers
            .iter()
            .zip(verified_commons.iter())
            .zip(decoded_ciphertext)
            .map(|((receiver, vcm), pem)| {
                let output = assert_valid(receiver.verify_and_decrypt(&pem, vcm).unwrap());
                (receiver.id, output)
            })
            .collect::<HashMap<_, _>>();

        let secrets = (0..dealer.batch_size)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.shares[0].batch[l], // Each receiver has a single share (weight=1 for all nodes)
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

        assert_eq!(secrets, secrets);
    }
    #[test]
    fn test_share_recovery() {
        // Dealer is honest at the AVID layer (consistent dispersal) but flips a byte in
        // receiver 0's plaintext, so receiver 0's decryption succeeds but the resulting
        // SharesForNode fails verification — triggering an Invalid complaint. The other receivers
        // verify the complaint and respond with their own shares; receiver 0 reconstructs.
        let t = 3;
        let f = 2;
        let n = 7;
        let batch_size_per_weight: u16 = 3;

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
        let dealer_id = 1;
        let dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            f,
            t,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    f,
                    t,
                    sid.clone(),
                    secret_key,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();

        let messages = dealer.create_message_cheating(&mut rng).unwrap();

        // Echo phase
        let (verified_commons, echos): (Vec<_>, Vec<_>) = receivers
            .iter()
            .map(|r| r.echo(&messages[r.id as usize]).unwrap())
            .unzip();
        let echoes_per_recipient = (0..n)
            .map(|i| echos.iter().map(|em| em[i].clone()).collect_vec())
            .collect_vec();

        // Process echoes + verify_and_decrypt. AVID is consistent for everyone in this test, so
        // every decode yields a Decoded outcome.
        let mut ciphertexts: HashMap<u16, Vec<u8>> = HashMap::new();
        let outcomes: HashMap<u16, DecryptionOutcome> = receivers
            .iter()
            .zip(verified_commons.iter())
            .zip(echoes_per_recipient.iter())
            .map(|((r, vcm), echoes)| {
                let verified = echoes
                    .iter()
                    .map(|e| r.verify_echo(e.clone(), vcm).unwrap())
                    .collect_vec();
                let pem = assert_decoded(r.decode_ciphertext(&verified, vcm).unwrap());
                ciphertexts.insert(r.id, pem.clone());
                (r.id, r.verify_and_decrypt(&pem, vcm).unwrap())
            })
            .collect();

        // Receiver 0 (the targeted victim) emits an Invalid complaint.
        let victim_id = 0u16;
        let mut outcomes = outcomes;
        let reveal = match outcomes.remove(&victim_id).unwrap() {
            DecryptionOutcome::Invalid(r) => r,
            ref other => panic!(
                "expected Invalid from victim, got {:?}",
                outcome_kind(other)
            ),
        };

        // The other receivers each get a Valid output.
        let mut outputs: HashMap<u16, ReceiverOutput> = outcomes
            .into_iter()
            .map(|(id, o)| match o {
                DecryptionOutcome::Valid { output, .. } => (id, output),
                ref other => panic!(
                    "expected Valid from honest receiver {id}, got {:?}",
                    outcome_kind(other)
                ),
            })
            .collect();

        // Each non-victim verifies the complaint and returns their own ciphertext + recovery package.
        let responses = receivers
            .iter()
            .zip(verified_commons.iter())
            .filter(|(r, _)| r.id != victim_id)
            .map(|(r, vcm)| {
                r.handle_reveal(&reveal, vcm, ciphertexts.get(&r.id).unwrap().clone())
                    .unwrap()
            })
            .collect_vec();

        // Victim verifies and then recovers via interpolation across t responses.
        let victim = &receivers[victim_id as usize];
        let vcm = &verified_commons[victim_id as usize];
        let verified_responses = responses
            .into_iter()
            .map(|r| victim.verify_complaint_response(r, vcm).unwrap())
            .collect_vec();
        let recovered = victim.recover(vcm, verified_responses).unwrap();
        outputs.insert(victim_id, recovered);

        // Sanity: every receiver now holds verifiable shares for every secret.
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
        // Dealer is honest at the share layer (decryption yields valid shares) but corrupts the
        // last f senders' shards for receiver 0's ciphertext. Receiver 0 collects the W - f
        // unaffected echoes, decodes the original ciphertext, decrypts valid shares, but
        // re-encoding the recovered ciphertext yields a tree root different from the dealer's
        // r_0 — triggering an InvalidDispersal complaint.
        let t = 3;
        let f = 2;
        let n = 7;
        let batch_size_per_weight: u16 = 3;

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
        let dealer_id = 1;
        let dealer = Dealer::new(
            nodes.clone(),
            dealer_id,
            f,
            t,
            sid.clone(),
            batch_size_per_weight,
        )
        .unwrap();

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(id, secret_key)| {
                Receiver::new(
                    nodes.clone(),
                    id as u16,
                    dealer_id,
                    f,
                    t,
                    sid.clone(),
                    secret_key,
                    batch_size_per_weight,
                )
                .unwrap()
            })
            .collect_vec();

        let messages = dealer.create_message_cheating_dispersal(&mut rng).unwrap();
        let victim_id = 0u16;

        // Echo phase
        let (verified_commons, echos): (Vec<_>, Vec<_>) = receivers
            .iter()
            .map(|r| r.echo(&messages[r.id as usize]).unwrap())
            .unzip();

        // Bundle echoes per recipient. For the victim, simulate the last f senders being silent
        // (their corrupted shards would otherwise make the receiver's decode fail outright).
        let echoes_per_recipient = (0..n)
            .map(|i| {
                let take = if i == victim_id as usize {
                    n - f as usize
                } else {
                    n
                };
                echos
                    .iter()
                    .take(take)
                    .map(|em| em[i].clone())
                    .collect_vec()
            })
            .collect_vec();

        // Decode each receiver's ciphertext. The victim hits the AVID inconsistency at the
        // decode stage and gets a [DecodeOutcome::InvalidDispersal] directly; everyone else
        // gets a [DecodeOutcome::Decoded] that they can pass through `verify_and_decrypt`.
        let mut decode_outcomes: HashMap<u16, DecodeOutcome> = receivers
            .iter()
            .zip(verified_commons.iter())
            .zip(echoes_per_recipient.iter())
            .map(|((r, vcm), echoes)| {
                let verified = echoes
                    .iter()
                    .map(|e| r.verify_echo(e.clone(), vcm).unwrap())
                    .collect_vec();
                (r.id, r.decode_ciphertext(&verified, vcm).unwrap())
            })
            .collect();

        let blame = match decode_outcomes.remove(&victim_id).unwrap() {
            DecodeOutcome::InvalidDispersal(blame) => blame,
            DecodeOutcome::Decoded(_) => panic!("expected InvalidDispersal from victim"),
        };
        // The other receivers each get a Valid output.
        let mut ciphertexts: HashMap<u16, Vec<u8>> = HashMap::new();
        let mut outputs: HashMap<u16, ReceiverOutput> = decode_outcomes
            .into_iter()
            .map(|(id, decoded)| {
                let pem = assert_decoded(decoded);
                ciphertexts.insert(id, pem.clone());
                let outcome = receivers[id as usize]
                    .verify_and_decrypt(&pem, &verified_commons[id as usize])
                    .unwrap();
                let output = match outcome {
                    DecryptionOutcome::Valid { output, .. } => output,
                    ref other => panic!(
                        "expected Valid from honest receiver {id}, got {:?}",
                        outcome_kind(other)
                    ),
                };
                (id, output)
            })
            .collect();

        // Each non-victim verifies the complaint and returns their own ciphertext + recovery package.
        let responses = receivers
            .iter()
            .zip(verified_commons.iter())
            .filter(|(r, _)| r.id != victim_id)
            .map(|(r, vcm)| {
                r.handle_blame(&blame, vcm, ciphertexts.get(&r.id).unwrap().clone())
                    .unwrap()
            })
            .collect_vec();

        // Victim verifies and then recovers via interpolation across t responses.
        let victim = &receivers[victim_id as usize];
        let vcm = &verified_commons[victim_id as usize];
        let verified_responses = responses
            .into_iter()
            .map(|r| victim.verify_complaint_response(r, vcm).unwrap())
            .collect_vec();
        let recovered = victim.recover(vcm, verified_responses).unwrap();
        outputs.insert(victim_id, recovered);

        // Sanity: every receiver now holds verifiable shares for every secret.
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

    fn assert_valid(outcome: DecryptionOutcome) -> ReceiverOutput {
        match outcome {
            DecryptionOutcome::Valid { output, .. } => output,
            ref other => panic!("expected valid outcome, got {:?}", outcome_kind(other)),
        }
    }

    fn assert_decoded(outcome: DecodeOutcome) -> Vec<u8> {
        match outcome {
            DecodeOutcome::Decoded(c) => c,
            DecodeOutcome::InvalidDispersal { .. } => {
                panic!("expected Decoded outcome, got InvalidDispersal")
            }
        }
    }

    fn outcome_kind(outcome: &DecryptionOutcome) -> &'static str {
        match outcome {
            DecryptionOutcome::Valid { .. } => "Valid",
            DecryptionOutcome::Invalid(_) => "Invalid",
        }
    }

    impl Dealer {
        /// Test-only: produce a [Message] in which receiver 0's plaintext has one byte flipped
        /// before encryption. AVID dispersal stays consistent (so the AVID checks pass for
        /// everyone), but receiver 0's BCS-deserialized [SharesForNode] fails verification.
        fn create_message_cheating(
            &self,
            rng: &mut impl AllowedRng,
        ) -> FastCryptoResult<Vec<Message>> {
            self.create_message_with_mutation(
                rng,
                |pk_and_msgs| {
                    pk_and_msgs[0].1[7] ^= 1;
                },
                |_| {},
            )
        }

        fn create_message_cheating_dispersal(
            &self,
            rng: &mut impl AllowedRng,
        ) -> FastCryptoResult<Vec<Message>> {
            let f = self.f as usize;
            let n = self.nodes.total_weight() as usize;
            self.create_message_with_mutation(
                rng,
                |_| {},
                |shards| {
                    // Flip a byte in the shards held by the last `f` senders for ciphertext 0.
                    for sender_shards in shards[0].iter_mut().skip(n - f) {
                        sender_shards[0].0[0] ^= 1;
                    }
                },
            )
        }
    }
}
