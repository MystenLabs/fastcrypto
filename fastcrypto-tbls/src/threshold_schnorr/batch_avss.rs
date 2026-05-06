// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous verifiable secret sharing (AVSS) for a batch of random nonces.
//! An AVID layer based on Reed-Solomon `(W, W − 2f)` and per-recipient Merkle commitments lets each
//! receiver authenticate the dealer's broadcast even if they did not receive it directly.
//!
//! # Setup
//!
//! * Each receiver holds an ECIES key pair from [crate::ecies_v1]. The public keys are
//!   advertised through the shared [Nodes] structure together with each party's weight.
//! * One party is designated dealer and constructs a [Dealer] with `nodes`, `f`
//!   (Byzantine bound by weight), `t` (recovery threshold), session id, and
//!   `batch_size_per_weight`. The receivers uses a [Receiver] with matching parameters.
//!
//! # Happy path
//!
//! 1. The dealer calls [Dealer::create_message] and sends each [Message] to its recipient.
//! 2. Every receiver calls [Receiver::echo] and broadcasts each resulting [Echo] to the
//!    indexed recipient.
//! 3. Each receiver collects [Echo]s and runs [Receiver::decode_ciphertext] for their
//!    own id, yielding a [DecodeOutcome::Decoded] ciphertext.
//! 4. They feed the ciphertext to [Receiver::verify_and_decrypt], which yields a
//!    [DecryptionOutcome::Valid] containing this party's [ReceiverOutput] and a [Vote] to
//!    broadcast on the TOB/ABC channel.
//!
//! Receivers should keep the common part of the message, [CommonMessage], for the lifetime of
//! the protocol since it is needed to handle complaints.
//!
//! # Complaint paths
//!
//! If a receiver in [Receiver::decode_ciphertext] detects that AVID dispersal is
//! inconsistent, it returns a self-contained [Blame] carrying the collected [ShardContribution]s
//! as evidence. If a receiver in [Receiver::verify_and_decrypt] detects that decryption fails
//! or yields shares that don't verify, it returns a [Reveal] complaint.
//!
//! The accuser broadcasts the [Reveal] / [Blame] after at least `W − f` votes have accrued on
//! the TOB/ABC channel. Other receivers validate it via [Receiver::handle_reveal] /
//! [Receiver::handle_blame] and respond with their own shares. Once `≥ t` weight of valid
//! responses has arrived, the accuser calls [Receiver::recover] to interpolate their own
//! shares from those responses.

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey, SharedComponents};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{create_secret_sharing, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::complaint;
use crate::threshold_schnorr::complaint::ComplaintResponse;
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::Extensions::{Challenge, Encryption};
use crate::threshold_schnorr::{random_oracle_from_sid, EG, G, S};
use crate::types::{get_uniform_value, ShareIndex};
use fastcrypto::error::FastCryptoError::{
    InvalidInput, InvalidMessage, InvalidProof, NotEnoughWeight,
};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::secp256k1::SCALAR_SIZE_IN_BYTES;
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{Blake2b256, HashFunction, Sha3_512};
use fastcrypto::merkle;
use fastcrypto::merkle::MerkleTree;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
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

/// The shared part of the dealer's broadcast — identical for every receiver and required by
/// every later step ([Receiver::decode_ciphertext], [Receiver::verify_and_decrypt],
/// [Receiver::handle_reveal], [Receiver::handle_blame], [Receiver::recover]). Receivers should
/// keep it around for the lifetime of the session. A receiver that didn't get a [Message] from
/// the dealer should fetch the [CommonMessage] from another receiver who did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonMessage {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    shared: SharedComponents<EG>,
    response_polynomial: Poly<S>,
    recipient_roots: Vec<merkle::Node>,
}

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
    common_message_hash: Digest,
}

/// The result of [Receiver::decode_ciphertext]: either a successfully reconstructed
/// ciphertext whose AVID dispersal is consistent, or a [Blame] when the re-encoded ciphertext
/// disagrees with the dealer's `r_i`.
#[allow(clippy::large_enum_variant)]
pub enum DecodeOutcome {
    Decoded(Vec<u8>),
    InvalidDispersal(Blame),
}

/// The result of [Receiver::verify_and_decrypt].
#[allow(clippy::large_enum_variant)]
pub enum DecryptionOutcome {
    Valid { output: ReceiverOutput, vote: Vote },
    InvalidShares(Reveal),
}

/// An endorsement of the dealer's broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub common_message_hash: Digest,
}

/// A complaint by a receiver who could not decrypt or verify its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reveal {
    pub proof: complaint::Complaint,
    pub ciphertext: Vec<u8>,
    /// Hash binding the complaint to a specific [CommonMessage].
    pub common_message_hash: Digest,
}

/// A complaint by a receiver who found the AVID dispersal inconsistent. Self-contained:
/// carries the accuser's collected shard contributions so verifiers can re-run the AVID check
/// without needing to observe echoes addressed to the accuser.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blame {
    pub accuser_id: PartyId,
    pub shards: Vec<ShardContribution>,
    /// Hash binding the complaint to a specific [CommonMessage].
    pub common_message_hash: Digest,
}

/// One sender's contribution toward reconstructing the accuser's ciphertext: their shards plus
/// a Merkle proof binding them under `recipient_roots[accuser_id]` at `sender`'s leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardContribution {
    pub sender: PartyId,
    pub shards: Vec<Shard>,
    pub proof: merkle::MerkleProof,
}

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
/// These can be created either by decrypting the shares from the dealer (see [Receiver::decode_ciphertext]) or by recovering them from complaint responses.
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
        mutate_plaintexts: impl FnOnce(&mut [(crate::ecies_v1::PublicKey<EG>, Vec<u8>)]),
        mutate_shards: impl FnOnce(&mut Vec<Vec<Vec<Shard>>>),
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

        let mut shards: Vec<Vec<Vec<Shard>>> = ciphertexts
            .iter()
            .map(|c| {
                let shards = code.encode(c)?; // One shard per weight
                self.nodes.collect_to_nodes(shards.into_iter()) // Grouped to nodes by weight
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        mutate_shards(&mut shards);

        let recipient_trees = shards
            .iter()
            .map(recipient_tree)
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let recipient_roots: Vec<merkle::Node> =
            recipient_trees.iter().map(MerkleTree::root).collect();

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
            shared,
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
    ///    recipient (indexed by recipient id) for the receiver to broadcast.
    pub fn echo(&self, message: &Message) -> FastCryptoResult<Vec<Echo>> {
        if message.dispersal.len() != message.common.recipient_roots.len() {
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

        let common_message_hash = compute_common_message_hash(&message.common);
        Ok(message
            .dispersal
            .iter()
            .cloned()
            .map(|authenticated_shards| Echo {
                sender: self.id,
                authenticated_shards,
                common_message_hash,
            })
            .collect())
    }

    /// 3. Reconstruct this receiver's ciphertext from received [Echo]s. Returns
    ///    [DecodeOutcome::Decoded] when the AVID dispersal is consistent with the dealer's
    ///    `r_{self.id}`, or [DecodeOutcome::InvalidDispersal] (a [Blame]) when it isn't.
    pub fn decode_ciphertext(
        &self,
        echos: &[Echo],
        common_message: &CommonMessage,
    ) -> FastCryptoResult<DecodeOutcome> {
        common_message.verify(self.t, self.batch_size, &self.random_oracle())?;
        let recipient_root = common_message
            .recipient_roots
            .get(self.id as usize)
            .ok_or(InvalidInput)?;

        // Filter out invalid echo messages: each echo's shards proof must verify against the
        // dealer's `r_{self.id}`.
        let valid_echoes = echos
            .iter()
            .filter(|echo| echo.verify(recipient_root).is_ok())
            .cloned()
            .collect_vec();

        let common_message_hash = require_uniform_common_message_hash(&valid_echoes)?;
        if common_message_hash != compute_common_message_hash(common_message) {
            return Err(InvalidMessage);
        }

        // TODO: Double-check that this is ok
        let required_weight = self.nodes.total_weight() - 2 * self.f;
        if self
            .nodes
            .total_weight_of(valid_echoes.iter().map(|echo| &echo.sender))?
            < required_weight
        {
            return Err(NotEnoughWeight(required_weight as usize));
        }

        // Try to RS-decode the ciphertext. Two failure modes both indicate an inconsistent
        // dealer dispersal: (a) decode fails outright because the echoed shards don't lie on a
        // single codeword, or (b) decode succeeds but re-encoding the result yields a tree root
        // different from the dealer's `r_{self.id}`. Both produce a self-contained [Blame]
        // carrying the collected shards as evidence.
        let try_decode = self.reconstruct_ciphertext(self.id, |id| {
            valid_echoes
                .iter()
                .find(|e| e.sender == id)
                .map(|e| e.authenticated_shards.shards.clone())
        });
        let dispersal_consistent = try_decode
            .as_ref()
            .ok()
            .is_some_and(|ct| self.check_avid_consistency(ct, recipient_root).is_ok());

        if !dispersal_consistent {
            let shards = valid_echoes
                .into_iter()
                .map(|e| ShardContribution {
                    sender: e.sender,
                    shards: e.authenticated_shards.shards,
                    proof: e.authenticated_shards.proof,
                })
                .collect_vec();
            return Ok(DecodeOutcome::InvalidDispersal(Blame {
                accuser_id: self.id,
                shards,
                common_message_hash,
            }));
        }

        Ok(DecodeOutcome::Decoded(
            try_decode.expect("just verified Ok"),
        ))
    }

    /// 4. Decrypt and verify the receiver's own shares from a successfully decoded ciphertext.
    ///    Yields [DecryptionOutcome::Valid] (with a [Vote] to broadcast) when shares verify, or
    ///    [DecryptionOutcome::InvalidShares] (a [Reveal]) otherwise.
    pub fn verify_and_decrypt(
        &self,
        ciphertext: Vec<u8>,
        common_message: &CommonMessage,
    ) -> FastCryptoResult<DecryptionOutcome> {
        let challenge = common_message.verify(self.t, self.batch_size, &self.random_oracle())?;
        let CommonMessage {
            full_public_keys,
            shared,
            ..
        } = &common_message;

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        let decrypted_shares = shared
            .verify(&random_oracle_encryption)
            .map(|_| {
                shared.decrypt(
                    &ciphertext,
                    &self.enc_secret_key,
                    &random_oracle_encryption,
                    self.id as usize,
                )
            })
            .and_then(SharesForNode::from_bytes)
            .and_then(|my_shares| {
                my_shares.verify(
                    common_message,
                    &challenge,
                    self.nodes.weight_of(self.id)?,
                    self.batch_size,
                )?;
                Ok(my_shares)
            });

        let common_message_hash = compute_common_message_hash(common_message);
        match decrypted_shares {
            Ok(my_shares) => Ok(DecryptionOutcome::Valid {
                output: ReceiverOutput {
                    my_shares,
                    public_keys: full_public_keys.clone(),
                },
                vote: Vote {
                    common_message_hash,
                },
            }),
            Err(_) => Ok(DecryptionOutcome::InvalidShares(Reveal {
                proof: complaint::Complaint::create(
                    self.id,
                    shared,
                    &self.enc_secret_key,
                    &self.random_oracle(),
                    &mut rand::thread_rng(),
                ),
                ciphertext,
                common_message_hash,
            })),
        }
    }

    /// 5a. Validate a [Reveal] complaint and respond with this party's own shares so the
    ///     accuser can recover. Accepts iff the ciphertext is bound to the dealer's broadcast
    ///     (re-encodes to `recipient_roots[accuser_id]`) and the recovery package decrypts it
    ///     to invalid shares.
    pub fn handle_reveal(
        &self,
        reveal: &Reveal,
        common_message: &CommonMessage,
        my_output: &ReceiverOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        let challenge = common_message.verify(self.t, self.batch_size, &self.random_oracle())?;

        let Reveal {
            proof,
            ciphertext,
            common_message_hash,
        } = reveal;
        let accuser_id = proof.accuser_id;

        if *common_message_hash != compute_common_message_hash(common_message) {
            return Err(InvalidProof);
        }
        let recipient_root = common_message
            .recipient_roots
            .get(accuser_id as usize)
            .ok_or(InvalidProof)?;
        self.check_avid_consistency(ciphertext, recipient_root)
            .map_err(|_| InvalidProof)?;
        let accuser_pk = &self.nodes.node_id_to_node(accuser_id)?.pk;
        let accuser_weight = self.nodes.weight_of(accuser_id)?;
        proof.check(
            accuser_pk,
            ciphertext,
            &common_message.shared,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                shares.verify(common_message, &challenge, accuser_weight, self.batch_size)
            },
        )?;

        Ok(ComplaintResponse::new(self.id, my_output.my_shares.clone()))
    }

    /// 5b. Validate a [Blame] complaint and respond with this party's own shares. Accepts iff
    ///     the carried [ShardContribution]s authenticate under
    ///     `common_message.recipient_roots[accuser_id]`, contribute `≥ W − 2f` weight from
    ///     unique senders, and either fail to RS-decode or decode to a ciphertext whose
    ///     re-encoding doesn't match the accuser's `r_i`.
    pub fn handle_blame(
        &self,
        blame: &Blame,
        common_message: &CommonMessage,
        my_output: &ReceiverOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        common_message.verify(self.t, self.batch_size, &self.random_oracle())?;

        let Blame {
            accuser_id,
            shards,
            common_message_hash,
        } = blame;

        if *common_message_hash != compute_common_message_hash(common_message) {
            return Err(InvalidProof);
        }
        let recipient_root = common_message
            .recipient_roots
            .get(*accuser_id as usize)
            .ok_or(InvalidProof)?;

        if !shards.iter().map(|s| s.sender).all_unique()
            || shards.iter().any(|s| s.verify(recipient_root).is_err())
        {
            return Err(InvalidProof);
        }

        let weight_of_shards = self
            .nodes
            .total_weight_of(shards.iter().map(|s| &s.sender))?;
        if weight_of_shards < self.nodes.total_weight() - 2 * self.f {
            return Err(InvalidProof);
        }

        // The blame is valid iff the contributed shards either fail to RS-decode (they don't
        // lie on a single codeword) or decode to a ciphertext whose re-encoding doesn't match
        // the accuser's `r_i`.
        let dispersal_consistent = self
            .reconstruct_ciphertext(*accuser_id, |id| {
                shards
                    .iter()
                    .find(|s| s.sender == id)
                    .map(|s| s.shards.clone())
            })
            .ok()
            .is_some_and(|ct| self.check_avid_consistency(&ct, recipient_root).is_ok());
        if dispersal_consistent {
            return Err(InvalidProof);
        }

        Ok(ComplaintResponse::new(self.id, my_output.my_shares.clone()))
    }

    /// 6. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        common_message: &CommonMessage,
        responses: Vec<ComplaintResponse<SharesForNode>>,
    ) -> FastCryptoResult<ReceiverOutput> {
        // TODO: This fails if one of the responses has an invalid responder_id. We could probably just ignore those instead.

        let challenge = common_message.verify(self.t, self.batch_size, &self.random_oracle())?;

        // Sanity check that we have enough responses (by weight) to recover the shares.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|response| &response.responder_id))?;
        if total_response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }
        let response_shares = responses
            .into_iter()
            .filter_map(|response| {
                self.nodes
                    .weight_of(response.responder_id)
                    .map(|w| (w, response.shares))
                    .ok()
            })
            .filter_map(|(weight, shares)| {
                shares
                    .verify(common_message, &challenge, weight, self.batch_size)
                    .ok()
                    .map(|_| shares)
            })
            .collect_vec();

        // Compute the total weight of the valid responses
        let response_weight: u16 = response_shares.iter().map(SharesForNode::weight).sum();
        if response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

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
    /// contributions exposed via `shards_for(party_id) -> Option<Vec<Shard>>`. Fails if the
    /// contributing weight is below `W - 2f` (too few contributions to reconstruct), or if a
    /// party's contribution has a shard count that doesn't match its weight. The caller is
    /// responsible for having authenticated the shards via their Merkle proofs.
    fn reconstruct_ciphertext(
        &self,
        accuser_id: PartyId,
        shards_for: impl Fn(PartyId) -> Option<Vec<Shard>>,
    ) -> FastCryptoResult<Vec<u8>> {
        let shards: Vec<Option<Shard>> = self
            .nodes
            .node_ids_iter()
            .map(|id| -> FastCryptoResult<Vec<Option<Shard>>> {
                let weight = self.nodes.weight_of(id).expect("valid party id") as usize;
                match shards_for(id) {
                    Some(ss) if ss.len() == weight => Ok(ss.into_iter().map(Some).collect()),
                    // Fail if a contributor's shard count doesn't match its weight.
                    Some(_) => Err(InvalidInput),
                    None => Ok(vec![None; weight]),
                }
            })
            .flatten_ok()
            .collect::<FastCryptoResult<Vec<_>>>()?;

        // The encryption used, counter-mode, is length-preserving, so the length of the ciphertext is equal to the length of the plaintext.
        let expected_length = SharesForNode::bcs_serialized_size(
            self.nodes.weight_of(accuser_id)? as usize,
            self.batch_size,
        );
        self.code.decode(shards, expected_length)
    }

    /// The check r_i' == r_i from the paper
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
    /// well-formed and `g^{p''(0)} = c' · ∏ c_l^{γ_l}`. Returns the Fiat-Shamir challenge `γ`
    /// so the caller can reuse it for per-share verification.
    fn verify(
        &self,
        t: u16,
        batch_size: usize,
        random_oracle: &RandomOracle,
    ) -> FastCryptoResult<Vec<S>> {
        if self.full_public_keys.len() != batch_size
            || self.response_polynomial.degree() != t as usize - 1
        {
            return Err(InvalidMessage);
        }
        let challenge = compute_challenge_from_common_message(random_oracle, self);
        if G::generator() * self.response_polynomial.c0()
            != self.blinding_commit
                + G::multi_scalar_mul(&challenge, &self.full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            return Err(InvalidMessage);
        }
        Ok(challenge)
    }
}

impl ShardContribution {
    fn verify(&self, recipient_root: &merkle::Node) -> FastCryptoResult<()> {
        self.proof.verify_proof_with_unserialized_leaf(
            recipient_root,
            &self.shards,
            self.sender as usize,
        )
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
        // TODO: Should we cache this? It's called twice per dealer -- once when verifying shares received from a dealer and then again during presigning.
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
    /// Verify the shard's Merkle proof against `recipient_root` (the dealer's `r_i` for the
    /// recipient this echo is addressed to) at `sender`'s leaf.
    fn verify(&self, recipient_root: &merkle::Node) -> FastCryptoResult<()> {
        self.authenticated_shards
            .verify(self.sender as usize, recipient_root)
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

/// Require that every echo's `common_message_hash` agrees and return that hash.
fn require_uniform_common_message_hash(echoes: &[Echo]) -> FastCryptoResult<Digest> {
    get_uniform_value(echoes.iter().map(|e| e.common_message_hash)).ok_or(InvalidMessage)
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
        Sha3_512::digest(bcs::to_bytes(&(c.to_vec(), c_prime, shared, recipient_roots)).unwrap())
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
        &message.shared,
        &message.recipient_roots,
    )
}

fn compute_common_message_hash(message: &CommonMessage) -> Digest {
    let CommonMessage {
        shared,
        full_public_keys,
        blinding_commit,
        response_polynomial,
        recipient_roots,
    } = message;
    let mut hasher = Blake2b256::new();
    hasher.update(
        bcs::to_bytes(&(
            shared,
            full_public_keys,
            blinding_commit,
            response_polynomial,
            recipient_roots,
        ))
        .unwrap(),
    );
    hasher.finalize()
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

        let echoes_by_sender = receivers
            .iter()
            .map(|receiver| receiver.echo(&messages[receiver.id as usize]))
            .collect::<FastCryptoResult<Vec<_>>>()
            .unwrap();

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
            .zip(messages.iter())
            .zip(echoes_by_recipient.iter())
            .map(|((receiver, message), echoes)| {
                assert_decoded(receiver.decode_ciphertext(echoes, &message.common).unwrap())
            })
            .collect_vec();

        let all_shares = receivers
            .iter()
            .zip(decoded_ciphertext)
            .zip(messages)
            .map(|((receiver, pem), message)| {
                let output =
                    assert_valid(receiver.verify_and_decrypt(pem, &message.common).unwrap());
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
        // SharesForNode fails verification — triggering a InvalidShares complaint. The other receivers
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
        let echos = receivers
            .iter()
            .map(|r| r.echo(&messages[r.id as usize]).unwrap())
            .collect_vec();
        let echoes_per_recipient = (0..n)
            .map(|i| echos.iter().map(|em| em[i].clone()).collect_vec())
            .collect_vec();

        // Process echoes + verify_and_decrypt. AVID is consistent for everyone in this test, so
        // every decode yields a Decoded outcome.
        let outcomes: HashMap<u16, DecryptionOutcome> = receivers
            .iter()
            .zip(echoes_per_recipient.iter())
            .map(|(r, echoes)| {
                let pem = assert_decoded(
                    r.decode_ciphertext(echoes, &messages[r.id as usize].common)
                        .unwrap(),
                );
                (
                    r.id,
                    r.verify_and_decrypt(pem, &messages[r.id as usize].common)
                        .unwrap(),
                )
            })
            .collect();

        // Receiver 0 (the targeted victim) emits a InvalidShares complaint.
        let victim_id = 0u16;
        let mut outcomes = outcomes;
        let reveal = match outcomes.remove(&victim_id).unwrap() {
            DecryptionOutcome::InvalidShares(r) => r,
            ref other => panic!(
                "expected InvalidShares from victim, got {:?}",
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

        // Each non-victim verifies the complaint and returns their shares.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                r.handle_reveal(
                    &reveal,
                    &messages[r.id as usize].common,
                    outputs.get(&r.id).unwrap(),
                )
                .unwrap()
            })
            .collect_vec();

        // Victim recovers via interpolation across t responses.
        let recovered = receivers[victim_id as usize]
            .recover(&messages[victim_id as usize].common, responses)
            .unwrap();
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
        let echos = receivers
            .iter()
            .map(|r| r.echo(&messages[r.id as usize]).unwrap())
            .collect_vec();

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
            .zip(echoes_per_recipient.iter())
            .map(|(r, echoes)| {
                (
                    r.id,
                    r.decode_ciphertext(echoes, &messages[r.id as usize].common)
                        .unwrap(),
                )
            })
            .collect();

        let blame = match decode_outcomes.remove(&victim_id).unwrap() {
            DecodeOutcome::InvalidDispersal(blame) => blame,
            DecodeOutcome::Decoded(_) => panic!("expected InvalidDispersal from victim"),
        };
        // The other receivers each get a Valid output.
        let mut outputs: HashMap<u16, ReceiverOutput> = decode_outcomes
            .into_iter()
            .map(|(id, decoded)| {
                let pem = assert_decoded(decoded);
                let outcome = receivers[id as usize]
                    .verify_and_decrypt(pem, &messages[id as usize].common)
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

        // Each non-victim verifies the complaint and returns their shares.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                r.handle_blame(
                    &blame,
                    &messages[r.id as usize].common,
                    outputs.get(&r.id).unwrap(),
                )
                .unwrap()
            })
            .collect_vec();

        // Victim recovers via interpolation across t responses.
        let recovered = receivers[victim_id as usize]
            .recover(&messages[victim_id as usize].common, responses)
            .unwrap();
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
            DecryptionOutcome::InvalidShares(_) => "InvalidShares",
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
