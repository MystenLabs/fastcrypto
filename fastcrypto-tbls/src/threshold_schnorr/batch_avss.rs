// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of an asynchronous verifiable secret sharing (AVSS) protocol to distribute secret shares for a batch of random nonces.
//! The size of the batch is proportional to the [Dealer]'s weight.
//!
//! Before the protocol starts, the following setup is needed:
//! * Each receiver has a encryption key pair (ECIES) and these public keys are known to all parties.
//! * The public keys along with the weights of each receiver are known to all parties and defined in the [Nodes] structure.
//! * Define a new [Dealer] with the secrets who begins by calling [Dealer::create_message].

use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey, SharedComponents};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{create_secret_sharing, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::batch_avss::DecryptionOutcome::Valid;
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
use fastcrypto::hash::{Blake2b256, Digest, HashFunction, Sha3_512};
use fastcrypto::merkle;
use fastcrypto::merkle::MerkleTree;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::iter::repeat_with;

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
    pub(crate) id: PartyId,
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

/// The message broadcast by the dealer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    common: CommonMessage,
    dispersal: Vec<AuthenticatedShards>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonMessage {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    shared: SharedComponents<EG>,
    response_polynomial: Poly<S>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    root: merkle::Node,
    shards: Vec<Shard>,
    shards_proof: merkle::MerkleProof,
}

/// One sender's echo to a single recipient: their shard for the recipient's ciphertext, with
/// Merkle proofs binding it to the dealer's broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EchoMessage {
    sender: PartyId,
    global_root: merkle::Node,
    /// Proof that `authenticated_shards.root` sits under `global_root` at the recipient's leaf.
    recipient_root_proof: merkle::MerkleProof,
    authenticated_shards: AuthenticatedShards,
    common_message_hash: Digest<32>,
}

/// The receiver's reconstructed ciphertext together with the metadata extracted from the echoes.
pub struct ProcessedEchoMessages {
    ciphertext: Vec<u8>,
    global_root: merkle::Node,
    recipient_root: merkle::Node,
    valid_echoes: Vec<EchoMessage>,
}

/// The result of [Receiver::verify_and_decrypt]: either valid shares plus a vote to broadcast, or
/// a complaint to broadcast instead.
#[allow(clippy::large_enum_variant)]
pub enum DecryptionOutcome {
    Valid { output: ReceiverOutput, vote: Vote },
    InvalidShares(Reveal),
    InvalidDispersal(Blame),
}

/// The message a receiver broadcasts after `verify_and_decrypt`: a [Vote] endorsing the dealer's
/// broadcast or a [InvalidShares] / [InvalidDispersal] complaint otherwise.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Vote(Vote),
    InvalidShares(Reveal),
    InvalidDispersal(Blame),
}

/// An endorsement of the dealer's broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub global_root: merkle::Node,
    pub common_message_hash: Digest<32>,
}

/// A complaint by a receiver who could not decrypt or verify its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reveal {
    pub proof: complaint::Complaint,
    pub ciphertext: Vec<u8>,
    /// `H(val)` from the dealer's broadcast, binding the complaint to a specific [CommonMessage].
    pub common_message_hash: Digest<32>,
}

/// A complaint by a receiver who decrypted valid shares but found the AVID dispersal
/// inconsistent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blame {
    pub accuser_id: PartyId,
    pub shards: Vec<ShardContribution>,
    pub common_message_hash: Digest<32>,
}

/// One sender's contribution of shards toward reconstructing the accuser's ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardContribution {
    pub sender: PartyId,
    pub shards: Vec<Shard>,
    /// Proof that `shards` sits under the accuser's `recipient_root` at `sender`'s leaf.
    pub shards_proof: merkle::MerkleProof,
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
/// These can be created either by decrypting the shares from the dealer (see [Receiver::process_echo_messages]) or by recovering them from complaint responses.
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

impl AuthenticatedShards {
    /// Verify that `shards` are the leaf at `leaf_index` under `root` using `shards_proof`.
    fn verify(&self, leaf_index: usize) -> FastCryptoResult<()> {
        self.shards_proof
            .verify_proof_with_unserialized_leaf(&self.root, &self.shards, leaf_index)
    }
}

impl DecryptionOutcome {
    /// Reduce this outcome to the message the party should broadcast to others: a [Vote] when
    /// the dealer's broadcast verified, otherwise the [InvalidShares] or [InvalidDispersal] itself.
    /// The receiver's local [ReceiverOutput] (in the Valid case) is consumed and not part of the
    /// wire format.
    pub fn into_response(self) -> Response {
        match self {
            DecryptionOutcome::Valid { vote, .. } => Response::Vote(vote),
            DecryptionOutcome::InvalidShares(r) => Response::InvalidShares(r),
            DecryptionOutcome::InvalidDispersal(b) => Response::InvalidDispersal(b),
        }
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
    /// BCS-serialized length of a `SharesForNode` for a node of the given weight at the given
    /// batch size.
    ///
    /// Layout:
    /// ```text
    /// SharesForNode = Vec<ShareBatch>
    ///   = ULEB128(weight) + weight × ShareBatch
    /// ShareBatch
    ///   = NonZeroU16 (= 2 bytes) + Vec<S> + S
    ///   = 2 + ULEB128(batch_size) + (batch_size + 1) × SCALAR_SIZE_IN_BYTES
    /// ```
    fn bcs_serialized_size(weight: usize, batch_size: usize) -> usize {
        // TODO: A bit of a hack — this hardcodes the BCS layout of `SharesForNode`/`ShareBatch`
        // and the 32-byte scalar size. Any change to those types' fields silently invalidates
        // this formula; the unit test catches it but only within the tested ranges.
        uleb128_len(weight)
            + weight * (2 + uleb128_len(batch_size) + (batch_size + 1) * SCALAR_SIZE_IN_BYTES)
    }

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

    fn verify(&self, message: &CommonMessage, challenge: &[S]) -> FastCryptoResult<()> {
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
}

impl BCSSerialized for SharesForNode {}

impl Dealer {
    /// Create a new dealer.
    ///
    /// * `nodes` defines the set of receivers and their weights.
    /// * `dealer_id` is the id of this dealer as a node.
    /// * `f` is the maximum number of Byzantine parties counted by weight.
    /// * `t` is the number of shares that are needed to reconstruct the full key/signature.
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

    /// 1. The Dealer generates shares for the secrets and creates a set of messages - one per receiver.
    pub fn create_message(&self, rng: &mut impl AllowedRng) -> FastCryptoResult<Vec<Message>> {
        self.create_message_with_mutation(rng, |_| {})
    }

    /// Like [Self::create_message] but exposes a mutation hook over the pre-encryption
    /// per-receiver plaintexts so tests can simulate a faulty dealer by corrupting one slot.
    fn create_message_with_mutation(
        &self,
        rng: &mut impl AllowedRng,
        mutate: impl FnOnce(&mut [(crate::ecies_v1::PublicKey<EG>, Vec<u8>)]),
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

        mutate(&mut pk_and_msgs);

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

        let shards = ciphertexts
            .iter()
            .map(|c| {
                let shards = code.encode(c)?; // One shard per weight
                self.nodes.collect_to_nodes(shards.into_iter()) // Grouped to nodes by weight
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        let trees = shards
            .iter()
            .map(MerkleTree::<Blake2b256>::build_from_unserialized)
            .collect::<FastCryptoResult<Vec<_>>>()?;

        let dispersals: Vec<Vec<AuthenticatedShards>> = self
            .nodes
            .node_ids_iter()
            .map(|id| {
                shards
                    .iter()
                    .zip(&trees)
                    .map(|(s, tree)| {
                        Ok(AuthenticatedShards {
                            root: tree.root(),
                            shards: s[id as usize].clone(),
                            shards_proof: tree.get_proof(id as usize)?,
                        })
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        let root =
            MerkleTree::<Blake2b256>::build_from_unserialized(trees.iter().map(MerkleTree::root))?
                .root();

        // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
        let challenge = compute_challenge(
            &self.random_oracle(),
            &full_public_keys,
            &blinding_commit,
            &shared,
            &root,
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

    /// 2. When a party receives its message, it verifies the Merkle tree path for it's shards and generates EchoMessages - one per party.
    pub fn echo_message(&self, message: &Message) -> FastCryptoResult<Vec<EchoMessage>> {
        if message
            .dispersal
            .iter()
            .any(|auth| auth.verify(self.id as usize).is_err())
        {
            return Err(InvalidMessage);
        }

        let tree = MerkleTree::<Blake2b256>::build_from_unserialized(
            message
                .dispersal
                .iter()
                .map(|auth| &auth.root),
        )?;
        let global_root = tree.root();
        let digest = compute_common_message_hash(&message.common);
        message
            .dispersal
            .iter()
            .enumerate()
            .map(|(i, authenticated_shards)| {
                Ok(EchoMessage {
                    sender: self.id,
                    global_root: global_root.clone(),
                    recipient_root_proof: tree.get_proof(i)?,
                    authenticated_shards: authenticated_shards.clone(),
                    common_message_hash: digest,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()
    }

    /// 3. When a party has received EchoMessages from parties with at least weight W - f, it
    ///    tries to process them. It first filters out invalid messages and checks if the EchoMessages
    ///    have the same digest, r and r_i values. If not, an InvalidMessage error is returned.
    ///    If the filtered set of EchoMessages does not have sufficient weight, an NotEnoughWeight error
    ///    is returned.
    ///
    ///    If these checks succeed, the party reconstructs it's message (ciphertext) from the echoed
    ///    shards along with the r and r_i values.
    pub fn process_echo_messages(
        &self,
        echo_messages: &[EchoMessage],
    ) -> FastCryptoResult<ProcessedEchoMessages> {
        // Filter out invalid echo messages
        let echo_messages = echo_messages
            .iter()
            .filter(|echo_message| {
                echo_message
                    .authenticated_shards
                    .verify(echo_message.sender as usize)
                    .is_ok()
                    && echo_message
                        .recipient_root_proof
                        .verify_proof_with_unserialized_leaf(
                            &echo_message.global_root,
                            &echo_message.authenticated_shards.root,
                            self.id as usize,
                        )
                        .is_ok()
            })
            .cloned()
            .collect_vec();

        let (global_root, recipient_root, _) = require_uniform_echo_metadata(&echo_messages)?;

        let required_weight = self.nodes.total_weight() - self.f;
        if self.nodes.total_weight_of(
            echo_messages
                .iter()
                .map(|echo_message| &echo_message.sender),
        )? < required_weight
        {
            return Err(NotEnoughWeight(required_weight as usize));
        }

        let ciphertext = self.reconstruct_ciphertext(self.id, |id| {
            echo_messages
                .iter()
                .find(|e| e.sender == id)
                .map(|e| e.authenticated_shards.shards.clone())
        })?;
        Ok(ProcessedEchoMessages {
            ciphertext,
            global_root,
            recipient_root,
            valid_echoes: echo_messages,
        })
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

        let mut ciphertext = self.code.decode(shards)?;
        // Reed-Solomon `decode` returns shard-aligned padding; trim back to the original encrypted
        // blob length.
        let weight = self.nodes.weight_of(accuser_id)? as usize;
        ciphertext.truncate(SharesForNode::bcs_serialized_size(weight, self.batch_size));
        Ok(ciphertext)
    }

    /// The check r_i' == r_i from the paper
    fn check_avid_consistency(
        &self,
        ciphertext: &[u8],
        root: &merkle::Node,
    ) -> FastCryptoResult<()> {
        let new_shards = self
            .nodes
            .collect_to_nodes(self.code.encode(ciphertext)?.into_iter())?;
        let new_tree = MerkleTree::<Blake2b256>::build_from_unserialized(new_shards.iter())?;

        if new_tree.root() != *root {
            return Err(InvalidMessage);
        }

        Ok(())
    }

    /// 4. If the party also received a valid Message from the dealer, it can now decrypt its shares.
    ///    If this succeeds (returns a DecryptionOutcome::Valid), the party should return a signed vote to the dealer.
    ///    The vote payload can be obtained by calling [DecryptionOutcome::into_response] on the
    ///    outcome, which yields a [Response::Vote] for the caller to sign.
    ///
    ///    When parties with weight at least W -f has submitted a vote, parties who didn't get a valid
    ///    Message from the dealer should request the CommonMessage part of that from the parties who voted.
    ///    Using this, the party can decrypt the shares and verify that the shares are valid.
    ///
    ///    If this function returns a [InvalidShares] or [InvalidDispersal] outcome, the party should broadcast it
    ///    to the other parties — but only after at least `W - f` votes from other parties have
    ///    appeared on the TOB/ABC channel.
    pub fn verify_and_decrypt(
        &self,
        processed_echo_messages: ProcessedEchoMessages,
        message: &Message,
    ) -> FastCryptoResult<DecryptionOutcome> {
        let CommonMessage {
            full_public_keys,
            blinding_commit,
            response_polynomial,
            shared,
        } = &message.common;

        let ProcessedEchoMessages {
            ciphertext,
            global_root,
            recipient_root,
            valid_echoes,
        } = processed_echo_messages;
        if full_public_keys.len() != self.batch_size
            || response_polynomial.degree() != self.t as usize - 1
        {
            return Err(InvalidMessage);
        }

        // TODO: What should happen if these checks fail?
        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        let challenge =
            compute_challenge_from_message(&self.random_oracle(), &global_root, &message.common);
        if G::generator() * response_polynomial.c0()
            != blinding_commit
                + G::multi_scalar_mul(&challenge, full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            return Err(InvalidMessage);
        }

        // Check r_i' == r_i from the paper
        let faulty_dealer = self
            .check_avid_consistency(&ciphertext, &recipient_root)
            .is_err();

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
            .and_then(|plaintext| SharesForNode::from_bytes(&plaintext))
            .and_then(|my_shares| {
                verify_shares(
                    &my_shares,
                    &self.nodes,
                    self.id,
                    &message.common,
                    &challenge,
                    self.batch_size,
                )?;
                Ok(my_shares)
            });

        // TODO: Revisit this dispatch.
        match (faulty_dealer, decrypted_shares) {
            (false, Ok(my_shares)) => Ok(Valid {
                output: ReceiverOutput {
                    my_shares,
                    public_keys: full_public_keys.clone(),
                },
                vote: Vote {
                    global_root,
                    common_message_hash: compute_common_message_hash(&message.common),
                },
            }),
            (true, Ok(_)) => {
                // Repackage each echo's per-shard proof as a ShardContribution. r_i stays
                // implicit — the responder reads it from its own [Message] rather than receiving
                // it via the complaint.
                let any_echo = valid_echoes.first().ok_or(InvalidMessage)?;
                let common_message_hash = any_echo.common_message_hash;
                let shards = valid_echoes
                    .into_iter()
                    .map(|e| ShardContribution {
                        sender: e.sender,
                        shards: e.authenticated_shards.shards,
                        shards_proof: e.authenticated_shards.shards_proof,
                    })
                    .collect_vec();
                Ok(DecryptionOutcome::InvalidDispersal(Blame {
                    accuser_id: self.id,
                    shards,
                    common_message_hash,
                }))
            }
            (_, Err(_)) => {
                let any_echo = valid_echoes.first().ok_or(InvalidMessage)?;
                Ok(DecryptionOutcome::InvalidShares(Reveal {
                    proof: complaint::Complaint::create(
                        self.id,
                        shared,
                        &self.enc_secret_key,
                        &self.random_oracle(),
                        &mut rand::thread_rng(),
                    ),
                    ciphertext,
                    common_message_hash: any_echo.common_message_hash,
                }))
            }
        }
    }

    /// 5. Upon receiving a [Reveal] from another party, verify it and respond with this party's
    ///    own shares so the accuser can recover. The ciphertext must be authenticated as the dealer's
    ///    by re-encoding under the locally-known `r_i`, and decryption with the recovery package must
    ///    yield invalid shares. `message` is the dealer's full [Message] as this party received it;
    ///    the verifier looks up the accuser's per-ciphertext root locally from
    ///    `message.dispersal[accuser_id]` rather than trusting the complaint to carry it.
    pub fn handle_reveal(
        &self,
        message: &Message,
        reveal: &Reveal,
        my_output: &ReceiverOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        let Reveal {
            proof,
            ciphertext,
            common_message_hash,
        } = reveal;
        let accuser_id = proof.accuser_id;
        let accuser_pk = &self.nodes.node_id_to_node(accuser_id)?.pk;
        let recipient_root = self.dispersal_root_for(message, accuser_id)?;
        let global_root = self.global_root(message)?;

        if common_message_hash != &compute_common_message_hash(&message.common)
            || self
                .check_avid_consistency(ciphertext, recipient_root)
                .is_err()
        {
            return Err(InvalidProof);
        }

        let challenge =
            compute_challenge_from_message(&self.random_oracle(), &global_root, &message.common);
        proof.check(
            accuser_pk,
            ciphertext,
            &message.common.shared,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                verify_shares(
                    shares,
                    &self.nodes,
                    accuser_id,
                    &message.common,
                    &challenge,
                    self.batch_size,
                )
            },
        )?;

        Ok(ComplaintResponse::new(self.id, my_output.my_shares.clone()))
    }

    /// Counterpart to [Self::handle_reveal] for [InvalidDispersal]. The accuser must have collected enough
    /// authenticated shards whose re-encoded ciphertext root differs from the locally-known
    /// `r_i`. On success, respond with this party's own shares.
    pub fn handle_blame(
        &self,
        message: &Message,
        blame: &Blame,
        my_output: &ReceiverOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        let Blame {
            accuser_id,
            shards,
            common_message_hash,
        } = blame;
        let accuser_id = *accuser_id;
        let recipient_root = self.dispersal_root_for(message, accuser_id)?;

        if common_message_hash != &compute_common_message_hash(&message.common) {
            return Err(InvalidProof);
        }

        if shards.iter().map(|s| s.sender).unique().count() != shards.len() {
            return Err(InvalidProof);
        }

        if shards.iter().any(|s| {
            s.shards_proof
                .verify_proof_with_unserialized_leaf(recipient_root, &s.shards, s.sender as usize)
                .is_err()
        }) {
            return Err(InvalidProof);
        }

        let weight_of_shards = self
            .nodes
            .total_weight_of(shards.iter().map(|s| &s.sender))?;
        if weight_of_shards < self.nodes.total_weight() - 2 * self.f {
            return Err(InvalidProof);
        }

        let ciphertext = self
            .reconstruct_ciphertext(accuser_id, |id| {
                shards
                    .iter()
                    .find(|s| s.sender == id)
                    .map(|s| s.shards.clone())
            })
            .map_err(|_| InvalidProof)?;

        // The blame is valid iff re-encoding the recovered ciphertext does not match `r_i`.
        if self
            .check_avid_consistency(&ciphertext, recipient_root)
            .is_ok()
        {
            return Err(InvalidProof);
        }

        Ok(ComplaintResponse::new(self.id, my_output.my_shares.clone()))
    }

    fn dispersal_root_for<'a>(
        &self,
        message: &'a Message,
        accuser_id: PartyId,
    ) -> FastCryptoResult<&'a merkle::Node> {
        Ok(&message
            .dispersal
            .get(accuser_id as usize)
            .ok_or(InvalidProof)?
            .root)
    }

    fn global_root(&self, message: &Message) -> FastCryptoResult<merkle::Node> {
        Ok(MerkleTree::<Blake2b256>::build_from_unserialized(
            message.dispersal.iter().map(|s| &s.root),
        )?
        .root())
    }

    /// 6. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &Message,
        responses: Vec<ComplaintResponse<SharesForNode>>,
    ) -> FastCryptoResult<ReceiverOutput> {
        // TODO: This fails if one of the responses has an invalid responder_id. We could probably just ignore those instead.

        // Sanity check that we have enough responses (by weight) to recover the shares.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|response| &response.responder_id))?;
        if total_response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let r = self.global_root(message)?;
        let challenge = compute_challenge_from_message(&self.random_oracle(), &r, &message.common);
        let response_shares = responses
            .into_iter()
            .filter_map(|response| {
                response
                    .shares
                    .verify(&message.common, &challenge)
                    .ok()
                    .map(|_| response.shares)
            })
            .collect_vec();

        // Compute the total weight of the valid responses
        let response_weight: u16 = response_shares.iter().map(SharesForNode::weight).sum();
        if response_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let my_shares = SharesForNode::recover(self, &response_shares)?;
        my_shares.verify(&message.common, &challenge)?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.common.full_public_keys.clone(),
        })
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
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

/// Pull the per-echo metadata that must agree across the entire echo set: the global Merkle root
/// `r`, the receiver's per-ciphertext root `r_i`, and the dealer's `H(val)`. Returns an error if
/// any field is non-uniform.
fn require_uniform_echo_metadata(
    echoes: &[EchoMessage],
) -> FastCryptoResult<(merkle::Node, merkle::Node, Digest<32>)> {
    get_uniform_value(echoes.iter().map(|e| {
        (
            e.global_root.clone(),
            e.authenticated_shards.root.clone(),
            e.common_message_hash,
        )
    }))
    .ok_or(InvalidMessage)
}

/// Verify a set of shares receiver from a Dealer
fn verify_shares(
    shares: &SharesForNode,
    nodes: &Nodes<EG>,
    receiver: PartyId,
    message: &CommonMessage,
    challenge: &[S],
    expected_batch_size: usize,
) -> FastCryptoResult<()> {
    if shares.weight() != nodes.weight_of(receiver)? {
        return Err(InvalidMessage);
    }
    // Skip the batch-size check for a zero-weight node, which holds no shares.
    if !shares.shares.is_empty() && shares.try_uniform_batch_size()? != expected_batch_size {
        return Err(InvalidMessage);
    }
    shares.verify(message, challenge)
}

fn compute_challenge(
    random_oracle: &RandomOracle,
    c: &[G],
    c_prime: &G,
    shared: &SharedComponents<EG>,
    root: &merkle::Node,
) -> Vec<S> {
    let random_oracle = random_oracle.extend(&Challenge.to_string());
    let inner_hash =
        Sha3_512::digest(bcs::to_bytes(&(c.to_vec(), c_prime, shared, root)).unwrap()).digest;
    (0..c.len())
        .map(|l| random_oracle.evaluate_to_group_element(&(l, inner_hash.to_vec())))
        .collect()
}

fn compute_challenge_from_message(
    random_oracle: &RandomOracle,
    root: &merkle::Node,
    message: &CommonMessage,
) -> Vec<S> {
    compute_challenge(
        random_oracle,
        &message.full_public_keys,
        &message.blinding_commit,
        &message.shared,
        root,
    )
}

fn compute_common_message_hash(message: &CommonMessage) -> Digest<32> {
    let CommonMessage {
        shared,
        full_public_keys,
        blinding_commit,
        response_polynomial,
    } = message;
    let mut hasher = Blake2b256::new();
    hasher.update(
        bcs::to_bytes(&(
            shared,
            full_public_keys,
            blinding_commit,
            response_polynomial,
        ))
        .unwrap(),
    );
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{
        Dealer, DecryptionOutcome, Message, Receiver, ReceiverOutput, ShareBatch, SharesForNode,
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
            .map(|receiver| receiver.echo_message(&messages[receiver.id as usize]))
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

        let processed_echo_messages = receivers
            .iter()
            .zip(messages.iter())
            .zip(echoes_by_recipient.iter())
            .map(|((receiver, _message), echoes)| receiver.process_echo_messages(echoes).unwrap())
            .collect_vec();

        let all_shares = receivers
            .iter()
            .zip(processed_echo_messages)
            .zip(messages)
            .map(
                |((receiver, pem), message)| match receiver.verify_and_decrypt(pem, &message) {
                    Ok(DecryptionOutcome::Valid { output, .. }) => (receiver.id, output),
                    _ => panic!(
                        "All receivers should be able to process the message in the happy path"
                    ),
                },
            )
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
        let echo_messages = receivers
            .iter()
            .map(|r| r.echo_message(&messages[r.id as usize]).unwrap())
            .collect_vec();
        let echoes_per_recipient = (0..n)
            .map(|i| echo_messages.iter().map(|em| em[i].clone()).collect_vec())
            .collect_vec();

        // Process echoes + verify_and_decrypt
        let outcomes: HashMap<u16, DecryptionOutcome> = receivers
            .iter()
            .zip(echoes_per_recipient.iter())
            .map(|(r, echoes)| {
                let pem = r.process_echo_messages(echoes).unwrap();
                (
                    r.id,
                    r.verify_and_decrypt(pem, &messages[r.id as usize]).unwrap(),
                )
            })
            .collect();

        // Receiver 0 (the targeted victim) emits a InvalidShares complaint.
        let victim_id = 0u16;
        let mut outcomes = outcomes;
        let reveal = match outcomes.remove(&victim_id).unwrap() {
            DecryptionOutcome::InvalidShares(r) => r,
            other => panic!(
                "expected InvalidShares from victim, got {:?}",
                outcome_kind(&other)
            ),
        };

        // The other receivers each get a Valid output.
        let mut outputs: HashMap<u16, ReceiverOutput> = outcomes
            .into_iter()
            .map(|(id, o)| match o {
                DecryptionOutcome::Valid { output, .. } => (id, output),
                other => panic!(
                    "expected Valid from honest receiver {id}, got {:?}",
                    outcome_kind(&other)
                ),
            })
            .collect();

        // Each non-victim verifies the complaint and returns their shares.
        let responses = receivers
            .iter()
            .filter(|r| r.id != victim_id)
            .map(|r| {
                r.handle_reveal(
                    &messages[r.id as usize],
                    &reveal,
                    outputs.get(&r.id).unwrap(),
                )
                .unwrap()
            })
            .collect_vec();

        // Victim recovers via interpolation across t responses.
        let recovered = receivers[victim_id as usize]
            .recover(&messages[victim_id as usize], responses)
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

    fn outcome_kind(outcome: &DecryptionOutcome) -> &'static str {
        match outcome {
            DecryptionOutcome::Valid { .. } => "Valid",
            DecryptionOutcome::InvalidShares(_) => "InvalidShares",
            DecryptionOutcome::InvalidDispersal(_) => "InvalidDispersal",
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
            self.create_message_with_mutation(rng, |pk_and_msgs| {
                // Flip a low-order byte in receiver 0's plaintext. Targeting an offset deep enough
                // to land inside an actual share (past BCS length prefixes) ensures the
                // deserialized struct is well-formed but holds an invalid scalar field.
                pk_and_msgs[0].1[7] ^= 1;
            })
        }
    }
}
