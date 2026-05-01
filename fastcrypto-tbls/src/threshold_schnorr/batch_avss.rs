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
use crate::nodes::{Node, Nodes, PartyId};
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
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage, InvalidProof, NotEnoughWeight};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hash::{Blake2b256, Digest, HashFunction, Sha3_512};
use fastcrypto::merkle;
use fastcrypto::merkle::MerkleTree;
use fastcrypto::traits::AllowedRng;
use fastcrypto::twisted_elgamal::Ciphertext;
use itertools::{repeat_n, Itertools};
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
    proof: merkle::MerkleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EchoMessage {
    party: PartyId,
    r: merkle::Node,
    pi_i: merkle::MerkleProof,
    r_i: merkle::Node,
    s_ij: Vec<Shard>,
    hash: Digest<32>,
    pub pi_ij: merkle::MerkleProof,
}

pub struct ProcessedEchoMessages {
    ciphertext: Vec<u8>,
    r: merkle::Node,
    r_i: merkle::Node,
    valid_echoes: Vec<EchoMessage>,
}

pub enum DecryptionOutcome {
    Valid(ReceiverOutput),
    Complaint(Complaint),
}

/// A complaint by a receiver after `verify_and_decrypt`. There are two flavors:
/// * [Complaint::Reveal] — the receiver could not decrypt or verify its shares.
/// * [Complaint::Blame] — the receiver decrypted valid shares but the AVID dispersal was
///   inconsistent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Complaint {
    Reveal {
        proof: complaint::Complaint,
        // TODO: Handle zero-padding
        /// The reconstructed accuser's ciphertext. The responder re-encodes this and checks that
        /// the resulting root matches `r_i`.
        ciphertext: Vec<u8>,
        r_i: merkle::Node,
        /// Proof that `r_i` sits under the global `r` at the accuser's leaf.
        pi_i: merkle::MerkleProof,
        /// `H(val)` from the dealer's broadcast, binding the complaint to a specific [CommonMessage].
        hash: Digest<32>,
    },
    Blame {
        accuser_id: PartyId,
        r_i: merkle::Node,
        /// Proof that `r_i` sits under the global `r` at `accuser_id`'s leaf.
        pi_i: merkle::MerkleProof,
        /// At least `W - 2f` weight worth of shards `s_{ji}`, each with a Merkle proof under `r_i`
        /// at the contributing party's leaf.
        shards: Vec<ShardContribution>,
        hash: Digest<32>,
    },
}

/// One sender's contribution of shards toward reconstructing the accuser's ciphertext, with a
/// Merkle proof binding the shards to the accuser's per-ciphertext root `r_i`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardContribution {
    pub party: PartyId,
    pub shards: Vec<Shard>,
    /// Proof that `shards` sits under the accuser's `r_i` at `party`'s leaf.
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
        let pk_and_msgs = self
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

        let messages = self
            .nodes
            .node_ids_iter()
            .map(|id| {
                shards
                    .iter()
                    .zip(&trees)
                    .map(|(s, tree)| {
                        let proof = tree.get_proof(id as usize)?;
                        Ok((tree.root(), s[id as usize].clone(), proof))
                    })
                    .collect::<FastCryptoResult<Vec<_>>>()
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        let roots = trees.iter().map(MerkleTree::root).collect_vec();
        let root = MerkleTree::<Blake2b256>::build_from_unserialized(roots.iter())?.root();

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

        Ok(messages
            .into_iter()
            .map(|m| Message {
                common: CommonMessage {
                    full_public_keys: full_public_keys.clone(),
                    shared: shared.clone(),
                    response_polynomial: response_polynomial.clone(),
                    blinding_commit,
                },
                dispersal: m
                    .iter()
                    .map(|m| AuthenticatedShards {
                        root: m.0.clone(),
                        shards: m.1.clone(),
                        proof: m.2.clone(),
                    })
                    .collect_vec(),
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
        if message.dispersal.iter().any(
            |AuthenticatedShards {
                 root,
                 shards,
                 proof,
                 ..
             }| {
                proof
                    .verify_proof_with_unserialized_leaf(root, &shards, self.id as usize)
                    .is_err()
            },
        ) {
            return Err(InvalidMessage);
        }

        let tree = MerkleTree::<Blake2b256>::build_from_unserialized(
            message.dispersal.iter().map(|AuthenticatedShards { root, .. }| root),
        )?;
        let r = tree.root();
        let digest = compute_common_message_hash(&message.common);
        message
            .dispersal
            .iter()
            .enumerate()
            .map(
                |(
                    i,
                    AuthenticatedShards {
                        root,
                        shards,
                        proof,
                        ..
                    },
                )| {
                    Ok(EchoMessage {
                        party: self.id,
                        r: r.clone(),
                        pi_ij: proof.clone(),
                        pi_i: tree.get_proof(i)?,
                        r_i: root.clone(),
                        s_ij: shards.clone(),
                        hash: digest,
                    })
                },
            )
            .collect::<FastCryptoResult<Vec<_>>>()
    }

    /// 3. When a party has received at EchoMessages from parties with at least weight W - f, it
    /// tries to process them. It first filters out invalid messages and checks if the EchoMessages
    /// have the same digest, r and r_i values. If not, an InvalidMessage error is returned.
    /// If the filtered set of EchoMessages does not have sufficient weight, an NotEnoughWeight error
    /// is returned.
    ///
    /// If these checks succeed, the party reconstructs it's message (ciphertext) from the echoed
    /// shards along with the r and r_i values.
    pub fn process_echo_messages(
        &self,
        echo_messages: &[EchoMessage],
    ) -> FastCryptoResult<ProcessedEchoMessages> {
        // Filter out invalid echo messages
        let echo_messages = echo_messages
            .iter()
            .filter(|echo_message| {
                echo_message
                    .pi_ij
                    .verify_proof_with_unserialized_leaf(
                        &echo_message.r_i,
                        &echo_message.s_ij,
                        echo_message.party as usize,
                    )
                    .is_ok()
                    && echo_message
                        .pi_i
                        .verify_proof_with_unserialized_leaf(
                            &echo_message.r,
                            &echo_message.r_i,
                            self.id as usize,
                        )
                        .is_ok()
            })
            .cloned()
            .collect_vec();

        let (r, r_i, _) = require_uniform_echo_metadata(&echo_messages)?;

        let required_weight = self.nodes.total_weight() - self.f;
        if self
            .nodes
            .total_weight_of(echo_messages.iter().map(|echo_message| &echo_message.party))?
            < required_weight
        {
            return Err(NotEnoughWeight(required_weight as usize));
        }

        let ciphertext = self.reconstruct_ciphertext_from_echoes(&echo_messages)?;
        Ok(ProcessedEchoMessages {
            ciphertext,
            r,
            r_i,
            valid_echoes: echo_messages,
        })
    }

    /// Reed-Solomon decode a ciphertext from a set of authenticated [EchoMessage]s. Each echo
    /// contributes `Some` shards for its sender's leaves; missing senders contribute `None`
    /// erasures. The caller is responsible for having verified the echoes' Merkle proofs and
    /// for ensuring the set has enough weight (≥ `W - 2f`) to decode.
    fn reconstruct_ciphertext_from_echoes(
        &self,
        echoes: &[EchoMessage],
    ) -> FastCryptoResult<Vec<u8>> {
        let shards: Vec<Option<Shard>> = self
            .nodes
            .node_ids_iter()
            .flat_map(|id| match echoes.iter().find(|e| e.party == id) {
                Some(e) => e.s_ij.iter().map(|s| Some(s.clone())).collect_vec(),
                None => repeat_n(None, self.nodes.weight_of(id).unwrap() as usize).collect_vec(),
            })
            .collect();

        self.code.decode(shards)
    }

    /// The check r_i' == r_i from the paper
    fn check_avid_consistency(&self, ciphertext: &[u8], root: &merkle::Node) -> FastCryptoResult<()> {
        let new_shards = self
            .nodes
            .collect_to_nodes(self.code.encode(ciphertext)?.into_iter())?;
        let new_tree = MerkleTree::<Blake2b256>::build_from_unserialized(new_shards.iter())?;

        if new_tree.root() != *root {
            return Err(InvalidMessage);
        }

        Ok(())
    }

    /// 3. If the party also received a valid Message from the dealer, it can now decrypt its shares.
    /// If this succeeds (returns a DecryptionOutcome::Valid), the party should return a signed vote to the dealer.
    ///
    /// When parties with weight at least W -f has submitted a vote, parties who didn't get a valid
    /// Message from the dealer should request the CommonMessage part of that from the parties who voted.
    /// Using this, the party can decrypt the shares and verify that the shares are valid.
    ///
    /// If this function returns a [DecryptionOutcome::Complaint], the party should broadcast it
    /// to the other parties.
    pub fn verify_and_decrypt(
        &self,
        processed_echo_messages: ProcessedEchoMessages,
        message: &CommonMessage,
    ) -> FastCryptoResult<DecryptionOutcome> {
        let CommonMessage {
            full_public_keys,
            blinding_commit,
            response_polynomial,
            shared,
        } = message;

        let ProcessedEchoMessages {
            ciphertext,
            r,
            r_i,
            valid_echoes,
        } = processed_echo_messages;
        if full_public_keys.len() != self.batch_size
            || response_polynomial.degree() != self.t as usize - 1
        {
            return Err(InvalidMessage);
        }

        // TODO: What should happen if these checks fail?
        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        let challenge = compute_challenge_from_message(&self.random_oracle(), &r, message);
        if G::generator() * response_polynomial.c0()
            != blinding_commit
                + G::multi_scalar_mul(&challenge, full_public_keys)
                    .expect("Inputs have constant lengths")
        {
            return Err(InvalidMessage);
        }

        // Check r_i' == r_i from the paper
        let faulty_dealer = self.check_avid_consistency(&ciphertext, &r_i).is_err();

        let random_oracle_encryption = self.random_oracle().extend(&Encryption.to_string());
        let decrypted_shares = shared
            .verify(&random_oracle_encryption)
            .map(|_| {
                // TODO: Handle zero-padding
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
                    message,
                    &challenge,
                    self.batch_size,
                )?;
                Ok(my_shares)
            });

        match (faulty_dealer, decrypted_shares) {
            (false, Ok(my_shares)) => Ok(Valid(ReceiverOutput {
                my_shares,
                public_keys: full_public_keys.clone(),
            })),
            (true, Ok(_)) => {
                // The accuser packages the echoes' shard-level proofs (`pi_ij`, leaf-on-r_i) as
                // ShardContributions, and lifts the `pi_i` (leaf-on-r) once into `pi_i`. This
                // gives the responder enough to replay the AVID inconsistency check.
                let any_echo = valid_echoes.first().ok_or(InvalidMessage)?;
                let pi_i = any_echo.pi_i.clone();
                let hash = any_echo.hash;
                let shards = valid_echoes
                    .into_iter()
                    .map(|e| ShardContribution {
                        party: e.party,
                        shards: e.s_ij,
                        proof: e.pi_ij,
                    })
                    .collect_vec();
                Ok(DecryptionOutcome::Complaint(Complaint::Blame {
                    accuser_id: self.id,
                    r_i,
                    pi_i,
                    shards,
                    hash,
                }))
            }
            (_, Err(_)) => {
                let any_echo = valid_echoes.first().ok_or(InvalidMessage)?;
                Ok(DecryptionOutcome::Complaint(Complaint::Reveal {
                    proof: complaint::Complaint::create(
                        self.id,
                        &shared,
                        &self.enc_secret_key,
                        &self.random_oracle(),
                        &mut rand::thread_rng(),
                    ),
                    ciphertext,
                    r_i,
                    pi_i: any_echo.pi_i.clone(),
                    hash: any_echo.hash,
                }))
            }
        }
    }

    /// 4. Upon receiving a [Complaint] from another party, verify it and, if valid, respond
    /// with this party's own shares so the accuser can recover.
    ///
    /// `root` is the global Merkle root that this party voted for, and `message` is the dealer's
    /// [CommonMessage]. The complaint is bound to both.
    pub fn handle_complaint(
        &self,
        message: &CommonMessage,
        root: &merkle::Node,
        complaint: &Complaint,
        my_output: &ReceiverOutput,
    ) -> FastCryptoResult<ComplaintResponse<SharesForNode>> {
        match complaint {
            Complaint::Reveal {
                proof,
                ciphertext,
                r_i,
                pi_i,
                hash,
            } => {
                self.verify_reveal(message, root, proof, ciphertext, r_i, pi_i, hash)?;
            }
            Complaint::Blame {
                accuser_id,
                r_i,
                pi_i,
                shards,
                hash,
            } => {
                self.verify_blame(message, root, *accuser_id, r_i, pi_i, shards, hash)?;
            }
        }
        Ok(ComplaintResponse::new(self.id, my_output.my_shares.clone()))
    }

    /// Verify a [Complaint::Reveal]: the ciphertext must be authenticated as the dealer's by
    /// re-encoding under `r_i`, and decryption with the recovery package must yield invalid
    /// shares.
    fn verify_reveal(
        &self,
        message: &CommonMessage,
        root: &merkle::Node,
        proof: &complaint::Complaint,
        ciphertext: &[u8],
        r_i: &merkle::Node,
        pi_i: &merkle::MerkleProof,
        hash: &Digest<32>,
    ) -> FastCryptoResult<()> {
        let accuser_id = proof.accuser_id;
        let accuser_pk = &self.nodes.node_id_to_node(accuser_id)?.pk;

        verify_outer_proof(root, r_i, pi_i, accuser_id)?;

        // Authenticate the ciphertext as the dealer's: re-encoding it must yield `r_i`.
        if hash != &compute_common_message_hash(message)
            || self.check_avid_consistency(ciphertext, r_i).is_err()
        {
            return Err(InvalidProof);
        }

        let challenge = compute_challenge_from_message(&self.random_oracle(), root, message);
        proof.check(
            accuser_pk,
            // TODO: Same padding issue as in `verify_and_decrypt` — `ciphertext` is shard-aligned and
            // its trailing zeros decrypt to junk that breaks `bcs::from_bytes`. Truncate to the
            // unpadded length once that's carried on the wire.
            ciphertext,
            &message.shared,
            &self.random_oracle(),
            |shares: &SharesForNode| {
                verify_shares(
                    shares,
                    &self.nodes,
                    accuser_id,
                    message,
                    &challenge,
                    self.batch_size,
                )
            },
        )
    }

    /// Verify a [Complaint::Blame]: the accuser must have collected enough authenticated shards
    /// whose re-encoded ciphertext root differs from the `r_i` the dealer committed to.
    #[allow(clippy::too_many_arguments)]
    fn verify_blame(
        &self,
        message: &CommonMessage,
        root: &merkle::Node,
        accuser_id: PartyId,
        r_i: &merkle::Node,
        pi_i: &merkle::MerkleProof,
        shards: &[ShardContribution],
        hash: &Digest<32>,
    ) -> FastCryptoResult<()> {
        self.nodes.node_id_to_node(accuser_id)?;

        if hash != &compute_common_message_hash(message) {
            return Err(InvalidProof);
        }

        verify_outer_proof(root, r_i, pi_i, accuser_id)?;

        if shards.iter().map(|s| s.party).unique().count() != shards.len() {
            return Err(InvalidProof);
        }

        if shards.iter().any(|s| {
            s.proof
                .verify_proof_with_unserialized_leaf(r_i, &s.shards, s.party as usize)
                .is_err()
        }) {
            return Err(InvalidProof);
        }

        let weight_of_shards = self
            .nodes
            .total_weight_of(shards.iter().map(|s| &s.party))?;
        if weight_of_shards < self.nodes.total_weight() - 2 * self.f {
            return Err(InvalidProof);
        }

        let ciphertext = self
            .reconstruct_ciphertext_from_shard_contributions(shards)
            .map_err(|_| InvalidProof)?;

        // The blame is valid iff re-encoding the recovered ciphertext does not match `r_i`:
        // that mismatch is the proof of dealer misbehavior.
        if self.check_avid_consistency(&ciphertext, r_i).is_ok() {
            return Err(InvalidProof);
        }

        Ok(())
    }

    /// Sibling of [Self::reconstruct_ciphertext_from_echoes] that operates on a slice of
    /// [ShardContribution] (the shape carried by [Complaint::Blame]).
    fn reconstruct_ciphertext_from_shard_contributions(
        &self,
        contributions: &[ShardContribution],
    ) -> FastCryptoResult<Vec<u8>> {
        let shards: Vec<Option<Shard>> = self
            .nodes
            .node_ids_iter()
            .flat_map(
                |id| match contributions.iter().find(|s| s.party == id) {
                    Some(s) => s.shards.iter().map(|s| Some(s.clone())).collect_vec(),
                    None => repeat_n(None, self.nodes.weight_of(id).unwrap() as usize)
                        .collect_vec(),
                },
            )
            .collect();

        self.code.decode(shards)
    }

    /// 5. Upon receiving t valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &CommonMessage,
        root: &merkle::Node,
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

        let challenge = compute_challenge_from_message(&self.random_oracle(), &root, &message);
        let response_shares = responses
            .into_iter()
            .filter_map(|response| {
                response
                    .shares
                    .verify(&message, &challenge)
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
        my_shares.verify(&message, &challenge)?;

        Ok(ReceiverOutput {
            my_shares,
            public_keys: message.full_public_keys.clone(),
        })
    }

    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    fn random_oracle(&self) -> RandomOracle {
        random_oracle_from_sid(&self.sid)
    }
}

/// Verify that `r_i` sits under the global `r` at the leaf indexed by `accuser_id`. Returns
/// `InvalidProof` on mismatch.
fn verify_outer_proof(
    r: &merkle::Node,
    r_i: &merkle::Node,
    pi_i: &merkle::MerkleProof,
    accuser_id: PartyId,
) -> FastCryptoResult<()> {
    pi_i.verify_proof_with_unserialized_leaf(r, r_i, accuser_id as usize)
        .map_err(|_| InvalidProof)
}

/// Pull the per-echo metadata that must agree across the entire echo set: the global Merkle root
/// `r`, the receiver's per-ciphertext root `r_i`, and the dealer's `H(val)`. Returns an error if
/// any field is non-uniform (which would indicate inconsistent echoes / a faulty sender).
fn require_uniform_echo_metadata(
    echoes: &[EchoMessage],
) -> FastCryptoResult<(merkle::Node, merkle::Node, Digest<32>)> {
    get_uniform_value(echoes.iter().map(|e| (e.r.clone(), e.r_i.clone(), e.hash)))
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
        &root,
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
        compute_challenge, Dealer, DecryptionOutcome, Message, ProcessedEchoMessages, Receiver,
        ReceiverOutput, ShareBatch, SharesForNode,
    };
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::bcs::BCSSerialized;
    use crate::threshold_schnorr::reed_solomon::ErasureCoder;
    use crate::threshold_schnorr::Extensions::Encryption;
    use crate::threshold_schnorr::{EG, G};
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::hash::Blake2b256;
    use fastcrypto::merkle;
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;
    use std::iter::repeat_with;

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

        let echo_messages = receivers
            .iter()
            .map(|receiver| receiver.echo_message(&messages[receiver.id as usize]))
            .collect::<FastCryptoResult<Vec<_>>>()
            .unwrap();

        let echo_messages = receivers
            .iter()
            .enumerate()
            .map(|(i, _)| echo_messages.iter().map(|em| em[i].clone()).collect_vec())
            .collect_vec();

        let processed_echo_messages = receivers
            .iter()
            .zip(messages.iter())
            .zip(echo_messages.iter())
            .map(|((receiver, _message), echo_message)| {
                receiver.process_echo_messages(echo_message).unwrap()
            })
            .collect_vec();

        let all_shares = receivers
            .iter()
            .zip(processed_echo_messages)
            .zip(messages)
            .map(
                |((receiver, pem), message)| match receiver.verify_and_decrypt(pem, &message.common) {
                    Ok(DecryptionOutcome::Valid(output)) => (receiver.id, output),
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
    //
    // #[test]
    // #[allow(clippy::single_match)]
    // fn test_happy_path_non_equal_weights() {
    //     // No complaints, all honest
    //     let t = 4;
    //     let f = 3;
    //     let weights: Vec<u16> = vec![1, 2, 3, 4];
    //     let batch_size_per_weight = 3;
    //
    //     let mut rng = rand::thread_rng();
    //     let sks = weights
    //         .iter()
    //         .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
    //         .collect::<Vec<_>>();
    //     let nodes = Nodes::new(
    //         weights
    //             .into_iter()
    //             .enumerate()
    //             .map(|(i, weight)| Node {
    //                 id: i as u16,
    //                 pk: PublicKey::from_private_key(&sks[i]),
    //                 weight,
    //             })
    //             .collect_vec(),
    //     )
    //     .unwrap();
    //
    //     let dealer_id = 2;
    //     let sid = b"tbls test".to_vec();
    //     let dealer: Dealer = Dealer::new(
    //         nodes.clone(),
    //         dealer_id,
    //         f,
    //         t,
    //         sid.clone(),
    //         batch_size_per_weight,
    //     )
    //     .unwrap();
    //
    //     let receivers = sks
    //         .into_iter()
    //         .enumerate()
    //         .map(|(i, secret_key)| {
    //             Receiver::new(
    //                 nodes.clone(),
    //                 i as u16,
    //                 dealer_id,
    //                 t,
    //                 sid.clone(),
    //                 secret_key,
    //                 batch_size_per_weight,
    //             )
    //             .unwrap()
    //         })
    //         .collect_vec();
    //
    //     let message = dealer.create_message(&mut rng).unwrap();
    //
    //     let all_shares = receivers
    //         .iter()
    //         .flat_map(|receiver| {
    //             assert_valid(receiver.process_message(&message).unwrap())
    //                 .my_shares
    //                 .shares
    //         })
    //         .collect::<Vec<_>>();
    //
    //     let secrets = (0..dealer.batch_size)
    //         .map(|l| {
    //             Poly::recover_c0(
    //                 t,
    //                 all_shares.iter().take(t as usize).map(|s| Eval {
    //                     index: s.index,
    //                     value: s.batch[l],
    //                 }),
    //             )
    //             .unwrap()
    //         })
    //         .collect::<Vec<_>>();
    //
    //     assert_eq!(secrets, secrets);
    // }
    //
    // #[test]
    // fn test_share_recovery() {
    //     let t = 3;
    //     let f = 2;
    //     let n = 7;
    //     let batch_size_per_weight: u16 = 3;
    //
    //     let mut rng = rand::thread_rng();
    //     let sks = (0..n)
    //         .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
    //         .collect::<Vec<_>>();
    //     let nodes = Nodes::new(
    //         sks.iter()
    //             .enumerate()
    //             .map(|(id, sk)| Node {
    //                 id: id as u16,
    //                 pk: PublicKey::from_private_key(sk),
    //                 weight: 1,
    //             })
    //             .collect::<Vec<_>>(),
    //     )
    //     .unwrap();
    //
    //     let sid = b"tbls test".to_vec();
    //
    //     let dealer_id = 1;
    //     let dealer: Dealer = Dealer::new(
    //         nodes.clone(),
    //         dealer_id,
    //         f,
    //         t,
    //         sid.clone(),
    //         batch_size_per_weight,
    //     )
    //     .unwrap();
    //
    //     let receivers = sks
    //         .into_iter()
    //         .enumerate()
    //         .map(|(id, secret_key)| {
    //             Receiver::new(
    //                 nodes.clone(),
    //                 id as u16,
    //                 dealer_id,
    //                 t,
    //                 sid.clone(),
    //                 secret_key,
    //                 batch_size_per_weight,
    //             )
    //             .unwrap()
    //         })
    //         .collect::<Vec<_>>();
    //
    //     let message = dealer.create_message_cheating(&mut rng).unwrap();
    //
    //     let mut all_shares = receivers
    //         .iter()
    //         .map(|receiver| (receiver.id, receiver.process_message(&message).unwrap()))
    //         .collect::<HashMap<_, _>>();
    //
    //     let complaint = assert_complaint(all_shares.remove(&receivers[0].id).unwrap());
    //     let mut all_shares = all_shares
    //         .into_iter()
    //         .map(|(id, pm)| (id, assert_valid(pm)))
    //         .collect::<HashMap<_, _>>();
    //
    //     let responses = receivers
    //         .iter()
    //         .skip(1)
    //         .map(|r| {
    //             r.handle_complaint(&message, &complaint, all_shares.get(&r.id).unwrap())
    //                 .unwrap()
    //         })
    //         .collect::<Vec<_>>();
    //     let shares = receivers[0].recover(&message, responses).unwrap();
    //     all_shares.insert(receivers[0].id, shares);
    //
    //     // Recover with the first f+1 shares, including the reconstructed
    //     let secrets = (0..dealer.batch_size)
    //         .map(|l| {
    //             let shares = all_shares
    //                 .iter()
    //                 .map(|(id, s)| (*id, s.my_shares.shares[0].batch[l]))
    //                 .collect::<Vec<_>>();
    //             Poly::recover_c0(
    //                 t,
    //                 shares.iter().take(t as usize).map(|(id, v)| Eval {
    //                     index: ShareIndex::try_from(id + 1).unwrap(),
    //                     value: *v,
    //                 }),
    //             )
    //             .unwrap()
    //         })
    //         .collect::<Vec<_>>();
    //
    //     assert_eq!(secrets, secrets);
    // }
    //
    // impl Dealer {
    //     /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
    //     pub fn create_message_cheating(
    //         &self,
    //         rng: &mut impl AllowedRng,
    //     ) -> FastCryptoResult<Message> {
    //         let polynomials = repeat_with(|| Poly::rand(self.t - 1, rng))
    //             .take(self.batch_size)
    //             .collect_vec();
    //
    //         // Compute the (full) public keys for all secrets
    //         let full_public_keys = polynomials
    //             .iter()
    //             .map(|p| G::generator() * p.c0())
    //             .collect_vec();
    //
    //         // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
    //         let blinding_poly = Poly::rand(self.t - 1, rng);
    //         let blinding_commit = G::generator() * blinding_poly.c0();
    //
    //         // Encrypt all shares to the receivers
    //         let mut pk_and_msgs = self
    //             .nodes
    //             .iter()
    //             .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
    //             .map(|(public_key, share_ids)| {
    //                 (
    //                     public_key,
    //                     SharesForNode {
    //                         shares: share_ids
    //                             .into_iter()
    //                             .map(|index| ShareBatch {
    //                                 index,
    //                                 batch: polynomials
    //                                     .iter()
    //                                     .map(|p_l| p_l.eval(index).value)
    //                                     .collect_vec(),
    //                                 blinding_share: blinding_poly.eval(index).value,
    //                             })
    //                             .collect_vec(),
    //                     },
    //                 )
    //             })
    //             .map(|(pk, shares_for_node)| (pk, shares_for_node.to_bytes()))
    //             .collect_vec();
    //
    //         // Modify the first share of the first receiver to simulate a cheating dealer
    //         pk_and_msgs[0].1[7] ^= 1;
    //
    //         let ciphertext = MultiRecipientEncryption::encrypt(
    //             &pk_and_msgs,
    //             &self.random_oracle().extend(&Encryption.to_string()),
    //             rng,
    //         );
    //
    //         let (shared, ciphertexts) = ciphertext.clone().into_parts();
    //         let code = ErasureCoder::new(
    //             self.nodes.total_weight() as usize,
    //             (self.nodes.total_weight() - 2 * self.f) as usize,
    //         )?;
    //         let roots = ciphertexts
    //             .iter()
    //             .map(|part| {
    //                 let shards = code.encode(part)?;
    //                 let tree =
    //                     fastcrypto::merkle::MerkleTree::<Blake2b256>::build_from_unserialized(
    //                         shards.iter(),
    //                     )?;
    //                 Ok(tree.root())
    //             })
    //             .collect::<FastCryptoResult<Vec<_>>>()?;
    //
    //         // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
    //         let challenge = compute_challenge(
    //             &self.random_oracle(),
    //             &full_public_keys,
    //             &blinding_commit,
    //             &shared,
    //             &roots,
    //         );
    //         let mut response_polynomial = blinding_poly;
    //         for (p_l, gamma_l) in polynomials.into_iter().zip_eq(&challenge) {
    //             response_polynomial += &(p_l * gamma_l);
    //         }
    //
    //         Ok(Message {
    //             full_public_keys,
    //             blinding_commit,
    //             ciphertext,
    //             response_polynomial,
    //             roots,
    //         })
    //     }
    // }
}
