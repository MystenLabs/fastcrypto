// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic Asynchronous Verifiable Information Dispersal (AVID).
//!
//! A dealer disperses one payload per recipient across weighted parties such that any `≥ W-2f`
//! weight of authenticated shards can reconstruct it, while a Merkle commitment binds every shard
//! to the dealer's broadcast. The set of recipients does not have to be all nodes.

use crate::nodes::{Nodes, PartyId};
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::EG;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage, NotEnoughWeight};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::Blake2b256;
use fastcrypto::merkle;
use fastcrypto::merkle::MerkleTree;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tap::TapFallible;
use tracing::warn;

/// AVID over a fixed node set and Byzantine bound `f`.
pub struct Avid {
    nodes: Arc<Nodes<EG>>,
    coder: ErasureCoder,
    f: u16,
}

/// The dealer's per-party dispersal message. One [AuthenticatedShards] per recipient.
pub type Dispersal = BTreeMap<PartyId, AuthenticatedShards>;

/// One disperser's shards for a recipient's payload with a Merkle proof against the corresponding
/// `recipient_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    pub(crate) shards: Vec<Shard>,
    pub(crate) proof: merkle::MerkleProof,
}

/// A precomputed dispersal-side cache produced by [Avid::prepare_echoes] to build [Echo]s.
pub struct EchoBuilder {
    disperser: PartyId,
    dispersal: Dispersal,
    top_tree: MerkleTree<Blake2b256>,
    leaf_index_by_id: BTreeMap<PartyId, usize>,
}

/// One disperser's echo to a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Echo {
    disperser: PartyId,
    authenticated_shards: AuthenticatedShards,
    top_root: merkle::Node,
    recipient_root_proof: merkle::MerkleProof,
}

/// An [Echo] verified by [Avid::verify_echo], paired with the validated `recipient_root` (cached
/// so callers don't recompute it on every accessor call).
#[derive(Clone, Debug)]
pub struct VerifiedEcho(Echo);

/// A complaint that a dispersal is inconsistent, carrying the shards the accuser collected so that
/// others can re-run the check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Complaint {
    pub accuser_id: PartyId,
    pub shards: BTreeMap<PartyId, AuthenticatedShards>,
    pub top_root: merkle::Node,
    pub accuser_recipient_root_proof: merkle::MerkleProof,
}

impl Avid {
    /// Build an AVID instance over `nodes` with Byzantine bound `f`, constructing the `(W, W − 2f)`
    /// Reed-Solomon coder once. Fails if `f == 0`, `W ≤ 2f`, or the RS parameters are otherwise
    /// invalid.
    pub fn new(nodes: Arc<Nodes<EG>>, f: u16) -> FastCryptoResult<Self> {
        let total_weight = nodes.total_weight();
        if f == 0 {
            return Err(InvalidInput);
        }
        let k = total_weight.checked_sub(2 * f).ok_or(InvalidInput)?;
        let coder = ErasureCoder::new(total_weight as usize, k as usize)?;
        Ok(Self { nodes, coder, f })
    }

    /// 1. Disperse one payload per recipient. Returns one per-party [Dispersal].
    ///    Fails if any of the payloads are empty.
    pub fn disperse(
        &self,
        payloads: &BTreeMap<PartyId, Vec<u8>>,
    ) -> FastCryptoResult<BTreeMap<PartyId, Dispersal>> {
        self.disperse_with_mutation(payloads, |_| {})
    }

    /// As [Self::disperse], but runs `mutate` over the per-recipient, per-disperser shards before the
    /// Merkle trees are built. Exposed for tests that corrupt a dispersal.
    /// Fails if any of the payloads are empty.
    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    pub(crate) fn disperse_with_mutation(
        &self,
        payloads_by_recipient: &BTreeMap<PartyId, Vec<u8>>,
        mutate: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<BTreeMap<PartyId, Dispersal>> {
        let code = &self.coder;

        // RS-encode each recipient's payload and bucket the shards by disperser.
        let mut shards_by_recipient: BTreeMap<PartyId, Vec<Vec<Shard>>> = payloads_by_recipient
            .iter()
            .map(|(&i, payload)| {
                let shards = code.encode(payload)?;
                let by_disperser = self.nodes.collect_to_nodes(shards.into_iter())?;
                Ok((i, by_disperser))
            })
            .collect::<FastCryptoResult<_>>()?;

        #[cfg(test)]
        mutate(&mut shards_by_recipient);

        let recipient_trees: BTreeMap<PartyId, MerkleTree<Blake2b256>> = shards_by_recipient
            .iter()
            .map(|(&i, shards)| {
                (
                    i,
                    recipient_tree(shards).expect("Fails only if serialization fails"),
                )
            })
            .collect();

        Ok(self
            .nodes
            .node_ids_iter()
            .map(|j| {
                let dispersal: Dispersal = recipient_trees
                    .iter()
                    .map(|(&i, tree)| {
                        let shards_of_i_via_j =
                            shards_by_recipient.get(&i).expect("populated above")[j as usize]
                                .clone();
                        (
                            i,
                            AuthenticatedShards {
                                shards: shards_of_i_via_j,
                                proof: tree.get_proof(j as usize).expect("valid recipient"),
                            },
                        )
                    })
                    .collect();
                (j, dispersal)
            })
            .collect())
    }

    /// 2. Verify the structural shape of `dispersal` and party `disperser`'s own Merkle proofs:
    ///    * every recipient id is valid,
    ///    * each entry's implied Merkle root is recomputed from its proof at leaf `disperser`,
    ///    * the top tree over those implied roots is built once and cached.
    ///
    /// Returns an [EchoBuilder] that can produce individual [Echo]s on demand via
    /// [EchoBuilder::create_echo].
    pub fn prepare_echoes(
        &self,
        dispersal: Dispersal,
        disperser: PartyId,
    ) -> FastCryptoResult<EchoBuilder> {
        if dispersal.keys().any(|i| !self.nodes.is_valid_id(*i)) {
            warn!("avid echo: dispersal contains an invalid recipient id");
            return Err(InvalidMessage);
        }

        let recipient_roots: BTreeMap<PartyId, merkle::Node> = dispersal
            .iter()
            .map(|(&i, shards)| {
                shards
                    .recipient_root(disperser as usize)
                    .tap_err(|err| {
                        warn!("avid echo: implied root failed at leaf {disperser}: {err:?}")
                    })
                    .map(|root| (i, root))
            })
            .collect::<FastCryptoResult<_>>()?;
        let (top_tree, leaf_index_by_id) = build_top_tree(&recipient_roots);
        Ok(EchoBuilder {
            disperser,
            dispersal,
            top_tree,
            leaf_index_by_id,
        })
    }

    /// 3a. Verify an [Echo] addressed to `receiver`.
    pub fn verify_echo(
        &self,
        echo: Echo,
        certified_top_root: &merkle::Node,
        pending_recipients: &BTreeSet<PartyId>,
        receiver: PartyId,
    ) -> FastCryptoResult<VerifiedEcho> {
        if echo.authenticated_shards.shards.len() != self.nodes.weight_of(echo.disperser)? as usize
            || echo.top_root != *certified_top_root
        {
            return Err(InvalidMessage);
        }
        let receiver_leaf_index = pending_recipients
            .iter()
            .position(|&id| id == receiver)
            .ok_or(InvalidInput)?;
        let recipient_root = echo
            .authenticated_shards
            .recipient_root(echo.disperser as usize)?;
        let leaf_bytes = bcs::to_bytes(&recipient_root).map_err(|_| InvalidInput)?;
        let computed_top_root = echo
            .recipient_root_proof
            .compute_root(&leaf_bytes, receiver_leaf_index)
            .ok_or(InvalidMessage)?;
        if computed_top_root != *certified_top_root {
            return Err(InvalidMessage);
        }
        Ok(VerifiedEcho(echo))
    }

    /// Authenticate `recipient_root` as `recipient`'s leaf in the top tree pinned by
    /// `expected_top_root` (typically from a quorum certificate over a
    /// [super::batch_avss_avid::Vote]).
    pub fn verify_recipient_root(
        &self,
        recipient: PartyId,
        recipient_root: &merkle::Node,
        proof: &merkle::MerkleProof,
        expected_top_root: &merkle::Node,
        pending_recipients: &BTreeSet<PartyId>,
    ) -> FastCryptoResult<()> {
        let leaf_index = pending_recipients
            .iter()
            .position(|&id| id == recipient)
            .ok_or(InvalidInput)?;
        let leaf_bytes = bcs::to_bytes(recipient_root).map_err(|_| InvalidInput)?;
        let top_root = proof
            .compute_root(&leaf_bytes, leaf_index)
            .ok_or(InvalidMessage)?;
        if top_root != *expected_top_root {
            return Err(InvalidMessage);
        }
        Ok(())
    }

    /// 3b. Reconstruct `my_id`'s payload from a quorum of [VerifiedEcho]s, or raise a [Complaint].
    ///     Rejects duplicate dispersers, requires `≥ W − 2f` weight (the RS-decode minimum), and
    ///     requires every echo to carry the same view of `my_id`'s `recipient_root` (outer `Err`).
    ///     With well-formed inputs returns `Ok(Ok(payload))` iff the shards reconstruct to a
    ///     consistent payload that also passes `payload_ok`, otherwise `Ok(Err(Complaint))` over
    ///     the shards.
    pub fn decode_or_complain(
        &self,
        my_id: PartyId,
        echoes: &[VerifiedEcho],
        expected_len: usize,
        top_root: merkle::Node,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<Result<Vec<u8>, Complaint>> {
        if echoes.is_empty() || !echoes.iter().map(|e| e.0.disperser).all_unique() {
            return Err(InvalidInput);
        }
        let required = self.required_weight();
        if self
            .nodes
            .total_weight_of(echoes.iter().map(|e| &e.0.disperser))?
            < required
        {
            return Err(NotEnoughWeight(required as usize));
        }
        // All verified echoes carry the same inclusion proof for `my_id`'s leaf in the top tree
        // (they all bind to the same `top_root`). Take any one to stamp into a Complaint.
        let recipient_root = echoes[0].0.recipient_root()?;
        let accuser_recipient_root_proof = echoes[0].0.recipient_root_proof.clone();
        let shards: BTreeMap<PartyId, AuthenticatedShards> = echoes
            .iter()
            .cloned()
            .map(|e| (e.0.disperser, e.0.authenticated_shards))
            .collect();
        Ok(
            match self.reconstruct(&shards, &recipient_root, expected_len) {
                Some(payload) if payload_ok(&payload) => Ok(payload),
                _ => Err(Complaint {
                    accuser_id: my_id,
                    shards,
                    top_root,
                    accuser_recipient_root_proof,
                }),
            },
        )
    }

    /// Check if `complaint` is a valid blame against the dispersal: its shards carry valid Merkle
    /// proofs, contribute `≥ W − 2f` weight, and do **not** reconstruct to a consistent
    /// payload that passes `payload_ok`. Returns `Ok(false)` for a malformed or unfounded
    /// complaint.
    pub fn complaint_is_valid(
        &self,
        complaint: &Complaint,
        recipient_root: &merkle::Node,
        expected_len: usize,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<bool> {
        if complaint
            .shards
            .iter()
            .any(|(&disperser, shards)| shards.verify(disperser as usize, recipient_root).is_err())
            || self.nodes.total_weight_of(complaint.shards.keys())? < self.required_weight()
        {
            return Ok(false);
        }
        Ok(!self
            .reconstruct(&complaint.shards, recipient_root, expected_len)
            .is_some_and(|payload| payload_ok(&payload)))
    }

    /// Reed-Solomon decode a payload from `shards` and check that it re-encodes to
    /// `recipient_root`. Returns `Some(payload)` iff the dispersal is consistent, `None` otherwise.
    /// `expected_len` is the dispersed payload's expected byte length (used to remove padding).
    fn reconstruct(
        &self,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
        recipient_root: &merkle::Node,
        expected_len: usize,
    ) -> Option<Vec<u8>> {
        let payload = self.decode(shards, expected_len).ok()?;
        if self.recipient_root_for(&payload).ok()? != *recipient_root {
            return None;
        }
        Some(payload)
    }

    /// RS-decode a payload from authenticated shard contributions keyed by disperser. Missing dispersers
    /// and dispersers whose shard count doesn't match their weight are treated as erasures, so
    /// decoding fails if those exceed `2f` weight.
    fn decode(
        &self,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
        expected_len: usize,
    ) -> FastCryptoResult<Vec<u8>> {
        let matrix = self
            .nodes
            .node_ids_iter()
            .flat_map(|id| -> Vec<Option<Shard>> {
                let weight = self.nodes.weight_of(id).expect("valid party id") as usize;
                match shards.get(&id) {
                    Some(auth) if auth.shards.len() == weight => {
                        auth.shards.iter().cloned().map(Some).collect_vec()
                    }
                    _ => vec![None; weight],
                }
            })
            .collect_vec();
        self.coder.decode(matrix, expected_len)
    }

    /// RS-encode `payload` and return the resulting per-recipient Merkle root. For an honest
    /// dealer, this matches the dispersed `recipient_root` for the recipient whose payload is
    /// `payload`.
    fn recipient_root_for(&self, payload: &[u8]) -> FastCryptoResult<merkle::Node> {
        let new_shards = self
            .nodes
            .collect_to_nodes(self.coder.encode(payload)?.into_iter())?;
        Ok(recipient_tree(&new_shards)?.root())
    }

    fn required_weight(&self) -> u16 {
        self.nodes.total_weight() - 2 * self.f
    }
}

impl AuthenticatedShards {
    /// Verify that `shards` are the leaf at `leaf_index` under `recipient_root`.
    fn verify(&self, leaf_index: usize, recipient_root: &merkle::Node) -> FastCryptoResult<()> {
        self.proof
            .verify_proof_with_unserialized_leaf(recipient_root, &self.shards, leaf_index)
    }

    /// Recompute the Merkle root implied by `shards` and the proof at `leaf_index`. Returns
    /// `InvalidInput` if bcs serialization fails or `leaf_index` is out of range.
    pub fn recipient_root(&self, leaf_index: usize) -> FastCryptoResult<merkle::Node> {
        let bytes = bcs::to_bytes(&self.shards).map_err(|_| InvalidInput)?;
        self.proof
            .compute_root(&bytes, leaf_index)
            .ok_or(InvalidInput)
    }
}

impl Echo {
    /// Recover the implied recipient root from this echo's shards and inner Merkle proof at
    /// `disperser`.
    pub fn recipient_root(&self) -> FastCryptoResult<merkle::Node> {
        self.authenticated_shards
            .recipient_root(self.disperser as usize)
    }
}

impl Complaint {
    /// Derive the accuser's `recipient_root` as the implied root of any one of `shards` at the
    /// accuser's leaf. All shards in a valid complaint open to the same root via their Merkle
    /// proofs. Handlers must still authenticate the result against a trusted `top_root` via
    /// `accuser_recipient_root_proof` (e.g. through [Avid::verify_recipient_root]) before using
    /// it.
    pub fn derive_accuser_recipient_root(&self) -> FastCryptoResult<merkle::Node> {
        let (&disperser, auth) = self.shards.iter().next().ok_or(InvalidInput)?;
        auth.recipient_root(disperser as usize)
    }
}

impl EchoBuilder {
    /// The recipients of the dispersal (sorted by [PartyId]).
    pub fn recipients(&self) -> BTreeSet<PartyId> {
        self.dispersal.keys().copied().collect()
    }

    pub fn top_root(&self) -> merkle::Node {
        self.top_tree.root()
    }

    /// Build an [Echo] for `recipient`. Returns [InvalidInput] if `recipient` isn't in the
    /// prepared dispersal. Each call is `O(log W)` work (the inclusion proof) plus cloning the
    /// recipient's shards.
    pub fn create_echo(&self, recipient: PartyId) -> FastCryptoResult<Echo> {
        let authenticated_shards = self.dispersal.get(&recipient).ok_or(InvalidInput)?.clone();
        let recipient_root_proof = self
            .leaf_index_by_id
            .get(&recipient)
            .ok_or(InvalidInput)
            .map(|&i| {
                self.top_tree
                    .get_proof(i)
                    .expect("leaf_index in range by construction")
            })?;
        Ok(Echo {
            disperser: self.disperser,
            authenticated_shards,
            top_root: self.top_tree.root(),
            recipient_root_proof,
        })
    }
}

/// Build the top Merkle tree whose leaves are the per-recipient roots in sorted-by-`PartyId`
/// order. Returns `(top_tree, leaf_index_by_id)` so callers can look up each recipient's leaf
/// position.
pub(super) fn build_top_tree(
    recipient_roots: &BTreeMap<PartyId, merkle::Node>,
) -> (MerkleTree<Blake2b256>, BTreeMap<PartyId, usize>) {
    let leaves: Vec<merkle::Node> = recipient_roots.values().cloned().collect();
    let tree = MerkleTree::<Blake2b256>::build_from_unserialized(leaves.iter())
        .expect("merkle::Node serialization cannot fail for small sets");
    let leaf_index_by_id = recipient_roots
        .keys()
        .enumerate()
        .map(|(idx, &id)| (id, idx))
        .collect();
    (tree, leaf_index_by_id)
}

/// Build the per-recipient Merkle tree over `shards` (per-node grouped shard chunks of one
/// payload). The root of this tree is the per-recipient `recipient_root`.
fn recipient_tree(shards: &[Vec<Shard>]) -> FastCryptoResult<MerkleTree<Blake2b256>> {
    MerkleTree::<Blake2b256>::build_from_unserialized(shards.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecies_v1;
    use crate::nodes::Node;
    use rand::{thread_rng, RngCore};

    fn nodes_with_weights(weights: &[u16]) -> Nodes<EG> {
        let mut rng = thread_rng();
        let nodes = weights
            .iter()
            .enumerate()
            .map(|(id, &weight)| {
                let sk = ecies_v1::PrivateKey::<EG>::new(&mut rng);
                Node::<EG> {
                    id: id as PartyId,
                    pk: ecies_v1::PublicKey::<EG>::from_private_key(&sk),
                    weight,
                }
            })
            .collect();
        Nodes::new(nodes).unwrap()
    }

    /// End-to-end happy path test
    #[test]
    fn disperse_and_reconstruct_random_bytes() {
        let weights = [1u16, 2, 1, 1]; // total weight W = 5
        let f = 1u16; // any W − 2f = 3 weight reconstructs
        let nodes = nodes_with_weights(&weights);
        let nodes = Arc::new(nodes);
        let avid = Avid::new(Arc::clone(&nodes), f).unwrap();

        // Random bytes to disperse to recipient 0.
        let recipient = 0u16;
        let mut payload = vec![0u8; 200];
        thread_rng().fill_bytes(&mut payload);
        let payloads: BTreeMap<PartyId, Vec<u8>> =
            std::iter::once((recipient, payload.clone())).collect();

        // 1. Dealer disperses: one message per party.
        let messages = avid.disperse(&payloads).unwrap();
        assert_eq!(messages.len(), weights.len());

        // 2. Each party verifies its dispersal and emits the echoes it will send to others.
        let party_echoes: Vec<BTreeMap<PartyId, Echo>> = messages
            .into_iter()
            .map(|(j, m)| {
                let builder = avid.prepare_echoes(m, j).unwrap();
                builder
                    .recipients()
                    .iter()
                    .map(|&r| (r, builder.create_echo(r).unwrap()))
                    .collect()
            })
            .collect();

        // The dispersal's recipient set (sorted) and the corresponding `top_root` any honest
        // verifier would derive.
        let recipients: BTreeSet<PartyId> = party_echoes[0].keys().copied().collect();
        let recipient_roots: BTreeMap<PartyId, merkle::Node> = party_echoes[0]
            .iter()
            .map(|(&i, e)| (i, e.recipient_root().unwrap()))
            .collect();
        let (top_tree, _) = super::build_top_tree(&recipient_roots);
        let top_root = top_tree.root();

        // The recipient verifies the echoes addressed to it.
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .map(|mut echoes| {
                let echo = echoes.remove(&recipient).unwrap();
                avid.verify_echo(echo, &top_root, &recipients, recipient)
                    .unwrap()
            })
            .collect();

        // 3. The recipient reconstructs its payload from the quorum of echoes.
        let recovered = avid
            .decode_or_complain(recipient, &echoes, payload.len(), top_root, |_| true)
            .unwrap()
            .unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn cheating_dealer_complaint() {
        let weights = [1u16; 5]; // total weight W = 5
        let f = 1u16; // any W − 2f = 3 weight reconstructs
        let nodes = nodes_with_weights(&weights);
        let nodes = Arc::new(nodes);
        let avid = Avid::new(Arc::clone(&nodes), f).unwrap();

        let recipient = 0u16;
        let cheater = 4u16;
        let mut payload = vec![0u8; 200];
        thread_rng().fill_bytes(&mut payload);
        let payloads: BTreeMap<PartyId, Vec<u8>> =
            std::iter::once((recipient, payload.clone())).collect();

        let messages = avid
            .disperse_with_mutation(&payloads, |shards| {
                shards.get_mut(&recipient).unwrap()[cheater as usize][0].0[0] ^= 1;
            })
            .unwrap();

        let party_echoes: Vec<BTreeMap<PartyId, Echo>> = messages
            .into_iter()
            .map(|(j, m)| {
                let builder = avid.prepare_echoes(m, j).unwrap();
                builder
                    .recipients()
                    .iter()
                    .map(|&r| (r, builder.create_echo(r).unwrap()))
                    .collect()
            })
            .collect();

        // The dispersal's recipient set and corresponding `top_root`.
        let recipients: BTreeSet<PartyId> = party_echoes[0].keys().copied().collect();
        let recipient_roots: BTreeMap<PartyId, merkle::Node> = party_echoes[0]
            .iter()
            .map(|(&i, e)| (i, e.recipient_root().unwrap()))
            .collect();
        let (top_tree, _) = super::build_top_tree(&recipient_roots);
        let top_root = top_tree.root();

        // The recipient gathers a quorum of honest echoes (everyone but the cheater) ...
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .enumerate()
            .filter(|(j, _)| *j as PartyId != cheater)
            .map(|(_, mut echoes)| {
                let echo = echoes.remove(&recipient).unwrap();
                avid.verify_echo(echo, &top_root, &recipients, recipient)
                    .unwrap()
            })
            .collect();

        // ... but they don't reconstruct consistently, so it raises a Complaint.
        let recipient_root = echoes[0].0.recipient_root().unwrap();
        let complaint = avid
            .decode_or_complain(recipient, &echoes, payload.len(), top_root, |_| true)
            .unwrap()
            .unwrap_err();

        // Another party validates the complaint.
        assert!(avid
            .complaint_is_valid(&complaint, &recipient_root, payload.len(), |_| true)
            .unwrap());
    }
}
