// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic Asynchronous Verifiable Information Dispersal (AVID).
//!
//! A dealer disperses one payload per recipient across `n` weighted parties so that
//! any `≥ W − 2f` weight of authenticated shards can reconstruct it, while a Merkle commitment binds
//! every shard to the dealer's broadcast. The set of recipients does not have to be all nodes.
//!
//! Flow:
//!   1. The dealer calls [Avid::disperse] to produce one [Dispersal] per party.
//!   2. A party verifies its [Dispersal] ([Avid::verify_dispersal]) and emits one [Echo] per
//!      recipient ([VerifiedDispersal::echoes]).
//!   3. A recipient verifies the echoes addressed to it ([Avid::verify_echo]), gathers a quorum
//!      ([Avid::collect_shards]) and reconstructs its payload — or raises a [Complaint] over the
//!      shards ([Avid::decode_or_complain]). Other parties validate a [Complaint] with
//!      [Avid::complaint_is_valid].

use crate::nodes::{Nodes, PartyId};
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::EG;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage, NotEnoughWeight};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::merkle;
use fastcrypto::merkle::MerkleTree;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tap::TapFallible;
use tracing::warn;

/// A Blake2b-256 digest. Used for the resulting `dispersal_hash`; the caller's binding context is
/// passed separately as a `dst: &[u8]`.
pub type Digest = fastcrypto::hash::Digest<{ Blake2b256::OUTPUT_SIZE }>;

/// One sender's shards for one recipient's payload, with a Merkle proof against the corresponding
/// `recipient_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    pub(crate) shards: Vec<Shard>,
    pub(crate) proof: merkle::MerkleProof,
}

impl AuthenticatedShards {
    /// Verify that `shards` are the leaf at `leaf_index` under `recipient_root`.
    fn verify(&self, leaf_index: usize, recipient_root: &merkle::Node) -> FastCryptoResult<()> {
        self.proof
            .verify_proof_with_unserialized_leaf(recipient_root, &self.shards, leaf_index)
    }
}

/// One recipient's slice of a dispersal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispersalEntry {
    pub recipient_root: merkle::Node,
    pub authenticated_shards: AuthenticatedShards,
}

/// The dealer's per-party dispersal message. One [DispersalEntry] per recipient, all bound to the
/// same `dispersal_hash`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dispersal {
    pub entries: BTreeMap<PartyId, DispersalEntry>,
    pub dispersal_hash: Digest,
}

impl Dispersal {
    /// The recipients this dispersal carries payload shards for.
    pub fn recipients(&self) -> impl ExactSizeIterator<Item = PartyId> + '_ {
        self.entries.keys().copied()
    }
}

/// A [Dispersal] whose structure and the holding party's Merkle proofs have been verified by
/// [Avid::verify_dispersal].
#[derive(Clone, Debug)]
pub struct VerifiedDispersal(Dispersal);

impl VerifiedDispersal {
    /// The combined `dispersal_hash = H(dst, roots)`.
    pub fn dispersal_hash(&self) -> &Digest {
        &self.0.dispersal_hash
    }

    /// The Merkle root committing `recipient`'s payload shards.
    pub fn recipient_root(&self, recipient: PartyId) -> FastCryptoResult<&merkle::Node> {
        self.0
            .entries
            .get(&recipient)
            .map(|e| &e.recipient_root)
            .ok_or(InvalidInput)
    }

    /// Emit one [Echo] per recipient, forwarding `sender_id`'s authenticated shards.
    pub fn echoes(&self, sender_id: PartyId) -> BTreeMap<PartyId, Echo> {
        self.0
            .entries
            .iter()
            .map(|(&recipient, entry)| {
                (
                    recipient,
                    Echo {
                        sender: sender_id,
                        authenticated_shards: entry.authenticated_shards.clone(),
                        dispersal_hash: self.0.dispersal_hash,
                    },
                )
            })
            .collect()
    }
}

/// One sender's echo to a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Echo {
    sender: PartyId,
    authenticated_shards: AuthenticatedShards,
    pub dispersal_hash: Digest,
}

/// An [Echo] verified against a [VerifiedDispersal] by [Avid::verify_echo].
#[derive(Clone, Debug)]
pub struct VerifiedEcho(Echo);

/// A complaint that a dispersal is inconsistent, carrying the shards the accuser collected so that
/// others can re-run the check. `accuser_id` is unauthenticated at this layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Complaint {
    pub accuser_id: PartyId,
    pub shards: BTreeMap<PartyId, AuthenticatedShards>,
    pub dispersal_hash: Digest,
}

/// AVID over a fixed node set and Byzantine bound `f`. Shares its node set (via [Arc]) with the
/// caller and owns a Reed-Solomon coder. Building the coder is O(k³) (it inverts a `k×k` matrix),
/// so construct one `Avid` per session and reuse it for every dispersal/reconstruction rather than
/// rebuilding it per call.
pub struct Avid {
    nodes: Arc<Nodes<EG>>,
    coder: ErasureCoder,
    f: u16,
}

impl Avid {
    /// Build an AVID instance over `nodes` with Byzantine bound `f`, constructing the
    /// `(W, W − 2f)` Reed-Solomon coder once. Fails if those parameters are invalid.
    pub fn new(nodes: Arc<Nodes<EG>>, f: u16) -> FastCryptoResult<Self> {
        let w = nodes.total_weight() as usize;
        let coder = ErasureCoder::new(w, w - 2 * f as usize)?;
        Ok(Self { nodes, coder, f })
    }

    /// The node set this AVID instance operates over.
    pub fn nodes(&self) -> &Nodes<EG> {
        &self.nodes
    }

    /// 1. Disperse one payload per recipient. Returns the `dispersal_hash` (the signing target
    ///    for the dispersal layer) and one [Dispersal] per party in `nodes`. The `dst`
    ///    is hashed into the `dispersal_hash` so the caller can bind the dispersal to a context.
    pub fn disperse(
        &self,
        dst: &[u8],
        payloads: &BTreeMap<PartyId, Vec<u8>>,
    ) -> FastCryptoResult<(Digest, BTreeMap<PartyId, Dispersal>)> {
        self.disperse_with_mutation(dst, payloads, |_| {})
    }

    /// As [Self::disperse], but runs `mutate` over the per-recipient, per-sender shards before the
    /// Merkle trees are built. Exposed for tests that corrupt a dispersal.
    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    pub(crate) fn disperse_with_mutation(
        &self,
        dst: &[u8],
        payloads: &BTreeMap<PartyId, Vec<u8>>,
        mutate: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<(Digest, BTreeMap<PartyId, Dispersal>)> {
        let code = &self.coder;

        // RS-encode each recipient's payload and bucket the shards by sender.
        let mut shards_by_recipient: BTreeMap<PartyId, Vec<Vec<Shard>>> = payloads
            .iter()
            .map(|(&i, payload)| {
                let shards = code.encode(payload)?;
                let by_sender = self.nodes.collect_to_nodes(shards.into_iter())?;
                Ok((i, by_sender))
            })
            .collect::<FastCryptoResult<_>>()?;

        #[cfg(test)]
        mutate(&mut shards_by_recipient);

        let recipient_trees: BTreeMap<PartyId, MerkleTree<Blake2b256>> = shards_by_recipient
            .iter()
            .map(|(&i, shards)| Ok((i, recipient_tree(shards)?)))
            .collect::<FastCryptoResult<_>>()?;

        let dispersal_hash = dispersal_hash(
            dst,
            recipient_trees.iter().map(|(&i, tree)| (i, tree.root())),
        );

        let messages = self
            .nodes
            .node_ids_iter()
            .map(|j| {
                let entries: BTreeMap<PartyId, DispersalEntry> = recipient_trees
                    .iter()
                    .map(|(&i, tree)| {
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
                Ok((
                    j,
                    Dispersal {
                        entries,
                        dispersal_hash,
                    },
                ))
            })
            .collect::<FastCryptoResult<BTreeMap<PartyId, Dispersal>>>()?;

        Ok((dispersal_hash, messages))
    }

    /// 2. Verify the structural shape of `dispersal` and party `my_id`'s own Merkle proofs:
    ///   * every recipient id is valid,
    ///   * `dispersal_hash == H(dst, roots)`,
    ///   * each entry's authenticated shards verify against its root at leaf `my_id`.
    pub fn verify_dispersal(
        &self,
        dispersal: Dispersal,
        dst: &[u8],
        my_id: PartyId,
    ) -> FastCryptoResult<VerifiedDispersal> {
        if dispersal
            .entries
            .keys()
            .any(|i| !self.nodes.is_valid_id(*i))
        {
            warn!("avid verify_dispersal: dispersal contains an invalid recipient id");
            return Err(InvalidMessage);
        }

        if dispersal.dispersal_hash
            != dispersal_hash(
                dst,
                dispersal
                    .entries
                    .iter()
                    .map(|(&i, e)| (i, e.recipient_root.clone())),
            )
        {
            warn!("avid verify_dispersal: dispersal_hash does not match H(dst, roots)");
            return Err(InvalidMessage);
        }

        for entry in dispersal.entries.values() {
            entry
                .authenticated_shards
                .verify(my_id as usize, &entry.recipient_root)
                .tap_err(|e| {
                    warn!("avid verify_dispersal: Merkle proof failed at leaf {my_id}: {e:?}")
                })?
        }

        Ok(VerifiedDispersal(dispersal))
    }

    /// 3a. Verify an [Echo] addressed to `recipient_id` against `dispersal`: the sender's shard count
    ///    matches its weight, the `dispersal_hash` matches, and the Merkle proof checks against
    ///    `recipient_id`'s root.
    pub fn verify_echo(
        &self,
        echo: Echo,
        dispersal: &VerifiedDispersal,
        recipient_id: PartyId,
    ) -> FastCryptoResult<VerifiedEcho> {
        let recipient_root = dispersal.recipient_root(recipient_id)?;
        if echo.authenticated_shards.shards.len() != self.nodes.weight_of(echo.sender)? as usize {
            return Err(InvalidMessage);
        }
        if echo.dispersal_hash != *dispersal.dispersal_hash() {
            return Err(InvalidMessage);
        }
        echo.authenticated_shards
            .verify(echo.sender as usize, recipient_root)?;
        Ok(VerifiedEcho(echo))
    }

    /// 3b. Collect the shards from a quorum of [VerifiedEcho]s, keyed by sender. Rejects duplicate
    ///     senders and requires `≥ W − 2f` weight.
    pub fn collect_shards(
        &self,
        echos: &[VerifiedEcho],
    ) -> FastCryptoResult<BTreeMap<PartyId, AuthenticatedShards>> {
        if !echos.iter().map(|e| e.0.sender).all_unique() {
            return Err(InvalidInput);
        }
        let required = self.required_weight();
        if self
            .nodes
            .total_weight_of(echos.iter().map(|e| &e.0.sender))?
            < required
        {
            return Err(NotEnoughWeight(required as usize));
        }
        Ok(echos
            .iter()
            .cloned()
            .map(|e| (e.0.sender, e.0.authenticated_shards))
            .collect())
    }

    /// 3c. Reconstruct `id`'s payload from collected `shards` (see [Self::collect_shards]),
    ///     or raise a [Complaint]. Returns `Ok(payload)` iff the shards reconstruct to a
    ///     root-consistent payload that also passes `payload_ok` — the caller's semantic check,
    ///     since AVID is payload-agnostic. Otherwise returns `Err(Complaint)` over the shards.
    pub fn decode_or_complain(
        &self,
        id: PartyId,
        shards: BTreeMap<PartyId, AuthenticatedShards>,
        recipient_root: &merkle::Node,
        expected_len: usize,
        dispersal_hash: Digest,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> Result<Vec<u8>, Complaint> {
        match self.reconstruct(&shards, recipient_root, expected_len) {
            Some(payload) if payload_ok(&payload) => Ok(payload),
            _ => Err(Complaint {
                accuser_id: id,
                shards,
                dispersal_hash,
            }),
        }
    }

    /// Whether `complaint` is a valid blame against the dispersal: its shards carry valid Merkle
    /// proofs, contribute `≥ W − 2f` weight, and do **not** reconstruct to a root-consistent
    /// payload that passes `payload_ok`. Returns `Ok(false)` for a malformed or unfounded
    /// complaint; the caller turns that into its own rejection error.
    pub fn complaint_is_valid(
        &self,
        complaint: &Complaint,
        recipient_root: &merkle::Node,
        expected_len: usize,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<bool> {
        if self
            .verify_shard_proofs(&complaint.shards, recipient_root)
            .is_err()
            || !self.sufficient_weight(&complaint.shards)?
        {
            return Ok(false);
        }
        Ok(!self
            .reconstruct(&complaint.shards, recipient_root, expected_len)
            .is_some_and(|payload| payload_ok(&payload)))
    }

    /// Verify the Merkle proof of every shard contribution in `shards` against `recipient_root`.
    /// Used to validate the shards carried by an untrusted [Complaint].
    fn verify_shard_proofs(
        &self,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
        recipient_root: &merkle::Node,
    ) -> FastCryptoResult<()> {
        for (&sender, auth) in shards {
            auth.verify(sender as usize, recipient_root)?;
        }
        Ok(())
    }

    /// Whether `shards` contribute the `≥ W − 2f` weight needed to reconstruct.
    fn sufficient_weight(
        &self,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
    ) -> FastCryptoResult<bool> {
        Ok(self.nodes.total_weight_of(shards.keys())? >= self.required_weight())
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
        let payload = self.rs_decode(shards, expected_len).ok()?;
        self.check_consistency(&payload, recipient_root)
            .ok()
            .map(|()| payload)
    }

    /// RS-decode a payload from authenticated shard contributions keyed by sender. Missing senders
    /// and senders whose shard count doesn't match their weight are treated as erasures, so
    /// decoding fails if those exceed `2f` weight.
    fn rs_decode(
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

    /// RS-encode `payload`, rebuild the per-recipient Merkle tree, and check its root matches
    /// `expected_root`. This is what binds a reconstructed payload to the dispersed `recipient_root`.
    pub fn check_consistency(
        &self,
        payload: &[u8],
        expected_root: &merkle::Node,
    ) -> FastCryptoResult<()> {
        let new_shards = self
            .nodes
            .collect_to_nodes(self.coder.encode(payload)?.into_iter())?;
        if recipient_tree(&new_shards)?.root() != *expected_root {
            return Err(InvalidMessage);
        }
        Ok(())
    }

    fn required_weight(&self) -> u16 {
        self.nodes.total_weight() - 2 * self.f
    }
}

/// Combined binding for a dispersal: `H(dst, roots)`, where `dst` is the caller's context.
fn dispersal_hash(
    dst: &[u8],
    recipient_roots: impl Iterator<Item = (PartyId, merkle::Node)>,
) -> Digest {
    let mut hasher = Blake2b256::new();
    hasher.update(dst);
    for (id, root) in recipient_roots {
        hasher.update(id.to_le_bytes());
        hasher.update(root.bytes());
    }
    hasher.finalize()
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
        let avid = Avid::new(Arc::new(nodes), f).unwrap();
        let dst = b"avid-e2e-test";

        // Random bytes to disperse to recipient 0.
        let recipient = 0u16;
        let mut payload = vec![0u8; 200];
        thread_rng().fill_bytes(&mut payload);
        let payloads: BTreeMap<PartyId, Vec<u8>> =
            std::iter::once((recipient, payload.clone())).collect();

        // 1. Dealer disperses: one message per party.
        let (_dispersal_hash, messages) = avid.disperse(dst, &payloads).unwrap();
        assert_eq!(messages.len(), weights.len());

        // 2. Each party verifies its own dispersal.
        let verified: Vec<VerifiedDispersal> = messages
            .into_iter()
            .map(|(j, m)| avid.verify_dispersal(m, dst, j).unwrap())
            .collect();

        // Every party echoes to the recipient; the recipient verifies those echoes.
        let echoes: Vec<VerifiedEcho> = verified
            .iter()
            .enumerate()
            .map(|(j, vd)| {
                let echo = vd.echoes(j as PartyId).remove(&recipient).unwrap();
                avid.verify_echo(echo, &verified[recipient as usize], recipient)
                    .unwrap()
            })
            .collect();

        // 3. The recipient reconstructs its payload from the quorum of echoes.
        let shards = avid.collect_shards(&echoes).unwrap();
        let recipient_root = verified[recipient as usize]
            .recipient_root(recipient)
            .unwrap();
        let recovered = avid
            .reconstruct(&shards, recipient_root, payload.len())
            .unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn cheating_dealer_complaint() {
        let weights = [1u16; 5]; // total weight W = 5
        let f = 1u16; // W − 2f = 3
        let nodes = nodes_with_weights(&weights);
        let avid = Avid::new(Arc::new(nodes), f).unwrap();
        let dst = b"avid-e2e-test";

        let recipient = 0u16;
        let cheater = 4u16;
        let mut payload = vec![0u8; 200];
        thread_rng().fill_bytes(&mut payload);
        let payloads: BTreeMap<PartyId, Vec<u8>> =
            std::iter::once((recipient, payload.clone())).collect();

        let (dispersal_hash, messages) = avid
            .disperse_with_mutation(dst, &payloads, |shards| {
                shards.get_mut(&recipient).unwrap()[cheater as usize][0].0[0] ^= 1;
            })
            .unwrap();

        let verified: Vec<VerifiedDispersal> = messages
            .into_iter()
            .map(|(j, m)| avid.verify_dispersal(m, dst, j).unwrap())
            .collect();

        // The recipient gathers a quorum of honest echoes (everyone but the cheater) ...
        let echoes: Vec<VerifiedEcho> = verified
            .iter()
            .enumerate()
            .filter(|(j, _)| *j as PartyId != cheater)
            .map(|(j, vd)| {
                let echo = vd.echoes(j as PartyId).remove(&recipient).unwrap();
                avid.verify_echo(echo, &verified[recipient as usize], recipient)
                    .unwrap()
            })
            .collect();

        // ... but they don't reconstruct consistently, so it raises a Complaint.
        let shards = avid.collect_shards(&echoes).unwrap();
        let recipient_root = verified[recipient as usize]
            .recipient_root(recipient)
            .unwrap();
        let complaint = avid
            .decode_or_complain(
                recipient,
                shards,
                recipient_root,
                payload.len(),
                dispersal_hash,
                |_| true,
            )
            .unwrap_err();

        // Another party validates the complaint.
        assert!(avid
            .complaint_is_valid(&complaint, recipient_root, payload.len(), |_| true)
            .unwrap());
    }
}
