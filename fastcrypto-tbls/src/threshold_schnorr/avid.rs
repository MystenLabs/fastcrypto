// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic Asynchronous Verifiable Information Dispersal (AVID).
//!
//! A dealer disperses one payload per recipient across weighted parties such that any `≥ W-2f`
//! weight of authenticated shards can reconstruct it, while a Merkle commitment binds every shard
//! to the dealer's broadcast. The set of recipients does not have to be all nodes.

use crate::nodes::{Nodes, PartyId};
use crate::threshold_schnorr::merkle::{NestedMerkleProof, NestedMerkleTree};
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard};
use crate::threshold_schnorr::EG;
use crate::types::get_uniform_value;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage, NotEnoughWeight};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::merkle;
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

/// Dealer-side cache that can create individual [Dispersal] messages on demand.
pub struct DispersalBuilder {
    nodes: Arc<Nodes<EG>>,
    tree: NestedMerkleTree,
    shards_by_recipient: BTreeMap<PartyId, Vec<Vec<Shard>>>,
}

/// The dealer's per-party dispersal message. One [AuthenticatedShards] per recipient.
pub type Dispersal = BTreeMap<PartyId, AuthenticatedShards>;

/// One disperser's shards for a recipient's payload with a two-level Merkle proof against the
/// dispersal's `top_root` (row proof to the recipient's row root, top proof binding that row root
/// to `top_root`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    pub(crate) shards: Vec<Shard>,
    pub(crate) proof: NestedMerkleProof,
}

/// An endorsement of a dispersal's `top_root` and the set of recipients it covers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub top_root: merkle::Node,
    pub recipients: BTreeSet<PartyId>,
}

/// A precomputed dispersal-side cache produced by [Avid::process_dispersal] to build [Echo]s.
pub struct EchoBuilder {
    dispersal: Dispersal,
    pub top_root: merkle::Node,
}

/// One disperser's echo to a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Echo {
    authenticated_shards: AuthenticatedShards,
}

/// An [Echo] verified by [Avid::verify_echo].
#[derive(Clone, Debug)]
pub struct VerifiedEcho {
    sender: PartyId,
    echo: Echo,
}

/// A complaint that a dispersal is inconsistent, carrying the shards the accuser collected so that
/// others can re-run the check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Complaint {
    pub shards: BTreeMap<PartyId, AuthenticatedShards>,
}

impl Avid {
    /// Build an AVID instance over `nodes` with Byzantine bound `f`, constructing the
    /// `(W, W − 2f)` Reed-Solomon coder once. Fails if `f == 0`, `W ≤ 2f`, or the RS parameters
    /// are otherwise invalid.
    pub fn new(nodes: Arc<Nodes<EG>>, f: u16) -> FastCryptoResult<Self> {
        let total_weight = nodes.total_weight();
        if f == 0 {
            return Err(InvalidInput);
        }
        let k = total_weight.checked_sub(2 * f).ok_or(InvalidInput)?;
        let coder = ErasureCoder::new(total_weight as usize, k as usize)?;
        Ok(Self { nodes, coder, f })
    }

    /// 1. RS-encode every payload and return a [DispersalBuilder] that can mint per-disperser
    ///    [Dispersal]s on demand via [DispersalBuilder::dispersal_for].
    ///
    ///    Runs `mutate` over the per-recipient, per-disperser shards before the Merkle tree is
    ///    built — production callers pass `|_| {}`. Fails if any of the payloads are empty.
    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    pub fn disperse_with_mutation(
        &self,
        payloads_by_recipient: &BTreeMap<PartyId, Vec<u8>>,
        mutate: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<DispersalBuilder> {
        // RS-encode each recipient's payload and bucket the shards by disperser.
        let mut shards_by_recipient: BTreeMap<PartyId, Vec<Vec<Shard>>> = payloads_by_recipient
            .iter()
            .map(|(&i, payload)| {
                let shards = self.coder.encode(payload)?;
                let by_disperser = self.nodes.collect_to_nodes(shards.into_iter())?;
                Ok((i, by_disperser))
            })
            .collect::<FastCryptoResult<_>>()?;

        #[cfg(test)]
        mutate(&mut shards_by_recipient);

        // Two-level Merkle commitment: per-recipient row trees + a top tree over the row roots.
        let tree = NestedMerkleTree::new(shards_by_recipient.values().cloned())?;

        Ok(DispersalBuilder {
            nodes: Arc::clone(&self.nodes),
            tree,
            shards_by_recipient,
        })
    }

    /// 2. Verify a [Dispersal] and return an [EchoBuilder] that can produce individual [Echo]s on demand via
    ///    [EchoBuilder::create_echo] and a [Vote] to return to the disperser.
    pub fn process_dispersal(
        &self,
        my_id: PartyId,
        dispersal: Dispersal,
    ) -> FastCryptoResult<(EchoBuilder, Vote)> {
        if dispersal.keys().any(|i| !self.nodes.is_valid_id(*i)) {
            warn!("avid echo: dispersal contains an invalid recipient id");
            return Err(InvalidMessage);
        }

        let implied_roots = dispersal
            .iter()
            .enumerate()
            .map(|(recipient_idx, (_, shards))| {
                shards
                    .proof
                    .derive_top_root(&shards.shards, recipient_idx, my_id as usize)
                    .tap_err(|err| warn!("avid echo: implied root failed at leaf {my_id}: {err:?}"))
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let top_root = get_uniform_value(implied_roots).ok_or(InvalidMessage)?;
        let recipients: BTreeSet<PartyId> = dispersal.keys().copied().collect();
        Ok((
            EchoBuilder {
                dispersal,
                top_root: top_root.clone(),
            },
            Vote {
                top_root,
                recipients,
            },
        ))
    }

    /// 3a. Verify an [Echo] addressed to `receiver`, against the certified [Vote] published
    ///     by the dealer.
    pub fn verify_echo(
        &self,
        echo: Echo,
        sender: PartyId,
        vote: &Vote,
        receiver: PartyId,
    ) -> FastCryptoResult<VerifiedEcho> {
        let auth = &echo.authenticated_shards;
        if auth.shards.len() != self.nodes.weight_of(sender)? as usize {
            return Err(InvalidMessage);
        }
        let receiver_idx = vote
            .recipients
            .iter()
            .position(|&id| id == receiver)
            .ok_or(InvalidInput)?;
        auth.proof
            .verify(&vote.top_root, &auth.shards, receiver_idx, sender as usize)?;
        Ok(VerifiedEcho { echo, sender })
    }

    /// 3b. Reconstruct the caller's payload from a quorum of [VerifiedEcho]s, or raise a
    ///     [Complaint]. Rejects duplicate dispersers, requires `≥ W − 2f` weight (the RS-decode
    ///     minimum). With well-formed inputs returns `Ok(Ok(payload))` iff the shards decode to a
    ///     payload that passes `payload_ok` and re-encoding it rebuilds a row tree whose root
    ///     matches the dispersal's `recipient_root` (so the dealer's cells form a valid
    ///     codeword). Otherwise `Ok(Err(Complaint))` over the shards.
    pub fn decode_or_complain(
        &self,
        echoes: &[VerifiedEcho],
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<Result<Vec<u8>, Complaint>> {
        if echoes.is_empty() || !echoes.iter().map(|e| e.sender).all_unique() {
            return Err(InvalidInput);
        }
        let required = self.required_weight();
        if self
            .nodes
            .total_weight_of(echoes.iter().map(|e| &e.sender))?
            < required
        {
            return Err(NotEnoughWeight(required as usize));
        }
        let shards: BTreeMap<PartyId, AuthenticatedShards> = echoes
            .iter()
            .cloned()
            .map(|e| (e.sender, e.echo.authenticated_shards))
            .collect();
        match self.decode_consistent(&shards, payload_ok)? {
            Some(payload) => Ok(Ok(payload)),
            None => Ok(Err(Complaint { shards })),
        }
    }

    /// RS-decode the payload from authenticated `shards` and confirm it is a consistent codeword.
    /// If this is the case, return `Some(payload)`.
    ///
    /// Returns `Err` only for malformed input or verification/re-encoding failures
    /// (for example, empty `shards`, row-root derivation failure, or row-root recomputation
    /// failure). Decode failure, payload rejection, or row-root mismatch return `Ok(None)`.
    fn decode_consistent(
        &self,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<Option<Vec<u8>>> {
        let payload = match self.decode(shards) {
            Ok(p) if payload_ok(&p) => p,
            _ => return Ok(None),
        };

        // Re-encode the payload and rebuild the row's Merkle tree.
        let re_encoded: Vec<Vec<Shard>> = self
            .nodes
            .collect_to_nodes(self.coder.encode(&payload)?.into_iter())?;

        // Take the expected recipient root from any shard's proof, since they all share the same top root and row index.
        let (sender, authenticated_shards) = shards.iter().next().ok_or(InvalidInput)?;
        let expected_recipient_root = authenticated_shards
            .proof
            .derive_row_root(&authenticated_shards.shards, *sender as usize)?;
        if NestedMerkleTree::compute_row_root(&re_encoded)? != expected_recipient_root {
            return Ok(None);
        }

        Ok(Some(payload))
    }

    /// Check if `complaint` is a valid complaint against the dispersal certified by `vote`.
    pub fn complaint_is_valid(
        &self,
        complaint: &Complaint,
        accuser_id: PartyId,
        vote: &Vote,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<bool> {
        // An accuser that is not a pending recipient cannot have a dispersal complaint at all, so
        // this is malformed input rather than an unsubstantiated (but well-formed) complaint.
        let accuser_idx = vote
            .recipients
            .iter()
            .position(|&id| id == accuser_id)
            .ok_or(InvalidInput)?;
        let shards_verify = complaint.shards.iter().all(|(&disperser, auth)| {
            auth.proof
                .verify(
                    &vote.top_root,
                    &auth.shards,
                    accuser_idx,
                    disperser as usize,
                )
                .is_ok()
        });
        if !shards_verify
            || self.nodes.total_weight_of(complaint.shards.keys())? < self.required_weight()
        {
            return Ok(false);
        }
        Ok(self
            .decode_consistent(&complaint.shards, payload_ok)?
            .is_none())
    }

    /// RS-decode a payload from authenticated shard contributions keyed by disperser. Missing dispersers
    /// and dispersers whose shard count doesn't match their weight are treated as erasures, so
    /// decoding fails if those exceed `2f` weight.
    fn decode(&self, shards: &BTreeMap<PartyId, AuthenticatedShards>) -> FastCryptoResult<Vec<u8>> {
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
        self.coder.decode(matrix)
    }

    fn required_weight(&self) -> u16 {
        self.nodes.total_weight() - 2 * self.f
    }
}

impl EchoBuilder {
    /// The recipients of the dispersal (sorted by [PartyId]).
    pub fn recipients(&self) -> BTreeSet<PartyId> {
        self.dispersal.keys().copied().collect()
    }

    /// Build an [Echo] for `recipient`. Returns [InvalidInput] if `recipient` isn't in the
    /// prepared dispersal.
    pub fn create_echo(&self, recipient: PartyId) -> FastCryptoResult<Echo> {
        let authenticated_shards = self.dispersal.get(&recipient).ok_or(InvalidInput)?.clone();
        Ok(Echo {
            authenticated_shards,
        })
    }
}

impl DispersalBuilder {
    /// The dispersal's `top_root`.
    #[allow(dead_code)]
    pub fn top_root(&self) -> merkle::Node {
        self.tree.top_root()
    }

    /// Build the [Dispersal] addressed to `recipient`. Returns [InvalidInput] if `recipient` is
    /// not a valid party id.
    pub fn dispersal_for(&self, recipient: PartyId) -> FastCryptoResult<Dispersal> {
        if !self.nodes.is_valid_id(recipient) {
            return Err(InvalidInput);
        }
        self.shards_by_recipient
            .iter()
            .enumerate()
            .map(|(recipient_idx, (&i, by_disperser))| {
                Ok((
                    i,
                    AuthenticatedShards {
                        shards: by_disperser[recipient as usize].clone(),
                        proof: self.tree.get_proof(recipient_idx, recipient as usize)?,
                    },
                ))
            })
            .collect()
    }
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

        // 1. Dealer disperses: builder mints messages on demand.
        let dispersal_builder = avid.disperse_with_mutation(&payloads, |_| {}).unwrap();

        // 2. Each party verifies its dispersal and emits the echoes it will send to others.
        let mut certified_vote = None;
        let party_echoes: Vec<(PartyId, BTreeMap<PartyId, Echo>)> = avid
            .nodes
            .node_ids_iter()
            .map(|j| {
                let m = dispersal_builder.dispersal_for(j).unwrap();
                let (builder, vote) = avid.process_dispersal(j, m).unwrap();
                if certified_vote.is_none() {
                    certified_vote = Some(vote);
                }
                let echoes = builder
                    .recipients()
                    .iter()
                    .map(|&r| (r, builder.create_echo(r).unwrap()))
                    .collect();
                (j, echoes)
            })
            .collect();
        let certified_vote = certified_vote.unwrap();

        // The recipient verifies the echoes addressed to it.
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .map(|(sender, mut echoes)| {
                let echo = echoes.remove(&recipient).unwrap();
                avid.verify_echo(echo, sender, &certified_vote, recipient)
                    .unwrap()
            })
            .collect();

        // 3. The recipient reconstructs its payload from the quorum of echoes.
        let recovered = avid.decode_or_complain(&echoes, |_| true).unwrap().unwrap();
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

        let dispersal_builder = avid
            .disperse_with_mutation(&payloads, |shards| {
                shards.get_mut(&recipient).unwrap()[cheater as usize][0].0[0] ^= 1;
            })
            .unwrap();

        let mut certified_vote = None;
        let party_echoes: Vec<(PartyId, BTreeMap<PartyId, Echo>)> = avid
            .nodes
            .node_ids_iter()
            .map(|j| {
                let m = dispersal_builder.dispersal_for(j).unwrap();
                let (builder, vote) = avid.process_dispersal(j, m).unwrap();
                if certified_vote.is_none() {
                    certified_vote = Some(vote);
                }
                let echoes = builder
                    .recipients()
                    .iter()
                    .map(|&r| (r, builder.create_echo(r).unwrap()))
                    .collect();
                (j, echoes)
            })
            .collect();
        let certified_vote = certified_vote.unwrap();

        // The recipient gathers a quorum of echoes including the cheater's ...
        let _ = cheater;
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .map(|(sender, mut echoes)| {
                let echo = echoes.remove(&recipient).unwrap();
                avid.verify_echo(echo, sender, &certified_vote, recipient)
                    .unwrap()
            })
            .collect();

        // ... but the cheater's shards don't fit any codeword with the rest, so it raises a
        // Complaint.
        let complaint = avid
            .decode_or_complain(&echoes, |_| true)
            .unwrap()
            .unwrap_err();

        // Another party validates the complaint.
        assert!(avid
            .complaint_is_valid(&complaint, recipient, &certified_vote, |_| true)
            .unwrap());
    }

    #[test]
    fn inconsistent_row_accepted_from_consistent_subset() {
        // The dealer commits an *inconsistent* full row (shards 3 and 4 corrupted before the tree
        // is built) but the first W − 2f = 3 shards are a clean subset of the intended codeword. An
        // accuser that gathers exactly those 3 shards decodes a valid payload, yet re-encoding it
        // disagrees with the committed row root, so it raises a Complaint. A validator must accept
        // that complaint even though the 3 shards alone form a consistent codeword — this is the
        // case that bare `decode` (without the re-encode check) would have wrongly rejected.
        let weights = [1u16; 5]; // total weight W = 5
        let f = 1u16; // W − 2f = 3
        let nodes = Arc::new(nodes_with_weights(&weights));
        let avid = Avid::new(Arc::clone(&nodes), f).unwrap();

        let recipient = 0u16;
        let mut payload = vec![0u8; 200];
        thread_rng().fill_bytes(&mut payload);
        let payloads: BTreeMap<PartyId, Vec<u8>> =
            std::iter::once((recipient, payload.clone())).collect();

        // Corrupt the shards held by dispersers 3 and 4, leaving 0, 1, 2 clean.
        let dispersal_builder = avid
            .disperse_with_mutation(&payloads, |shards| {
                let row = shards.get_mut(&recipient).unwrap();
                row[3][0].0[0] ^= 1;
                row[4][0].0[0] ^= 1;
            })
            .unwrap();

        let mut certified_vote = None;
        let party_echoes: Vec<(PartyId, Echo)> = avid
            .nodes
            .node_ids_iter()
            .map(|j| {
                let m = dispersal_builder.dispersal_for(j).unwrap();
                let (builder, vote) = avid.process_dispersal(j, m).unwrap();
                if certified_vote.is_none() {
                    certified_vote = Some(vote);
                }
                (j, builder.create_echo(recipient).unwrap())
            })
            .collect();
        let certified_vote = certified_vote.unwrap();

        // Gather exactly the W − 2f = 3 clean echoes (dispersers 0, 1, 2).
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .filter(|(sender, _)| *sender < 3)
            .map(|(sender, echo)| {
                avid.verify_echo(echo, sender, &certified_vote, recipient)
                    .unwrap()
            })
            .collect();

        // The clean subset decodes, but re-encoding disagrees with the committed (corrupted) row.
        let complaint = avid
            .decode_or_complain(&echoes, |_| true)
            .unwrap()
            .unwrap_err();

        // A validator accepts the complaint via the same re-encode check.
        assert!(avid
            .complaint_is_valid(&complaint, recipient, &certified_vote, |_| true)
            .unwrap());
    }
}
