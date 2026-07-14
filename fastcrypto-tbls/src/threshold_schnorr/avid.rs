// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous Verifiable Information Dispersal (AVID).
//!
//! A dealer disperses one payload per recipient across weighted parties such that any `≥ W-2f`
//! weight of authenticated shards can reconstruct it, while a Merkle commitment binds every shard
//! to the dealer's broadcast. The set of recipients does not have to be all nodes.
//! We call the message from the dealer to the recipients a "dispersal", and the message from a
//! disperser to a recipient an "echo".

use crate::nodes::{Nodes, PartyId};
use crate::threshold_schnorr::merkle::{NestedMerkleProof, NestedMerkleTree};
use crate::threshold_schnorr::reed_solomon::{ErasureCoder, Shard, Shards};
use crate::threshold_schnorr::EG;
use crate::types::get_uniform_value;
use fastcrypto::error::FastCryptoError::{
    InvalidInput, InvalidMessage, InvalidProof, NotEnoughWeight,
};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::merkle;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tap::TapFallible;
use tracing::warn;

/// A payload dispersed to a single recipient (an opaque byte string).
pub(crate) type Payload = Vec<u8>;

/// AVID parameters over a fixed node set and Byzantine bound `f`.
pub struct Avid {
    nodes: Arc<Nodes<EG>>,
    coder: ErasureCoder,
    f: u16,
}

/// Dealer-side builder that can create individual [Dispersal] messages on demand.
pub struct DispersalBuilder {
    nodes: Arc<Nodes<EG>>,
    tree: NestedMerkleTree,
    shards_by_recipient: BTreeMap<PartyId, Vec<Shards>>,
}

/// The dealer's per-party dispersal message. One [AuthenticatedShards] per message recipient.
pub type Dispersal = BTreeMap<PartyId, AuthenticatedShards>;

/// One disperser's shards for a recipient's payload with a two-level Merkle proof against the
/// dispersal's `top_root` (row proof to the recipient's row root, top proof binding that row root
/// to `top_root`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedShards {
    pub(crate) shards: Shards,
    pub(crate) proof: NestedMerkleProof,
}

/// An endorsement of a dispersal's `top_root` and the set of recipients it covers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub top_root: merkle::Node,
    pub recipients: BTreeSet<PartyId>,
}

impl Vote {
    /// The position of `id` among this vote's recipients.
    fn recipient_index(&self, id: PartyId) -> FastCryptoResult<usize> {
        self.recipients
            .iter()
            .position(|&r| r == id)
            .ok_or(InvalidInput)
    }
}

/// A precomputed dispersal-side builder produced to build [Echo]s.
pub struct EchoBuilder {
    dispersal: Dispersal,
    pub top_root: merkle::Node,
}

/// One disperser's message to a single message recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Echo {
    authenticated_shards: AuthenticatedShards,
}

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

/// The outcome of [Avid::decode_or_complain]: either the reconstructed payload, or a [Complaint]
/// witnessing that the dealer's dispersal is inconsistent.
#[derive(Clone, Debug)]
pub enum DecodeOutcome {
    Decoded(Payload),
    Complaint(Complaint),
}

#[cfg(test)]
impl DecodeOutcome {
    fn unwrap_decoded(self) -> Payload {
        match self {
            Self::Decoded(payload) => payload,
            Self::Complaint(_) => panic!("expected a decoded payload, got a complaint"),
        }
    }

    fn unwrap_complaint(self) -> Complaint {
        match self {
            Self::Complaint(complaint) => complaint,
            Self::Decoded(_) => panic!("expected a complaint, got a decoded payload"),
        }
    }
}

impl Avid {
    /// Build an AVID instance over `nodes` with Byzantine bound `f`, constructing the
    /// `(W, W − 2f)` Reed-Solomon coder once. Fails if `f == 0`, `W ≤ 2f`, or the RS parameters
    /// are otherwise invalid.
    /// W can be assumed to be <=10000.
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
    ///    [Dispersal]s on demand via [DispersalBuilder::dispersal_for]. Fails if any of the
    ///    payloads are empty.
    pub fn disperse(
        &self,
        payloads_by_recipient: &BTreeMap<PartyId, Payload>,
    ) -> FastCryptoResult<DispersalBuilder> {
        self.commit(self.encode_and_bucket(payloads_by_recipient)?)
    }

    /// Test-only variant of [Self::disperse] that runs `mutate` over the per-recipient,
    /// per-disperser shards before they are committed, to simulate a cheating dealer.
    #[cfg(test)]
    pub(crate) fn disperse_with_mutation(
        &self,
        payloads_by_recipient: &BTreeMap<PartyId, Payload>,
        mutate: impl FnOnce(&mut BTreeMap<PartyId, Vec<Shards>>),
    ) -> FastCryptoResult<DispersalBuilder> {
        let mut shards_by_recipient = self.encode_and_bucket(payloads_by_recipient)?;
        mutate(&mut shards_by_recipient);
        self.commit(shards_by_recipient)
    }

    /// RS-encode each recipient's payload and bucket the shards by disperser.
    fn encode_and_bucket(
        &self,
        payloads_by_recipient: &BTreeMap<PartyId, Payload>,
    ) -> FastCryptoResult<BTreeMap<PartyId, Vec<Shards>>> {
        payloads_by_recipient
            .iter()
            .map(|(&i, payload)| {
                let shards = self.coder.encode(payload)?;
                let by_disperser = self.nodes.collect_to_nodes(shards.into_iter())?;
                Ok((i, by_disperser))
            })
            .collect()
    }

    /// Build the two-level Merkle commitment (per-recipient row trees + a top tree over the row
    /// roots) over `shards_by_recipient` and return the [DispersalBuilder].
    fn commit(
        &self,
        shards_by_recipient: BTreeMap<PartyId, Vec<Shards>>,
    ) -> FastCryptoResult<DispersalBuilder> {
        let tree = NestedMerkleTree::new(shards_by_recipient.values().cloned())?;
        Ok(DispersalBuilder {
            nodes: Arc::clone(&self.nodes),
            tree,
            shards_by_recipient,
        })
    }

    /// 2. Verify a [Dispersal] and return an [EchoBuilder] that can produce individual [Echo]s on
    ///    demand and a [Vote] to return to the disperser.
    pub fn process_dispersal(
        &self,
        my_id: PartyId,
        dispersal: Dispersal,
    ) -> FastCryptoResult<(EchoBuilder, Vote)> {
        if dispersal.is_empty() {
            warn!("avid echo: empty dispersal");
            return Err(InvalidMessage);
        }
        if dispersal.keys().any(|i| !self.nodes.is_valid_id(*i)) {
            warn!("avid echo: dispersal contains an invalid recipient id");
            return Err(InvalidMessage);
        }

        // Every recipient's row must carry exactly this disperser's own share of the shards.
        let my_weight = self.nodes.weight_of(my_id)? as usize;
        let implied_roots = dispersal
            .iter()
            .enumerate()
            .map(|(recipient_idx, (_, shards))| {
                if shards.shards.len() != my_weight {
                    warn!("avid echo: dispersal has wrong shard count for disperser {my_id}");
                    return Err(InvalidMessage);
                }
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

    // Steps 3 and 4 happen at the caller level:
    //   3. The dealer collects W-f votes to form a certificate.
    //   4. A party seeing the certificate can ask signers to send their echoes.

    /// 5. Verify an [Echo] addressed to `receiver`, against the certified [Vote].
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
        let receiver_idx = vote.recipient_index(receiver)?;
        auth.proof
            .verify(&vote.top_root, &auth.shards, receiver_idx, sender as usize)?;
        Ok(VerifiedEcho { echo, sender })
    }

    /// 6. Reconstruct the caller's payload from a quorum of [VerifiedEcho]s, or raise a
    ///    [Complaint]. Rejects duplicate dispersers, requires `≥ W − 2f` weight.
    pub fn decode_or_complain(
        &self,
        echoes: &[VerifiedEcho],
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<DecodeOutcome> {
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
        Ok(match self.decode_consistent(&shards, payload_ok) {
            Ok(payload) => DecodeOutcome::Decoded(payload),
            Err(_) => DecodeOutcome::Complaint(Complaint { shards }),
        })
    }

    /// RS-decode the payload from authenticated `shards` and confirm it is a consistent codeword
    /// accepted by `payload_ok`, returning the payload.
    fn decode_consistent(
        &self,
        shards: &BTreeMap<PartyId, AuthenticatedShards>,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<Payload> {
        let payload = self.decode(shards)?;
        if !payload_ok(&payload) {
            return Err(InvalidProof);
        }

        // Re-encode the payload and rebuild the row's Merkle tree.
        let re_encoded: Vec<Shards> = self
            .nodes
            .collect_to_nodes(self.coder.encode(&payload)?.into_iter())?;

        // Take the expected recipient root from any shard's proof, since they all share the same
        // top root and row index.
        let (sender, authenticated_shards) = shards.iter().next().ok_or(InvalidInput)?;
        let expected_recipient_root = authenticated_shards
            .proof
            .derive_row_root(&authenticated_shards.shards, *sender as usize)?;
        if NestedMerkleTree::compute_row_root(&re_encoded)? != expected_recipient_root {
            return Err(InvalidProof);
        }

        Ok(payload)
    }

    /// Verify that `complaint` is a valid complaint against the dispersal certified by `vote`.
    pub fn verify_complaint(
        &self,
        complaint: &Complaint,
        accuser_id: PartyId,
        vote: &Vote,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<()> {
        // An accuser that is not a pending recipient cannot have a dispersal complaint.
        let accuser_idx = vote.recipient_index(accuser_id)?;
        for (&disperser, auth) in complaint.shards.iter() {
            if auth.shards.len() != self.nodes.weight_of(disperser)? as usize {
                return Err(InvalidInput);
            }
            auth.proof.verify(
                &vote.top_root,
                &auth.shards,
                accuser_idx,
                disperser as usize,
            )?;
        }
        let weight = self.nodes.total_weight_of(complaint.shards.keys())?;
        if weight < self.required_weight() {
            return Err(NotEnoughWeight(weight as usize));
        }
        // A consistent payload means the complaint is unsubstantiated. The shards were
        // proof-checked above and carry enough weight, so a decode error here reflects a genuine
        // inconsistency.
        if self
            .decode_consistent(&complaint.shards, payload_ok)
            .is_ok()
        {
            return Err(InvalidProof);
        }
        Ok(())
    }

    /// RS-decode a payload from authenticated shard contributions keyed by disperser. Missing
    /// dispersers and dispersers whose shard count doesn't match their weight are treated as
    /// erasures, so decoding fails if those exceed `2f` weight.
    fn decode(&self, shards: &BTreeMap<PartyId, AuthenticatedShards>) -> FastCryptoResult<Payload> {
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
    /// The recipients of the dispersal.
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
        let payloads: BTreeMap<PartyId, Payload> =
            std::iter::once((recipient, payload.clone())).collect();

        // 1. Dealer disperses: builder mints messages on demand.
        let dispersal_builder = avid.disperse(&payloads).unwrap();

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
        let recovered = avid
            .decode_or_complain(&echoes, |_| true)
            .unwrap()
            .unwrap_decoded();
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
        let payloads: BTreeMap<PartyId, Payload> =
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
            .unwrap_complaint();

        // Another party validates the complaint.
        avid.verify_complaint(&complaint, recipient, &certified_vote, |_| true)
            .unwrap();
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
        let payloads: BTreeMap<PartyId, Payload> =
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
            .unwrap_complaint();

        // A validator accepts the complaint via the same re-encode check.
        avid.verify_complaint(&complaint, recipient, &certified_vote, |_| true)
            .unwrap();
    }
}
