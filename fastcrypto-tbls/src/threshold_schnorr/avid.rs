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

/// An endorsement of a dispersal's `top_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub top_root: merkle::Node,
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

    /// 1. Disperse one payload per recipient. Returns one per-party [Dispersal]. Runs `mutate`
    ///    over the per-recipient, per-disperser shards before the Merkle trees are built — for
    ///    production callers pass `|_| {}`.
    ///    Fails if any of the payloads are empty.
    #[cfg_attr(not(test), allow(unused_variables, unused_mut))]
    pub fn disperse_with_mutation(
        &self,
        payloads_by_recipient: &BTreeMap<PartyId, Vec<u8>>,
        mutate: impl FnOnce(&mut BTreeMap<PartyId, Vec<Vec<Shard>>>),
    ) -> FastCryptoResult<BTreeMap<PartyId, Dispersal>> {
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

        Ok(self
            .nodes
            .node_ids_iter()
            .map(|j| {
                let dispersal: Dispersal = shards_by_recipient
                    .iter()
                    .enumerate()
                    .map(|(recipient_idx, (&i, by_disperser))| {
                        (
                            i,
                            AuthenticatedShards {
                                shards: by_disperser[j as usize].clone(),
                                proof: tree
                                    .get_proof(recipient_idx, j as usize)
                                    .expect("valid leaf index"),
                            },
                        )
                    })
                    .collect();
                (j, dispersal)
            })
            .collect())
    }

    /// 2. Verify a [Dispersal] and return an [EchoBuilder] that can produce individual [Echo]s on demand via
    ///    [EchoBuilder::create_echo] and a [Vote] to return to the disperser. When the disperser
    ///    has `W-f` weight of signed [Vote]s, he can publish the certified `top_root`.
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
        Ok((
            EchoBuilder {
                dispersal,
                top_root: top_root.clone(),
            },
            Vote { top_root },
        ))
    }

    /// 3a. Verify an [Echo] addressed to `receiver`. Use the published `certified_top_root`.
    pub fn verify_echo(
        &self,
        echo: Echo,
        sender: PartyId,
        certified_top_root: &merkle::Node,
        pending_recipients: &BTreeSet<PartyId>,
        receiver: PartyId,
    ) -> FastCryptoResult<VerifiedEcho> {
        let auth = &echo.authenticated_shards;
        if auth.shards.len() != self.nodes.weight_of(sender)? as usize {
            return Err(InvalidMessage);
        }
        let receiver_idx = pending_recipients
            .iter()
            .position(|&id| id == receiver)
            .ok_or(InvalidInput)?;
        auth.proof.verify(
            certified_top_root,
            &auth.shards,
            receiver_idx,
            sender as usize,
        )?;
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
        let payload = match self.decode(&shards) {
            Ok(p) if payload_ok(&p) => p,
            _ => return Ok(Err(Complaint { shards })),
        };

        // Re-encode the payload and rebuild the row's Merkle tree.
        let re_encoded: Vec<Vec<Shard>> = self
            .nodes
            .collect_to_nodes(self.coder.encode(&payload)?.into_iter())?;

        // Take the expected recipient root from any verified echo's proof, since they all share the same top root and row index.
        let (sender, authenticated_shards) =
            shards.iter().next().expect("non-empty by check above");
        let expected_recipient_root = authenticated_shards
            .proof
            .derive_row_root(&authenticated_shards.shards, *sender as usize)?;
        if NestedMerkleTree::compute_row_root(&re_encoded)? != expected_recipient_root {
            return Ok(Err(Complaint { shards }));
        }

        Ok(Ok(payload))
    }

    /// Check if `complaint` is a valid complaint against the dispersal.
    pub fn complaint_is_valid(
        &self,
        complaint: &Complaint,
        accuser_id: PartyId,
        top_root: &merkle::Node,
        pending_recipients: &BTreeSet<PartyId>,
        payload_ok: impl Fn(&[u8]) -> bool,
    ) -> FastCryptoResult<bool> {
        let Some(accuser_idx) = pending_recipients.iter().position(|&id| id == accuser_id) else {
            return Ok(false);
        };
        let shards_verify = complaint.shards.iter().all(|(&disperser, auth)| {
            auth.proof
                .verify(top_root, &auth.shards, accuser_idx, disperser as usize)
                .is_ok()
        });
        if !shards_verify
            || self.nodes.total_weight_of(complaint.shards.keys())? < self.required_weight()
        {
            return Ok(false);
        }
        Ok(!self
            .decode(&complaint.shards)
            .is_ok_and(|payload| payload_ok(&payload)))
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
        let messages = avid.disperse_with_mutation(&payloads, |_| {}).unwrap();
        assert_eq!(messages.len(), weights.len());

        // 2. Each party verifies its dispersal and emits the echoes it will send to others.
        let mut top_root = None;
        let mut recipients = BTreeSet::new();
        let party_echoes: Vec<(PartyId, BTreeMap<PartyId, Echo>)> = messages
            .into_iter()
            .map(|(j, m)| {
                let (builder, vote) = avid.process_dispersal(j, m).unwrap();
                if top_root.is_none() {
                    top_root = Some(vote.top_root);
                    recipients = builder.recipients();
                }
                let echoes = builder
                    .recipients()
                    .iter()
                    .map(|&r| (r, builder.create_echo(r).unwrap()))
                    .collect();
                (j, echoes)
            })
            .collect();
        let top_root = top_root.unwrap();

        // The recipient verifies the echoes addressed to it.
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .map(|(sender, mut echoes)| {
                let echo = echoes.remove(&recipient).unwrap();
                avid.verify_echo(echo, sender, &top_root, &recipients, recipient)
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

        let messages = avid
            .disperse_with_mutation(&payloads, |shards| {
                shards.get_mut(&recipient).unwrap()[cheater as usize][0].0[0] ^= 1;
            })
            .unwrap();

        let mut top_root = None;
        let mut recipients = BTreeSet::new();
        let party_echoes: Vec<(PartyId, BTreeMap<PartyId, Echo>)> = messages
            .into_iter()
            .map(|(j, m)| {
                let (builder, vote) = avid.process_dispersal(j, m).unwrap();
                if top_root.is_none() {
                    top_root = Some(vote.top_root);
                    recipients = builder.recipients();
                }
                let echoes = builder
                    .recipients()
                    .iter()
                    .map(|&r| (r, builder.create_echo(r).unwrap()))
                    .collect();
                (j, echoes)
            })
            .collect();
        let top_root = top_root.unwrap();

        // The recipient gathers a quorum of echoes including the cheater's ...
        let _ = cheater;
        let echoes: Vec<VerifiedEcho> = party_echoes
            .into_iter()
            .map(|(sender, mut echoes)| {
                let echo = echoes.remove(&recipient).unwrap();
                avid.verify_echo(echo, sender, &top_root, &recipients, recipient)
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
            .complaint_is_valid(&complaint, recipient, &top_root, &recipients, |_| true)
            .unwrap());
    }
}
