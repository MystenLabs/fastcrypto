// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::dl_verification::verify_poly_evals;
use crate::ecies;
use crate::ecies::{MultiRecipientEncryption, PublicKey, RecoveryPackage};
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::{Eval, Poly, PrivatePoly, PublicPoly};
use crate::random_oracle::RandomOracle;
use crate::tbls::Share;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Generics below use `G: GroupElement' for the group of the VSS public key, and `EG: GroupElement'
/// for the group of the ECIES public key.

/// Party in the DKG protocol.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party<G: GroupElement, EG: GroupElement> {
    id: PartyId,
    nodes: Nodes<EG>,
    t: u32,
    random_oracle: RandomOracle,
    ecies_sk: ecies::PrivateKey<EG>,
    vss_sk: PrivatePoly<G>,
}

/// The higher-level protocol is responsible for verifying that the 'sender' is correct in the
/// following messages (based on the chain's signatures).

/// [Message] holds all encrypted shares a dealer sends during the first phase of the
/// protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    pub sender: PartyId,
    /// The commitment of the secret polynomial created by the sender.
    // TODO: [security] add a proof of possession/knowledge?
    pub vss_pk: PublicPoly<G>,
    /// The encrypted shares created by the sender. Sorted according to the receivers.
    pub encrypted_shares: MultiRecipientEncryption<EG>,
}

/// A complaint/fraud claim against a dealer that created invalid encrypted share.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Complaint<EG: GroupElement> {
    encryption_sender: PartyId,
    package: RecoveryPackage<EG>,
}

/// A [Confirmation] is sent during the second phase of the protocol. It includes complaints
/// created by receiver of invalid encrypted shares.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation<EG: GroupElement> {
    pub sender: PartyId,
    /// List of complaints against other parties. Empty if there are none.
    pub complaints: Vec<Complaint<EG>>,
}

pub struct ProcessedMessage<G: GroupElement, EG: GroupElement> {
    message: Message<G, EG>,
    shares: Vec<Share<G::ScalarType>>, //possibly empty
    complaint: Option<Complaint<EG>>,
}

/// Mapping from node id to the shares received from that sender.
pub type SharesMap<S> = HashMap<PartyId, Vec<Share<S>>>;

/// [Output] is the final output of the DKG protocol in case it runs
/// successfully. It can be used later with [ThresholdBls], see examples in tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output<G: GroupElement, EG: GroupElement> {
    pub nodes: Nodes<EG>,
    pub vss_pk: Poly<G>,
    pub shares: Vec<Share<G::ScalarType>>,
}

/// A dealer in the DKG ceremony.
///
/// Can be instantiated with G1Curve or G2Curve.
impl<G: GroupElement, EG: GroupElement> Party<G, EG>
where
    G: MultiScalarMul + Serialize + DeserializeOwned,
    EG: Serialize + DeserializeOwned,
    <EG as GroupElement>::ScalarType: FiatShamirChallenge,
{
    /// 1. Create a new ECIES private key and send the public key to all parties.
    /// 2. After all parties have sent their ECIES public keys, create the set of nodes.
    /// 3. Create a new Party instance with the ECIES private key and the set of nodes.
    pub fn new<R: AllowedRng>(
        ecies_sk: ecies::PrivateKey<EG>,
        nodes: Vec<Node<EG>>,
        t: u32, // The number of parties that are needed to reconstruct the full key/signature.
        random_oracle: RandomOracle,
        rng: &mut R,
    ) -> Result<Self, FastCryptoError> {
        let ecies_pk = ecies::PublicKey::<EG>::from_private_key(&ecies_sk);
        let my_id = nodes
            .iter()
            .find(|n| n.pk == ecies_pk)
            .ok_or(FastCryptoError::InvalidInput)?
            .id;
        let nodes = Nodes::new(nodes)?;
        if t >= nodes.n() {
            return Err(FastCryptoError::InvalidInput);
        }
        // TODO: [comm opt] Instead of generating the polynomial at random, use PRF generated values
        // to reduce communication.
        let vss_sk = PrivatePoly::<G>::rand(t - 1, rng);

        Ok(Self {
            id: my_id,
            nodes,
            t,
            random_oracle,
            ecies_sk,
            vss_sk,
        })
    }

    pub fn t(&self) -> u32 {
        self.t
    }

    /// 4. Create the first message to be broadcasted.
    pub fn create_message<R: AllowedRng>(&self, rng: &mut R) -> Message<G, EG> {
        let pk_and_shares: Vec<(PublicKey<EG>, Vec<u8>)> = self
            .nodes
            .iter()
            .map(|node| {
                let share_ids = self.nodes.share_ids_of(node.id);
                let shares = share_ids
                    .iter()
                    .map(|share_id| self.vss_sk.eval(*share_id).value)
                    .collect::<Vec<_>>();
                let buff = bcs::to_bytes(&shares).expect("serialize of shares should never fail");
                (node.pk.clone(), buff)
            })
            .collect();
        let encrypted_shares = MultiRecipientEncryption::encrypt(
            &pk_and_shares,
            &self.random_oracle.extend(&format!("encs {}", self.id)),
            rng,
        );

        Message {
            sender: self.id,
            vss_pk: self.vss_sk.commit(),
            encrypted_shares,
        }
    }

    fn sanity_check_message(&self, msg: &Message<G, EG>) -> FastCryptoResult<()> {
        self.nodes.node_id_to_node(msg.sender)?;
        if self.t != msg.vss_pk.degree() + 1 {
            return Err(FastCryptoError::InvalidInput);
        }
        if self.nodes.num_nodes() != msg.encrypted_shares.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        msg.encrypted_shares
            .verify_knowledge(&self.random_oracle.extend(&format!("encs {}", msg.sender)))?;
        Ok(())
    }

    /// 5. Process a message and create the second message to be broadcasted.
    ///    The second message contains the list of complaints on invalid shares. In addition, it
    ///    returns a set of valid shares (so far).
    pub fn process_message<R: AllowedRng>(
        &self,
        message: Message<G, EG>,
        rng: &mut R,
    ) -> FastCryptoResult<ProcessedMessage<G, EG>> {
        // Ignore if invalid (and other honest parties will ignore as well).
        self.sanity_check_message(&message)?;

        let my_share_ids = self.nodes.share_ids_of(self.id);
        let encrypted_shares = &message
            .encrypted_shares
            .get_encryption(self.id as usize)
            .expect("checked above that there are enough encryptions");
        let decrypted_shares = Self::decrypt_and_get_share(&self.ecies_sk, encrypted_shares).ok();

        if decrypted_shares.is_none()
            || decrypted_shares.as_ref().unwrap().len() != my_share_ids.len()
        {
            let complaint = Complaint {
                encryption_sender: message.sender,
                package: self.ecies_sk.create_recovery_package(
                    encrypted_shares,
                    &self
                        .random_oracle
                        .extend(&format!("recovery {} {}", self.id, message.sender)),
                    rng,
                ),
            };
            return Ok(ProcessedMessage {
                message,
                shares: vec![],
                complaint: Some(complaint),
            });
        }

        let decrypted_shares = decrypted_shares
            .expect("checked above")
            .iter()
            .zip(my_share_ids)
            .map(|(s, i)| Eval {
                index: i,
                value: *s,
            })
            .collect::<Vec<_>>();

        if verify_poly_evals(&decrypted_shares, &message.vss_pk, rng).is_err() {
            let complaint = Complaint {
                encryption_sender: message.sender,
                package: self.ecies_sk.create_recovery_package(
                    encrypted_shares,
                    &self
                        .random_oracle
                        .extend(&format!("recovery {} {}", self.id, message.sender)),
                    rng,
                ),
            };
            return Ok(ProcessedMessage {
                message,
                shares: vec![],
                complaint: Some(complaint),
            });
        }

        Ok(ProcessedMessage {
            message,
            shares: decrypted_shares,
            complaint: None,
        })
    }

    /// 6. Merge results from multiple process_message calls so only one message needs to be sent.
    ///    Returns InputTooShort if the threshold t is not met.
    pub fn merge(
        &self,
        processed_messages: &[ProcessedMessage<G, EG>],
    ) -> FastCryptoResult<(SharesMap<G::ScalarType>, Confirmation<EG>)> {
        // Verify unique senders
        let senders = processed_messages
            .iter()
            .map(|m| m.message.sender)
            .collect::<HashSet<_>>();
        if senders.len() != processed_messages.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        // Verify we have enough messages
        let total_weight = processed_messages
            .iter()
            .map(|m| {
                self.nodes
                    .node_id_to_node(m.message.sender)
                    .expect("checked in process_message")
                    .weight as u32
            })
            .sum::<u32>();
        if total_weight < self.t {
            return Err(FastCryptoError::InputTooShort(self.t as usize));
        }

        let mut shares = HashMap::new();
        let mut conf = Confirmation {
            sender: self.id,
            complaints: Vec::new(),
        };
        for m in processed_messages {
            shares.insert(m.message.sender, m.shares.clone());
            if m.complaint.is_some() {
                let complaint = m.complaint.clone().unwrap();
                conf.complaints.push(complaint);
            }
        }
        Ok((shares, conf))
    }

    /// 7. Process all confirmations, check all complaints, and update the local set of
    ///    valid shares accordingly.
    ///
    ///    minimal_threshold is the minimal number of second round messages we expect. Its value is
    ///    application dependent but in most cases it should be at least t+f to guarantee that at
    ///    least t honest nodes have valid shares.
    ///    Returns InputTooShort if the threshold minimal_threshold is not met.
    pub fn process_confirmations<R: AllowedRng>(
        &self,
        messages: &[Message<G, EG>],
        confirmations: &[Confirmation<EG>],
        shares: SharesMap<G::ScalarType>,
        minimal_threshold: u32,
        rng: &mut R,
    ) -> Result<SharesMap<G::ScalarType>, FastCryptoError> {
        if minimal_threshold < self.t {
            return Err(FastCryptoError::InvalidInput);
        }
        // Ignore confirmations with invalid sender
        let confirmations = confirmations
            .iter()
            .filter(|c| self.nodes.node_id_to_node(c.sender).is_ok())
            .collect::<Vec<_>>();
        // Verify we have enough confirmations
        let total_weight = confirmations
            .iter()
            .map(|c| {
                self.nodes
                    .node_id_to_node(c.sender)
                    .expect("checked above")
                    .weight as u32
            })
            .sum::<u32>();
        if total_weight < minimal_threshold {
            return Err(FastCryptoError::InputTooShort(minimal_threshold as usize));
        }

        // Two hash maps for faster access in the main loop below.
        let id_to_pk: HashMap<PartyId, &ecies::PublicKey<EG>> =
            self.nodes.iter().map(|n| (n.id, &n.pk)).collect();
        let id_to_m1: HashMap<PartyId, &Message<G, EG>> =
            messages.iter().map(|m| (m.sender, m)).collect();

        let mut shares = shares;
        'outer: for m2 in confirmations {
            'inner: for complaint in &m2.complaints[..] {
                let accused = complaint.encryption_sender;
                // Ignore senders that are already not relevant, or invalid complaints.
                if !shares.contains_key(&accused) {
                    continue 'inner;
                }
                let accuser = m2.sender;
                let accuser_pk = id_to_pk
                    .get(&accuser)
                    .expect("checked above that accuser is valid id");
                let related_m1 = id_to_m1.get(&accused);
                // If the claim refers to a non existing message, it's an invalid complaint.
                let valid_complaint = related_m1.is_some() && {
                    let encrypted_shares = &related_m1
                        .expect("checked above that is not None")
                        .encrypted_shares
                        .get_encryption(accuser as usize)
                        .expect("checked above that there are enough encryptions");
                    Self::check_delegated_key_and_share(
                        &complaint.package,
                        accuser_pk,
                        &self.nodes.share_ids_of(accuser),
                        &related_m1.expect("checked above that is not None").vss_pk,
                        encrypted_shares,
                        &self
                            .random_oracle
                            .extend(&format!("recovery {} {}", accuser, accused)),
                        rng,
                    )
                    .is_err()
                };
                match valid_complaint {
                    // Ignore accused from now on, and continue processing complaints from the
                    // current accuser.
                    true => {
                        shares.remove(&accused);
                        continue 'inner;
                    }
                    // Ignore the accuser from now on, including its other complaints (not critical
                    // for security, just saves some work).
                    false => {
                        shares.remove(&accuser);
                        continue 'outer;
                    }
                }
            }
        }

        Ok(shares)
    }

    /// 8. Aggregate the valid shares (as returned from the previous step) and the public key.
    pub fn aggregate(
        &self,
        first_messages: &[Message<G, EG>],
        shares: SharesMap<G::ScalarType>,
    ) -> Output<G, EG> {
        let id_to_m1: HashMap<_, _> = first_messages.iter().map(|m| (m.sender, m)).collect();
        let mut vss_pk = PublicPoly::<G>::zero();

        let my_share_ids = self.nodes.share_ids_of(self.id);

        let mut final_shares = my_share_ids
            .iter()
            .map(|share_id| {
                (
                    share_id,
                    Share {
                        index: *share_id,
                        value: G::ScalarType::zero(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        for (from_sender, shares_from_sender) in shares {
            vss_pk.add(&id_to_m1.get(&from_sender).unwrap().vss_pk);
            for share in shares_from_sender {
                final_shares.get_mut(&share.index).unwrap().value += share.value;
            }
        }

        Output {
            nodes: self.nodes.clone(),
            vss_pk,
            shares: final_shares.values().cloned().collect(),
        }
    }

    fn decrypt_and_get_share(
        sk: &ecies::PrivateKey<EG>,
        encrypted_shares: &ecies::Encryption<EG>,
    ) -> FastCryptoResult<Vec<G::ScalarType>> {
        let buffer = sk.decrypt(encrypted_shares);
        bcs::from_bytes(buffer.as_slice()).map_err(|_| FastCryptoError::InvalidInput)
    }

    fn check_delegated_key_and_share<R: AllowedRng>(
        recovery_pkg: &RecoveryPackage<EG>,
        ecies_pk: &ecies::PublicKey<EG>,
        share_ids: &[ShareIndex],
        vss_pk: &PublicPoly<G>,
        encrypted_share: &ecies::Encryption<EG>,
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> FastCryptoResult<()> {
        let buffer =
            ecies_pk.decrypt_with_recovery_package(recovery_pkg, random_oracle, encrypted_share)?;
        let decrypted_shares: Vec<G::ScalarType> =
            bcs::from_bytes(buffer.as_slice()).map_err(|_| FastCryptoError::InvalidInput)?;
        if decrypted_shares.len() != share_ids.len() {
            return Err(FastCryptoError::InvalidInput);
        }

        let decrypted_shares = decrypted_shares
            .into_iter()
            .zip(share_ids)
            .map(|(s, i)| Eval {
                index: *i,
                value: s,
            })
            .collect::<Vec<_>>();

        verify_poly_evals(&decrypted_shares, vss_pk, rng)
    }
}
