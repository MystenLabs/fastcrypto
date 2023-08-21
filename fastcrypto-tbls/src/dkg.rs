// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::dl_verification::verify_poly_evals;
use crate::ecies;
use crate::ecies::RecoveryPackage;
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::{Eval, Poly, PrivatePoly, PublicPoly};
use crate::random_oracle::RandomOracle;
use crate::tbls::Share;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, HashToGroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

/// Generics below use `G: GroupElement' for the group of the VSS public key, and `EG: GroupElement'
/// for the group of the ECIES public key.

/// Party in the DKG protocol.
#[derive(Clone, PartialEq, Eq)]
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
    /// The encrypted shares created by the sender.
    pub encrypted_shares: Vec<ecies::Encryption<EG>>,
}

/// A complaint/fraud claim against a dealer that created invalid encrypted share.
// TODO: add Serialize & Deserialize.
#[derive(Clone, PartialEq, Eq)]
pub struct Complaint<EG: GroupElement> {
    encryption_sender: PartyId,
    package: RecoveryPackage<EG>,
}

/// A [Confirmation] is sent during the second phase of the protocol. It includes complaints
/// created by receiver of invalid encrypted shares.
#[derive(Clone, PartialEq, Eq)]
pub struct Confirmation<EG: GroupElement> {
    pub sender: PartyId,
    /// List of complaints against other parties. Empty if there are none.
    pub complaints: Vec<Complaint<EG>>,
}

/// Mapping from node id to the shares received from that sender.
pub type SharesMap<S> = HashMap<PartyId, Vec<Share<S>>>;

/// [Output] is the final output of the DKG protocol in case it runs
/// successfully. It can be used later with [ThresholdBls], see examples in tests.
#[derive(Clone, Debug)]
pub struct Output<G: GroupElement, EG: GroupElement> {
    pub nodes: Nodes<EG>,
    pub vss_pk: Poly<G>,
    pub shares: Vec<Share<G::ScalarType>>,
}

// TODO: [comm & perf opt] Run the DKG with G1Curve and add another round in which parties send
// their partial pk in G2. This will reduce communication but will add another round.

/// A dealer in the DKG ceremony.
///
/// Can be instantiated with G1Curve or G2Curve.
impl<G: GroupElement, EG: GroupElement> Party<G, EG>
where
    <G as GroupElement>::ScalarType: Serialize + DeserializeOwned,
    EG: Serialize,
    G: MultiScalarMul + DeserializeOwned,
    <EG as GroupElement>::ScalarType: HashToGroupElement,
{
    /// 1. Create a new ECIES private key and send the public key to all parties.
    /// 2. After all parties have sent their ECIES public keys, create the set of nodes.
    /// 3. Create a new Party instance with the ECIES private key and the set of nodes.
    pub fn new<R: AllowedRng>(
        ecies_sk: ecies::PrivateKey<EG>,
        nodes: Vec<Node<EG>>,
        t: u32, // The number of parties that are needed to reconstruct the full signature.
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
        let n = nodes.n();
        if t >= n {
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
        let encrypted_shares = self
            .nodes
            .iter()
            .map(|node| {
                let share_ids = self.nodes.share_ids_of(node.id);
                let mut shares = Vec::new();
                for share_id in share_ids {
                    shares.push(self.vss_sk.eval(share_id).value);
                }
                let buff = bcs::to_bytes(&shares).expect("serialize of shares should never fail");
                node.pk.encrypt(&buff, rng)
            })
            .collect();

        Message {
            sender: self.id,
            vss_pk: self.vss_sk.commit(),
            encrypted_shares,
        }
    }

    /// 5. Process a message and create the second message to be broadcasted.
    ///    The second message contains the list of complaints on invalid shares. In addition, it
    ///    returns a set of valid shares (so far).
    pub fn process_message<R: AllowedRng>(
        &self,
        message: &Message<G, EG>,
        rng: &mut R,
    ) -> FastCryptoResult<(SharesMap<G::ScalarType>, Confirmation<EG>)> {
        let mut shares = HashMap::new(); // Will include only valid shares.
        let mut next_message = Confirmation {
            sender: self.id,
            complaints: Vec::new(),
        };

        let my_share_ids = self.nodes.share_ids_of(self.id);
        // Ignore if invalid (and other honest parties will ignore as well).
        if (message.vss_pk.degree() != self.t - 1)
            || (message.encrypted_shares.len() != self.nodes.num_nodes() as usize)
        {
            return Err(FastCryptoError::InvalidProof);
        }

        let encrypted_shares = &message.encrypted_shares[self.id as usize];
        let decrypted_shares = Self::decrypt_and_get_share(&self.ecies_sk, encrypted_shares).ok();

        if decrypted_shares.is_none()
            || decrypted_shares.as_ref().unwrap().len() != my_share_ids.len()
        {
            next_message.complaints.push(Complaint {
                encryption_sender: message.sender,
                package: self.ecies_sk.create_recovery_package(
                    encrypted_shares,
                    &self.random_oracle.extend("ecies"),
                    rng,
                ),
            });
            return Ok((shares, next_message)); // 1 complaint per message is enough
        }

        let decrypted_shares = decrypted_shares
            .unwrap()
            .iter()
            .zip(my_share_ids)
            .map(|(s, i)| Eval {
                index: i,
                value: *s,
            })
            .collect::<Vec<_>>();

        if verify_poly_evals(&decrypted_shares, &message.vss_pk, rng).is_err() {
            next_message.complaints.push(Complaint {
                encryption_sender: message.sender,
                package: self.ecies_sk.create_recovery_package(
                    encrypted_shares,
                    &self.random_oracle.extend("ecies"),
                    rng,
                ),
            });
            return Ok((shares, next_message)); // 1 complaint per message is enough
        }

        shares.insert(message.sender, decrypted_shares.into());
        Ok((shares, next_message))
    }

    /// 6. Merge results from multiple process_message calls so only one message needs to be sent.
    pub fn merge(
        &self,
        processed_messages: &[(SharesMap<G::ScalarType>, Confirmation<EG>)],
    ) -> (SharesMap<G::ScalarType>, Confirmation<EG>) {
        // TODO: verify we have messages from more than t weights
        // TODO: verify unique senders
        // let num_of_unique_senders =
        //     .iter()
        //     .map(|m| m.sender)
        //     .collect::<HashSet<_>>()
        //     .len();
        // if num_of_unique_senders != messages.len() {
        //     return Err(FastCryptoError::InputTooShort(num_of_unique_senders));
        // }

        let mut shares = HashMap::new();
        let mut conf = Confirmation {
            sender: self.id,
            complaints: Vec::new(),
        };
        for m in processed_messages {
            assert_eq!(self.id, m.1.sender);
            shares.extend(m.0.clone().into_iter());
            conf.complaints.extend(m.1.complaints.clone().into_iter());
        }
        (shares, conf)
    }

    /// 7. Process all confirmations, check all complaints, and update the local set of
    ///    valid shares accordingly.
    ///
    ///    minimal_threshold is the minimal number of second round messages we expect. Its value is
    ///    application dependent but in most cases it should be at least t+f to guarantee that at
    ///    least t honest nodes have valid shares.
    pub fn process_confirmations<R: AllowedRng>(
        &self,
        messages: &[Message<G, EG>],
        confirmations: &[Confirmation<EG>],
        shares: SharesMap<G::ScalarType>,
        _minimal_threshold: usize,
        rng: &mut R,
    ) -> Result<SharesMap<G::ScalarType>, FastCryptoError> {
        // TODO: update next line's checks to check the weights
        // if messages.len() != self.t as usize || confirmations.len() < minimal_threshold {
        //     return Err(FastCryptoError::InvalidInput);
        // }

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
                // TODO: check that current accuser is in nodes (and thus in id_to_pk).
                let accuser_pk = id_to_pk.get(&accuser).unwrap();
                let related_m1 = id_to_m1.get(&accused);
                // If the claim refers to a non existing message, it's an invalid complaint.
                // TODO: check the share id is in the range, etc
                let valid_complaint = related_m1.is_some() && {
                    let encrypted_shares = &related_m1
                        .expect("checked above that is not None")
                        .encrypted_shares[(accuser) as usize];
                    Self::check_delegated_key_and_share(
                        &complaint.package,
                        accuser_pk,
                        &self.nodes.share_ids_of(accuser),
                        &related_m1.expect("checked above that is not None").vss_pk,
                        encrypted_shares,
                        &self.random_oracle.extend("ecies"),
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
