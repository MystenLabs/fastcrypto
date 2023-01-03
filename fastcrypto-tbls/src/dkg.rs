// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::ecies;
use crate::ecies::RecoveryPackage;
use crate::polynomial::{Poly, PrivatePoly, PublicPoly};
use crate::random_oracle::RandomOracle;
use crate::tbls::Share;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{GroupElement, HashToGroupElement};
use fastcrypto::traits::AllowedRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

// TODO: add weights to PkiNode, and change the DKG accordingly

/// PKI node, with a unique id and its encryption public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiNode<EG: GroupElement> {
    pub id: ShareIndex,
    pub pk: ecies::PublicKey<EG>,
}

pub type Nodes<EG> = Vec<PkiNode<EG>>;

/// Party in the DKG protocol.
#[derive(Clone, PartialEq, Eq)]
struct Party<G: GroupElement, EG: GroupElement> {
    id: ShareIndex,
    nodes: Nodes<EG>,
    ecies_sk: ecies::PrivateKey<EG>,
    ecies_pk: ecies::PublicKey<EG>,
    vss_sk: PrivatePoly<G>,
    vss_pk: PublicPoly<G>,
    threshold: u32,
    random_oracle: RandomOracle,
}

/// [EncryptedShare] holds the ECIES encryption of a share destined to the receiver.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedShare<EG: GroupElement> {
    pub receiver: ShareIndex,
    // TODO: Replace with a Enc(hkdf(g^{sk_i sk_j}), share) instead of sending a random group
    // element, or extend ECIES to work like that.
    pub encryption: ecies::Encryption<EG>,
}

/// [DkgFirstMessage] holds all encrypted shares a dealer creates during the first
/// phase of the protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirstMessage<G: GroupElement, EG: GroupElement> {
    pub sender: ShareIndex,
    /// The encrypted shares created by the sender.
    pub encrypted_shares: Vec<EncryptedShare<EG>>,
    /// The commitment of the secret polynomial created by the sender.
    // TODO: add a proof of possession/knowledge.
    pub vss_pk: PublicPoly<G>,
}

/// A complaint/fraud claim against a dealer that created invalid encrypted share.
#[derive(Clone, PartialEq)]
pub enum Complaint<EG: GroupElement> {
    /// The identity of the sender.
    NoShare(ShareIndex),
    /// The identity of the sender and the delegated key.
    // An alternative to using ECIES & ZKPoK for complaints is to use different ECIES public key
    // for each sender, and in case of a complaint, simply reveal the relevant secret key.
    // This saves the ZKPoK with the price of publishing one ECIES public key & PoP for each party,
    // resulting in larger communication in the happy path.
    InvalidEncryptedShare(ShareIndex, RecoveryPackage<EG>),
}

/// A [DkgSecondMessage] is sent during the second phase of the protocol. It includes complaints
/// created by receiver of invalid encrypted shares.
#[derive(Clone, PartialEq)]
pub struct SecondMessage<EG: GroupElement> {
    pub sender: ShareIndex,
    // List of complaints against other parties. Empty if there are non.
    pub complaints: Vec<Complaint<EG>>,
}

/// Mapping from node id to the share I received from that leader.
pub type SharesMap<G> = HashMap<ShareIndex, <G as GroupElement>::ScalarType>;

/// [DkgOutput] is the final output of the DKG protocol in case it runs
/// successfully. It can be used later with [ThresholdBls], see examples in tests.
#[derive(Clone, Debug)]
pub struct DkgOutput<G: GroupElement, EG: GroupElement> {
    pub nodes: Nodes<EG>, // do we need this?
    pub vss_pk: Poly<G>,
    pub share: Share<G::ScalarType>,
}

/// A dealer in the DKG ceremony.
///
/// Can be instantiated with G1Curve or G2Curve.
impl<G: GroupElement, EG: GroupElement> Party<G, EG>
where
    <G as GroupElement>::ScalarType: Serialize + DeserializeOwned,
    EG: Serialize,
    <EG as GroupElement>::ScalarType: HashToGroupElement,
{
    /// 1. Create a new ECIES private key and send the public key to all parties.
    /// 2. After all parties have sent their ECIES public keys, create the set of nodes.
    /// 3. Create a new Party instance with the ECIES private key and the set of nodes.
    pub fn new<R: AllowedRng>(
        ecies_sk: ecies::PrivateKey<EG>,
        nodes: Nodes<EG>,
        threshold: u32,
        random_oracle: RandomOracle,
        rng: &mut R,
    ) -> Result<Self, FastCryptoError> {
        let ecies_pk = ecies::PublicKey::<EG>::from_private_key(&ecies_sk);

        // Check if the public key is in one of the nodes.
        let curr_node = nodes
            .iter()
            .find(|n| &n.pk == &ecies_pk)
            .ok_or_else(|| FastCryptoError::InvalidInput)?;

        // Generate a secret polynomial and commit to it.
        let vss_sk = PrivatePoly::<G>::rand(threshold - 1, rng);
        let vss_pk = vss_sk.commit::<G>();

        Ok(Self {
            id: curr_node.id,
            nodes,
            ecies_sk,
            ecies_pk,
            vss_sk,
            vss_pk,
            threshold,
            random_oracle,
        })
    }

    /// 4. Create the first message to be broadcasted.
    pub fn create_first_message<R: AllowedRng>(&self, rng: &mut R) -> FirstMessage<G, EG> {
        let encrypted_shares = self
            .nodes
            .iter()
            .map(|n| {
                let share = self.vss_sk.eval(n.id);
                let buff = bincode::serialize(&share.value).unwrap();
                let encryption = n.pk.encrypt(&buff, rng);
                EncryptedShare {
                    receiver: n.id,
                    encryption,
                }
            })
            .collect();

        FirstMessage {
            sender: self.id,
            encrypted_shares,
            vss_pk: self.vss_pk.clone(),
        }
    }

    /// 5. Process the first messages of exactly 'threshold' nodes and create the second message to
    ///    be broadcast.
    ///    The second message contains the list of complaints on invalid shares. In addition, it
    ///    returns a set of valid shares (so far).
    ///    Since we assume that at most t-1 of the nodes are malicious, we only need messages from
    ///    t nodes to guarantee an unbiasable and unpredictable beacon. (The result is secure with
    ///    rushing adversaries according to https://eprint.iacr.org/2021/005.pdf.)
    pub fn create_second_message<R: AllowedRng>(
        &self,
        messages: &[FirstMessage<G, EG>],
        rng: &mut R,
    ) -> Result<(SharesMap<G>, SecondMessage<EG>), FastCryptoError> {
        if messages.len() != self.threshold as usize {
            return Err(FastCryptoError::InputLengthWrong(self.threshold as usize));
        }

        let my_id = self.id;
        let mut shares = HashMap::new(); // Will include only valid shares.
        let mut next_message = SecondMessage {
            sender: my_id,
            complaints: Vec::new(),
        };

        for message in messages {
            // Ignore if the threshold is different (and other honest parties will ignore as well).
            if message.vss_pk.degree() != self.threshold - 1 {
                continue;
            }
            // TODO: check that current dealer is in the list of pki nodes.
            // Get the relevant encrypted share (or skip message).
            let encrypted_share = message
                .encrypted_shares
                .iter()
                .find(|n| n.receiver == my_id);
            // No share for me.
            if encrypted_share.is_none() {
                next_message
                    .complaints
                    .push(Complaint::NoShare(message.sender));
                continue;
            }
            // Else, decrypt it.
            let share = Self::decrypt_and_check_share(
                &self.ecies_sk,
                my_id,
                &message.vss_pk,
                encrypted_share.unwrap(),
            );
            match share {
                Ok(sh) => {
                    shares.insert(message.sender, sh);
                }
                Err(_) => {
                    next_message
                        .complaints
                        .push(Complaint::InvalidEncryptedShare(
                            message.sender,
                            self.ecies_sk.create_recovery_package(
                                &encrypted_share.unwrap().encryption,
                                &self.random_oracle.extend("ecies"),
                                rng,
                            ),
                        ));
                }
            }
        }

        Ok((shares, next_message))
    }

    /// 6. Process all the second messages, check all complaints, and update the local set of
    ///    valid shares accordingly.
    ///
    ///    minimal_threshold is the minimal number of second round messages we expect. Its value is
    ///    application dependent but in most cases it should be at least 2t-1 to guarantee that at
    ///    least t honest nodes have valid shares.
    pub fn process_responses(
        &self,
        first_messages: &[FirstMessage<G, EG>],
        second_messages: &[SecondMessage<EG>],
        shares: SharesMap<G>,
        minimal_threshold: usize,
    ) -> Result<SharesMap<G>, FastCryptoError> {
        if first_messages.len() != self.threshold as usize
            || second_messages.len() < minimal_threshold
        {
            return Err(FastCryptoError::InvalidInput);
        }
        // Two hash maps for faster access in the main loop below.
        let id_to_pk: HashMap<ShareIndex, &ecies::PublicKey<EG>> =
            self.nodes.iter().map(|n| (n.id, &n.pk)).collect();
        let id_to_m1: HashMap<ShareIndex, &FirstMessage<G, EG>> =
            first_messages.iter().map(|m| (m.sender, m)).collect();

        let mut shares = shares;
        'outer: for m2 in second_messages {
            'inner: for complaint in &m2.complaints[..] {
                let accused = match complaint {
                    Complaint::NoShare(l) => *l,
                    Complaint::InvalidEncryptedShare(l, _) => *l,
                };
                // Ignore senders that are already not relevant, or invalid complaints.
                if !shares.contains_key(&accused) {
                    continue 'inner;
                }
                // TODO: check that current accuser is in nodes (and thus in id_to_pk).
                let accuser = m2.sender;
                let accuser_pk = id_to_pk.get(&accuser).unwrap();
                let relevant_m1 = id_to_m1.get(&accused);
                // If the claim refers to a non existing message, it's an invalid complaint.
                let mut valid_complaint = relevant_m1.is_some() && {
                    let encrypted_share = relevant_m1
                        .unwrap()
                        .encrypted_shares
                        .iter()
                        .find(|s| s.receiver == accuser);
                    match complaint {
                        Complaint::NoShare(_) => {
                            // Check if there is a share.
                            encrypted_share.is_none()
                        }
                        Complaint::InvalidEncryptedShare(accused, recovery_pkg) => {
                            if encrypted_share.is_none() {
                                false // Strange case indeed, but still an invalid claim.
                            } else {
                                Self::check_delegated_key_and_share(
                                    recovery_pkg,
                                    &accuser_pk,
                                    accuser,
                                    &relevant_m1.unwrap().vss_pk,
                                    encrypted_share.unwrap(),
                                    &self.random_oracle.extend("ecies"),
                                )
                                .is_ok()
                            }
                        }
                    }
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

    /// 7. Aggregate the valid shares (as returned from the previous step) and the public key.
    pub fn aggregate(
        &self,
        first_messages: &[FirstMessage<G, EG>],
        shares: SharesMap<G>,
    ) -> DkgOutput<G, EG> {
        let id_to_m1: HashMap<_, _> = first_messages.iter().map(|m| (m.sender, m)).collect();
        let mut nodes = Vec::new();
        let mut vss_pk = PublicPoly::<G>::zero();
        let mut sk = G::ScalarType::zero();
        for (from_sender, share) in shares {
            nodes.push(
                self.nodes
                    .iter()
                    .find(|n| n.id == from_sender)
                    .unwrap() // Safe since the caller already checked that previously.
                    .clone(),
            );
            vss_pk.add(&id_to_m1.get(&from_sender).unwrap().vss_pk);
            sk += share;
        }

        DkgOutput {
            nodes,
            vss_pk,
            share: Share {
                index: self.id,
                value: sk,
            },
        }
    }

    fn decrypt_and_check_share(
        sk: &ecies::PrivateKey<EG>,
        id: ShareIndex,
        vss_pk: &PublicPoly<G>,
        encrypted_share: &EncryptedShare<EG>,
    ) -> Result<G::ScalarType, FastCryptoError> {
        let buffer = sk.decrypt(&encrypted_share.encryption);
        Self::deserialize_and_check_share(buffer, id, vss_pk)
    }

    fn deserialize_and_check_share(
        buffer: Vec<u8>,
        id: ShareIndex,
        vss_pk: &PublicPoly<G>,
    ) -> Result<G::ScalarType, FastCryptoError> {
        let share: G::ScalarType =
            bincode::deserialize(&buffer).map_err(|_| FastCryptoError::InvalidInput)?;
        if !vss_pk.is_valid_share(id, &share) {
            return Err(FastCryptoError::InvalidProof);
        }
        Ok(share)
    }

    fn check_delegated_key_and_share(
        recovery_pkg: &RecoveryPackage<EG>,
        ecies_pk: &ecies::PublicKey<EG>,
        id: ShareIndex,
        vss_pk: &PublicPoly<G>,
        encrypted_share: &EncryptedShare<EG>,
        random_oracle: &RandomOracle,
    ) -> Result<G::ScalarType, FastCryptoError> {
        let buffer = ecies_pk.decrypt_with_recovery_package(
            &recovery_pkg,
            random_oracle,
            &encrypted_share.encryption,
        )?;
        Self::deserialize_and_check_share(buffer, id, vss_pk)
    }
}
