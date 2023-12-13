// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//

use crate::dl_verification::{
    verify_deg_t_poly, verify_equal_exponents, verify_pairs, verify_triplets,
};
use crate::ecies;
use crate::ecies::{PublicKey, RecoveryPackage};
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::{Eval, Poly, PrivatePoly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{bls12381, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use fastcrypto::hmac::{hmac_sha3_256, HmacKey};
use fastcrypto::traits::{AllowedRng, ToFromBytes};
use itertools::izip;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroU32;

/// Party in the DKG protocol.
pub struct Party<G: GroupElement>
where
    G::ScalarType: Serialize + DeserializeOwned,
{
    id: PartyId,
    nodes: Nodes<G>,
    t: u32,
    random_oracle: RandomOracle,
    ecies_sk: ecies::PrivateKey<G>,
    vss_sk: PrivatePoly<G>,
    // Precomputed values to be used when verifying messages.
    precomputed_dual_code_coefficients: Vec<G::ScalarType>,
}

const NUM_OF_ENCRYPTIONS_PER_SHARE: usize = 2;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Encryptions<G: GroupElement> {
    values: [ecies::Encryption<G>; NUM_OF_ENCRYPTIONS_PER_SHARE],
}

#[derive(Clone, Debug, Serialize)]
enum EncryptionInfo<G: GroupElement> {
    // Let the encryption be (k*G, AES_{hkdf(k*xG)}(k)).

    // k_x_g is used instead of k to reduce verification time.
    ForVerification { k_x_g: G },
    // share - k
    ForEvaluation { diff: G::ScalarType },
}

#[derive(Clone, Serialize)]
struct ProcessedEncryptions<G: GroupElement>
where
    G::ScalarType: Serialize + DeserializeOwned,
{
    infos: [EncryptionInfo<G>; NUM_OF_ENCRYPTIONS_PER_SHARE],
}

#[derive(Clone, Serialize)]
pub struct Message<G: GroupElement>
where
    G::ScalarType: Serialize + DeserializeOwned,
{
    sender: PartyId,
    // Next vectors have one item per share, ordered according to the share ids.
    partial_pks: Vec<G>, // TODO: [security] need a proof of possession/knowledge?
    encryptions: Vec<Encryptions<G>>,
    processed_encryptions: Vec<ProcessedEncryptions<G>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Complaint<G: GroupElement> {
    sender: u16,
    share_id: ShareIndex,
    package: RecoveryPackage<G>, // There is at most one with ForVerification encryption.
}

/// A dealer in the DKG protocol.
impl<G> Party<G>
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    <G as GroupElement>::ScalarType: Serialize + DeserializeOwned + FiatShamirChallenge,
{
    /// 1. Create a new private key and send the public key to all parties.
    ///
    /// 2. After all parties have sent their public keys, create the set of nodes. We assume here
    ///    that the set of nodes is the same for all parties, and that their ids are 0..n-1.
    ///
    /// 3. Create a new Party instance with the private key and the set of nodes.
    pub fn new<R: AllowedRng>(
        ecies_sk: ecies::PrivateKey<G>,
        nodes: Vec<Node<G>>,
        t: u32, // The number of shares that are needed to reconstruct the full signature.
        random_oracle: RandomOracle,
        rng: &mut R,
    ) -> Result<Self, FastCryptoError> {
        let ecies_pk = ecies::PublicKey::<G>::from_private_key(&ecies_sk);
        let my_id = nodes
            .iter()
            .find(|n| n.pk == ecies_pk)
            .ok_or(FastCryptoError::InvalidInput)?
            .id;
        let nodes = Nodes::new(nodes)?;
        let n = nodes.total_weight();
        if t >= n {
            return Err(FastCryptoError::InvalidInput);
        }
        let vss_sk = PrivatePoly::<G>::rand(t - 1, rng);

        // Precompute the dual code coefficients.
        let ids_as_scalars = (1..=n)
            .map(|i| (i, G::ScalarType::from(i as u64)))
            .collect::<HashMap<_, _>>();
        let precomputed_dual_code_coefficients = (1..=n)
            .map(|i| {
                (1..=n)
                    .filter(|j| i != *j)
                    .map(|j| ids_as_scalars[&i] - ids_as_scalars[&j])
                    .fold(G::ScalarType::generator(), |acc, x| acc * x)
                    .inverse()
                    .expect("non zero")
            })
            .collect();

        Ok(Self {
            id: my_id,
            nodes,
            t,
            random_oracle,
            ecies_sk,
            vss_sk,
            precomputed_dual_code_coefficients,
        })
    }

    /// 4. Create the message to be sent to all parties.
    pub fn create_message<R: AllowedRng>(&self, rng: &mut R) -> Message<G> {
        // TODO: Can this be done faster?
        let partial_pks = self
            .nodes
            .share_ids_iter()
            .map(|i| G::generator() * self.vss_sk.eval(i).value)
            .collect();
        let mut interim_values: Vec<[(G::ScalarType, G); NUM_OF_ENCRYPTIONS_PER_SHARE]> =
            Vec::new();
        let pairs = self
            .nodes
            .share_ids_iter()
            .map(|share_id| {
                let mut values = Vec::new();
                let node = self
                    .nodes
                    .share_id_to_node(&share_id)
                    .expect("using valid share id");
                let encryptions = (0..NUM_OF_ENCRYPTIONS_PER_SHARE)
                    .map(|_| {
                        let r = G::ScalarType::rand(rng);
                        let msg = bcs::to_bytes(&r).expect("serialization should work");
                        let r_g = G::generator() * r;
                        let r_x_g = *node.pk.as_element() * r;
                        // Save also the points instead of recomputing them later.
                        values.push((r, r_x_g));
                        PublicKey::deterministic_encrypt(&msg, &r_g, &r_x_g)
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("should work");
                interim_values.push(values.try_into().expect("should work"));
                Encryptions {
                    values: encryptions,
                }
            })
            .collect();
        let msg_before_fiat_shamir = Message {
            sender: self.id,
            encryptions: pairs,
            partial_pks,
            processed_encryptions: Vec::new(), // pre fiat-shamir
        };
        // Compute the cut-and-choose challenge bits.
        let ro = self
            .random_oracle
            .extend(format!("_{}_cut_and_choose", self.id).as_str());
        let seed = ro.evaluate(&msg_before_fiat_shamir);
        let challenge = Self::challenge(seed.as_slice(), self.nodes.total_weight());

        // Reveal the scalars corresponding to the challenge bits.
        let processed_pairs = izip!(
            self.nodes.share_ids_iter(),
            challenge.iter(),
            interim_values.iter()
        )
        .map(|(share_id, chal, &values)| {
            let share = self.vss_sk.eval(share_id).value;
            let infos = (0..NUM_OF_ENCRYPTIONS_PER_SHARE)
                .map(|i| {
                    if chal[i] {
                        EncryptionInfo::ForVerification { k_x_g: values[i].1 }
                    } else {
                        EncryptionInfo::ForEvaluation {
                            diff: share - values[i].0,
                        }
                    }
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("should work");
            ProcessedEncryptions { infos }
        })
        .collect();

        Message {
            processed_encryptions: processed_pairs,
            ..msg_before_fiat_shamir
        }
    }

    /// 5. Verify messages (and store the valid ones elsewhere).
    pub fn verify_message<R: AllowedRng>(
        &self,
        msg: &Message<G>,
        rng: &mut R,
    ) -> FastCryptoResult<()> {
        // Check the degree of the sender's polynomial..
        verify_deg_t_poly(
            self.nodes.total_weight() - self.t - 1,
            &msg.partial_pks,
            &self.precomputed_dual_code_coefficients,
            rng,
        )?;

        // Check the cut-and-choose encryptions.
        let msg_before_fiat_shamir = Message {
            processed_encryptions: Vec::new(),
            ..msg.clone()
        };
        let ro = self
            .random_oracle
            .extend(format!("_{}_cut_and_choose", msg.sender).as_str());
        let seed = ro.evaluate(&msg_before_fiat_shamir);
        let challenge = Self::challenge(seed.as_slice(), self.nodes.total_weight());

        let mut pairs_to_check = Vec::new();
        let mut tuples_to_check = Vec::new();
        let all_ok = izip!(
            self.nodes.share_ids_iter(),
            msg.encryptions.iter(),
            challenge.iter(),
            msg.processed_encryptions.iter(),
            msg.partial_pks.iter()
        )
        .all(
            |(share_id, encryptions, chal, proc_encryptions, partial_pk)| {
                let node = self
                    .nodes
                    .share_id_to_node(&share_id)
                    .expect("valid share id");
                for (i, enc) in encryptions.values.iter().enumerate() {
                    // Some of the checks are verified as a batch below, using MSM.
                    match (chal[i], &proc_encryptions.infos[i]) {
                        (true, EncryptionInfo::ForVerification { k_x_g }) => {
                            let msg = enc.decrypt_from_partial_decryption(k_x_g);
                            let k: G::ScalarType = match bcs::from_bytes(&msg) {
                                Ok(k) => k,
                                Err(_) => {
                                    return false;
                                }
                            };
                            pairs_to_check.push((k, *enc.ephemeral_key()));
                            tuples_to_check.push((k, *node.pk.as_element(), *k_x_g))
                        }
                        (false, EncryptionInfo::ForEvaluation { diff }) => {
                            pairs_to_check.push((*diff, *partial_pk - enc.ephemeral_key()))
                        }
                        _ => {
                            return false;
                        }
                    }
                }
                true
            },
        );

        if all_ok {
            verify_pairs(&pairs_to_check, rng)?;
            verify_triplets(&tuples_to_check, rng)?;
            Ok(())
        } else {
            Err(FastCryptoError::InvalidProof)
        }
    }

    pub fn is_above_t(&self, messages: &[Message<G>]) -> FastCryptoResult<()> {
        let id_to_weight = self
            .nodes
            .iter()
            .map(|n| (n.id, n.weight))
            .collect::<HashMap<_, _>>();
        let sum = messages
            .iter()
            .map(|m| id_to_weight[&m.sender] as u32)
            .sum::<u32>();
        if sum < self.t {
            Err(FastCryptoError::InvalidInput)
        } else {
            Ok(())
        }
    }

    /// 6. Given enough verified messages, compute the final public keys.
    pub fn compute_final_pks(&self, messages: &[Message<G>]) -> (G, Vec<G>) {
        assert!(self.is_above_t(messages).is_ok());

        let partial_pks = (0..self.nodes.total_weight())
            .map(|i| {
                messages
                    .iter()
                    .map(|m| m.partial_pks[i as usize])
                    .fold(G::zero(), |acc, pk| acc + pk)
            })
            .collect::<Vec<_>>();

        // Compute the BLS pk
        let evals = partial_pks
            .iter()
            .take(self.t as usize)
            .enumerate()
            .map(|(i, pk)| Eval {
                index: NonZeroU32::new((i + 1) as u32).expect("non zero"),
                value: *pk,
            });
        let pk = Poly::<G>::recover_c0(self.t, evals).expect("enough shares");

        (pk, partial_pks)
    }

    /// 7. Process a verified message and return decrypted shares and/or complaints.
    ///    The higher level code could send each complaint individually or wrap in a vector.
    pub fn process_message<R: AllowedRng>(
        &self,
        msg: &Message<G>,
        rng: &mut R,
    ) -> (Vec<PartialShare<G>>, Vec<Complaint<G>>) {
        let mut shares = Vec::new();
        let mut complaints = Vec::new();
        self.nodes
            .share_ids_iter()
            .filter(|id| self.nodes.share_id_to_node(id).expect("valid share id").id == self.id)
            .for_each(|share_id| {
                let offset = (share_id.get() - 1) as usize;
                let partial_pk = &msg.partial_pks[offset];
                let encryptions = &msg.encryptions[offset];
                let processed_encs = &msg.processed_encryptions[offset];
                for i in 0..NUM_OF_ENCRYPTIONS_PER_SHARE {
                    if let EncryptionInfo::ForEvaluation { diff } = processed_encs.infos[i] {
                        let decrypted_value = self.ecies_sk.decrypt(&encryptions.values[i]);
                        let k: G::ScalarType =
                            bcs::from_bytes(&decrypted_value).expect("deserialization should work");
                        if G::generator() * (k + diff) == *partial_pk {
                            shares.push(PartialShare {
                                message_sender: msg.sender,
                                share_id,
                                value: k + diff,
                            });
                        } else {
                            let ro = self
                                .random_oracle
                                .extend(format!("-{}-recovery", self.id).as_str());
                            complaints.push(Complaint {
                                sender: msg.sender,
                                share_id,
                                package: self.ecies_sk.create_recovery_package(
                                    &encryptions.values[i],
                                    &ro,
                                    rng,
                                ),
                            });
                        }
                    }
                }
            });

        (shares, complaints)
    }

    /// 8. Process each complaint individually. If valid, get the identifier of the malicious sender.
    ///    The higher level code can handle each complaint individually or together. For each
    ///    malicious sender, the higher level code should send the current party's shares received
    ///    from that sender.
    pub fn process_complaint(
        &self,
        verified_messages: &[Message<G>],
        complaint: &Complaint<G>,
    ) -> FastCryptoResult<u16> {
        //
        let sender = complaint.sender;
        let msg = verified_messages
            .iter()
            .find(|msg| msg.sender == sender)
            .ok_or(FastCryptoError::InvalidProof)?;
        let offset = (complaint.share_id.get() - 1) as usize;
        let encryptions = &msg.encryptions[offset];
        let processed_encs = &msg.processed_encryptions[offset];
        let reciever_node = self.nodes.share_id_to_node(&complaint.share_id)?;
        for i in 0..NUM_OF_ENCRYPTIONS_PER_SHARE {
            if let EncryptionInfo::ForEvaluation { diff: _ } = processed_encs.infos[i] {
                let ro = self
                    .random_oracle
                    .extend(format!("-{}-recovery", reciever_node.id).as_str());
                let descrypted_msg = reciever_node.pk.decrypt_with_recovery_package(
                    &complaint.package,
                    &ro,
                    &encryptions.values[i],
                )?;
                let k: G::ScalarType =
                    bcs::from_bytes(&descrypted_msg).expect("deserialization should work");
                let k_g = G::generator() * k;
                if k_g == *encryptions.values[i].ephemeral_key() {
                    return Err(FastCryptoError::InvalidProof);
                }
            }
        }
        Ok(msg.sender)
    }

    // Returns deterministic n pairs of challenge bits 00/01/11.
    fn challenge(seed: &[u8], n: u32) -> Vec<[bool; NUM_OF_ENCRYPTIONS_PER_SHARE]> {
        let hmac_key = HmacKey::from_bytes(seed).expect("HMAC key should be valid");
        let mut res = Vec::new();
        let mut i: u32 = 0;
        let mut random_bits = Vec::new();
        while res.len() < n as usize {
            if random_bits.is_empty() {
                let random_bytes = hmac_sha3_256(&hmac_key, i.to_le_bytes().as_slice()).to_vec();
                random_bits = random_bytes
                    .iter()
                    .flat_map(|&byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
                    .collect();
                i += 1;
            }
            // random_bits.len() is always even.
            let b0 = random_bits.pop().expect("non empty");
            let b1 = random_bits.pop().expect("non empty");
            // skip 11
            if !b0 | !b1 {
                res.push([b0, b1]);
            }
        }
        res
    }

    #[cfg(test)]
    pub fn modify_message_swap_partial_pks(message: &mut Message<G>, i: usize, j: usize) {
        message.partial_pks.swap(i, j);
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PartialShare<G: GroupElement> {
    message_sender: u16,
    share_id: ShareIndex,
    value: G::ScalarType,
}

impl Party<bls12381::G1Element> {
    /// *4. [optional] Create the partial public key in bls12381::G2Element.
    pub fn create_partial_pks_in_g2(&self) -> Vec<bls12381::G2Element> {
        self.nodes
            .share_ids_iter()
            .map(|i| bls12381::G2Element::generator() * self.vss_sk.eval(i).value)
            .collect()
    }

    /// 5*. [optional] Verify the partial pk in bls12381::G2Element.
    pub fn verify_partial_pks_in_g2<R: AllowedRng>(
        msg: &Message<bls12381::G1Element>,
        partial_pk: &[bls12381::G2Element],
        rng: &mut R,
    ) -> FastCryptoResult<()> {
        verify_equal_exponents(&msg.partial_pks, partial_pk, rng)
    }
}
