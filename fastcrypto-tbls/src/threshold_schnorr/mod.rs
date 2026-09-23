// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module implements threshold Schnorr signatures.
//! The signatures are compatible with BIP-0340.
//!
//! It provides the following protocols:
//!
//! 1. A Distributed Key Generation (DKG) protocol to generate a shared signing key without a
//!    trusted dealer. The protocol also allows resharing of a share from a previous DKG, allowing
//!    for key rotation. This is implemented in the [avss] module.
//! 2. A protocol to generate a batch of secret shared nonces for signing. This is implemented in
//!    the [batch_avss_avid] module.
//! 3. A presigning protocol to create presigning tuples from the secret shared nonces. This is
//!    implemented in the [presigning] module. The presigning tuples can be created in advance of
//!    knowing the message to be signed, and one tuple is consumed for each signature.
//! 4. A signing protocol which allows parties to create partial signatures from a presigning
//!    tuple and aggregate them into a full signature if there are enough partial signatures. This
//!    is implemented in the [signing] module.
//!
//! For both the DKG and nonce generation protocols, it is assumed that each party has an
//! encryption key pair (ECIES) and these public keys are known to all parties. These can be
//! reused for all instances of the protocols.
//!
//! It is also assumed that all messages between parties are sent over authenticated channels, so
//! that the receiver of a message knows who sent it and that it was not modified.
//!
//! The thresholds are defined as follows:
//! * <i>W</i> = total weight of all parties
//! * <i>f</i> = maximum Byzantine weight
//! * <i>t</i> = threshold for signing
//!
//! For the weights used here, [Parameters::validate] checks the basic invariants `t < W`,
//! `t &geq; f` and `t + f &leq; W`. The AVID-based nonce protocol additionally requires `W > 2f`
//! (enforced in `Avid::new`).

use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::Extensions::{Challenge, Encryption, Recovery};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::GroupElement;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

mod avid;
pub mod avss;
pub mod batch_avss_avid;
mod bcs;
pub mod key_derivation;
mod merkle;
mod pascal_matrix;
pub mod presigning;
pub mod recovery_proof;
pub(crate) mod reed_solomon;
pub mod signing;

/// The group to use for the signing
pub type G = groups::secp256k1::ProjectivePoint;

/// Default scalar
pub type S = <G as GroupElement>::ScalarType;

/// The group used for multi-recipient encryption. Any group that has a secure hash-to-group can
/// be used here.
type EG = RistrettoPoint;

/// An address on the Sui network.
pub type Address = [u8; 32];

/// Threshold parameters for the AVSS protocols.
#[derive(Copy, Clone, Debug)]
pub struct Parameters {
    /// Reconstruction threshold: `≥ t` valid shares (by weight) reconstruct a secret.
    pub t: u16,
    /// Byzantine bound by share-weight.
    pub f: u16,
}

impl Parameters {
    /// Validate `(t, f)` against the given total weight `W`, checking the basic invariants needed
    /// for the sharing here: `0 < f`, `t < W`, `t ≥ f` and `t + f ≤ W`. Note the AVID-based nonce
    /// protocol has a further requirement, `W > 2f`, which is enforced when its Reed-Solomon coder
    /// is built (`Avid::new`), not here.
    pub fn validate(&self, total_weight: u16) -> FastCryptoResult<()> {
        let Parameters { t, f } = *self;
        if f == 0
            || t == 0
            || t >= total_weight
            || t < f
            || t as u32 + f as u32 > total_weight as u32
        {
            return Err(InvalidInput);
        }
        Ok(())
    }
}

/// Helper function to create a random oracle from a session ID.
fn random_oracle_from_sid(sid: &[u8]) -> RandomOracle {
    RandomOracle::new(&Hex::encode(sid))
}

/// Domain-specific extensions/tags for the random oracle for this module.
enum Extensions {
    Recovery(PartyId),
    Encryption,
    Challenge,
}

/// This represents a certificate over a payload that a subset of the parties have signed.
/// Here, the implementation is abstract, and it is up to the caller to implement the actual
/// verification functionality.
pub trait Certificate {
    type Payload;

    fn signers(&self) -> &BTreeSet<PartyId>;

    fn payload(&self) -> &Self::Payload;

    fn verify(&self) -> FastCryptoResult<()>;

    fn to_verified(&self) -> FastCryptoResult<VerifiedCertificate<Self>>
    where
        Self: Clone,
    {
        self.verify().map(|_| VerifiedCertificate(self.clone()))
    }
}

/// A [Certificate] that has already been verified.
pub struct VerifiedCertificate<C>(C);

impl<C: Certificate> VerifiedCertificate<C> {
    pub fn certificate(&self) -> &C {
        &self.0
    }

    pub fn payload(&self) -> &C::Payload {
        self.0.payload()
    }
}

impl Display for Extensions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Recovery(accuser) => write!(f, "recovery of {accuser}"),
            Encryption => write!(f, "encryption"),
            Challenge => write!(f, "challenge"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::batch_avss_avid::{ShareBatch, SharesForNode};
    use crate::threshold_schnorr::key_derivation::{
        derive_verifying_key, derive_verifying_key_internal,
    };
    use crate::threshold_schnorr::presigning::Presignatures;
    use crate::threshold_schnorr::signing::{
        aggregate_signatures, generate_partial_signatures, Excluded,
    };
    use crate::threshold_schnorr::{avss, batch_avss_avid, Address, Parameters, EG, G, S};
    use crate::types::{get_uniform_value, IndexedValue, ShareIndex};
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::collections::HashMap;
    use std::hash::Hash;
    /// A happy-path smoke test, not a reference for integrating the protocols.
    #[test]
    fn test_e2e() {
        // No complaints, all honest
        let t = 3;
        let f = 2;
        let weights = [1, 2, 2, 2];
        let n = weights.len();

        let batch_size_per_weight: u16 = 10;

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<EG>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .zip(weights)
                .map(|((id, sk), weight)| Node {
                    id: id as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        //
        // DKG
        //

        // Map from each party to the outputs it has received
        let mut dkg_outputs = HashMap::<PartyId, HashMap<PartyId, avss::AvssOutput>>::new();
        nodes.node_ids_iter().for_each(|id| {
            dkg_outputs.insert(id, HashMap::new());
        });

        for dealer_id in nodes.node_ids_iter() {
            let sid = format!("dkg-test-session-{}", dealer_id).into_bytes();
            let dealer: avss::Dealer = avss::Dealer::new(
                None,
                nodes.clone(),
                Parameters { t, f },
                sid.clone(),
                &mut rng,
            )
            .unwrap();
            let receivers = sks
                .iter()
                .enumerate()
                .map(|(id, enc_secret_key)| {
                    avss::Receiver::new(
                        nodes.clone(),
                        id as u16,
                        Parameters { t, f },
                        sid.clone(),
                        None,
                        enc_secret_key.clone(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            // Each dealer creates a message
            let message = dealer.create_message(&mut rng);

            // Each receiver processes the message. In this case, we assume all are honest and there are no complaints.
            receivers.iter().for_each(|receiver| {
                let output = assert_valid(receiver.process_message(&message, &mut rng).unwrap());
                dkg_outputs
                    .get_mut(&receiver.id())
                    .unwrap()
                    .insert(dealer_id, output);
            });
        }

        // The dealers to form the certificate should have weight >= t, and are the ones whose outputs will be used to create the final shares.
        let dkg_cert = [PartyId::from(1u8), PartyId::from(2u8)];

        // Now, each party has collected their outputs from all dealers. We use the output from the dealers in dkg_cert create the final shares for signing.
        // Each party should still keep the outputs from all dealers until the end of the epoch to handle complaints.
        let merged_shares = nodes
            .iter()
            .map(|node| {
                (
                    node.id,
                    avss::DkOutput::complete_dkg(
                        t,
                        &nodes,
                        restrict(dkg_outputs.get(&node.id).unwrap(), dkg_cert.into_iter()),
                    )
                    .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        // All receivers should now have the same verifying key
        let vk = get_uniform_value(merged_shares.values().map(|output| output.vk)).unwrap();

        // For testing, we now recover the secret key from t shares and check that the secret key matches the verification key.
        // In practice, the parties should never do this...
        let shares = merged_shares
            .values()
            .flat_map(|output| output.my_shares.shares.clone())
            .take(t as usize);
        let sk = Poly::recover_c0(t, shares).unwrap();
        assert_eq!(G::generator() * sk, vk);

        //
        // PRESIGNING
        //

        // Generate a batch of nonces for each party's share
        let mut presigning_outputs =
            HashMap::<PartyId, Vec<batch_avss_avid::ReceiverOutput>>::new();
        nodes.node_ids_iter().for_each(|id| {
            presigning_outputs.insert(id, Vec::new());
        });

        // Each dealer generates a batch of presigs per share they control.
        for dealer_id in nodes.node_ids_iter() {
            let sid = format!("presig-test-session-{}", dealer_id).into_bytes();
            let params = Parameters { t, f };
            let dealer: batch_avss_avid::Dealer = batch_avss_avid::Dealer::new(
                nodes.clone(),
                dealer_id,
                params,
                sid.clone(),
                batch_size_per_weight,
            )
            .unwrap();
            let receivers = sks
                .iter()
                .enumerate()
                .map(|(id, enc_secret_key)| {
                    batch_avss_avid::Receiver::new(
                        nodes.clone(),
                        id as u16,
                        dealer_id,
                        params,
                        sid.clone(),
                        enc_secret_key.clone(),
                        batch_size_per_weight,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            // Optimistic phase: every receiver confirms, so no pessimistic AVID phase is needed.
            let state = dealer.create_avss_messages(&mut rng).unwrap();
            for r in &receivers {
                let (output, _confirm, _verified_common) = r
                    .process_avss_message(&state.message_for(r.id).unwrap())
                    .unwrap();
                presigning_outputs.get_mut(&r.id).unwrap().push(output);
            }
        }

        // Each party can process their presigs locally from the secret shared nonces
        let mut presigs = presigning_outputs
            .into_iter()
            .map(|(id, outputs)| {
                (
                    id,
                    Presignatures::new(outputs, batch_size_per_weight, Parameters { t, f })
                        .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(
            presigs.get(&PartyId::from(1u8)).unwrap().len(),
            batch_size_per_weight as usize * (weights.iter().sum::<u16>() as usize - f as usize)
        );

        //
        // SIGNING
        //

        let message = b"Hello, world!";

        // Mock a value from the random beacon
        let beacon_value = S::rand(&mut rng);

        // Each party generates their partial signatures
        let partial_signatures = nodes
            .iter()
            .map(|node| {
                generate_partial_signatures(
                    message,
                    presigs.get_mut(&node.id).unwrap().next().unwrap(),
                    &beacon_value,
                    &merged_shares.get(&node.id).unwrap().my_shares,
                    &vk,
                    None,
                )
                .unwrap()
            })
            .collect_vec();

        // The public parts should all be the same
        let public_presig = get_uniform_value(
            partial_signatures
                .iter()
                .map(|partial_signature| partial_signature.0),
        )
        .unwrap();

        // Aggregate partial signatures
        let (signature, excluded) = aggregate_signatures(
            message,
            &public_presig,
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, s)| s.clone())
                .collect_vec(),
            Parameters { t, f },
            &vk,
            None,
        )
        .unwrap();
        assert_eq!(excluded, Excluded::NoCorrection);

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&vk)
            .unwrap()
            .verify(message, &signature)
            .unwrap();

        //
        // KEY ROTATION
        //

        // Map from each party to the ordered list of outputs it has received.
        // Here, each party will act as dealer multiple times -- once per share they have.
        let mut dkg_outputs_after_rotation =
            HashMap::<(PartyId, ShareIndex), avss::AvssOutput>::new();

        for dealer_id in nodes.node_ids_iter() {
            for share_index in nodes.share_ids_of(dealer_id).unwrap() {
                let sid =
                    format!("key-rotation-test-session-{}-{}", dealer_id, share_index).into_bytes();

                // Each dealer uses their existing share as the secret to reshare
                let secret = merged_shares
                    .get(&dealer_id)
                    .unwrap()
                    .share_for_index(share_index)
                    .unwrap()
                    .value;
                let dealer: avss::Dealer = avss::Dealer::new(
                    Some(secret),
                    nodes.clone(),
                    Parameters { t, f },
                    sid.clone(),
                    &mut rng,
                )
                .unwrap();

                let receivers = sks
                    .iter()
                    .enumerate()
                    .map(|(id, enc_secret_key)| {
                        let commitment = merged_shares
                            .get(&(id as u16))
                            .unwrap()
                            .commitment_for_index(share_index)
                            .unwrap()
                            .value;
                        avss::Receiver::new(
                            nodes.clone(),
                            id as u16,
                            Parameters { t, f },
                            sid.clone(),
                            Some(commitment),
                            enc_secret_key.clone(),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();

                // Each dealer creates a message
                let message = dealer.create_message(&mut rng);

                // Each receiver processes the message. In this case, we assume all are honest and there are no complaints.
                receivers.iter().for_each(|receiver| {
                    let output =
                        assert_valid(receiver.process_message(&message, &mut rng).unwrap());
                    dkg_outputs_after_rotation.insert((receiver.id(), share_index), output);
                });
            }
        }

        // The first t dealers (counted by weight) form the certificate and are the ones whose outputs will be used to create the final shares.
        let key_rotation_cert = [PartyId::from(1u8), PartyId::from(2u8)];
        let share_indices_in_cert = key_rotation_cert
            .iter()
            .flat_map(|id| nodes.share_ids_of(*id).unwrap())
            .collect_vec();

        // Now, each party has collected their outputs from all dealers and can form their new shares from the ones in the certificate.
        let merged_shares = nodes
            .node_ids_iter()
            .map(|receiver_id| {
                let my_shares_from_cert = share_indices_in_cert
                    .iter()
                    .map(|&index| IndexedValue {
                        index,
                        value: dkg_outputs_after_rotation
                            .get(&(receiver_id, index))
                            .unwrap()
                            .clone(),
                    })
                    .collect_vec();
                (
                    receiver_id,
                    avss::DkOutput::complete_key_rotation(
                        t,
                        receiver_id,
                        &nodes,
                        &my_shares_from_cert
                            .into_iter()
                            .take(t as usize)
                            .collect_vec(),
                    )
                    .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        // The verifying key should be the same as  before
        for output in merged_shares.values() {
            assert_eq!(output.vk, vk);
        }

        // For testing, we now recover the secret key from t shares and check that the secret key matches the verification key.
        // In practice, the parties should never do this...
        let shares = merged_shares
            .values()
            .flat_map(|output| output.my_shares.shares.clone())
            .take(t as usize);
        let sk = Poly::recover_c0(t, shares).unwrap();
        assert_eq!(G::generator() * sk, vk);

        // Check commitments on the reshared secret from the first dealer
        let commitment_1 = merged_shares.get(&0).unwrap().commitments.first().unwrap();
        let secret_1 = merged_shares
            .get(&0)
            .unwrap()
            .share_for_index(commitment_1.index)
            .unwrap()
            .value;
        assert_eq!(G::generator() * secret_1, commitment_1.value);

        //
        // SIGNING (again)
        //

        let message_2 = b"Hello again, world!";

        // Mock a value from the random beacon
        let beacon_value = S::rand(&mut rng);

        // Each party generates their partial signatures
        let partial_signatures = nodes
            .iter()
            .map(|node| {
                generate_partial_signatures(
                    message_2,
                    presigs.get_mut(&node.id).unwrap().next().unwrap(),
                    &beacon_value,
                    &merged_shares.get(&node.id).unwrap().my_shares,
                    &vk,
                    None,
                )
                .unwrap()
            })
            .collect_vec();

        // The public parts should all be the same
        let public_presig = get_uniform_value(
            partial_signatures
                .iter()
                .map(|partial_signature| partial_signature.0),
        )
        .unwrap();

        // Aggregate partial signatures
        let (signature_2, excluded) = aggregate_signatures(
            message_2,
            &public_presig,
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, s)| s.clone())
                .collect_vec(),
            Parameters { t, f },
            &vk,
            None,
        )
        .unwrap();
        assert_eq!(excluded, Excluded::NoCorrection);

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&vk)
            .unwrap()
            .verify(message_2, &signature_2)
            .unwrap();
    }

    fn assert_valid(pm: avss::ProcessedMessage) -> avss::AvssOutput {
        match pm {
            avss::ProcessedMessage::Valid(po) => po,
            avss::ProcessedMessage::Complaint(_) => panic!("expected valid avss output"),
        }
    }

    /// Restrict a `HashMap` to a given set of keys.
    /// Panics if the given subset is not a subset of the maps' keys.
    pub(crate) fn restrict<T: Clone, I: Eq + Hash>(
        map: &HashMap<I, T>,
        keys_subset: impl Iterator<Item = I>,
    ) -> HashMap<I, T>
    where
        usize: From<I>,
    {
        keys_subset
            .map(|i| {
                let value = map.get(&i).unwrap().clone();
                (i, value)
            })
            .collect()
    }

    #[test]
    fn test_signing() {
        let f = 2;
        let t = f + 1;
        let n = 3 * f + 1;

        let mut rng = rand::thread_rng();

        // Mock DKG
        // Here, we don't assume anything about the parity of the vk's Y coordinate since we can't do that in a real DKG.
        let sk_element = S::rand(&mut rng);
        let vk_element = G::generator() * sk_element;

        let sk_shares = mock_shares(&mut rng, sk_element, t, n);

        // Mock nonce generation
        let batch_size_per_weight: u16 = 10;
        let nonces_for_dealer = (0..n)
            .map(|_| {
                let nonces = (0..batch_size_per_weight)
                    .map(|_| S::rand(&mut rng))
                    .collect_vec();
                let public_keys = nonces.iter().map(|s| G::generator() * s).collect_vec();
                let nonce_shares: Vec<Vec<S>> = nonces
                    .iter()
                    .map(|&nonce| {
                        mock_shares(&mut rng, nonce, t, n)
                            .iter()
                            .map(|s| s.value)
                            .collect_vec()
                    })
                    .collect_vec();
                (nonces, public_keys, nonce_shares)
            })
            .collect_vec();

        let outputs = (0..n)
            .map(|i| {
                (0..n)
                    .map(|j| {
                        batch_avss_avid::ReceiverOutput {
                            my_shares: SharesForNode {
                                shares: vec![ShareBatch {
                                    batch: (0..batch_size_per_weight as usize)
                                        .map(|l| nonces_for_dealer[j as usize].2[l][i as usize])
                                        .collect_vec(),
                                    blinding_share: Default::default(), // Not used for this test
                                }],
                            },
                            public_keys: nonces_for_dealer[j as usize].1.clone(),
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let mut presigning = outputs
            .into_iter()
            .map(|output| {
                Presignatures::new(output, batch_size_per_weight, Parameters { t, f }).unwrap()
            })
            .collect_vec();

        assert_eq!(
            presigning[0].len(),
            batch_size_per_weight as usize * (n - f) as usize
        );

        let message = b"Hello, world!";

        let beacon_value = S::rand(&mut rng);

        let partial_signatures = presigning
            .iter_mut()
            .enumerate()
            .map(|(i, presigning)| {
                let my_shares = avss::SharesForNode {
                    shares: vec![sk_shares[i].clone()],
                };
                generate_partial_signatures(
                    message,
                    presigning.next().unwrap(),
                    &beacon_value,
                    &my_shares,
                    &vk_element,
                    None,
                )
                .unwrap()
            })
            .collect_vec();

        let public = get_uniform_value(
            partial_signatures
                .iter()
                .map(|partial_signature| partial_signature.0),
        )
        .unwrap();

        let (signature, excluded) = aggregate_signatures(
            message,
            &public,
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
            Parameters { t, f },
            &vk_element,
            None,
        )
        .unwrap();
        assert_eq!(excluded, Excluded::NoCorrection);

        // Check that this produced a valid signature
        SchnorrPublicKey::try_from(&vk_element)
            .unwrap()
            .verify(message, &signature)
            .unwrap();

        // A single invalid partial signature is corrected and its index reported.
        let mut corrupted = partial_signatures
            .iter()
            .flat_map(|(_, sigs)| sigs.clone())
            .collect_vec();
        corrupted[0].value = S::rand(&mut rng);
        let (corrected, excluded) = aggregate_signatures(
            message,
            &public,
            &beacon_value,
            &corrupted,
            Parameters { t, f },
            &vk_element,
            None,
        )
        .unwrap();
        assert_eq!(excluded, Excluded::Blamable(vec![corrupted[0].index]));
        SchnorrPublicKey::try_from(&vk_element)
            .unwrap()
            .verify(message, &corrected)
            .unwrap();

        // Honest partial signatures with the wrong beacon here: the decoding rules them out as the
        // cause, so this is reported as the inputs disagreeing rather than as a bad signature.
        let honest = partial_signatures
            .iter()
            .flat_map(|(_, sigs)| sigs.clone())
            .collect_vec();
        assert!(matches!(
            aggregate_signatures(
                message,
                &public,
                &(beacon_value + S::generator()),
                &honest,
                Parameters { t, f },
                &vk_element,
                None,
            ),
            Err(fastcrypto::error::FastCryptoError::InconsistentInputs)
        ));

        // The same fault is still corrected from five partial signatures, but excluding it leaves
        // four, short of the `t + f` the aggregation wants before it will name an index.
        let (corrected, excluded) = aggregate_signatures(
            message,
            &public,
            &beacon_value,
            &corrupted[..5],
            Parameters { t, f },
            &vk_element,
            None,
        )
        .unwrap();
        assert_eq!(excluded, Excluded::Inconclusive(vec![corrupted[0].index]));
        SchnorrPublicKey::try_from(&vk_element)
            .unwrap()
            .verify(message, &corrected)
            .unwrap();
    }

    /// Sign with every combination of the Y parities of the verifying key, the nonce R and the
    /// derived verifying key, since each selects a different branch in the BIP-0340 adjustments.
    #[test]
    fn test_signing_all_parities() {
        let (t, f, n) = (3u16, 2u16, 5u16);
        let message = b"parity";
        let mut rng = rand::thread_rng();
        let has_even_y = |p: &G| p.has_even_y().unwrap();

        for vk_even in [true, false] {
            let sk = loop {
                let sk = S::rand(&mut rng);
                if has_even_y(&(G::generator() * sk)) == vk_even {
                    break sk;
                }
            };
            let vk = G::generator() * sk;
            let sk_shares = mock_shares(&mut rng, sk, t, n);

            // No derivation, and addresses whose derived verifying keys have even and odd Y.
            let address_with = |derived_even: bool| -> Address {
                (0u8..=255)
                    .map(|i| [i; 32])
                    .find(|a| {
                        has_even_y(&derive_verifying_key_internal(&vk, a).unwrap()) == derived_even
                    })
                    .unwrap()
            };
            for address in [None, Some(address_with(true)), Some(address_with(false))] {
                for nonce_even in [true, false] {
                    let presig = S::rand(&mut rng);
                    let public_presig = G::generator() * presig;
                    let presig_shares = mock_shares(&mut rng, presig, t, n);
                    let beacon = loop {
                        let beacon = S::rand(&mut rng);
                        if has_even_y(&(public_presig + G::generator() * beacon)) == nonce_even {
                            break beacon;
                        }
                    };

                    let partial_signatures = (0..n as usize)
                        .flat_map(|i| {
                            generate_partial_signatures(
                                message,
                                (vec![presig_shares[i].value], public_presig),
                                &beacon,
                                &avss::SharesForNode {
                                    shares: vec![sk_shares[i].clone()],
                                },
                                &vk,
                                address.as_ref(),
                            )
                            .unwrap()
                            .1
                        })
                        .collect_vec();
                    let (signature, excluded) = aggregate_signatures(
                        message,
                        &public_presig,
                        &beacon,
                        &partial_signatures,
                        Parameters { t, f },
                        &vk,
                        address.as_ref(),
                    )
                    .unwrap();
                    assert_eq!(excluded, Excluded::NoCorrection);

                    match address {
                        Some(address) => derive_verifying_key(&vk, &address).unwrap(),
                        None => SchnorrPublicKey::try_from(&vk).unwrap(),
                    }
                    .verify(message, &signature)
                    .unwrap();
                }
            }
        }
    }

    fn mock_shares(rng: &mut impl AllowedRng, secret: S, t: u16, n: u16) -> Vec<Eval<S>> {
        let p = Poly::rand_fixed_c0(t - 1, secret, rng);
        (1..=n)
            .map(|i| p.eval(ShareIndex::new(i).unwrap()))
            .collect_vec()
    }

    #[test]
    fn test_derived_signing() {
        let f = 2;
        let t = f + 1;
        let n = 3 * f + 1;

        let mut rng = rand::thread_rng();

        // Mock DKG
        // Here, we don't assume anything about the parity of the vk's Y coordinate since we can't do that in a real DKG.
        let sk_element = S::rand(&mut rng);
        let vk_element = G::generator() * sk_element;

        let sk_shares = mock_shares(&mut rng, sk_element, t, n);

        // Mock nonce generation
        let batch_size_per_weight: u16 = 100;
        let nonces_for_dealer = (0..n)
            .map(|_| {
                let nonces = (0..batch_size_per_weight)
                    .map(|_| S::rand(&mut rng))
                    .collect_vec();
                let public_keys = nonces.iter().map(|s| G::generator() * s).collect_vec();
                let nonce_shares: Vec<Vec<S>> = nonces
                    .iter()
                    .map(|&nonce| {
                        mock_shares(&mut rng, nonce, t, n)
                            .iter()
                            .map(|s| s.value)
                            .collect_vec()
                    })
                    .collect_vec();
                (nonces, public_keys, nonce_shares)
            })
            .collect_vec();

        let outputs = (0..n)
            .map(|i| {
                (0..n as usize)
                    .map(|j| {
                        batch_avss_avid::ReceiverOutput {
                            my_shares: SharesForNode {
                                shares: vec![ShareBatch {
                                    batch: (0..batch_size_per_weight as usize)
                                        .map(|l| nonces_for_dealer[j].2[l][i as usize])
                                        .collect_vec(),
                                    blinding_share: Default::default(), // Not used for this test
                                }],
                            },
                            public_keys: nonces_for_dealer[j].1.clone(),
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let mut presigning = outputs
            .into_iter()
            .map(|output| {
                Presignatures::new(output, batch_size_per_weight, Parameters { t, f }).unwrap()
            })
            .collect_vec();

        assert_eq!(
            presigning[0].len(),
            batch_size_per_weight as usize * (n - f) as usize
        );

        let message = b"Hello, world!";

        let beacon_value = S::rand(&mut rng);
        let address = [7u8; 32];
        let partial_signatures = presigning
            .iter_mut()
            .enumerate()
            .map(|(i, presigning)| {
                let my_shares = avss::SharesForNode {
                    shares: vec![sk_shares[i].clone()],
                };
                generate_partial_signatures(
                    message,
                    presigning.next().unwrap(),
                    &beacon_value,
                    &my_shares,
                    &vk_element,
                    Some(&address),
                )
                .unwrap()
            })
            .collect_vec();

        let public = get_uniform_value(
            partial_signatures
                .iter()
                .map(|partial_signature| partial_signature.0),
        )
        .unwrap();

        let (signature, excluded) = aggregate_signatures(
            message,
            &public,
            &beacon_value,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
            Parameters { t, f },
            &vk_element,
            Some(&address),
        )
        .unwrap();
        assert_eq!(excluded, Excluded::NoCorrection);

        // Check that this produced a valid signature
        derive_verifying_key(&vk_element, &address)
            .unwrap()
            .verify(message, &signature)
            .unwrap();
    }
}
