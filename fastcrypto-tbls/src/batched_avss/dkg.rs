// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::batched_avss::complaint::{Complaint, ComplaintResponse};
use crate::batched_avss::ro_extension::Extension::Encryption;
use crate::batched_avss::ro_extension::RandomOracleExtensions;
use crate::batched_avss::SharesForNode as _;
use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{interpolate_at_index, Eval, Poly, PublicPoly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InputLengthWrong, InvalidInput};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{
    FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul, Scalar,
};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tap::TapFallible;
use tracing::warn;
use zeroize::Zeroize;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<G: GroupElement, EG: GroupElement> {
    threshold: u16,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
    secrets_batch: Vec<G::ScalarType>,
    _group: PhantomData<G>,
}

pub struct Receiver<G, EG: GroupElement>
where
    EG::ScalarType: Zeroize,
{
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    previous_round_commitments: Vec<G>, // Commitments to the polynomials of the previous round, used to verify the shares
    random_oracle: RandomOracle,
    threshold: u16,
    _group: PhantomData<G>,
}

/// The output of a receiver: The shares for each nonce. This can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<G: GroupElement> {
    pub my_shares: SharesForNode<G::ScalarType>,
}

/// All the shares given to a node -- one batch per share index/weight.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesForNode<C> {
    batches: Vec<ShareBatch<C>>,
}

impl<C: Scalar> super::SharesForNode<C> for SharesForNode<C> {
    fn weight(&self) -> usize {
        self.batches.len()
    }

    fn shares_for_secret(&self, i: usize) -> FastCryptoResult<Vec<Eval<C>>> {
        if i >= self.batch_size() {
            return Err(InvalidInput);
        }
        Ok(self
            .batches
            .iter()
            .map(|share_batch| Eval {
                index: share_batch.index,
                value: share_batch.shares[i],
            })
            .collect())
    }

    fn indices(&self) -> Vec<ShareIndex> {
        self.batches.iter().map(|b| b.index).collect()
    }

    fn recover(indices: Vec<ShareIndex>, other_shares: &[Self]) -> FastCryptoResult<Self> {
        if other_shares.is_empty() || !other_shares.iter().map(|s| s.batch_size()).all_equal() {
            return Err(InvalidInput);
        }
        let batch_size = other_shares[0].batch_size();

        let batches = indices
            .into_iter()
            .map(|index| {
                let shares = (0..batch_size)
                    .map(|i| {
                        let evaluations: Vec<Eval<C>> = other_shares
                            .iter()
                            .flat_map(|s| s.shares_for_secret(i).expect("Size checked above"))
                            .collect_vec();
                        interpolate_at_index(index, &evaluations).unwrap().value
                    })
                    .collect_vec();

                Ok(ShareBatch { index, shares })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self { batches })
    }

    fn batch_size(&self) -> usize {
        assert!(!self.batches.is_empty());
        self.batches[0].shares.len()
    }
}

/// The message broadcast by the dealer, containing the encrypted shares and the public keys of the nonces.
#[derive(Clone, Debug)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    ciphertext: MultiRecipientEncryption<EG>,
    commitments: Vec<PublicPoly<G>>,
}

/// A certificate on a [Message].
pub trait Certificate<G: GroupElement, EG: GroupElement> {
    fn is_valid(&self, message: &Message<G, EG>, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}

/// The result of processing a certificate by a receiver: Either valid shares, a complaint, or ignore if the receiver was already included.
#[derive(Debug, Clone)]
pub enum ProcessCertificateResult<G: GroupElement, EG: GroupElement> {
    Valid(ReceiverOutput<G>),
    Complaint(Complaint<EG>),
    Ignore,
}

/// The shares for a receiver, containing shares for each nonce and one for the combined polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch<C> {
    pub index: ShareIndex,
    pub shares: Vec<C>,
}

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    pub fn new(
        secrets_batch: Vec<G::ScalarType>,
        nodes: Nodes<EG>,
        threshold: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
    ) -> FastCryptoResult<Self> {
        // Sanity check that the threshold makes sense (t <= n/2 since we later wait for 2t-1).
        if threshold > (nodes.total_weight() / 2) {
            return Err(InvalidInput);
        }
        Ok(Self {
            secrets_batch,
            threshold,
            nodes,
            random_oracle,
            _group: PhantomData,
        })
    }

    /// 1. The Dealer samples nonces, generates shares and broadcasts the encrypted shares.
    ///    This also returns the output of the protocol, e.g., the nonces.
    pub fn create_message<Rng: AllowedRng>(
        &self,
        rng: &mut Rng,
    ) -> FastCryptoResult<Message<G, EG>> {
        let polynomials = self
            .secrets_batch
            .iter()
            .map(|c0| Poly::rand_fixed_c0(self.threshold, *c0, rng))
            .collect_vec();

        let commitments = polynomials.iter().map(Poly::commit).collect_vec();

        // Encrypt all shares to the receivers
        let pk_and_msgs = self
            .nodes
            .iter()
            .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
            .map(|(public_key, share_ids)| {
                (
                    public_key,
                    SharesForNode {
                        batches: share_ids
                            .into_iter()
                            .map(|index| ShareBatch {
                                index,
                                shares: polynomials
                                    .iter()
                                    .map(|p_l| p_l.eval(index).value)
                                    .collect(),
                            })
                            .collect_vec(),
                    },
                )
            })
            .map(|(pk, shares)| (pk, shares.to_bytes()))
            .collect_vec();

        let ciphertext =
            MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

        Ok(Message {
            ciphertext,
            commitments,
        })
    }
}

impl<
        G: GroupElement + Serialize + MultiScalarMul,
        EG: GroupElement + HashToGroupElement + Serialize,
    > Receiver<G, EG>
where
    G::ScalarType: FiatShamirChallenge,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
    pub fn my_indices(&self) -> Vec<ShareIndex> {
        self.nodes.share_ids_of(self.id).unwrap()
    }

    pub fn my_weight(&self) -> usize {
        self.nodes
            .total_weight_of(std::iter::once(self.id))
            .unwrap() as usize
    }

    /// 2. Each receiver processes the message, verifies and decrypts its shares. If this works, the shares are stored and the receiver can contribute a signature on the message to a certificate.
    pub fn process_message(&self, message: &Message<G, EG>) -> FastCryptoResult<ReceiverOutput<G>> {
        let random_oracle_encryption = self.extension(Encryption);

        message.ciphertext.verify(&random_oracle_encryption)?;
        let plaintext = message.ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );
        let my_shares = SharesForNode::from_bytes(&plaintext)?;

        // Check that we received the correct number of shares.
        if my_shares.weight() != self.my_weight() {
            return Err(InvalidInput);
        }

        self.verify_shares(message, &my_shares)?;

        Ok(ReceiverOutput { my_shares })
    }

    /// 3. When 2t+1 signatures have been collected in the certificate, the receivers can now verify it.
    ///  - If the receiver is already in the certificate, return [ProcessCertificateResult::Ignore].
    ///  - If it is not in the certificate, but it is able to decrypt and verify its shares, return [ProcessCertificateResult::Valid] with its shares.
    ///  - If it is not in the certificate and cannot decrypt or verify its shares, it returns a [ProcessCertificateResult::Complaint] with a complaint.
    ///
    /// Returns an error if the certificate or the encrypted shares are invalid.
    pub fn process_certificate(
        &self,
        message: &Message<G, EG>,
        cert: &impl Certificate<G, EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ProcessCertificateResult<G, EG>> {
        if !cert.is_valid(message, (2 * self.threshold + 1) as usize) {
            return Err(InvalidInput);
        }

        if cert.includes(&self.id) {
            return Ok(ProcessCertificateResult::Ignore);
        }

        // TODO: Verify message is called both in process_message and in create_complaint, so a receiver will call it up to three times
        match self.process_message(message) {
            Ok(output) => Ok(ProcessCertificateResult::Valid(output)),
            Err(_) => {
                // Create a complaint
                Ok(ProcessCertificateResult::Complaint(Complaint::create(
                    self.id,
                    &message.ciphertext,
                    &self.enc_secret_key,
                    self,
                    rng,
                )?))
            }
        }
    }

    /// 4. Upon receiving a complaint, a receiver verifies it and responds with a recovery package for the shares of the accuser.
    pub fn handle_complaint(
        &self,
        message: &Message<G, EG>,
        complaint: &Complaint<EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse<EG>> {
        complaint.check::<G, SharesForNode<G::ScalarType>>(
            &self.nodes.node_id_to_node(complaint.accuser_id)?.pk,
            &message.ciphertext,
            self,
            |shares| self.verify_shares(message, shares),
        )?;
        Ok(ComplaintResponse::create(
            self.id,
            &message.ciphertext,
            &self.enc_secret_key,
            self,
            rng,
        ))
    }

    /// 5. Upon receiving f+1 valid responses to a complaint, the accuser can recover its shares.
    ///    Fails if there are not enough valid responses to recover the shares or if any of the responses come from an invalid party.
    pub fn recover(
        &self,
        message: &Message<G, EG>,
        responses: &[ComplaintResponse<EG>],
    ) -> FastCryptoResult<ReceiverOutput<G>> {
        // TODO: This fails if one of the responses has an invalid responder_id. We could probably just ignore those instead.

        // Sanity check that we have enough responses (by weight) to recover the shares.
        let total_response_weight = self
            .nodes
            .total_weight_of(responses.iter().map(|response| response.responder_id))?;
        if total_response_weight < self.threshold + 1 {
            return Err(FastCryptoError::InputTooShort(
                (self.threshold + 1) as usize,
            ));
        }

        let response_shares: Vec<SharesForNode<G::ScalarType>> = responses
            .iter()
            .filter_map(|response| {
                self.nodes
                    .node_id_to_node(response.responder_id)
                    .and_then(|node| {
                        response.decrypt_with_response(self, &node.pk, &message.ciphertext)
                    })
                    .tap_err(|_| {
                        warn!(
                            "Ignoring invalid recovery package from {}",
                            response.responder_id
                        )
                    })
                    .ok()
            })
            .collect_vec();

        // Compute the total weight of the valid responses
        let response_weight = response_shares
            .iter()
            .map(SharesForNode::weight)
            .sum::<usize>();
        if response_weight < (self.threshold + 1) as usize {
            return Err(FastCryptoError::GeneralError(
                "Not enough valid responses".to_string(),
            ));
        }

        let my_shares = SharesForNode::recover(self.my_indices(), &response_shares)?;
        self.verify_shares(message, &my_shares)?;

        Ok(ReceiverOutput { my_shares })
    }

    /// Helper function to verify the consistency of the shares, e.g., that <i>r' + &Sigma;<sub>l</sub> &gamma;<sub>l</sub> r<sub>li</sub> = p''(i)<i>.
    fn verify_shares(
        &self,
        message: &Message<G, EG>,
        shares: &SharesForNode<G::ScalarType>,
    ) -> FastCryptoResult<()> {
        if shares.batch_size() != self.previous_round_commitments.len() {
            return Err(InputLengthWrong(self.previous_round_commitments.len()));
        }

        // Verify that the shares are consistent with the previous round's commitments.
        for (commitment, previous) in message
            .commitments
            .iter()
            .zip(&self.previous_round_commitments)
        {
            if commitment.c0() != previous {
                return Err(InvalidInput);
            }
        }

        // Verify shares against commitments.
        for batch in shares.batches.iter() {
            for (share, c) in batch.shares.iter().zip(message.commitments.iter()) {
                c.verify_share(batch.index, share)?;
            }
        }
        Ok(())
    }
}

impl<G: GroupElement, EG: GroupElement> RandomOracleExtensions for Dealer<G, EG> {
    fn base(&self) -> &RandomOracle {
        &self.random_oracle
    }
}

impl<G: GroupElement, EG: GroupElement> RandomOracleExtensions for Receiver<G, EG>
where
    EG::ScalarType: Zeroize,
{
    fn base(&self) -> &RandomOracle {
        &self.random_oracle
    }
}

#[cfg(test)]
mod tests {
    use crate::batched_avss::dkg::{
        Certificate, Dealer, Message, RandomOracleExtensions, Receiver,
    };
    use crate::batched_avss::dkg::{Complaint, ProcessCertificateResult};
    use crate::batched_avss::dkg::{ShareBatch, SharesForNode};
    use crate::batched_avss::ro_extension::Extension::Encryption;
    use crate::batched_avss::SharesForNode as _;
    use crate::ecies_v1;
    use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::{Eval, Poly};
    use crate::random_oracle::RandomOracle;
    use crate::types::ShareIndex;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::bls12381::{G1Element, G2Element};
    use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::marker::PhantomData;
    use zeroize::Zeroize;

    pub struct TestCertificate<EG: GroupElement> {
        included: Vec<u16>,
        nodes: Nodes<EG>,
    }

    impl<G: GroupElement, EG: GroupElement + Serialize> Certificate<G, EG> for TestCertificate<EG> {
        fn is_valid(&self, _message: &Message<G, EG>, threshold: usize) -> bool {
            let weights = self
                .included
                .iter()
                .map(|id| self.nodes.share_ids_of(*id).unwrap().len())
                .collect_vec();
            weights.iter().sum::<usize>() >= threshold
        }

        fn includes(&self, index: &PartyId) -> bool {
            self.included.contains(index)
        }
    }

    impl<G: GroupElement, EG: GroupElement> ProcessCertificateResult<G, EG> {
        fn assert_complaint(&self) -> &Complaint<EG> {
            if let ProcessCertificateResult::Complaint(c) = self {
                c
            } else {
                panic!("Expected a complaint");
            }
        }

        fn assert_no_complaint(&self) {
            if let ProcessCertificateResult::Complaint(_) = self {
                panic!("Expected no complaint");
            }
        }
    }

    #[test]
    fn test_sharing() {
        // No complaints, all honest. All have weight 1
        let threshold = 2;
        let n = 3 * threshold + 1;
        let number_of_nonces = 3;

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<G2Element>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(i, sk)| Node {
                    id: i as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let random_oracle = RandomOracle::new("tbls test");

        let nonces = (0..number_of_nonces)
            .map(|_| Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let previous_round_commitments = nonces
            .iter()
            .map(|nonce| G1Element::generator() * nonce)
            .collect_vec();

        let dealer: Dealer<G1Element, G2Element> = Dealer {
            secrets_batch: nonces.clone(),
            threshold,
            nodes: nodes.clone(),
            random_oracle,
            _group: PhantomData,
        };

        let mut receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                previous_round_commitments: previous_round_commitments.clone(),
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                nodes: nodes.clone(),
                _group: PhantomData,
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .map(|receiver| (receiver.id, receiver.process_message(&message).unwrap()))
            .collect::<HashMap<_, _>>();

        let certificate = TestCertificate {
            included: vec![1, 2, 3, 4, 5], // 2f+1
            nodes: nodes.clone(),
        };

        for receiver in receivers.iter_mut() {
            receiver
                .process_certificate(&message, &certificate, &mut rng)
                .unwrap()
                .assert_no_complaint();
        }

        let secrets = (0..number_of_nonces)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.batches[0].shares[l as usize],
                        )
                    })
                    .collect::<Vec<_>>();
                Poly::recover_c0(
                    threshold + 1,
                    shares
                        .iter()
                        .take((threshold + 1) as usize)
                        .map(|(id, v)| Eval {
                            index: ShareIndex::try_from(id + 1).unwrap(),
                            value: *v,
                        }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        for l in 0..number_of_nonces {
            assert_eq!(secrets[l as usize], nonces[l as usize]);
        }
    }

    #[test]
    fn test_share_recovery() {
        let threshold = 2;
        let n = 3 * threshold + 1;
        let number_of_nonces = 3;

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<G2Element>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(id, sk)| Node {
                    id: id as u16,
                    pk: PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let random_oracle = RandomOracle::new("tbls test");
        let nonces = (0..number_of_nonces)
            .map(|_| Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let dealer: Dealer<G1Element, G2Element> = Dealer {
            secrets_batch: nonces.clone(),
            threshold,
            nodes: nodes.clone(),
            random_oracle,
            _group: PhantomData,
        };

        let previous_round_commitments = nonces
            .iter()
            .map(|nonce| G1Element::generator() * nonce)
            .collect_vec();

        println!(
            "Previous round commitments: {:?}",
            previous_round_commitments
        );

        let receivers = sks
            .into_iter()
            .enumerate()
            .map(|(i, secret_key)| Receiver {
                id: i as u16,
                enc_secret_key: secret_key,
                previous_round_commitments: previous_round_commitments.clone(),
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                _group: PhantomData,
                nodes: nodes.clone(),
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message_cheating(&mut rng).unwrap();

        let mut all_shares = receivers
            .iter()
            .map(|receiver| receiver.process_message(&message).map(|s| (receiver.id, s)))
            .filter_map(Result::ok)
            .collect::<HashMap<_, _>>();

        // First receiver should fail to decrypt/verify its shares
        assert!(all_shares.get(&0).is_none());

        let certificate = TestCertificate {
            included: vec![2, 3, 4, 5, 6], // 2f+1
            nodes: nodes.clone(),
        };

        for i in 0..n {
            let complaint = receivers[i as usize]
                .process_certificate(&message, &certificate, &mut rng)
                .unwrap();
            if i == 0 {
                let c = complaint.assert_complaint();
                let responses = receivers
                    .iter()
                    .skip(1)
                    .map(|r| r.handle_complaint(&message, c, &mut rng).unwrap())
                    .collect::<Vec<_>>();
                let shares = receivers[0].recover(&message, &responses).unwrap();
                all_shares.insert(0, shares);
            } else {
                complaint.assert_no_complaint();
            }
        }

        // Recover with the first f+1 shares, including the reconstructed
        let secrets = (0..number_of_nonces)
            .map(|l| {
                let shares = all_shares
                    .iter()
                    .map(|(id, s)| (*id, s.my_shares.batches[0].shares[l as usize]))
                    .collect::<Vec<_>>();
                Poly::recover_c0(
                    threshold + 1,
                    shares
                        .iter()
                        .take((threshold + 1) as usize)
                        .map(|(id, v)| Eval {
                            index: ShareIndex::try_from(id + 1).unwrap(),
                            value: *v,
                        }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        for l in 0..number_of_nonces {
            assert_eq!(secrets[l as usize], nonces[l as usize]);
        }
    }

    impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
    where
        EG::ScalarType: FiatShamirChallenge + Zeroize,
        G::ScalarType: FiatShamirChallenge,
    {
        pub fn create_message_cheating<Rng: AllowedRng>(
            &self,
            rng: &mut Rng,
        ) -> FastCryptoResult<Message<G, EG>> {
            let polynomials = self
                .secrets_batch
                .iter()
                .map(|c0| Poly::rand_fixed_c0(self.threshold, *c0, rng))
                .collect_vec();

            let commitments = polynomials.iter().map(Poly::commit).collect_vec();

            // Encrypt all shares to the receivers
            let mut pk_and_msgs = self
                .nodes
                .iter()
                .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
                .map(|(public_key, share_ids)| {
                    (
                        public_key,
                        SharesForNode {
                            batches: share_ids
                                .into_iter()
                                .map(|index| ShareBatch {
                                    index,
                                    shares: polynomials
                                        .iter()
                                        .map(|p_l| p_l.eval(index).value)
                                        .collect(),
                                })
                                .collect_vec(),
                        },
                    )
                })
                .map(|(pk, shares)| (pk, shares.to_bytes()))
                .collect_vec();

            // Modify the first share of the first receiver to simulate a cheating dealer
            pk_and_msgs[0].1[7] += 1;

            let ciphertext =
                MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

            Ok(Message {
                ciphertext,
                commitments,
            })
        }
    }
}
