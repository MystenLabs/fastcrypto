use crate::batched_avss::certificate::Certificate;
use crate::batched_avss::complaint::{Complaint, ComplaintResponse};
use crate::batched_avss::ro_extension::Extension::{Challenge, Encryption};
use crate::batched_avss::ro_extension::RandomOracleExtensions;
use crate::batched_avss::SharesForNode as _;
use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{interpolate_at_index, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{
    FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul, Scalar,
};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use tap::TapFallible;
use tracing::warn;
use zeroize::Zeroize;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<G: GroupElement, EG: GroupElement> {
    secrets: Vec<G::ScalarType>,
    threshold: u16,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
    _group: PhantomData<G>,
}

pub struct Receiver<G, EG: GroupElement>
where
    EG::ScalarType: Zeroize,
{
    id: PartyId,
    enc_secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    batch_size: u16,
    random_oracle: RandomOracle,
    threshold: u16,
    _group: PhantomData<G>,
}

/// The output of a receiver: The shares for each secret.
/// This can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<G: GroupElement> {
    pub my_shares: SharesForNode<G::ScalarType>,
}

/// The message broadcast by the dealer, containing the encrypted shares and the public keys of the secrets.
#[derive(Clone, Debug)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    full_public_keys: Vec<G>,
    blinding_commit: G,
    ciphertext: MultiRecipientEncryption<EG>,
    response: Poly<G::ScalarType>,
}

/// The result of processing a certificate by a receiver: Either valid shares, a complaint, or ignore if the receiver was already included.
#[derive(Debug, Clone)]
pub enum ProcessCertificateResult<G: GroupElement, EG: GroupElement> {
    Valid(ReceiverOutput<G>),
    Complaint(Complaint<EG>),
    Ignore,
}

impl<C: Scalar> ShareBatch<C> {
    fn verify<G: GroupElement<ScalarType = C>, EG: GroupElement>(
        &self,
        message: &Message<G, EG>,
        challenge: &[C],
    ) -> FastCryptoResult<()> {
        if challenge.len() != self.shares.len() {
            return Err(InvalidInput);
        }

        // Verify that r' + sum_l r_l * gamma_l == p''(i)
        if self
            .shares
            .iter()
            .zip(challenge)
            .fold(self.blinding_share, |acc, (r_l, gamma_l)| {
                acc + (*r_l * gamma_l)
            })
            != message.response.eval(self.index).value
        {
            return Err(InvalidInput);
        }
        Ok(())
    }
}

/// A batch of shares for a single share index, containing shares for each secret and one for the "blinding" polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBatch<C> {
    /// The index of the share (i.e., the share id).
    pub index: ShareIndex,

    /// The shares for each secret.
    pub shares: Vec<C>,

    /// The share for the blinding polynomial.
    pub blinding_share: C,
}

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

                let blinding_share = interpolate_at_index(
                    index,
                    &other_shares
                        .iter()
                        .flat_map(|s| &s.batches)
                        .map(|batch| Eval {
                            index: batch.index,
                            value: batch.blinding_share,
                        })
                        .collect_vec(),
                )?
                .value;

                Ok(ShareBatch {
                    index,
                    shares,
                    blinding_share,
                })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(Self { batches })
    }

    fn batch_size(&self) -> usize {
        self.batches[0].shares.len()
    }
}

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    pub fn new(
        secrets: Vec<G::ScalarType>,
        nodes: Nodes<EG>,
        threshold: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
    ) -> FastCryptoResult<Self> {
        // Sanity check that the threshold makes sense (t <= n/2 since we later wait for 2t-1).
        if threshold > (nodes.total_weight() / 2) {
            return Err(InvalidInput);
        }
        Ok(Self {
            secrets,
            threshold,
            nodes,
            random_oracle,
            _group: PhantomData,
        })
    }

    /// 1. The Dealer generates shares for the secrets and broadcasts the encrypted shares.
    pub fn create_message<Rng: AllowedRng>(
        &self,
        rng: &mut Rng,
    ) -> FastCryptoResult<Message<G, EG>> {
        let polynomials = self
            .secrets
            .iter()
            .map(|c0| Poly::rand_fixed_c0(self.threshold, *c0, rng))
            .collect_vec();

        // Compute the (full) public keys for all secrets
        let full_public_keys = polynomials
            .iter()
            .map(|p| G::generator() * p.c0())
            .collect_vec();

        // "blinding" polynomial as defined in https://eprint.iacr.org/2023/536.pdf.
        let blinding_poly = Poly::rand(self.threshold, rng);
        let blinding_commit = G::generator() * blinding_poly.c0();

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
                                blinding_share: blinding_poly.eval(index).value,
                            })
                            .collect_vec(),
                    },
                )
            })
            .map(|(pk, shares_for_node)| (pk, shares_for_node.to_bytes()))
            .collect_vec();

        let ciphertext =
            MultiRecipientEncryption::encrypt(&pk_and_msgs, &self.extension(Encryption), rng);

        // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
        let challenge = self.compute_challenge(&full_public_keys, &blinding_commit, &ciphertext);
        let mut response = blinding_poly;
        for (p_l, gamma_l) in polynomials.into_iter().zip(&challenge) {
            response += &(p_l * gamma_l);
        }

        Ok(Message {
            full_public_keys,
            blinding_commit,
            ciphertext,
            response,
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
        if message.response.degree() > self.threshold as usize {
            return Err(InvalidInput);
        }

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

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        let challenge = self.compute_challenge_from_message(message);
        if G::generator() * message.response.c0()
            != message.blinding_commit + G::multi_scalar_mul(&challenge, &message.full_public_keys)?
        {
            return Err(InvalidInput);
        }

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
        cert: &impl Certificate<Message<G, EG>>,
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
            &complaint,
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

    fn verify_shares(
        &self,
        message: &Message<G, EG>,
        nonce_shares: &SharesForNode<G::ScalarType>,
    ) -> FastCryptoResult<()> {
        let challenge = self.compute_challenge_from_message(message);
        for shares in &nonce_shares.batches {
            if shares.shares.len() != self.batch_size as usize {
                return Err(InvalidInput);
            }
            shares.verify(message, &challenge)?;
        }
        Ok(())
    }
}

trait FiatShamirImpl<G: GroupElement + Serialize, EG: GroupElement + Serialize>:
    RandomOracleExtensions
where
    G::ScalarType: FiatShamirChallenge,
{
    fn compute_challenge(
        &self,
        c: &[G],
        c_prime: &G,
        e: &MultiRecipientEncryption<EG>,
    ) -> Vec<G::ScalarType> {
        let random_oracle = self.extension(Challenge);
        c.iter()
            .enumerate()
            .map(|(l, c_l)| random_oracle.evaluate(&(l, c_l, c_prime, e)))
            .map(|bytes| G::ScalarType::fiat_shamir_reduction_to_group_element(&bytes))
            .collect_vec()
    }

    fn compute_challenge_from_message(&self, message: &Message<G, EG>) -> Vec<G::ScalarType> {
        self.compute_challenge(
            message.full_public_keys.as_slice(),
            &message.blinding_commit,
            &message.ciphertext,
        )
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

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize>
    FiatShamirImpl<G, EG> for Dealer<G, EG>
where
    G::ScalarType: FiatShamirChallenge,
{
}

impl<G: GroupElement + Serialize, EG: GroupElement + Serialize> FiatShamirImpl<G, EG>
    for Receiver<G, EG>
where
    G::ScalarType: FiatShamirChallenge,
    EG::ScalarType: Zeroize,
{
}

#[cfg(test)]
mod tests {
    use super::{Complaint, Dealer, ProcessCertificateResult, Receiver};
    use crate::batched_avss::certificate::TestCertificate;
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::nodes::{Node, Nodes};
    use crate::polynomial::{Eval, Poly};
    use crate::random_oracle::RandomOracle;
    use crate::types::ShareIndex;
    use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
    use fastcrypto::groups::{GroupElement, Scalar as _};
    use itertools::Itertools;
    use std::collections::HashMap;
    use std::marker::PhantomData;

    #[test]
    fn test_happy_path() {
        // No complaints, all honest. All have weight 1
        let threshold = 2;
        let n = 3 * threshold + 1;
        let batch_size = 3;

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

        let secrets = (0..batch_size)
            .map(|_| Scalar::rand(&mut rng))
            .collect_vec();

        let dealer: Dealer<G1Element, G2Element> = Dealer {
            secrets: secrets.clone(),
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
                batch_size,
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

        let secrets = (0..batch_size)
            .map(|l| {
                let shares = receivers
                    .iter()
                    .map(|r| {
                        (
                            r.id,
                            all_shares.get(&r.id).unwrap().my_shares.batches[0].shares[l as usize], // Each receiver has a single batch (weight 1)
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

        for l in 0..batch_size {
            assert_eq!(secrets[l as usize], secrets[l as usize]);
        }
    }

    #[test]
    #[allow(clippy::single_match)]
    fn test_happy_path_non_equal_weights() {
        // No complaints, all honest
        let threshold = 2;
        let weights: Vec<u16> = vec![1, 2, 3, 4];
        let batch_size = 3;

        let mut rng = rand::thread_rng();
        let sks = weights
            .iter()
            .map(|_| ecies_v1::PrivateKey::<G2Element>::new(&mut rng))
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            weights
                .into_iter()
                .enumerate()
                .map(|(i, weight)| Node {
                    id: i as u16,
                    pk: PublicKey::from_private_key(&sks[i]),
                    weight,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let random_oracle = RandomOracle::new("tbls test");
        let secrets = (0..batch_size)
            .map(|_| Scalar::rand(&mut rng))
            .collect_vec();
        let dealer: Dealer<G1Element, G2Element> = Dealer {
            secrets: secrets.clone(),
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
                batch_size,
                random_oracle: RandomOracle::new("tbls test"),
                threshold,
                nodes: nodes.clone(),
                _group: PhantomData,
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng).unwrap();

        let all_shares = receivers
            .iter()
            .flat_map(|receiver| {
                receiver
                    .process_message(&message)
                    .unwrap()
                    .my_shares
                    .batches
            })
            .collect::<Vec<_>>();

        let certificate = TestCertificate {
            included: vec![0, 1, 2],
            nodes: nodes.clone(),
        };

        for receiver in receivers.iter_mut() {
            // Expect no complaints
            match receiver
                .process_certificate(&message, &certificate, &mut rng)
                .unwrap()
            {
                ProcessCertificateResult::Complaint(_) => panic!("Expected no complaints"),
                _ => {}
            }
        }

        let secrets = (0..batch_size)
            .map(|l| {
                Poly::recover_c0(
                    threshold + 1,
                    all_shares
                        .iter()
                        .take((threshold + 1) as usize)
                        .map(|s| Eval {
                            index: s.index,
                            value: s.shares[l as usize],
                        }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        for l in 0..batch_size {
            assert_eq!(secrets[l as usize], secrets[l as usize]);
        }
    }
    //
    //
    // #[test]
    // fn test_share_recovery() {
    //     let threshold = 2;
    //     let n = 3 * threshold + 1;
    //     let number_of_nonces = 3;
    //
    //     let mut rng = rand::thread_rng();
    //     let sks = (0..n)
    //         .map(|_| ecies_v1::PrivateKey::<G2Element>::new(&mut rng))
    //         .collect::<Vec<_>>();
    //     let nodes = Nodes::new(
    //         sks.iter()
    //             .enumerate()
    //             .map(|(id, sk)| Node {
    //                 id: id as u16,
    //                 pk: PublicKey::from_private_key(sk),
    //                 weight: 1,
    //             })
    //             .collect::<Vec<_>>(),
    //     )
    //     .unwrap();
    //
    //     let random_oracle = RandomOracle::new("tbls test");
    //     let nonces = (0..number_of_nonces)
    //         .map(|_| Scalar::rand(&mut rng))
    //         .collect_vec();
    //
    //     let dealer: Dealer<G1Element, G2Element> = Dealer {
    //         nonces: nonces.clone(),
    //         threshold,
    //         nodes: nodes.clone(),
    //         random_oracle,
    //         _group: PhantomData,
    //     };
    //
    //     let receivers = sks
    //         .into_iter()
    //         .enumerate()
    //         .map(|(i, secret_key)| Receiver {
    //             id: i as u16,
    //             enc_secret_key: secret_key,
    //             number_of_nonces,
    //             random_oracle: RandomOracle::new("tbls test"),
    //             threshold,
    //             _group: PhantomData,
    //             nodes: nodes.clone(),
    //         })
    //         .collect::<Vec<_>>();
    //
    //     let message = dealer.create_message_cheating(&mut rng).unwrap();
    //
    //     let mut all_shares = receivers
    //         .iter()
    //         .map(|receiver| receiver.process_message(&message).map(|s| (receiver.id, s)))
    //         .filter_map(Result::ok)
    //         .collect::<HashMap<_, _>>();
    //
    //     assert!(all_shares.get(&0).is_none());
    //
    //     let certificate = TestCertificate {
    //         included: vec![2, 3, 4, 5, 6], // 2f+1
    //         nodes: nodes.clone(),
    //     };
    //
    //     for i in 0..n {
    //         let complaint = receivers[i as usize]
    //             .process_certificate(&message, &certificate, &mut rng)
    //             .unwrap();
    //         if i == 0 {
    //             let c = complaint.assert_complaint();
    //             let responses = receivers
    //                 .iter()
    //                 .skip(1)
    //                 .map(|r| r.handle_complaint(&message, c, &mut rng).unwrap())
    //                 .collect::<Vec<_>>();
    //             let shares = receivers[0].recover(&message, &responses).unwrap();
    //             all_shares.insert(0, shares);
    //         } else {
    //             complaint.assert_no_complaint();
    //         }
    //     }
    //
    //     // Recover with the first f+1 shares, including the reconstructed
    //     let secrets = (0..number_of_nonces)
    //         .map(|l| {
    //             let shares = all_shares
    //                 .iter()
    //                 .map(|(id, s)| (*id, s.shares[0].shares[l as usize]))
    //                 .collect::<Vec<_>>();
    //             Poly::recover_c0(
    //                 threshold + 1,
    //                 shares
    //                     .iter()
    //                     .take((threshold + 1) as usize)
    //                     .map(|(id, v)| Eval {
    //                         index: ShareIndex::try_from(id + 1).unwrap(),
    //                         value: *v,
    //                     }),
    //             )
    //             .unwrap()
    //         })
    //         .collect::<Vec<_>>();
    //
    //     for l in 0..number_of_nonces {
    //         assert_eq!(secrets[l as usize], nonces[l as usize]);
    //     }
    // }
    //
    // impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
    // where
    //     EG::ScalarType: FiatShamirChallenge + Zeroize,
    //     G::ScalarType: FiatShamirChallenge,
    // {
    //     /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
    //     pub fn create_message_cheating<Rng: AllowedRng>(
    //         &self,
    //         rng: &mut Rng,
    //     ) -> FastCryptoResult<Message<G, EG>> {
    //         let n = self.nodes.total_weight();
    //
    //         let polynomials = self
    //             .nonces
    //             .iter()
    //             .map(|nonce| Poly::rand_fixed_c0(self.threshold, *nonce, rng))
    //             .collect::<Vec<_>>();
    //         let public_keys = polynomials
    //             .iter()
    //             .map(|p_l| G::generator() * p_l.c0())
    //             .collect::<Vec<_>>();
    //
    //         let p_prime = Poly::rand(self.threshold, rng);
    //         let c_prime = G::generator() * p_prime.c0();
    //
    //         let mut r: Vec<Vec<G::ScalarType>> = polynomials
    //             .iter()
    //             .map(|p_l| {
    //                 (0..n)
    //                     .map(|j| p_l.eval(ShareIndex::try_from(j + 1).unwrap()).value)
    //                     .collect()
    //             })
    //             .collect();
    //         let r_prime: Vec<G::ScalarType> = (0..n)
    //             .map(|j| p_prime.eval(ShareIndex::try_from(j + 1).unwrap()).value)
    //             .collect();
    //
    //         // Modify the first share of the first nonce to be incorrect
    //         r[0][0] += G::ScalarType::from(1u128);
    //
    //         let shares_for_node = self
    //             .nodes
    //             .iter()
    //             .map(|node| {
    //                 let share_ids = self.nodes.share_ids_of(node.id)?;
    //                 Ok(share_ids
    //                     .iter()
    //                     .map(|share_id| ShareBatch {
    //                         index: *share_id,
    //                         shares: r.iter()
    //                             .map(|r_l| r_l[share_id.get() as usize - 1])
    //                             .collect(),
    //                         blinding_share: r_prime[share_id.get() as usize - 1],
    //                     })
    //                     .collect::<Vec<ShareBatch<G::ScalarType>>>())
    //             })
    //             .collect::<FastCryptoResult<Vec<Vec<ShareBatch<G::ScalarType>>>>>()?;
    //
    //         let ciphertext = MultiRecipientEncryption::encrypt(
    //             &self
    //                 .nodes
    //                 .iter()
    //                 .map(|node| {
    //                     (
    //                         node.pk.clone(),
    //                         bcs::to_bytes(&shares_for_node[node.id as usize]).unwrap(),
    //                     )
    //                 })
    //                 .collect::<Vec<_>>(),
    //             &self.random_oracle_extension(Encryption),
    //             rng,
    //         );
    //
    //         let gamma = self.compute_challenge(&public_keys, &c_prime, &ciphertext);
    //
    //         let mut q = p_prime;
    //         for (p_l, gamma_l) in polynomials.iter().zip(&gamma) {
    //             q += &(p_l.clone() * gamma_l);
    //         }
    //
    //         Ok(Message {
    //             full_public_keys: public_keys,
    //             blinding_commit: c_prime,
    //             ciphertext,
    //             response: q,
    //         })
    //     }
    // }

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
}
