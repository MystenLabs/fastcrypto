// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::batched_avss::dkg::Extension::{Encryption, Recovery};
use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey, RecoveryPackage};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{interpolate_at_index, Eval, Poly, PublicPoly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InputLengthWrong, InvalidInput, InvalidProof};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tap::TapFallible;
use tracing::{debug, warn};
use zeroize::Zeroize;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<G: GroupElement, EG: GroupElement> {
    threshold: u16,
    nodes: Nodes<EG>,
    random_oracle: RandomOracle,
    nonces: Vec<G::ScalarType>,
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

/// The output of the dealer: The distributed nonces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DealerOutput<G: GroupElement> {
    pub nonces: Vec<G::ScalarType>,
}

/// The output of a receiver: The shares for each nonce. This can be created either by decrypting the shares from the dealer (see [Receiver::process_message]) or by recovering them from complaint responses.
#[derive(Debug, Clone)]
pub struct ReceiverOutput<G: GroupElement> {
    pub all_shares: Vec<NonceShares<G::ScalarType>>,
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

/// A complaint by a receiver that it could not decrypt or verify its shares.
#[derive(Clone, Debug)]
pub struct Complaint<EG: GroupElement> {
    accuser_id: PartyId,
    proof: RecoveryPackage<EG>,
}

/// A response to a complaint, containing a recovery package for the accuser.
#[derive(Debug, Clone)]
pub struct ComplaintResponse<EG: GroupElement> {
    responder_id: PartyId,
    recovery_package: RecoveryPackage<EG>,
}

/// The shares for a receiver, containing shares for each nonce and one for the combined polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceShares<C: GroupElement> {
    pub index: ShareIndex,
    pub r: Vec<C>,
}

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    pub fn new(
        nonces: Vec<G::ScalarType>,
        nodes: Nodes<EG>,
        threshold: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
    ) -> FastCryptoResult<Self> {
        // Sanity check that the threshold makes sense (t <= n/2 since we later wait for 2t-1).
        if threshold > (nodes.total_weight() / 2) {
            return Err(InvalidInput);
        }
        Ok(Self {
            nonces,
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
    ) -> FastCryptoResult<(Message<G, EG>, DealerOutput<G>)> {
        let polynomials = self
            .nonces
            .iter()
            .map(|nonce| Poly::rand_fixed_c0(self.threshold, *nonce, rng))
            .collect_vec();

        let commitments = polynomials.iter().map(|p| p.commit()).collect_vec();

        // Encrypt all shares to the receivers
        let pk_and_msgs = self
            .nodes
            .iter()
            .map(|node| (node.pk.clone(), self.nodes.share_ids_of(node.id).unwrap()))
            .map(|(public_key, share_ids)| {
                (
                    public_key,
                    share_ids
                        .into_iter()
                        .map(|index| NonceShares {
                            index,
                            r: polynomials
                                .iter()
                                .map(|p_l| p_l.eval(index).value)
                                .collect(),
                        })
                        .collect_vec(),
                )
            })
            .map(|(pk, shares)| (pk, bcs::to_bytes(&shares).unwrap()))
            .collect_vec();

        let ciphertext = MultiRecipientEncryption::encrypt(
            &pk_and_msgs,
            &self.random_oracle_extension(Encryption),
            rng,
        );

        Ok((
            Message {
                ciphertext,
                commitments,
            },
            DealerOutput {
                nonces: self.nonces.clone(),
            },
        ))
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
    /// 2. Each receiver processes the message, verifies and decrypts its shares. If this works, the shares are stored and the receiver can contribute a signature on the message to a certificate.
    pub fn process_message(&self, message: &Message<G, EG>) -> FastCryptoResult<ReceiverOutput<G>> {
        let random_oracle_encryption = self.random_oracle_extension(Encryption);

        message.ciphertext.verify(&random_oracle_encryption)?;
        let plaintext = message.ciphertext.decrypt(
            &self.enc_secret_key,
            &random_oracle_encryption,
            self.id as usize,
        );
        let all_shares: Vec<NonceShares<G::ScalarType>> =
            bcs::from_bytes(&plaintext).map_err(|_| InvalidInput)?;

        // Check that we received the correct number of shares.
        if all_shares.len() != self.nodes.share_ids_of(self.id)?.len() {
            return Err(InvalidInput);
        }

        for shares in &all_shares {
            self.verify_shares(shares, message)?;
        }

        Ok(ReceiverOutput { all_shares })
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
                message
                    .ciphertext
                    .verify(&self.random_oracle_extension(Encryption))?;
                Ok(ProcessCertificateResult::Complaint(Complaint {
                    accuser_id: self.id,
                    proof: message.ciphertext.create_recovery_package(
                        &self.enc_secret_key,
                        &self.random_oracle_extension(Recovery(self.id)),
                        rng,
                    ),
                }))
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
        self.check_complaint_proof(message, complaint)?;
        message
            .ciphertext
            .verify(&self.random_oracle_extension(Encryption))?;
        Ok(ComplaintResponse {
            responder_id: self.id,
            recovery_package: message.ciphertext.create_recovery_package(
                &self.enc_secret_key,
                &self.random_oracle_extension(Recovery(self.id)),
                rng,
            ),
        })
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

        let ro_encryption = self.random_oracle_extension(Encryption);

        let response_shares = responses
            .iter()
            .filter_map(|response| {
                self.nodes
                    .node_id_to_node(response.responder_id)
                    .and_then(|node| {
                        message.ciphertext.decrypt_with_recovery_package(
                            &response.recovery_package,
                            &self.random_oracle_extension(Recovery(node.id)),
                            &ro_encryption,
                            &node.pk,
                            response.responder_id as usize,
                        )
                    })
                    .and_then(|bytes| {
                        bcs::from_bytes::<Vec<NonceShares<G::ScalarType>>>(bytes.as_slice())
                            .map_err(|_| InvalidInput)
                    })
                    .tap_err(|_| {
                        warn!(
                            "Ignoring invalid recovery package from {}",
                            response.responder_id
                        )
                    })
                    .ok()
            })
            .flatten()
            .collect_vec();

        // We ignore the invalid responses and just check that we have enough valid ones here.
        if response_shares.len() < (self.threshold + 1) as usize {
            return Err(FastCryptoError::GeneralError(
                "Not enough valid responses".to_string(),
            ));
        }

        let n = self.previous_round_commitments.len();
        let all_shares = self
            .nodes
            .share_ids_of(self.id)?
            .iter()
            .map(|index| {
                let index = *index;
                let r = (0..n)
                    .map(|l| {
                        interpolate_at_index(
                            index,
                            &response_shares
                                .iter()
                                .map(|s| Eval {
                                    index: s.index,
                                    value: s.r[l as usize],
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .map_ok(|res| res.value)
                    .collect::<FastCryptoResult<Vec<_>>>()?;

                Ok(NonceShares { index, r })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        for shares in &all_shares {
            self.verify_shares(shares, message)?;
        }
        Ok(ReceiverOutput { all_shares })
    }

    /// Helper function to verify the consistency of the shares, e.g., that <i>r' + &Sigma;<sub>l</sub> &gamma;<sub>l</sub> r<sub>li</sub> = p''(i)<i>.
    fn verify_shares(
        &self,
        shares: &NonceShares<G::ScalarType>,
        message: &Message<G, EG>,
    ) -> FastCryptoResult<()> {
        if shares.r.len() != self.previous_round_commitments.len() {
            return Err(InputLengthWrong(self.previous_round_commitments.len()));
        }

        // Verify that the shares are consistent with the previous round commitments.
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
        for (share, c) in shares.r.iter().zip(&message.commitments) {
            c.verify_share(shares.index, share)?;
        }
        Ok(())
    }

    /// Helper function to verify that the complaint is valid, i.e., that the recovery package decrypts to valid shares.
    /// This returns [Ok] if the complaint is valid, and [Err] if it is invalid.
    fn check_complaint_proof(
        &self,
        message: &Message<G, EG>,
        complaint: &Complaint<EG>,
    ) -> FastCryptoResult<()> {
        let enc_pk = &self.nodes.node_id_to_node(complaint.accuser_id)?.pk;

        // Check that the recovery package is valid, and if not, return an error since the complaint is invalid.
        let buffer = message.ciphertext.decrypt_with_recovery_package(
            &complaint.proof,
            &self.random_oracle_extension(Recovery(complaint.accuser_id)),
            &self.random_oracle_extension(Encryption),
            enc_pk,
            complaint.accuser_id as usize,
        )?;

        let shares: NonceShares<G::ScalarType> = match bcs::from_bytes(buffer.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                debug!("check_complaint_proof failed to deserialize shares");
                return Ok(());
            }
        };

        if shares.r.len() != self.previous_round_commitments.len() as usize {
            debug!("check_complaint_proof recovered invalid number of shares");
            return Ok(());
        }

        if self.verify_shares(&shares, message).is_err() {
            return Ok(());
        }

        Err(InvalidProof)
    }
}

enum Extension {
    Recovery(PartyId),
    Encryption,
}

/// Helper trait to extend a random oracle with context-specific strings.
trait RandomOracleExtensions {
    fn base(&self) -> &RandomOracle;

    /// Extend the base random oracle with a context-specific string.
    fn random_oracle_extension(&self, extension: Extension) -> RandomOracle {
        let extension_string = match extension {
            Recovery(accuser) => &format!("recovery of {accuser}"),
            Encryption => "encryption",
            Challenge => "challenge",
        };
        self.base().extend(extension_string)
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
    use crate::batched_avss::dkg::{Certificate, Dealer, Message, Receiver};
    use crate::batched_avss::dkg::{Complaint, ProcessCertificateResult};
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::nodes::{Node, Nodes, PartyId};
    use crate::polynomial::{Eval, Poly};
    use crate::random_oracle::RandomOracle;
    use crate::types::ShareIndex;
    use fastcrypto::groups::bls12381::{G1Element, G2Element};
    use fastcrypto::groups::{GroupElement, Scalar};
    use itertools::Itertools;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::marker::PhantomData;

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
            nonces,
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

        let (message, output) = dealer.create_message(&mut rng).unwrap();

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
                            all_shares.get(&r.id).unwrap().all_shares[0].r[l as usize],
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
            assert_eq!(secrets[l as usize], output.nonces[l as usize]);
        }
    }
}
