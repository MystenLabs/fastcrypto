// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests;

use crate::batched_avss::Extension::{Challenge, Encryption, Recovery};
use crate::ecies_v1::{MultiRecipientEncryption, PrivateKey, RecoveryPackage};
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{interpolate, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
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
pub struct Dealer<G, EG: GroupElement> {
    number_of_nonces: u16,
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
    number_of_nonces: u16,
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
    public_keys: Vec<G>,
    c_prime: G,
    ciphertext: MultiRecipientEncryption<EG>,
    q: Poly<G::ScalarType>,
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
    pub r_prime: C,
}

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    pub fn new(
        number_of_nonces: u16,
        nodes: Nodes<EG>,
        threshold: u16, // The number of parties that are needed to reconstruct the full key/signature (f+1).
        random_oracle: RandomOracle, // Should be unique for each invocation, but the same for all parties.
    ) -> FastCryptoResult<Self> {
        // Sanity check that the threshold makes sense (t <= n/2 since we later wait for 2t-1).
        if threshold > (nodes.total_weight() / 2) {
            return Err(InvalidInput);
        }
        Ok(Self {
            number_of_nonces,
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
        let polynomials = (0..self.number_of_nonces)
            .map(|_| Poly::rand(self.threshold, rng))
            .collect_vec();
        let public_keys = polynomials.iter().map(pk_from_sk).collect_vec();

        // Random secrets (nonces) to be shared
        let nonces = polynomials.iter().map(|p_l| *p_l.c0()).collect();

        // "blinding" polynomials as defined in https://eprint.iacr.org/2023/536.pdf.
        let p_prime = Poly::rand(self.threshold, rng);
        let c_prime = pk_from_sk(&p_prime);

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
                            r_prime: p_prime.eval(index).value,
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

        let gamma = self.compute_gamma(&public_keys, &c_prime, &ciphertext);

        // "response" polynomials from https://eprint.iacr.org/2023/536.pdf
        let mut q = p_prime;
        for (p_l, gamma_l) in polynomials.into_iter().zip(&gamma) {
            q += &(p_l * gamma_l);
        }

        Ok((
            Message {
                public_keys,
                c_prime,
                ciphertext,
                q,
            },
            DealerOutput { nonces },
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
        if message.q.degree() > self.threshold as usize {
            return Err(InvalidInput);
        }

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

        let gamma = self.compute_gamma_from_message(message);
        for shares in &all_shares {
            self.verify_shares(shares, Some(&gamma), message)?;
        }

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        if G::generator() * message.q.c0()
            != message.c_prime + G::multi_scalar_mul(&gamma, &message.public_keys)?
        {
            return Err(InvalidInput);
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

        let all_shares = self
            .nodes
            .share_ids_of(self.id)?
            .iter()
            .map(|index| {
                let index = *index;
                let r_prime = interpolate(
                    index,
                    &response_shares
                        .iter()
                        .map(|s| Eval {
                            index: s.index,
                            value: s.r_prime,
                        })
                        .collect::<Vec<_>>(),
                )?
                .value;

                let r = (0..self.number_of_nonces)
                    .map(|l| {
                        interpolate(
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

                Ok(NonceShares { index, r, r_prime })
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        let gamma = self.compute_gamma_from_message(message);
        for shares in &all_shares {
            self.verify_shares(shares, Some(&gamma), message)?;
        }
        Ok(ReceiverOutput { all_shares })
    }

    /// Helper function to verify the consistency of the shares, e.g., that <i>r' + &Sigma;<sub>l</sub> &gamma;<sub>l</sub> r<sub>li</sub> = p''(i)<i>.
    fn verify_shares(
        &self,
        shares: &NonceShares<G::ScalarType>,
        gamma: Option<&Vec<G::ScalarType>>,
        message: &Message<G, EG>,
    ) -> FastCryptoResult<()> {
        if shares.r.len() != self.number_of_nonces as usize {
            return Err(InvalidInput);
        }

        let gamma = match gamma {
            Some(g) => g,
            None => &self.compute_gamma_from_message(message),
        };

        if gamma.len() != self.number_of_nonces as usize {
            return Err(InvalidInput);
        }

        // Verify that r' + sum_l r_l * gamma_l == p''(i)
        if shares
            .r
            .iter()
            .zip(gamma)
            .fold(shares.r_prime, |acc, (r_l, gamma_l)| acc + (*r_l * gamma_l))
            != message.q.eval(shares.index).value
        {
            return Err(InvalidInput);
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

        if shares.r.len() != self.number_of_nonces as usize {
            debug!("check_complaint_proof recovered invalid number of shares");
            return Ok(());
        }

        if self.verify_shares(&shares, None, message).is_err() {
            return Ok(());
        }

        Err(InvalidProof)
    }
}

enum Extension {
    Recovery(PartyId),
    Encryption,
    Challenge,
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

trait FiatShamirImpl<G: GroupElement + Serialize, EG: GroupElement + Serialize>:
    RandomOracleExtensions
where
    G::ScalarType: FiatShamirChallenge,
{
    fn compute_gamma(
        &self,
        c: &[G],
        c_prime: &G,
        e: &MultiRecipientEncryption<EG>,
    ) -> Vec<G::ScalarType> {
        let random_oracle = self.random_oracle_extension(Challenge);
        (0..c.len())
            .map(|l| random_oracle.evaluate(&(l, c, c_prime, e)))
            .map(|bytes| G::ScalarType::fiat_shamir_reduction_to_group_element(&bytes))
            .collect::<Vec<_>>()
    }

    fn compute_gamma_from_message(&self, message: &Message<G, EG>) -> Vec<G::ScalarType> {
        self.compute_gamma(
            message.public_keys.as_slice(),
            &message.c_prime,
            &message.ciphertext,
        )
    }
}

/// Compute g^{p(0)} from the polynomial p.
fn pk_from_sk<G: GroupElement>(p: &Poly<G::ScalarType>) -> G {
    G::generator() * p.c0()
}

impl<G, EG: GroupElement> RandomOracleExtensions for Dealer<G, EG> {
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
