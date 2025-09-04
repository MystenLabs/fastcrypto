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
    secret_key: PrivateKey<EG>,
    nodes: Nodes<EG>,
    number_of_nonces: u16,
    random_oracle: RandomOracle,
    threshold: u16,
    _group: PhantomData<G>,
}

#[derive(Clone, Debug)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    public_keys: Vec<G>,
    c_prime: G,
    ciphertext: MultiRecipientEncryption<EG>,
    q: Poly<G::ScalarType>,
}

pub struct ComplaintResponse<EG: GroupElement> {
    recovery_package: RecoveryPackage<EG>,
}

#[derive(Clone, Debug)]
pub struct Complaint<EG: GroupElement> {
    party_id: PartyId,
    proof: RecoveryPackage<EG>,
}

pub trait Certificate<G: GroupElement, EG: GroupElement> {
    fn message(&self) -> Message<G, EG>;
    fn is_valid(&self, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}

/// The shares for a receiver, containing shares for each nonce and one for the combined polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceShares<C: GroupElement> {
    pub index: ShareIndex,
    pub r: Vec<C>,
    pub r_prime: C,
}

/// The output of the dealer: The nonces and their corresponding public keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output<G: GroupElement> {
    nonces: Vec<G::ScalarType>,
}

pub struct ReceiverOutput<G: GroupElement> {
    pub shares: Vec<NonceShares<G::ScalarType>>,
    pub partial_public_keys: Vec<G>,
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
    ///    This also returns the nonces along with their corresponding public keys.
    pub fn create_message<Rng: AllowedRng>(
        &self,
        rng: &mut Rng,
    ) -> FastCryptoResult<(Message<G, EG>, Output<G>)> {
        let polynomials = (0..self.number_of_nonces)
            .map(|_| Poly::rand(self.threshold, rng))
            .collect_vec();
        let public_keys = polynomials.iter().map(pk_from_sk).collect_vec();

        // Secrets to be shared
        let nonces = polynomials.iter().map(|p_l| *p_l.c0()).collect();

        let p_prime = Poly::rand(self.threshold, rng);
        let c_prime = pk_from_sk(&p_prime);

        // Encrypt
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

        let mut q = p_prime;
        for (p_l, gamma_l) in polynomials.into_iter().zip(&gamma) {
            q += &(p_l * gamma_l); // TODO: Impl MSM for polynomials?
        }

        Ok((
            Message {
                public_keys,
                c_prime,
                ciphertext,
                q,
            },
            Output { nonces },
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
    pub fn process_message(
        &self,
        message: &Message<G, EG>,
    ) -> FastCryptoResult<Vec<NonceShares<G::ScalarType>>> {
        if message.q.degree() > self.threshold as usize {
            return Err(InvalidInput);
        }

        let random_oracle_encryption = self.random_oracle_extension(Encryption);

        message.ciphertext.verify(&random_oracle_encryption)?;
        let plaintext = message.ciphertext.decrypt(
            &self.secret_key,
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

        Ok(all_shares)
    }

    /// 4. When 2t+1 signatures have been collected in the certificate, the receivers can now verify it.
    ///  - If the receiver is already in the certificate, do nothing.
    ///  - If it is not in the certificate, but it is able to decrypt and verify its shares, store the shares and do nothing.
    ///  - If it is not in the certificate and cannot decrypt or verify its shares, it creates a complaint with a recovery package for its shares.
    ///
    /// Returns an error if the certificate or the encrypted shares are invalid.
    pub fn process_certificate(
        &self,
        cert: &impl Certificate<G, EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Option<Complaint<EG>>> {
        if !cert.is_valid((2 * self.threshold + 1) as usize) {
            return Err(InvalidInput);
        }

        if cert.includes(&self.id) {
            return Ok(None);
        }

        // TODO: Verify message is called both in process_message and in create_complaint, so a receiver will call it up to three times
        match self.process_message(&cert.message()) {
            Ok(_) => Ok(None),
            Err(_) => Ok(Some(self.create_complaint(&cert.message(), rng)?)),
        }
    }

    fn create_complaint(
        &self,
        message: &Message<G, EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Complaint<EG>> {
        message
            .ciphertext
            .verify(&self.random_oracle_extension(Encryption))?;
        Ok(Complaint {
            party_id: self.id,
            proof: message.ciphertext.create_recovery_package(
                &self.secret_key,
                &self.random_oracle_extension(Recovery(self.id)),
                rng,
            ),
        })
    }

    /// 5. Upon receiving a complaint, a receiver verifies it and responds with a recovery package for the shares of the accuser.
    pub fn handle_complaint(
        &self,
        message: &Message<G, EG>,
        complaint: &Complaint<EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse<EG>> {
        self.check_complaint_proof(message, complaint, complaint.party_id)?;
        message
            .ciphertext
            .verify(&self.random_oracle_extension(Encryption))?;
        Ok(ComplaintResponse {
            recovery_package: message.ciphertext.create_recovery_package(
                &self.secret_key,
                &self.random_oracle_extension(Recovery(self.id)),
                rng,
            ),
        })
    }

    /// Helper function to verify the consistency of the shares, e.g. that <i>r' + &Sigma;<sub>l</sub> &gamma;<sub>l</sub> r<sub>li</sub> = p''(i)<i>.
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

    /// 6. Upon receiving f+1 valid responses, the accuser can recover its shares.
    /// Fails if there are not enough valid responses to recover the shares.
    pub fn recover_shares(
        &mut self,
        message: &Message<G, EG>,
        responses: &[(PartyId, ComplaintResponse<EG>)],
    ) -> FastCryptoResult<Vec<NonceShares<G::ScalarType>>> {
        // Sanity check that we have enough responses (by weight) to recover the shares.
        let response_weights = responses
            .iter()
            .map(|(id, _)| self.nodes.share_ids_of(*id))
            .map_ok(|ids| ids.len())
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let total_response_weight: usize = response_weights.iter().sum();
        if total_response_weight < (self.threshold + 1) as usize {
            return Err(FastCryptoError::InputTooShort(
                (self.threshold + 1) as usize,
            ));
        }

        let ro_encryption = self.random_oracle_extension(Encryption);

        let response_shares = responses
            .iter()
            .filter_map(|(id, response)| {
                self.nodes
                    .node_id_to_node(*id)
                    .and_then(|node| {
                        message.ciphertext.decrypt_with_recovery_package(
                            &response.recovery_package,
                            &self.random_oracle_extension(Recovery(node.id)),
                            &ro_encryption,
                            &node.pk,
                            *id as usize,
                        )
                    })
                    .and_then(|bytes| {
                        bcs::from_bytes::<Vec<NonceShares<G::ScalarType>>>(bytes.as_slice())
                            .map_err(|_| InvalidInput)
                    })
                    .tap_err(|_| warn!("Ignoring invalid recovery package from {}", id))
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

        let my_shares = self
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
        for shares in &my_shares {
            self.verify_shares(shares, Some(&gamma), message)?;
        }
        Ok(my_shares)
    }

    /// Helper function to verify that the complaint is valid, i.e., that the recovery package decrypts to valid shares.
    /// This returns [Ok] if the complaint is valid, and [Err] if it is invalid.
    fn check_complaint_proof(
        &self,
        message: &Message<G, EG>,
        complaint: &Complaint<EG>,
        id: PartyId,
    ) -> FastCryptoResult<()> {
        let pk = &self.nodes.node_id_to_node(id)?.pk;

        // Check that the recovery package is valid, and if not, return an error since the complaint is invalid.
        let buffer = message.ciphertext.decrypt_with_recovery_package(
            &complaint.proof,
            &self.random_oracle_extension(Recovery(complaint.party_id)),
            &self.random_oracle_extension(Encryption),
            &pk,
            complaint.party_id as usize,
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
