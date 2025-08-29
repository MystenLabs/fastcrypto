// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod tests;

use crate::batched_avss::Extension::{Challenge, Encryption, Recovery};
use crate::ecies_v1;
use crate::ecies_v1::{MultiRecipientEncryption, PublicKey, RecoveryPackage};
use crate::nodes::PartyId;
use crate::polynomial::{interpolate, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidProof;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tracing::debug;
use zeroize::Zeroize;

/// This represents a Dealer in the AVSS. There is exactly one dealer, who creates the shares and broadcasts the encrypted shares.
pub struct Dealer<G, EG: GroupElement> {
    number_of_nonces: u16,
    f: u16,
    public_keys: Vec<PublicKey<EG>>,
    random_oracle: RandomOracle,
    _group: PhantomData<G>,
}

pub struct Receiver<G, EG: GroupElement>
where
    EG::ScalarType: Zeroize,
{
    index: u16,
    secret_key: ecies_v1::PrivateKey<EG>,
    number_of_nonces: u16,
    random_oracle: RandomOracle,
    f: u16,
    _group: PhantomData<G>,
}

#[derive(Clone, Debug)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    c: Vec<G>,
    c_prime: G,
    encryptions: MultiRecipientEncryption<EG>,
    p_double_prime: Poly<G::ScalarType>,
}

pub struct ComplaintResponse<EG: GroupElement> {
    recovery_package: RecoveryPackage<EG>,
}

#[derive(Clone, Debug)]
pub struct Complaint<EG: GroupElement> {
    index: PartyId,
    proof: RecoveryPackage<EG>,
}

pub trait Certificate<G: GroupElement, EG: GroupElement> {
    fn message(&self) -> Message<G, EG>;
    fn is_valid(&self, threshold: usize) -> bool;
    fn includes_receiver(&self, index: u16) -> bool;
}

/// The shares for a receiver, containing L shares and one for the combined polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shares<C: GroupElement> {
    pub r: Vec<C>,
    pub r_prime: C,
}

/// The output of the dealer: The nonces and their corresponding public keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output<G: GroupElement>(Vec<(G, G::ScalarType)>);

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
    pub fn create_message<Rng: AllowedRng>(&self, rng: &mut Rng) -> (Message<G, EG>, Output<G>) {
        // TODO: weights + higher thresholds
        let n = 3 * self.f + 1;

        let p = (0..self.number_of_nonces)
            .map(|_| Poly::<G::ScalarType>::rand(self.f, rng))
            .collect::<Vec<_>>();
        let p_prime = Poly::<G::ScalarType>::rand(self.f, rng);
        let c = p
            .iter()
            .map(|p_l| G::generator() * p_l.c0())
            .collect::<Vec<_>>();
        let c_prime = G::generator() * p_prime.c0();
        let r: Vec<Vec<G::ScalarType>> = p
            .iter()
            .map(|p_l| {
                (1..=n)
                    .map(|j| p_l.eval(ShareIndex::new(j).unwrap()).value)
                    .collect()
            })
            .collect();
        let r_prime: Vec<G::ScalarType> = (1..=n)
            .map(|j| p_prime.eval(ShareIndex::new(j).unwrap()).value)
            .collect();

        let encryptions = MultiRecipientEncryption::encrypt(
            &self
                .public_keys
                .iter()
                .enumerate()
                .map(|(j, pk)| {
                    let msg = Shares {
                        r: r.iter().map(|r_l| r_l[j]).collect(),
                        r_prime: r_prime[j],
                    };
                    (pk.clone(), bcs::to_bytes(&msg).unwrap())
                })
                .collect::<Vec<_>>(),
            &self.random_oracle_extension(Encryption),
            rng,
        );

        let gamma = self.compute_gamma(&c, &c_prime, &encryptions);

        let mut p_double_prime = p_prime;
        for (p_l, gamma_l) in p.iter().zip(&gamma) {
            p_double_prime += &(p_l.clone() * gamma_l);
        }

        let nonces = p
            .iter()
            .zip(c.iter())
            .map(|(p_l, c_l)| (*c_l, *p_l.c0()))
            .collect();

        (
            Message {
                c,
                c_prime,
                encryptions,
                p_double_prime,
            },
            Output(nonces),
        )
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
    ) -> FastCryptoResult<Shares<G::ScalarType>> {
        // TODO: Sanity checks?

        let random_oracle_encryption = self.random_oracle_extension(Encryption);
        message.encryptions.verify(&random_oracle_encryption)?;

        let decrypted = message.encryptions.decrypt(
            &self.secret_key,
            &random_oracle_encryption,
            (self.index - 1) as usize,
        );
        let shares = bcs::from_bytes(&decrypted).map_err(|_| FastCryptoError::InvalidInput)?;

        let gamma = self.compute_gamma_from_message(&message);
        self.verify_shares(&shares, Some(&gamma), &message)?;

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        if G::generator() * message.p_double_prime.c0()
            != message.c_prime + G::multi_scalar_mul(&gamma, &message.c)?
        {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(shares)
    }

    /// 4. When 2f+1 signatures has been collected in the certificate, the receivers can now verify it.
    ///  - If the receiver is already in the certificate, do nothing.
    ///  - If it is not in the certificate, but it is able to decrypt and verify its shares, store the shares and do nothing.
    ///  - If it is not in the certificate and cannot decrypt or verify its shares, it creates a complaint with a recovery package for its shares.
    pub fn process_certificate(
        &self,
        cert: &impl Certificate<G, EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Option<Complaint<EG>>> {
        if !cert.is_valid((2 * self.f + 1) as usize) {
            return Err(FastCryptoError::InvalidInput);
        }

        if cert.includes_receiver(self.index) {
            return Ok(None);
        }

        match self.process_message(&cert.message()) {
            Ok(_) => Ok(None),
            Err(_) => {
                cert.message()
                    .encryptions
                    .verify(&self.random_oracle_extension(Encryption))?;
                Ok(Some(Complaint {
                    index: self.index,
                    proof: cert.message().encryptions.create_recovery_package(
                        &self.secret_key,
                        &self.random_oracle_extension(Recovery(self.index)),
                        rng,
                    ),
                }))
            }
        }
    }

    /// 5. Upon receiving a complaint, a receiver verifies it and responds with a recovery package for the shares of the accuser.
    pub fn handle_complaint(
        &self,
        message: &Message<G, EG>,
        pk: &PublicKey<EG>,
        complaint: &Complaint<EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse<EG>> {
        self.check_complaint_proof(message, complaint, pk)?;

        Ok(ComplaintResponse {
            recovery_package: message.encryptions.create_recovery_package(
                &self.secret_key,
                &self.random_oracle_extension(Recovery(self.index)),
                rng,
            ),
        })
    }

    /// Helper function to verify the consistency of the shares, e.g. that <i>r' + &Sigma;<sub>l</sub> &gamma;<sub>l</sub> r<sub>li</sub> = p''(i)<i>.
    fn verify_shares(
        &self,
        shares: &Shares<G::ScalarType>,
        gamma: Option<&Vec<G::ScalarType>>,
        message: &Message<G, EG>,
    ) -> FastCryptoResult<()> {
        if shares.r.len() != self.number_of_nonces as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        let gamma = match gamma {
            Some(g) => g,
            None => &self.compute_gamma_from_message(message),
        };

        if gamma.len() != self.number_of_nonces as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        // Verify that r' + sum_l r_l * gamma_l == p''(i)
        if shares
            .r
            .iter()
            .zip(gamma)
            .fold(shares.r_prime, |acc, (r_l, gamma_l)| acc + (*r_l * gamma_l))
            != message
                .p_double_prime
                .eval(ShareIndex::new(self.index).unwrap())
                .value
        {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(())
    }

    /// 6. Upon receiving f+1 valid responses, the accuser can recover its shares.
    pub fn recover_shares(
        &mut self,
        message: &Message<G, EG>,
        responses: Vec<(PartyId, PublicKey<EG>, ComplaintResponse<EG>)>,
    ) -> FastCryptoResult<Shares<G::ScalarType>> {
        if responses.len() < (self.f + 1) as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        let ro_encryption = self.random_oracle_extension(Encryption);

        // Ignore invalid responses
        let shares = responses
            .iter()
            .map(|(i, pk, r)| {
                message
                    .encryptions
                    .decrypt_with_recovery_package(
                        &r.recovery_package,
                        &self.random_oracle_extension(Recovery(*i)),
                        &ro_encryption,
                        pk,
                        *i as usize - 1,
                    )
                    .map(|b| (i, b))
            })
            .map_ok(|(i, b)| {
                bcs::from_bytes::<Shares<G::ScalarType>>(b.as_slice())
                    .map_err(|_| FastCryptoError::InvalidInput)
                    .map(|b| (i, b))
            })
            .filter_map(Result::ok)
            .collect::<FastCryptoResult<Vec<_>>>()?;

        if shares.len() < (self.f + 1) as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        let share_index = ShareIndex::new(self.index).unwrap();
        let r_prime = interpolate(
            share_index,
            &shares
                .iter()
                .map(|(i, s)| Eval {
                    index: ShareIndex::new(**i as u16).unwrap(),
                    value: s.r_prime,
                })
                .collect::<Vec<_>>(),
        )?
        .value;

        let r = (0..self.number_of_nonces)
            .map(|l| {
                interpolate(
                    share_index,
                    &shares
                        .iter()
                        .map(|(i, s)| Eval {
                            index: ShareIndex::new(**i as u16).unwrap(),
                            value: s.r[l as usize],
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap()
                .value
            })
            .collect::<Vec<_>>();

        let shares = Shares {
            r: r.clone(),
            r_prime,
        };
        self.verify_shares(&shares, None, message)?;
        Ok(Shares { r, r_prime })
    }

    fn check_complaint_proof(
        &self,
        message: &Message<G, EG>,
        complaint: &Complaint<EG>,
        receiver_pk: &PublicKey<EG>,
    ) -> FastCryptoResult<()> {
        // Check that the recovery package is valid, and if not, return an error since the complaint
        // is invalid.
        let buffer = message.encryptions.decrypt_with_recovery_package(
            &complaint.proof,
            &self.random_oracle_extension(Recovery(complaint.index)),
            &self.random_oracle_extension(Encryption),
            receiver_pk,
            complaint.index as usize - 1,
        )?;

        let shares: Shares<G::ScalarType> = match bcs::from_bytes(buffer.as_slice()) {
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

        let gamma = self.compute_gamma_from_message(message);

        if shares
            .r
            .iter()
            .zip(&gamma)
            .fold(shares.r_prime, |acc, (r_l, gamma_l)| acc + (*r_l * gamma_l))
            != message
                .p_double_prime
                .eval(ShareIndex::new(self.index).unwrap())
                .value
        {
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
        let ro_gamma = self.random_oracle_extension(Challenge);
        (1..=c.len())
            .map(|l| ro_gamma.evaluate(&(l, c, c_prime, e)))
            .map(|b| G::ScalarType::fiat_shamir_reduction_to_group_element(&b))
            .collect::<Vec<_>>()
    }

    fn compute_gamma_from_message(&self, message: &Message<G, EG>) -> Vec<G::ScalarType> {
        self.compute_gamma(message.c.as_slice(), &message.c_prime, &message.encryptions)
    }
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
