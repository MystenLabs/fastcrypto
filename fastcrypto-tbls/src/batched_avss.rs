// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::ecies_v1::{PublicKey, RecoveryPackage};
use crate::nodes::PartyId;
use crate::polynomial::{interpolate, Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidProof;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{
    FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul, Scalar,
};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tracing::debug;
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shares<C: GroupElement> {
    pub r: Vec<C>,
    pub r_prime: C,
}

pub struct Dealer<G, EG: GroupElement> {
    L: u16,
    f: u16,
    public_keys: Vec<PublicKey<EG>>,
    random_oracle: RandomOracle,
    _group: PhantomData<G>,
}

#[derive(Clone, Debug)]
pub struct Message<G: GroupElement, EG: GroupElement> {
    c: Vec<G>,
    c_prime: G,
    e: ecies_v1::MultiRecipientEncryption<EG>,
    p_double_prime: Poly<G::ScalarType>,
}

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    pub fn create_message<Rng: AllowedRng>(&self, rng: &mut Rng) -> Message<G, EG> {
        let n = 3 * self.f + 1;

        let p = (0..self.L)
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

        let e = ecies_v1::MultiRecipientEncryption::encrypt(
            &self
                .public_keys
                .iter()
                .enumerate()
                .map(|(j, pk)| {
                    let msg: Shares<G::ScalarType> = Shares {
                        r: r.iter().map(|r_l| r_l[j]).collect(),
                        r_prime: r_prime[j],
                    };
                    (pk.clone(), bcs::to_bytes(&msg).unwrap())
                })
                .collect::<Vec<_>>(),
            &self.random_oracle.extend("encryption"),
            rng,
        );

        let ro = self.random_oracle.extend("fiatshamir");
        let gamma = (1..=self.L)
            .map(|l| ro.evaluate(&(l, &c, c_prime, &e)))
            .map(|b| G::ScalarType::fiat_shamir_reduction_to_group_element(&b))
            .collect::<Vec<_>>();

        let mut p_double_prime = p_prime;
        for (p_l, gamma_l) in p.iter().zip(&gamma) {
            p_double_prime += &(p_l.clone() * gamma_l);
        }

        Message {
            c,
            c_prime,
            e,
            p_double_prime,
        }
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
    pub fn process_message(&mut self, message: &Message<G, EG>) -> FastCryptoResult<()> {
        // TODO: Sanity checks?

        message.e.verify(&self.random_oracle.extend("encryption"))?;

        let decrypted = message.e.decrypt(
            &self.secret_key,
            &self.random_oracle.extend("encryption"),
            (self.index - 1) as usize,
        );
        let shares: Shares<G::ScalarType> =
            bcs::from_bytes(&decrypted).map_err(|_| FastCryptoError::InvalidInput)?;

        let gamma = self.compute_gamma(&message);

        self.verify_shares(&shares.r, &shares.r_prime, Some(&gamma), &message)?;

        // Verify that g^{p''(0)} == c' * prod_l c_l^{gamma_l}
        if G::generator() * message.p_double_prime.c0()
            != message.c_prime + G::multi_scalar_mul(&gamma, &message.c)?
        {
            return Err(FastCryptoError::InvalidInput);
        }

        self.shares = Some(shares);

        Ok(())
    }

    pub fn process_certificate(
        &mut self,
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
                let ro = self.random_oracle.extend("encryption");
                cert.message().e.verify(&ro)?;
                Ok(Some(Complaint {
                    index: self.index,
                    proof: cert
                        .message()
                        .e
                        .create_recovery_package(&self.secret_key, &ro, rng),
                }))
            }
        }
    }

    pub fn handle_complaint(
        &self,
        message: &Message<G, EG>,
        pk: PublicKey<EG>,
        complaint: &Complaint<EG>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<ComplaintResponse<EG>> {
        self.check_complaint_proof(message, &complaint, &pk)?;

        Ok(ComplaintResponse {
            recovery_package: message.e.create_recovery_package(
                &self.secret_key,
                &self.random_oracle.extend("encryption"),
                rng,
            ),
        })
    }

    fn compute_gamma(&self, message: &Message<G, EG>) -> Vec<G::ScalarType> {
        let ro_gamma = self.random_oracle.extend("fiatshamir");
        (1..=self.L)
            .map(|l| ro_gamma.evaluate(&(l, &message.c, message.c_prime, &message.e)))
            .map(|b| G::ScalarType::fiat_shamir_reduction_to_group_element(&b))
            .collect::<Vec<_>>()
    }

    fn verify_shares(
        &self,
        r: &[G::ScalarType],
        r_prime: &G::ScalarType,
        gamma: Option<&Vec<G::ScalarType>>,
        message: &Message<G, EG>,
    ) -> FastCryptoResult<()> {
        if r.len() != self.L as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        let gamma = match gamma {
            Some(g) => g,
            None => &self.compute_gamma(message),
        };

        if gamma.len() != self.L as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        // Verify that r' + sum_l r_l * gamma_l == p''(i)
        if r.iter()
            .zip(gamma)
            .fold(*r_prime, |acc, (r_l, gamma_l)| acc + (*r_l * gamma_l))
            != message
                .p_double_prime
                .eval(ShareIndex::new(self.index).unwrap())
                .value
        {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(())
    }

    pub fn recover_shares(
        &mut self,
        message: &Message<G, EG>,
        responses: Vec<(PartyId, PublicKey<EG>, ComplaintResponse<EG>)>,
    ) -> FastCryptoResult<()> {
        if responses.len() < (self.f + 1) as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        let ro = self.random_oracle_recovery(self.index);
        let ro_enc = self.random_oracle.extend("encryption");

        // Ignore invalid responses
        let shares = responses
            .iter()
            .map(|(i, pk, r)| {
                message
                    .e
                    .decrypt_with_recovery_package(
                        &r.recovery_package,
                        &ro,
                        &ro_enc,
                        pk,
                        *i as usize,
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

        let r = (0..self.L)
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

        self.verify_shares(&r, &r_prime, None, message)?;
        self.shares = Some(Shares { r, r_prime });

        Ok(())
    }

    fn random_oracle_recovery(&self, accuser: PartyId) -> RandomOracle {
        self.random_oracle
            .extend(&format!("recovery of {accuser}",))
    }

    #[allow(clippy::too_many_arguments)]
    fn check_complaint_proof(
        &self,
        message: &Message<G, EG>,
        complaint: &Complaint<EG>,
        receiver_pk: &PublicKey<EG>,
    ) -> FastCryptoResult<()> {
        // Check that the recovery package is valid, and if not, return an error since the complaint
        // is invalid.
        let buffer = message.e.decrypt_with_recovery_package(
            &complaint.proof,
            &self.random_oracle_recovery(complaint.index),
            &self.random_oracle.extend("encryption"),
            receiver_pk,
            complaint.index as usize,
        )?;

        let shares: Shares<G::ScalarType> = match bcs::from_bytes(buffer.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                debug!("check_complaint_proof failed to deserialize shares");
                return Ok(());
            }
        };

        if shares.r.len() != self.L as usize {
            debug!("check_complaint_proof recovered invalid number of shares");
            return Ok(());
        }

        let gamma = self.compute_gamma(message);

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

pub struct ComplaintResponse<EG: GroupElement> {
    recovery_package: RecoveryPackage<EG>,
}

pub struct Complaint<EG: GroupElement> {
    index: PartyId,
    proof: RecoveryPackage<EG>,
}

pub trait Certificate<G: GroupElement, EG: GroupElement> {
    fn message(&self) -> Message<G, EG>;
    fn is_valid(&self, threshold: usize) -> bool;
    fn includes_receiver(&self, index: u16) -> bool;
}

pub struct Receiver<G: GroupElement, EG: GroupElement>
where
    EG::ScalarType: Zeroize,
{
    index: u16,
    secret_key: ecies_v1::PrivateKey<EG>,
    L: u16,
    random_oracle: RandomOracle,
    f: u16,
    shares: Option<Shares<G::ScalarType>>,
}

#[cfg(test)]
mod tests {
    use crate::batched_avss::{Certificate, Dealer, Message, Receiver};
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::random_oracle::RandomOracle;
    use fastcrypto::groups::bls12381::{G1Element, G2Element};
    use fastcrypto::groups::GroupElement;

    #[test]
    fn test_e2e() {
        let f = 2;
        let n = 3 * f + 1;

        let mut rng = rand::thread_rng();
        let sks = (0..n)
            .map(|_| ecies_v1::PrivateKey::<G2Element>::new(&mut rng))
            .collect::<Vec<_>>();
        let pks = sks
            .iter()
            .map(PublicKey::from_private_key)
            .collect::<Vec<_>>();

        let random_oracle = RandomOracle::new("tbls test");

        let dealer: Dealer<G1Element, G2Element> = Dealer {
            L: 3,
            f: 2,
            public_keys: pks,
            random_oracle,
            _group: Default::default(),
        };

        let mut receivers = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| Receiver {
                index: (i + 1) as u16,
                secret_key: sk.clone(),
                L: 3,
                random_oracle: RandomOracle::new("tbls test"),
                f: 2,
                shares: None,
            })
            .collect::<Vec<_>>();

        let message = dealer.create_message(&mut rng);

        for receiver in receivers.iter_mut() {
            receiver.process_message(&message).unwrap();
            assert!(receiver.shares.is_some());
        }

        let certificate = TestCertificate {
            message: message.clone(),
            included: vec![1, 2, 3, 4, 5, 6, 7],
        };

        for receiver in receivers.iter_mut() {
            // Expect no complaints
            assert!(receiver
                .process_certificate(&certificate, &mut rng)
                .unwrap()
                .is_none());
        }
    }

    pub struct TestCertificate<G: GroupElement, EG: GroupElement> {
        message: Message<G, EG>,
        included: Vec<u16>,
    }

    impl<G: GroupElement, EG: GroupElement> Certificate<G, EG> for TestCertificate<G, EG> {
        fn message(&self) -> Message<G, EG> {
            self.message.clone()
        }

        fn is_valid(&self, threshold: usize) -> bool {
            self.included.len() >= threshold
        }

        fn includes_receiver(&self, index: u16) -> bool {
            self.included.contains(&index)
        }
    }
}
