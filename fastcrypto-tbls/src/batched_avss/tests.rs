use crate::batched_avss::Extension::Encryption;
use crate::batched_avss::{
    Certificate, Complaint, Dealer, DealerOutput, FiatShamirImpl, Message, NonceShares,
    ProcessCertificateResult, RandomOracleExtensions, Receiver,
};
use crate::ecies_v1;
use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::Serialize;
use std::collections::HashMap;
use std::marker::PhantomData;
use zeroize::Zeroize;

#[test]
fn test_happy_path() {
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

    let dealer: Dealer<G1Element, G2Element> = Dealer {
        number_of_nonces,
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
            number_of_nonces,
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

#[test]
fn test_happy_path_non_equal_weights() {
    // No complaints, all honest
    let threshold = 2;
    let weights: Vec<u16> = vec![1, 2, 3, 4];
    let number_of_nonces = 3;

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

    let dealer: Dealer<G1Element, G2Element> = Dealer {
        number_of_nonces,
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
            number_of_nonces,
            random_oracle: RandomOracle::new("tbls test"),
            threshold,
            nodes: nodes.clone(),
            _group: PhantomData,
        })
        .collect::<Vec<_>>();

    let (message, output) = dealer.create_message(&mut rng).unwrap();

    let all_shares = receivers
        .iter()
        .map(|receiver| receiver.process_message(&message).unwrap().all_shares)
        .flatten()
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

    let secrets = (0..number_of_nonces)
        .map(|l| {
            Poly::recover_c0(
                threshold + 1,
                all_shares
                    .iter()
                    .take((threshold + 1) as usize)
                    .map(|s| Eval {
                        index: s.index,
                        value: s.r[l as usize],
                    }),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    for l in 0..number_of_nonces {
        assert_eq!(secrets[l as usize], output.nonces[l as usize]);
    }
}

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

    let dealer: Dealer<G1Element, G2Element> = Dealer {
        number_of_nonces,
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
            number_of_nonces,
            random_oracle: RandomOracle::new("tbls test"),
            threshold,
            _group: PhantomData,
            nodes: nodes.clone(),
        })
        .collect::<Vec<_>>();

    let (message, output) = dealer.create_message_cheating(&mut rng).unwrap();

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
                .map(|(id, s)| (*id, s.all_shares[0].r[l as usize]))
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

impl<G: GroupElement + Serialize, EG: GroupElement + HashToGroupElement + Serialize> Dealer<G, EG>
where
    EG::ScalarType: FiatShamirChallenge + Zeroize,
    G::ScalarType: FiatShamirChallenge,
{
    /// 1. The Dealer samples L nonces, generates shares and broadcasts the encrypted shares. This also returns the nonces to be secret shared along with their corresponding public keys.
    pub fn create_message_cheating<Rng: AllowedRng>(
        &self,
        rng: &mut Rng,
    ) -> FastCryptoResult<(Message<G, EG>, DealerOutput<G>)> {
        let n = self.nodes.total_weight();

        let polynomials = (0..self.number_of_nonces)
            .map(|_| Poly::rand(self.threshold, rng))
            .collect::<Vec<_>>();
        let public_keys = polynomials
            .iter()
            .map(|p_l| G::generator() * p_l.c0())
            .collect::<Vec<_>>();

        let p_prime = Poly::rand(self.threshold, rng);
        let c_prime = G::generator() * p_prime.c0();

        let mut r: Vec<Vec<G::ScalarType>> = polynomials
            .iter()
            .map(|p_l| {
                (0..n)
                    .map(|j| p_l.eval(ShareIndex::try_from(j + 1).unwrap()).value)
                    .collect()
            })
            .collect();
        let r_prime: Vec<G::ScalarType> = (0..n)
            .map(|j| p_prime.eval(ShareIndex::try_from(j + 1).unwrap()).value)
            .collect();

        // Modify the first share of the first nonce to be incorrect
        r[0][0] += G::ScalarType::from(1u128);

        let shares_for_node = self
            .nodes
            .iter()
            .map(|node| {
                let share_ids = self.nodes.share_ids_of(node.id)?;
                Ok(share_ids
                    .iter()
                    .map(|share_id| NonceShares {
                        index: *share_id,
                        r: r.iter()
                            .map(|r_l| r_l[share_id.get() as usize - 1])
                            .collect(),
                        r_prime: r_prime[share_id.get() as usize - 1],
                    })
                    .collect::<Vec<NonceShares<G::ScalarType>>>())
            })
            .collect::<FastCryptoResult<Vec<Vec<NonceShares<G::ScalarType>>>>>()?;

        let ciphertext = MultiRecipientEncryption::encrypt(
            &self
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.pk.clone(),
                        bcs::to_bytes(&shares_for_node[node.id as usize]).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
            &self.random_oracle_extension(Encryption),
            rng,
        );

        let gamma = self.compute_gamma(&public_keys, &c_prime, &ciphertext);

        let mut q = p_prime;
        for (p_l, gamma_l) in polynomials.iter().zip(&gamma) {
            q += &(p_l.clone() * gamma_l);
        }

        let nonces = polynomials.iter().map(|p_l| *p_l.c0()).collect();

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

impl<G: GroupElement, EG: GroupElement> ProcessCertificateResult<G, EG> {
    fn assert_complaint(&self) -> &Complaint<EG> {
        match self {
            ProcessCertificateResult::Complaint(c) => c,
            _ => panic!("Expected a complaint"),
        }
    }

    fn assert_no_complaint(&self) {
        match self {
            ProcessCertificateResult::Complaint(_) => panic!("Expected no complaint"),
            _ => {}
        }
    }
}
