use crate::batched_avss::Extension::Encryption;
use crate::batched_avss::{
    to_index, Certificate, Dealer, FiatShamirImpl, Message, Node, Output, RandomOracleExtensions,
    Receiver, Shares,
};
use crate::ecies_v1;
use crate::ecies_v1::{MultiRecipientEncryption, PublicKey};
use crate::nodes::Nodes;
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement};
use fastcrypto::traits::AllowedRng;
use serde::Serialize;
use std::collections::HashMap;
use std::marker::PhantomData;
use zeroize::Zeroize;

#[test]
fn test_happy_path() {
    // No complaints, all honest
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
            secret_key,
            number_of_nonces,
            random_oracle: RandomOracle::new("tbls test"),
            threshold,
            nodes: nodes.clone(),
            _group: PhantomData,
        })
        .collect::<Vec<_>>();

    let (message, output) = dealer.create_message(&mut rng);

    let all_shares = receivers
        .iter()
        .map(|receiver| (receiver.id, receiver.process_message(&message).unwrap()))
        .collect::<HashMap<_, _>>();

    let certificate = TestCertificate {
        message: message.clone(),
        included: vec![1, 2, 3, 4, 5], // 2f+1
    };

    for receiver in receivers.iter_mut() {
        // Expect no complaints
        assert!(receiver
            .process_certificate(&certificate, &mut rng)
            .unwrap()
            .is_none());
    }

    let secrets = (0..number_of_nonces)
        .map(|l| {
            let shares = receivers
                .iter()
                .map(|r| (r.id, all_shares.get(&r.id).unwrap().r[l as usize]))
                .collect::<Vec<_>>();
            Poly::recover_c0(
                threshold + 1,
                shares
                    .iter()
                    .take((threshold + 1) as usize)
                    .map(|(id, v)| Eval {
                        index: to_index(id),
                        value: *v,
                    }),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    for l in 0..number_of_nonces {
        assert_eq!(secrets[l as usize], output.nonces[l as usize]);
        assert_eq!(
            G1Element::generator() * secrets[l as usize],
            output.public_keys[l as usize]
        );
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
            secret_key,
            number_of_nonces,
            random_oracle: RandomOracle::new("tbls test"),
            threshold,
            _group: PhantomData,
            nodes: nodes.clone(),
        })
        .collect::<Vec<_>>();

    let (message, output) = dealer.create_message_cheating(&mut rng);

    let mut all_shares = receivers
        .iter()
        .map(|receiver| receiver.process_message(&message).map(|s| (receiver.id, s)))
        .filter_map(Result::ok)
        .collect::<HashMap<_, _>>();

    // First receiver should fail to decrypt/verify its shares
    assert!(all_shares.get(&0).is_none());

    let certificate = TestCertificate {
        message: message.clone(),
        included: vec![2, 3, 4, 5, 6], // 2f+1
    };

    for i in 0..n {
        let complaint = receivers[i as usize]
            .process_certificate(&certificate, &mut rng)
            .unwrap();
        if i == 0 {
            assert!(complaint.is_some());
            let responses = receivers
                .iter()
                .skip(1)
                .map(|r| {
                    (
                        r.id,
                        r.handle_complaint(&message, &complaint.clone().unwrap(), &mut rng)
                            .unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let shares = receivers[0].recover_shares(&message, &responses).unwrap();
            all_shares.insert(0, shares);
        } else {
            assert!(complaint.is_none());
        }
    }

    // Recover with the first f+1 shares, including the reconstructed
    let secrets = (0..number_of_nonces)
        .map(|l| {
            let shares = all_shares
                .iter()
                .map(|(id, s)| (*id, s.r[l as usize]))
                .collect::<Vec<_>>();
            Poly::recover_c0(
                threshold + 1,
                shares
                    .iter()
                    .take((threshold + 1) as usize)
                    .map(|(id, v)| Eval {
                        index: to_index(id),
                        value: *v,
                    }),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    for l in 0..number_of_nonces {
        assert_eq!(secrets[l as usize], output.nonces[l as usize]);
        assert_eq!(
            G1Element::generator() * secrets[l as usize],
            output.public_keys[l as usize]
        );
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
    ) -> (Message<G, EG>, Output<G>) {
        // TODO: weights + higher thresholds
        let n = 3 * self.threshold + 1;

        let p = (0..self.number_of_nonces)
            .map(|_| Poly::<G::ScalarType>::rand(self.threshold, rng))
            .collect::<Vec<_>>();
        let p_prime = Poly::<G::ScalarType>::rand(self.threshold, rng);
        let c = p
            .iter()
            .map(|p_l| G::generator() * p_l.c0())
            .collect::<Vec<_>>();
        let c_prime = G::generator() * p_prime.c0();
        let mut r: Vec<Vec<G::ScalarType>> = p
            .iter()
            .map(|p_l| (0..n).map(|j| p_l.eval(to_index(j)).value).collect())
            .collect();
        let r_prime: Vec<G::ScalarType> = (0..n).map(|j| p_prime.eval(to_index(j)).value).collect();

        // Modify the first share of the first nonce to be incorrect
        r[0][0] += G::ScalarType::from(1u128);

        let encryptions = MultiRecipientEncryption::encrypt(
            &self
                .nodes
                .iter()
                .enumerate()
                .map(|(j, node)| {
                    let msg = Shares {
                        r: r.iter().map(|r_l| r_l[j]).collect(),
                        r_prime: r_prime[j],
                    };
                    (node.pk.clone(), bcs::to_bytes(&msg).unwrap())
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

        let nonces = p.iter().map(|p_l| *p_l.c0()).collect();
        let public_keys = c.clone();

        (
            Message {
                c,
                c_prime,
                encryptions,
                p_double_prime,
            },
            Output {
                nonces,
                public_keys,
            },
        )
    }
}
