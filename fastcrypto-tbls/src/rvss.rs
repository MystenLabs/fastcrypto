use crate::dl_verification::{verify_pairs, verify_triplets};
use crate::polynomial::Poly;
use crate::random_oracle::RandomOracle;
use either::Either;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::{
    error::{FastCryptoError, FastCryptoResult},
    groups::{ristretto255, GroupElement, HashToGroupElement, Scalar},
};
use itertools::Itertools;
use rand::thread_rng;
use serde::Serialize;
use std::num::NonZeroU16;

// Quick and dirty implementation of the RVSS protocol for performance testing

//////// Recovery gadget ////////
#[derive(Serialize)]
pub struct Gadget {
    h: ristretto255::RistrettoPoint,
    h_omega: ristretto255::RistrettoPoint,
    t: Vec<(ristretto255::RistrettoPoint, Vec<u8>)>,
    t_prime: Vec<Either<ristretto255::RistrettoPoint, ristretto255::RistrettoScalar>>,
}

impl Gadget {
    pub fn new(
        k: usize,
        h: ristretto255::RistrettoPoint,
        omega: ristretto255::RistrettoScalar,
    ) -> Self {
        let ro = RandomOracle::new("gadget");
        let r = (0..k)
            .map(|_i| ristretto255::RistrettoScalar::rand(&mut thread_rng()))
            .collect_vec();

        let h_omega = h * omega;
        let g = ristretto255::RistrettoPoint::generator();

        let t = r
            .iter()
            .enumerate()
            .map(|(j, r_j)| {
                let g_j = g * *r_j;
                let hash = &ro.evaluate(&(j, &g_j))[0..32];
                let xored = hash
                    .iter()
                    .zip(r_j.to_byte_array())
                    .map(|(&x1, x2)| x1 ^ x2)
                    .collect();
                (h * *r_j, xored)
            })
            .collect_vec();

        let challenge = ro.evaluate(&(h, h_omega, &t));
        let t_prime = (0..k)
            .map(|i| {
                if challenge[i / 8] & (1 << (i % 8)) == 0 {
                    Either::Left(g * r[i])
                } else {
                    Either::Right(r[i] - omega)
                }
            })
            .collect();

        Self {
            h,
            h_omega,
            t,
            t_prime,
        }
    }

    pub fn verify(&self, k: usize) -> FastCryptoResult<()> {
        let ro = RandomOracle::new("gadget");
        let challenge = ro.evaluate(&(self.h, self.h_omega, &self.t));
        let mut tuples_1 = Vec::new();
        let mut tuples_2 = Vec::new();
        for i in 0..k {
            let bit = challenge[i / 8] & (1 << (i % 8));
            if bit == 0 {
                if let Either::Left(g_j) = self.t_prime[i] {
                    let hash = &ro.evaluate(&(i, &g_j))[0..32];
                    let r_j = hash
                        .iter()
                        .zip(&self.t[i].1)
                        .map(|(x1, &x2)| x1 ^ x2)
                        .collect_vec();
                    let r_j: ristretto255::RistrettoScalar =
                        ristretto255::RistrettoScalar::from_byte_array(
                            &r_j[0..32].try_into().unwrap(),
                        )
                        .unwrap();
                    tuples_1.push((r_j, g_j));
                    tuples_2.push((r_j, self.t[i].0));
                } else {
                    return Err(FastCryptoError::InvalidProof);
                }
            } else {
                if let Either::Right(t_prime_j) = self.t_prime[i] {
                    tuples_2.push((t_prime_j, self.t[i].0 - self.h_omega));
                } else {
                    return Err(FastCryptoError::InvalidProof);
                }
            }
        }
        verify_pairs(
            &ristretto255::RistrettoPoint::generator(),
            &tuples_1,
            &mut thread_rng(),
        )?;
        verify_pairs(&self.h, &tuples_2, &mut thread_rng())
    }
}

//////// Low degree zk proof ////////
#[derive(Serialize)]
pub struct LDProof {
    challenge: ristretto255::RistrettoScalar,
    z_poly: Poly<ristretto255::RistrettoScalar>,
    bases_to_z: Vec<(ristretto255::RistrettoPoint, ristretto255::RistrettoPoint)>,
    exponents_to_challenge: Vec<(ristretto255::RistrettoPoint, ristretto255::RistrettoPoint)>,
}

impl LDProof {
    pub fn new(
        bases1: &[ristretto255::RistrettoPoint],
        bases2: &[ristretto255::RistrettoPoint],
        exponents1: &[ristretto255::RistrettoPoint],
        exponents2: &[ristretto255::RistrettoPoint],
        secret_poly: &Poly<ristretto255::RistrettoScalar>,
    ) -> LDProof {
        assert!(bases1.len() == bases2.len());
        assert!(bases1.len() == exponents1.len());
        assert!(bases1.len() == exponents2.len());

        let ro = RandomOracle::new("mldei");

        let r_poly = Poly::rand(secret_poly.degree() as u16, &mut thread_rng());
        let x = bases1
            .iter()
            .zip(bases2.iter())
            .enumerate()
            .map(|(j, (base1, base2))| {
                let r_j = r_poly.eval(share_index(j)).value;
                (base1 * r_j, base2 * r_j)
            })
            .collect_vec();

        let challenge: ristretto255::RistrettoScalar =
            ristretto255::RistrettoScalar::hash_to_group_element(
                &ro.evaluate(&(bases1, bases2, exponents1, exponents2, x)),
            );

        let z_poly = r_poly + &(secret_poly.clone() * &challenge);

        let bases_to_z = bases1
            .iter()
            .zip(bases2.iter())
            .enumerate()
            .map(|(j, (base1, base2))| {
                let z_j = z_poly.eval(share_index(j)).value;
                (base1 * z_j, base2 * z_j)
            })
            .collect_vec();

        let exponents_to_challenge = exponents1
            .iter()
            .zip(exponents2.iter())
            .map(|(exp1, exp2)| (exp1 * challenge, exp2 * challenge))
            .collect_vec();

        LDProof {
            challenge,
            z_poly,
            bases_to_z,
            exponents_to_challenge,
        }
    }

    pub fn verify(
        &self,
        t: usize,
        bases1: &[ristretto255::RistrettoPoint],
        bases2: &[ristretto255::RistrettoPoint],
        exponents1: &[ristretto255::RistrettoPoint],
        exponents2: &[ristretto255::RistrettoPoint],
    ) -> FastCryptoResult<()> {
        let ro = RandomOracle::new("mldei");
        if self.z_poly.degree() != t {
            return Err(FastCryptoError::InvalidProof);
        }

        let mut tuples = Vec::new();
        (0..bases1.len()).into_iter().for_each(|j| {
            let z_j = self
                .z_poly
                .eval(NonZeroU16::new((j + 1) as u16).unwrap())
                .value;
            tuples.push((z_j, bases1[j], self.bases_to_z[j].0));
            tuples.push((z_j, bases2[j], self.bases_to_z[j].1));
            tuples.push((
                self.challenge,
                exponents1[j],
                self.exponents_to_challenge[j].0,
            ));
            tuples.push((
                self.challenge,
                exponents2[j],
                self.exponents_to_challenge[j].1,
            ));
        });
        verify_triplets(&tuples, &mut thread_rng())?;

        let x = (0..bases1.len())
            .map(|j| {
                (
                    self.bases_to_z[j].0 - self.exponents_to_challenge[j].0,
                    self.bases_to_z[j].1 - self.exponents_to_challenge[j].1,
                )
            })
            .collect_vec();

        let challenge = ristretto255::RistrettoScalar::hash_to_group_element(
            &ro.evaluate(&(bases1, bases2, exponents1, exponents2, x)),
        );
        if challenge != self.challenge {
            return Err(FastCryptoError::InvalidProof);
        }
        Ok(())
    }
}

//////// The RVSS protocol (share and verify) ////////
#[derive(Serialize)]
pub struct RVSS {
    v: Vec<ristretto255::RistrettoPoint>,
    c_hat: Vec<ristretto255::RistrettoPoint>,
    c: Vec<[u8; 32]>,
    gadget: Gadget,
    mdlei_proof: LDProof,
}

impl RVSS {
    pub fn new(
        k: usize, // security parameter for the recovery gadget
        t: usize,
        omega: ristretto255::RistrettoScalar,
        pks: &[ristretto255::RistrettoPoint],
    ) -> RVSS {
        let ro = RandomOracle::new("rvss");
        let mut rng = thread_rng();
        let (g, h) = Self::bases();

        let poly = Poly::rand_fixed_c0(t as u16, omega, &mut rng);

        let mut v = Vec::new();
        let mut c = Vec::new();
        let mut c_hat = Vec::new();

        for (j, pk) in pks.iter().enumerate() {
            let s_j = poly.eval(NonZeroU16::new((j + 1) as u16).unwrap()).value;
            let s_hat_j = g * s_j;
            let v_j = h * s_j;
            let c_hat_j = pk * s_j;
            let c_j: [u8; 32] = ro.evaluate(&(j, &s_hat_j))[0..32]
                .iter()
                .zip(&s_j.to_byte_array())
                .map(|(x1, &x2)| x1 ^ x2)
                .collect_vec()
                .try_into()
                .unwrap();

            v.push(v_j);
            c_hat.push(c_hat_j);
            c.push(c_j);
        }

        let gadget = Gadget::new(k, h, omega);
        let h_n_times = (0..pks.len()).map(|_| h).collect_vec();

        let mdlei_proof = LDProof::new(pks, &h_n_times, &c_hat, &v, &poly);

        RVSS {
            v,
            c_hat,
            c,
            gadget,
            mdlei_proof,
        }
    }

    pub fn verify(
        &self,
        k: usize,
        t: usize,
        pks: &[ristretto255::RistrettoPoint],
    ) -> FastCryptoResult<()> {
        let n = pks.len();
        let (_g, h) = Self::bases();

        let h_n_times = (0..n).map(|_| h).collect_vec();
        self.mdlei_proof
            .verify(t, pks, &h_n_times, &self.c_hat, &self.v)?;
        self.gadget.verify(k)?;

        Ok(())
    }

    // Just to measure performance in the case of an honest dealer
    pub fn optimistic_decrypt(
        &self,
        i: usize,
        sk: &ristretto255::RistrettoScalar,
    ) -> FastCryptoResult<ristretto255::RistrettoScalar> {
        let ro = RandomOracle::new("rvss");
        let (_g, h) = Self::bases();
        let c_i = self.c[i];
        let c_hat_i = self.c_hat[i];
        let sk_inv = sk.inverse().unwrap();
        let s_hat_j = c_hat_i * sk_inv;

        let s_i = ro.evaluate(&(i, &s_hat_j))[0..32]
            .iter()
            .zip(&c_i)
            .map(|(x1, &x2)| x1 ^ x2)
            .collect_vec();
        let s_i = ristretto255::RistrettoScalar::from_byte_array(&s_i[0..32].try_into().unwrap())?;
        if h * s_i != self.v[i] {
            return Err(FastCryptoError::InvalidProof);
        }
        Ok(s_i)
    }

    fn bases() -> (ristretto255::RistrettoPoint, ristretto255::RistrettoPoint) {
        let ro = RandomOracle::new("base");
        let g = ristretto255::RistrettoPoint::generator();
        let h = ristretto255::RistrettoPoint::hash_to_group_element(&ro.evaluate(&(g, g)));
        (g, h)
    }
}


fn share_index(i: usize) -> NonZeroU16 {
    NonZeroU16::new((i + 1) as u16).expect("index must be non-zero")
}


#[test]
fn test_gadget() {
    let h = ristretto255::RistrettoPoint::generator();
    let omega = ristretto255::RistrettoScalar::rand(&mut thread_rng());
    let gadget = Gadget::new(128, h, omega);
    gadget.verify(128).unwrap();
}

#[test]
fn test_mldei() {
    let bases1 = (1..=100)
        .map(|i| {
            ristretto255::RistrettoPoint::generator()
                * ristretto255::RistrettoScalar::from(i as u128)
        })
        .collect_vec();
    let bases2 = (1..=100)
        .map(|i| {
            ristretto255::RistrettoPoint::generator()
                * ristretto255::RistrettoScalar::from(i as u128)
        })
        .collect_vec();

    let t = 31;
    let p = Poly::rand(t, &mut thread_rng());
    let exponents1 = (0..100)
        .map(|i| bases1[i] * &p.eval(NonZeroU16::new((i + 1) as u16).unwrap()).value)
        .collect_vec();
    let exponents2 = (0..100)
        .map(|i| bases2[i] * &p.eval(NonZeroU16::new((i + 1) as u16).unwrap()).value)
        .collect_vec();

    let proof = LDProof::new(&bases1, &bases2, &exponents1, &exponents2, &p);
    proof
        .verify(t.into(), &bases1, &bases2, &exponents1, &exponents2)
        .unwrap();
}

#[test]
fn test_rvss() {
    let k = 128;
    let n = 100;
    let t = (n / 3) * 2;

    let pks = (1..=n)
        .map(|i| {
            ristretto255::RistrettoPoint::generator()
                * ristretto255::RistrettoScalar::from(i as u128)
        })
        .collect_vec();

    let omega = ristretto255::RistrettoScalar::rand(&mut thread_rng());
    let rvss = RVSS::new(k, t, omega, &pks);
    rvss.verify(k, t, &pks).unwrap();

    rvss.optimistic_decrypt(10, &ristretto255::RistrettoScalar::from(11u128))
        .unwrap();
}
