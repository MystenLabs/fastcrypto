use crate::dl_verification::verify_triplets;
use crate::nizk::DLNizk;
use crate::polynomial::Poly;
use crate::random_oracle::RandomOracle;
use either::Either;
use fastcrypto::groups::{MultiScalarMul, Pairing};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::{
    error::{FastCryptoError, FastCryptoResult},
    groups::{bls12381, GroupElement, HashToGroupElement, Scalar},
};
use itertools::Itertools;
use rand::thread_rng;
use serde::Serialize;
use std::num::NonZeroU16;

// Quick and dirty implementation of the RVSS protocol for performance testing

#[derive(Serialize)]
pub struct Gadget {
    h: bls12381::G1Element,
    pk: bls12381::G2Element,
    t: Vec<(bls12381::G2Element, Vec<u8>)>,
    t_prime: Vec<Either<bls12381::G1Element, bls12381::Scalar>>,
}

impl Gadget {
    pub fn new(k: usize, h: bls12381::G1Element, omega: bls12381::Scalar) -> Self {
        let ro = RandomOracle::new("gadget");
        let mut rng = thread_rng();
        let g2 = bls12381::G2Element::generator();
        let pk = g2 * omega;
        let r = (0..k)
            .map(|i| bls12381::Scalar::rand(&mut rng))
            .collect_vec();
        let t = r
            .iter()
            .enumerate()
            .map(|(j, r_j)| {
                let h_j = h * *r_j;
                let hash = &ro.evaluate(&(j, &h_j))[0..32];
                let xored = hash
                    .iter()
                    .zip(r_j.to_byte_array())
                    .map(|(&x1, x2)| x1 ^ x2)
                    .collect();
                (g2 * *r_j, xored)
            })
            .collect_vec();

        let d = ro.evaluate(&(h, pk, &t));
        let t_prime = (0..k)
            .map(|i| {
                if d[i / 8] & (1 << (i % 8)) == 0 {
                    Either::Left(h * r[i])
                } else {
                    Either::Right(r[i] - omega)
                }
            })
            .collect();

        Self { h, pk, t, t_prime }
    }

    pub fn verify(&self, k: usize) -> FastCryptoResult<()> {
        let ro = RandomOracle::new("gadget");
        let d = ro.evaluate(&(self.h, self.pk, &self.t));
        let mut tuples_1 = Vec::new();
        let mut tuples_2 = Vec::new();
        for i in 0..k {
            if d[i / 8] & (1 << (i % 8)) == 0 {
                if let Either::Left(h_j) = self.t_prime[i] {
                    let hash = &ro.evaluate(&(i, &h_j))[0..32];
                    let r_j = hash
                        .iter()
                        .zip(&self.t[i].1)
                        .map(|(x1, &x2)| x1 ^ x2)
                        .collect_vec();
                    let r_j: bls12381::Scalar =
                        bls12381::Scalar::from_byte_array(&r_j[0..32].try_into().unwrap()).unwrap();

                    tuples_1.push((r_j, self.h, h_j));
                    tuples_2.push((r_j, bls12381::G2Element::generator(), self.t[i].0));
                } else {
                    return Err(FastCryptoError::InvalidProof);
                }
            } else {
                if let Either::Right(t_prime_j) = self.t_prime[i] {
                    tuples_2.push((
                        t_prime_j,
                        bls12381::G2Element::generator(),
                        self.t[i].0 - self.pk,
                    ));
                } else {
                    return Err(FastCryptoError::InvalidProof);
                }
            }
        }
        let mut rng = thread_rng();
        verify_triplets(&tuples_1, &mut rng)?;
        verify_triplets(&tuples_2, &mut rng)
    }
}

#[derive(Serialize)]
pub struct RVSS {
    h1: bls12381::G1Element,
    h2: bls12381::G2Element,
    pi: DLNizk<bls12381::G1Element>,
    v: Vec<bls12381::G2Element>,
    c: Vec<bls12381::G1Element>,
    e: Vec<[u8; 32]>,
    pk: bls12381::G2Element,
    gadget: Gadget,
}

impl RVSS {
    pub fn new(
        k: usize,
        t: usize,
        omega: bls12381::Scalar,
        pks: &Vec<bls12381::G1Element>,
    ) -> RVSS {
        let ro = RandomOracle::new("rvss");
        let mut rng = thread_rng();
        let g1 = bls12381::G1Element::generator();
        let g2 = bls12381::G2Element::generator();

        let r = bls12381::Scalar::rand(&mut thread_rng());
        let h1 = g1 * r;
        let h2 = g2 * r;
        let pi = DLNizk::create(&r, &h1, &ro, &mut thread_rng());
        let h = bls12381::G1Element::hash_to_group_element(&ro.evaluate(&(&h1, &h2)));
        let poly = Poly::rand(t as u16, &mut rng);

        let mut v = Vec::new();
        let mut c = Vec::new();
        let mut e = Vec::new();

        for (j, pk) in pks.iter().enumerate() {
            let s_j: bls12381::Scalar = poly.eval(NonZeroU16::new((j + 1) as u16).unwrap()).value;
            let v_j = g2 * s_j;
            let s_j_prime = h * s_j;
            let c_j = pk * r + s_j_prime;
            let e_j: [u8; 32] = ro.evaluate(&(j, &s_j_prime))[0..32]
                .iter()
                .zip(&s_j.to_byte_array())
                .map(|(x1, &x2)| x1 ^ x2)
                .collect_vec()
                .try_into()
                .unwrap();

            v.push(v_j);
            c.push(c_j);
            e.push(e_j);
        }

        let gadget = Gadget::new(k, h, omega);

        RVSS {
            h1,
            h2,
            pi,
            v,
            c,
            e,
            pk: bls12381::G2Element::generator() * omega,
            gadget,
        }
    }

    pub fn verify(
        &self,
        k: usize,
        _t: usize,
        pks: &Vec<bls12381::G1Element>,
    ) -> FastCryptoResult<()> {
        let ro = RandomOracle::new("rvss");
        let mut rng = thread_rng();
        let n = pks.len();

        self.pi.verify(&self.h1, &ro)?;
        if self.h1.pairing(&bls12381::G2Element::generator())
            != bls12381::G1Element::generator().pairing(&self.h2)
        {
            return Err(FastCryptoError::InvalidProof);
        }
        self.gadget.verify(k)?;

        let h = bls12381::G1Element::hash_to_group_element(&ro.evaluate(&(&self.h1, &self.h2)));

        // not in use for now (though just additive neg overhead)
        let _y = (0..n)
            .map(|_| bls12381::Scalar::rand(&mut rng))
            .collect_vec();

        let r = (0..n)
            .map(|_| bls12381::Scalar::rand(&mut rng))
            .collect_vec();

        let eks = bls12381::G1Element::multi_scalar_mul(&r, &pks).unwrap();
        let vs = bls12381::G2Element::multi_scalar_mul(&r, &self.v).unwrap();
        let cs = bls12381::G1Element::multi_scalar_mul(&r, &self.c).unwrap();

        if eks.pairing(&self.h2) + h.pairing(&vs) != cs.pairing(&bls12381::G2Element::generator()) {
            return Err(FastCryptoError::InvalidProof);
        }

        Ok(())
    }

    // Just to measure performance in the case of an honest dealer
    pub fn optimistic_decrypt(
        &self,
        i: usize,
        sk: &bls12381::Scalar,
    ) -> FastCryptoResult<(bls12381::Scalar, bls12381::G1Element)> {
        let ro = RandomOracle::new("rvss");

        let c_i = self.c[i];
        let e_i = self.e[i];
        let h = self.h1 * sk;
        let s_i_prime = c_i - h;
        let s_i = ro.evaluate(&(i, &s_i_prime))[0..32]
            .iter()
            .zip(&e_i)
            .map(|(x1, &x2)| x1 ^ x2)
            .collect_vec();
        let s_i = bls12381::Scalar::from_byte_array(&s_i[0..32].try_into().unwrap())?;
        Ok((s_i, s_i_prime))
    }
}

#[test]
fn test_gadget() {
    let h = bls12381::G1Element::generator();
    let omega = bls12381::Scalar::rand(&mut thread_rng());
    let gadget = Gadget::new(128, h, omega);
    gadget.verify(128).unwrap();
}

#[test]
fn test_rvss() {
    let K = 128;
    let n = 100;
    let t = (n / 3) * 2;

    let pks = (1..=n)
        .map(|i| bls12381::G1Element::generator() * bls12381::Scalar::from(i as u128))
        .collect_vec();

    let omega = bls12381::Scalar::rand(&mut thread_rng());
    let rvss = RVSS::new(K, t, omega, &pks);
    rvss.verify(K, t, &pks).unwrap();

    rvss.optimistic_decrypt(10, &bls12381::Scalar::from(11))
        .unwrap();
}
