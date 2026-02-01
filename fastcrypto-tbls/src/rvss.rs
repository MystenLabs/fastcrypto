use crate::dl_verification::verify_pairs;
use crate::polynomial::Poly;
use crate::random_oracle::RandomOracle;
use either::Either;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::{
    error::{FastCryptoError, FastCryptoResult},
    groups::{GroupElement, HashToGroupElement, Scalar as GScalar},
};
use itertools::Itertools;
use rand::{thread_rng, RngCore};
use serde::Serialize;
use std::num::NonZeroU16;

/////// Implementation of the RVSS protocol for performance testing ONLY ///////

// Switch the group by commenting and uncommenting the following lines

/////// BLS12-381 test ///////
// use fastcrypto::groups::bls12381;
// pub type Point = bls12381::G1Element;
// pub type Scalar = bls12381::Scalar;

/////// Ristretto255 test ///////
use fastcrypto::groups::{ristretto255, MultiScalarMul};
pub type Point = ristretto255::RistrettoPoint;
pub type Scalar = ristretto255::RistrettoScalar;

//////// Recovery gadget ////////

#[derive(Serialize)]
pub struct Gadget {
    h: Point,
    h_omega: Point,
    t: Vec<(Point, Vec<u8>)>,
    u: Vec<Either<Point, Scalar>>,
}

impl Gadget {
    pub fn new(k: usize, h: Point, omega: Scalar) -> Self {
        let ro = RandomOracle::new("gadget");
        let h_omega = h * omega;
        let g = Point::generator();

        let r = (0..k)
            .map(|_i| Scalar::rand(&mut thread_rng()))
            .collect_vec();
        let t = r
            .iter()
            .enumerate()
            .map(|(j, r_j)| {
                let g_j = g * *r_j;
                let h_j = h * *r_j;
                let hash = &ro.evaluate(&(j, &g_j))[0..32];
                let t_j = hash
                    .iter()
                    .zip(r_j.to_byte_array())
                    .map(|(&x1, x2)| x1 ^ x2)
                    .collect();
                (h_j, t_j)
            })
            .collect_vec();

        let d = ro.evaluate(&(h, h_omega, &t));
        // d == 1^k with neg probability

        let u = (0..k)
            .map(|i| {
                if d[i / 8] & (1 << (i % 8)) == 0 {
                    Either::Left(g * r[i])
                } else {
                    Either::Right(r[i] - omega)
                }
            })
            .collect();

        Self { h, h_omega, t, u }
    }

    pub fn verify(&self, k: usize) -> FastCryptoResult<()> {
        let ro = RandomOracle::new("gadget");

        // We check all exponents in a batch
        let mut tuples_1 = Vec::new();
        let mut tuples_2 = Vec::new();

        let d = ro.evaluate(&(self.h, self.h_omega, &self.t));
        for i in 0..k {
            let bit = d[i / 8] & (1 << (i % 8));
            if bit == 0 {
                if let Either::Left(u_j) = self.u[i] {
                    let hash = &ro.evaluate(&(i, &u_j))[0..32];
                    let r_j = hash
                        .iter()
                        .zip(&self.t[i].1)
                        .map(|(x1, &x2)| x1 ^ x2)
                        .collect_vec();
                    let r_j: Scalar =
                        Scalar::from_byte_array(&r_j[0..32].try_into().unwrap()).unwrap();
                    // check that g_j = g * r_j
                    tuples_1.push((r_j, u_j));
                    // check that t_j = h * r_j
                    tuples_2.push((r_j, self.t[i].0));
                } else {
                    return Err(FastCryptoError::InvalidProof);
                }
            } else {
                if let Either::Right(u_j) = self.u[i] {
                    tuples_2.push((u_j, self.t[i].0 - self.h_omega));
                } else {
                    return Err(FastCryptoError::InvalidProof);
                }
            }
        }
        verify_pairs(&Point::generator(), &tuples_1, &mut thread_rng())?;
        verify_pairs(&self.h, &tuples_2, &mut thread_rng())
    }
}

//////// Low degree zk proof ////////

#[derive(Serialize)]
pub struct LDProof {
    x: Vec<[Point; 2]>,
    z: Poly<Scalar>,
}

impl LDProof {
    pub fn new(
        g1: &[Point],
        g2: &[Point],
        h1: &[Point],
        h2: &[Point],
        w: &Poly<Scalar>,
    ) -> LDProof {
        assert!(g1.len() == g2.len());
        assert!(g1.len() == h1.len());
        assert!(g1.len() == h2.len());

        let ro = RandomOracle::new("mldei");

        let r = Poly::rand(w.degree() as u16, &mut thread_rng());

        let x = g1
            .iter()
            .zip(g2.iter())
            .enumerate()
            .map(|(j, (base1, base2))| {
                let r_j = r.eval(share_index(j)).value;
                [base1 * r_j, base2 * r_j]
            })
            .collect_vec();

        let e: Scalar = Scalar::hash_to_group_element(&ro.evaluate(&(g1, g2, h1, h2, &x)));
        let neg_e = -e;
        let z = r + &(w.clone() * &neg_e);

        LDProof { x, z }
    }

    pub fn verify(
        &self,
        t: usize,
        g1: &[Point],
        g2: &[Point],
        h1: &[Point],
        h2: &[Point],
    ) -> FastCryptoResult<()> {
        let ro = RandomOracle::new("mldei");
        let mut rng = thread_rng();

        if self.z.degree() > t {
            return Err(FastCryptoError::InvalidProof);
        }

        let e = Scalar::hash_to_group_element(&ro.evaluate(&(g1, g2, h1, h2, &self.x)));

        let r = (0..self.x.len())
            .map(|_| {
                [
                    Scalar::from(rng.next_u64() as u128),
                    Scalar::from(rng.next_u64() as u128),
                ]
            })
            .collect::<Vec<_>>();

        let z_values = (0..self.x.len())
            .map(|i| self.z.eval(share_index(i)).value)
            .collect::<Vec<_>>();

        let mut scalars = Vec::new();
        let mut points = Vec::new();

        let g = [g1, g2];
        let h = [h1, h2];

        for i in 0..self.x.len() {
            let z = z_values[i];
            for j in 0..2 {
                scalars.push(z * r[i][j]);
                points.push(g[j][i]);

                scalars.push(e * r[i][j]);
                points.push(h[j][i]);

                scalars.push(-r[i][j]);
                points.push(self.x[i][j]);
            }
        }

        let msm = Point::multi_scalar_mul(&scalars[..], &points[..]).expect("valid sizes");

        if msm == Point::zero() {
            return Ok(());
        } else {
            return Err(FastCryptoError::InvalidProof);
        }
    }
}

//////// The RVSS protocol (share and verify) ////////
#[derive(Serialize)]
pub struct RVSS {
    v: Vec<Point>,
    c_hat: Vec<Point>,
    c: Vec<[u8; 32]>,
    gadget: Gadget,
    mldei_proof: LDProof,
}

impl RVSS {
    pub fn new(
        k: usize, // security parameter for the recovery gadget
        t: usize,
        omega: Scalar,
        pks: &[Point],
    ) -> RVSS {
        let ro = RandomOracle::new("rvss");
        let mut rng = thread_rng();
        let (g, h) = Self::bases();

        let poly = Poly::rand_fixed_c0(t as u16, omega, &mut rng);

        let mut v = Vec::new();
        let mut c = Vec::new();
        let mut c_hat = Vec::new();

        for (j, pk) in pks.iter().enumerate() {
            let s_j = poly.eval(share_index(j)).value;
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

        let mldei_proof = LDProof::new(pks, &h_n_times, &c_hat, &v, &poly);

        RVSS {
            v,
            c_hat,
            c,
            gadget,
            mldei_proof,
        }
    }

    pub fn verify(&self, k: usize, t: usize, pks: &[Point]) -> FastCryptoResult<()> {
        let n = pks.len();
        let (_g, h) = Self::bases();

        let h_n_times = (0..n).map(|_| h).collect_vec();
        self.mldei_proof
            .verify(t, pks, &h_n_times, &self.c_hat, &self.v)?;
        self.gadget.verify(k)?;

        Ok(())
    }

    // To measure performance in the case of an honest dealer
    pub fn optimistic_decrypt(&self, i: usize, sk: &Scalar) -> FastCryptoResult<Scalar> {
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
        let s_i = Scalar::from_byte_array(&s_i[0..32].try_into().unwrap())?;
        if h * s_i != self.v[i] {
            return Err(FastCryptoError::InvalidProof);
        }
        Ok(s_i)
    }

    fn bases() -> (Point, Point) {
        let ro = RandomOracle::new("base");
        let g = Point::generator();
        let h = Point::hash_to_group_element(&ro.evaluate(&(g, g)));
        (g, h)
    }
}

fn share_index(i: usize) -> NonZeroU16 {
    NonZeroU16::new((i + 1) as u16).expect("index must be non-zero")
}

// Following tests check the e2e functionalities but not edge cases

#[test]
fn test_gadget() {
    let h = Point::generator();
    let omega = Scalar::rand(&mut thread_rng());
    let gadget = Gadget::new(128, h, omega);
    gadget.verify(128).unwrap();
}

#[test]
fn test_mldei() {
    let bases1 = (1..=100)
        .map(|i| Point::generator() * Scalar::from(i as u128))
        .collect_vec();
    let bases2 = (1..=100)
        .map(|i| Point::generator() * Scalar::from(i as u128))
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
        .map(|i| Point::generator() * Scalar::from(i as u128))
        .collect_vec();

    let omega = Scalar::rand(&mut thread_rng());
    let rvss = RVSS::new(k, t, omega, &pks);
    rvss.verify(k, t, &pks).unwrap();

    rvss.optimistic_decrypt(10, &Scalar::from(11u128)).unwrap();
}
