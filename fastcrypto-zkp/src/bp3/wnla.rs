#![allow(non_snake_case)]

use crate::bp3::util::*;
use fastcrypto::serde_helpers::ToFromByteArray;
use merlin::Transcript;
use std::ops::{Add, Mul, Sub};

pub struct WeightNormLinearArgument<GroupElement, Scalar, const N: usize> {
    pub Gen: GroupElement,
    pub G: Vec<GroupElement>,
    pub H: Vec<GroupElement>,
    pub c: Vec<Scalar>,
    pub rho: Scalar,
    pub mu: Scalar,
}

#[derive(Clone, Debug)]
pub struct Proof<GroupElement, Scalar> {
    pub R: Vec<GroupElement>,
    pub X: Vec<GroupElement>,
    pub l: Vec<Scalar>,
    pub n: Vec<Scalar>,
}

impl<GroupElement, Scalar, const N: usize> WeightNormLinearArgument<GroupElement, Scalar, N>
where
    GroupElement: Copy
        + Default
        + Add<Output = GroupElement>
        + Mul<Scalar, Output = GroupElement>
        + ToFromByteArray<N>
        + PartialEq,
    Scalar: Copy
        + Default
        + Add<Output = Scalar>
        + Sub<Output = Scalar>
        + Mul<Scalar, Output = Scalar>
        + From<u128>
        + fastcrypto::groups::Scalar,
{
    /// Computes a weight norm linear argument commitment `C` for vectors `l` and `n`:
    /// `C = v * Gen + <H, l> + <G, n> with v = <c, l> + <n, n>_mu`.
    pub fn commit(&self, l: &[Scalar], n: &[Scalar]) -> GroupElement {
        let v = inner_product(&self.c, l).add(weighted_inner_product(n, n, &self.mu));
        self.Gen
            .mul(v)
            .add(inner_product(&self.H, l))
            .add(inner_product(&self.G, n))
    }

    /// Verifies a weight norm linear argument proof.
    /// TODO: This is the "naive" (recursive) verification. We can optimize it as described on page 14 of the paper.
    pub fn verify(
        &self,
        C: &GroupElement,
        t: &mut Transcript,
        proof: &Proof<GroupElement, Scalar>,
    ) -> bool
    where
        GroupElement: PartialEq,
        Scalar: Sub<Output = Scalar>,
    {
        if proof.X.len() != proof.R.len() {
            return false;
        }

        if proof.X.is_empty() {
            return C.eq(&self.commit(&proof.l, &proof.n));
        }

        let (c0, c1) = reduce(&self.c);
        let (G0, G1) = reduce(&self.G);
        let (H0, H1) = reduce(&self.H);

        // Add messages to Fiat Shamir transcript
        t.append_message(b"wnla:C", &C.to_byte_array());
        t.append_message(b"wnla:X", &proof.X.last().unwrap().to_byte_array());
        t.append_message(b"wnla:R", &proof.R.last().unwrap().to_byte_array());
        t.append_u64(b"wlna:l.len", self.H.len() as u64);
        t.append_u64(b"wlna:n.len", self.G.len() as u64);

        // Compute Fiat Shamir challenge gamma
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"wnla:gamma", &mut buf);
        let gamma = Scalar::from(u128::from_le_bytes(buf[..16].try_into().unwrap()));

        // G' = rho * G0 + gamma * G1
        let Gp = add(&scale(&G0, self.rho), &scale(&G1, gamma));
        // H' = H0 + gamma * H1
        let Hp = add(&H0, &scale(&H1, gamma));
        // c' = c0 + gamma * c1
        let cp = add(&c0, &scale(&c1, gamma));
        // C' = C + gamma * X + (gamma^2 - 1) * R
        let Cp = C.add(proof.X.last().unwrap().mul(gamma)).add(
            proof
                .R
                .last()
                .unwrap()
                .mul(gamma.mul(gamma).sub(Scalar::from(1u128))),
        );

        let wnla = WeightNormLinearArgument {
            Gen: self.Gen,
            G: Gp,
            H: Hp,
            c: cp,
            rho: self.mu,
            mu: self.mu.mul(self.mu),
        };

        let proofp = Proof {
            R: proof.R[..proof.R.len() - 1].to_vec(),
            X: proof.X[..proof.X.len() - 1].to_vec(),
            l: proof.l.clone(),
            n: proof.n.clone(),
        };

        wnla.verify(&Cp, t, &proofp)
    }

    /// Creates a weight norm linear argument proof.
    pub fn prove(
        &self,
        C: &GroupElement,
        t: &mut Transcript,
        l: Vec<Scalar>,
        n: Vec<Scalar>,
    ) -> Proof<GroupElement, Scalar> {
        if l.len() + n.len() < 6 {
            return Proof {
                R: vec![],
                X: vec![],
                l: l,
                n: n,
            };
        }

        let rho_inv = self.rho.inverse().unwrap();

        let (c0, c1) = reduce(&self.c);
        let (l0, l1) = reduce(&l);
        let (n0, n1) = reduce(&n);
        let (G0, G1) = reduce(&self.G);
        let (H0, H1) = reduce(&self.H);

        let mu_squared = self.mu.mul(&self.mu);

        // v_x = 2 * rho_inv * <n0, n1>_{mu_squared} + <c0, l1> + <c1, l0>
        let vx = weighted_inner_product(&n0, &n1, &mu_squared)
            .mul(&rho_inv.mul(&Scalar::from(2u128)))
            .add(&inner_product(&c0, &l1))
            .add(&inner_product(&c1, &l0));

        // v_r = <n1, n1>_{mu_squared} + <c1, l1>
        let vr = weighted_inner_product(&n1, &n1, &mu_squared).add(&inner_product(&c1, &l1));

        // X = v_x * Gen + <H0, l1> + <H1, l0> + <G0, rho * n1> + <G1, rho_inv * n0>
        let X = self
            .Gen
            .mul(vx)
            .add(inner_product(&H0, &l1))
            .add(inner_product(&H1, &l0))
            .add(inner_product(&G0, &scale(&n1, &self.rho)))
            .add(inner_product(&G1, &scale(&n0, &rho_inv)));

        // R = v_r * Gen + <H1, l1> + <G1, n1>
        let R = self
            .Gen
            .mul(vr)
            .add(inner_product(&H1, &l1))
            .add(inner_product(&G1, &n1));

        // Add messages to Fiat Shamir transcript
        t.append_message(b"wnla:C", &C.to_byte_array());
        t.append_message(b"wnla:X", &X.to_byte_array());
        t.append_message(b"wnla:R", &R.to_byte_array());
        t.append_u64(b"wlna:l.len", l.len() as u64);
        t.append_u64(b"wlna:n.len", n.len() as u64);

        // Compute Fiat Shamir challenge gamma
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"wnla:gamma", &mut buf);
        let gamma = Scalar::from(u128::from_le_bytes(buf[..16].try_into().unwrap()));

        // H' = H0 + gamma * H1
        let Hp = add(&H0, &scale(&H1, gamma));
        // G' = rho * G0 + gamma * G1
        let Gp = add(&scale(&G0, self.rho), &scale(&G1, gamma));
        // c' = c0 + gamma * c1
        let cp = add(&c0, &scale(&c1, &gamma));
        // l' = l0 + gamma * l1
        let lp = add(&l0, &scale(&l1, &gamma));
        // n' = rho_inv * n0 + gamma * n1
        let np = add(&scale(&n0, &rho_inv), &scale(&n1, &gamma));

        let wnla = WeightNormLinearArgument {
            Gen: self.Gen,
            G: Gp,
            H: Hp,
            c: cp,
            rho: self.mu,
            mu: mu_squared,
        };

        let mut proof = wnla.prove(&wnla.commit(&lp, &np), t, lp, np);
        proof.R.push(R);
        proof.X.push(X);
        proof
    }
}

#[cfg(test)]
mod tests {
    use crate::bp3::wnla::WeightNormLinearArgument;
    use ark_std::rand::thread_rng;
    use fastcrypto::groups::ristretto255::*;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use std::ops::Mul;

    fn get_random_point<R: AllowedRng>(rng: &mut R) -> RistrettoPoint {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        RistrettoPoint::from_uniform_bytes(&bytes)
    }

    fn get_random_scalar<R: AllowedRng>(rng: &mut R) -> RistrettoScalar {
        RistrettoScalar::rand(rng)
    }

    #[test]
    fn test_weight_norm_linear_argument() {
        const M: usize = 4;
        let mut rand = thread_rng();

        let Gen = RistrettoPoint::generator();
        let G = (0..M)
            .map(|_| get_random_point(&mut rand))
            .collect::<Vec<_>>();
        let H = (0..M)
            .map(|_| get_random_point(&mut rand))
            .collect::<Vec<_>>();
        let c = (0..M)
            .map(|_| get_random_scalar(&mut rand))
            .collect::<Vec<_>>();
        let rho = get_random_scalar(&mut rand);

        let wnla: WeightNormLinearArgument<RistrettoPoint, RistrettoScalar, 32> =
            WeightNormLinearArgument {
                Gen,
                G,
                H,
                c,
                rho,
                mu: rho.mul(&rho),
            };

        let l = (0..M)
            .map(|_| get_random_scalar(&mut rand))
            .collect::<Vec<_>>();
        let n = (0..M)
            .map(|_| get_random_scalar(&mut rand))
            .collect::<Vec<_>>();

        let C = wnla.commit(&l, &n);

        let mut pt = merlin::Transcript::new(b"wnla test");
        let proof = wnla.prove(&C, &mut pt, l, n);
        let mut vt = merlin::Transcript::new(b"wnla test");
        assert!(wnla.verify(&C, &mut vt, &proof));
    }
}
