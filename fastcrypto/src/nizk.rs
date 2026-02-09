// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::MultiScalarMul;
use crate::groups::{FiatShamirChallenge, GroupElement, Scalar};
use crate::hash::{HashFunction, Sha3_256};
use crate::traits::AllowedRng;
use serde::{Deserialize, Deserializer, Serialize};
use std::ops::Neg;

/// NIZKPoK for the DDH tuple `(G, H=eG, xG, xH)` where `e` is implicit and `x` is the witness.
/// - Prover selects a random `r` and sends `(A=rG, B=rH)`.
/// - Prover computes challenge `c` and sends `z=r+c*x`.
/// - Verifier checks that `zG=A+c(xG)` and `zH=B+c(xH)`.
///
/// The NIZK is `(A, B, z)` where `c` is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DdhTupleNizk<G: GroupElement>(G, G, G::ScalarType);

impl<G> DdhTupleNizk<G>
where
    G: MultiScalarMul + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    /// Create a new NIZKPoK for the DDH tuple `(G, H=eG, xG, xH)` using the given RNG.
    pub fn create<R: AllowedRng>(
        x: &G::ScalarType,
        g: &G,
        h: &G,
        x_g: &G,
        x_h: &G,
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = *g * r;
        let b = *h * r;
        let challenge = Self::fiat_shamir_challenge(g, h, x_g, x_h, &a, &b);
        let z = challenge * x + r;
        DdhTupleNizk(a, b, z)
    }

    /// Verify this NIZKPoK.
    pub fn verify(&self, g: &G, h: &G, x_g: &G, x_h: &G) -> FastCryptoResult<()> {
        if *g == G::zero() || *h == G::zero() || *x_g == G::zero() || *x_h == G::zero() {
            // We should never see this, but just in case
            return Err(FastCryptoError::InvalidProof);
        }
        let challenge = Self::fiat_shamir_challenge(g, h, x_g, x_h, &self.0, &self.1);
        if !is_valid_relation(
            &self.0, // A
            x_g, g, &self.2, // z
            &challenge,
        ) || !is_valid_relation(
            &self.1, // B
            x_h, h, &self.2, // z
            &challenge,
        ) {
            Err(FastCryptoError::InvalidProof)
        } else {
            Ok(())
        }
    }

    /// Returns the challenge for Fiat-Shamir.
    fn fiat_shamir_challenge(g: &G, h: &G, x_g: &G, x_h: &G, a: &G, b: &G) -> G::ScalarType {
        let output = Sha3_256::digest(bcs::to_bytes(&(g, h, x_g, x_h, a, b)).unwrap());
        G::ScalarType::fiat_shamir_reduction_to_group_element(&output.digest)
    }
}

impl<'de, G> Deserialize<'de> for DdhTupleNizk<G>
where
    G: GroupElement + Deserialize<'de>,
    G::ScalarType: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tuple = <(G, G, G::ScalarType)>::deserialize(deserializer)?;
        if tuple.0 == G::zero() || tuple.1 == G::zero() || tuple.2 == G::ScalarType::zero() {
            return Err(serde::de::Error::custom(
                "Invalid proof: one of the elements is inf/zero",
            ));
        }
        Ok(DdhTupleNizk(tuple.0, tuple.1, tuple.2))
    }
}

/// Checks if e1 + c e2 = z e3
fn is_valid_relation<G: MultiScalarMul>(
    e1: &G,
    e2: &G,
    e3: &G,
    z: &G::ScalarType,
    c: &G::ScalarType,
) -> bool {
    *e1 == G::multi_scalar_mul(&[c.neg(), *z], &[*e2, *e3]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{Encoding, Hex};
    use crate::groups::ristretto255::RistrettoPoint as G;
    use crate::groups::ristretto255::RistrettoScalar as S;
    use crate::serde_helpers::ToFromByteArray;
    use rand::thread_rng;

    #[test]
    fn test_nizk_flow() {
        let e = S::rand(&mut thread_rng());
        let x = S::rand(&mut thread_rng());
        let g = G::generator() * S::rand(&mut thread_rng());
        let h = g * e;
        let x_g = g * x;
        let x_h = h * x;
        let nizk = DdhTupleNizk::create(&x, &g, &h, &x_g, &x_h, &mut thread_rng());
        assert!(nizk.verify(&g, &h, &x_g, &x_h).is_ok());

        let invalid_witness = x + S::generator();
        let invalid_nizk =
            DdhTupleNizk::create(&invalid_witness, &g, &h, &x_g, &x_h, &mut thread_rng());
        assert!(invalid_nizk.verify(&g, &h, &x_g, &x_h).is_err());

        let other_g = g + G::generator();
        assert!(nizk.verify(&other_g, &h, &x_g, &x_h).is_err());

        let other_h = h + G::generator();
        assert!(nizk.verify(&g, &other_h, &x_g, &x_h).is_err());

        let other_x_g = x_g + G::generator();
        assert!(nizk.verify(&g, &h, &other_x_g, &x_h).is_err());

        let other_x_h = x_h + G::generator();
        assert!(nizk.verify(&g, &h, &x_g, &other_x_h).is_err());
    }

    #[test]
    fn challenge_regression_test() {
        let e = S::from(7u64);
        let x = S::from(31u64);
        let g = G::generator() * S::from(71u64);
        let h = g * e;
        let x_g = g * x;
        let x_h = h * x;
        let r = S::from(91u64);
        let a = g * r;
        let b = h * r;
        let c = DdhTupleNizk::fiat_shamir_challenge(&g, &h, &x_g, &x_h, &a, &b);
        assert_eq!(
            &c.to_byte_array(),
            Hex::decode("30db2f4121471c4af67d2dcfdede1f4aefb15475867c20c0dd5c228c0721f80e")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_invalid_proofs() {
        // x_g/h_g/h=inf should be rejected
        let e = S::zero();
        let x = S::rand(&mut thread_rng());
        let g = G::generator() * S::rand(&mut thread_rng());
        let h = g * e;
        let x_g = g * x;
        let x_h = h * x;
        let nizk = DdhTupleNizk::create(&x, &g, &h, &x_g, &x_h, &mut thread_rng());

        assert!(nizk.verify(&G::zero(), &h, &x_g, &x_h).is_err());
        assert!(nizk.verify(&g, &G::zero(), &x_g, &x_h).is_err());
        assert!(nizk.verify(&g, &h, &G::zero(), &x_h).is_err());
        assert!(nizk.verify(&g, &h, &x_g, &G::zero()).is_err());
    }

    #[test]
    fn test_serde() {
        let e = S::rand(&mut thread_rng());
        let x2 = S::rand(&mut thread_rng());
        let g = G::generator() * S::rand(&mut thread_rng());
        let h = g * e;
        let x_g = g * x2;
        let x_h = h * x2;
        let nizk = DdhTupleNizk::create(&x2, &g, &h, &x_g, &x_h, &mut thread_rng());
        assert!(nizk.verify(&g, &h, &x_g, &x_h).is_ok());

        let as_bytes = bcs::to_bytes(&nizk).unwrap();
        let nizk2: DdhTupleNizk<G> = bcs::from_bytes(&as_bytes).unwrap();
        assert_eq!(nizk, nizk2);

        let as_bytes = bcs::to_bytes(&(G::generator(), G::generator(), S::generator())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_ok());
        let as_bytes = bcs::to_bytes(&(G::zero(), G::generator(), S::generator())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_err());
        let as_bytes = bcs::to_bytes(&(G::generator(), G::zero(), S::generator())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_err());
        let as_bytes = bcs::to_bytes(&(G::generator(), G::generator(), S::zero())).unwrap();
        assert!(bcs::from_bytes::<DdhTupleNizk<G>>(&as_bytes).is_err());
    }
}
