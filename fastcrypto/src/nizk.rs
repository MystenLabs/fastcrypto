// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::MultiScalarMul;
use crate::groups::{FiatShamirChallenge, GroupElement, Scalar};
use crate::traits::AllowedRng;
use serde::{Deserialize, Deserializer, Serialize};
use std::ops::Neg;

/// NIZKPoK for the DDH tuple `(G, H=eG, xG, xH)` where `e` is implicit and `x` is the witness.
/// - Prover selects a random `r` and sends `(A=rG, B=rH)`.
/// - Prover computes challenge `c` and sends `z=r+c*x`.
/// - Verifier checks that `zG=A+c(xG)` and `zH=B+c(xH)`.
///
/// The NIZK is `(A, B, z)` where `c` is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DdhTupleNizk<G: GroupElement + Serialize + for<'d> Deserialize<'d>> {
    #[serde(deserialize_with = "check_non_zero")]
    a: G,
    #[serde(deserialize_with = "check_non_zero")]
    b: G,
    #[serde(deserialize_with = "check_non_zero")]
    z: G::ScalarType,
}

impl<G> DdhTupleNizk<G>
where
    G: MultiScalarMul + Serialize + for<'d> Deserialize<'d>,
    G::ScalarType: FiatShamirChallenge,
{
    /// Create a new NIZKPoK for the DDH tuple `(G, H=eG, xG, xH)` using the given RNG.
    /// The generators `g` and `h` are not bound into the challenge, so the soundness relies
    /// on `dst` being unique to the calling context and fixed with the choice of `g` and `h`.
    pub fn create<R: AllowedRng>(
        x: &G::ScalarType,
        g: &G,
        h: &G,
        x_g: &G,
        x_h: &G,
        dst: &[u8],
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = *g * r;
        let b = *h * r;
        let challenge = Self::challenge(x_g, x_h, &a, &b, dst);
        let z = challenge * x + r;
        DdhTupleNizk { a, b, z }
    }

    /// Verify this NIZKPoK. `dst` must match the value used in [Self::create].
    pub fn verify(&self, g: &G, h: &G, x_g: &G, x_h: &G, dst: &[u8]) -> FastCryptoResult<()> {
        if *g == G::zero() || *h == G::zero() || *x_g == G::zero() || *x_h == G::zero() {
            return Err(FastCryptoError::InvalidProof);
        }
        let challenge = Self::challenge(x_g, x_h, &self.a, &self.b, dst);
        if !is_valid_relation(&self.a, x_g, g, &self.z, &challenge)
            || !is_valid_relation(
                &self.b, // B
                x_h, h, &self.z, &challenge,
            )
        {
            Err(FastCryptoError::InvalidProof)
        } else {
            Ok(())
        }
    }

    /// DDH-tuple Fiat-Shamir challenge: bcs-encoded `vector<vector<u8>>` of `[dst, xG, xH, A, B]`
    /// reduced via the scalar's [FiatShamirChallenge] impl. For Ristretto255 this matches Contra's
    /// Move/TS construction.
    fn challenge(x_g: &G, x_h: &G, a: &G, b: &G, dst: &[u8]) -> G::ScalarType {
        let chunks: Vec<Vec<u8>> = vec![
            dst.to_vec(),
            bcs::to_bytes(x_g).expect("Serialization succeeds"),
            bcs::to_bytes(x_h).expect("Serialization succeeds"),
            bcs::to_bytes(a).expect("Serialization succeeds"),
            bcs::to_bytes(b).expect("Serialization succeeds"),
        ];
        G::ScalarType::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&chunks).expect("Serialization succeeds"),
        )
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

/// Custom deserializer for GroupElements which fails if the result is zero.
fn check_non_zero<'de, D, G: GroupElement + Deserialize<'de>>(d: D) -> Result<G, D::Error>
where
    D: Deserializer<'de>,
{
    let g: G = G::deserialize(d)?;
    if g == G::zero() {
        Err(serde::de::Error::custom("zero element"))
    } else {
        Ok(g)
    }
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
        let dst = b"test";
        let e = S::rand(&mut thread_rng());
        let x = S::rand(&mut thread_rng());
        let g = G::generator() * S::rand(&mut thread_rng());
        let h = g * e;
        let x_g = g * x;
        let x_h = h * x;
        let nizk = DdhTupleNizk::create(&x, &g, &h, &x_g, &x_h, dst, &mut thread_rng());
        assert!(nizk.verify(&g, &h, &x_g, &x_h, dst).is_ok());

        // A different DST must not verify
        assert!(nizk.verify(&g, &h, &x_g, &x_h, b"other").is_err());

        let invalid_witness = x + S::generator();
        let invalid_nizk =
            DdhTupleNizk::create(&invalid_witness, &g, &h, &x_g, &x_h, dst, &mut thread_rng());
        assert!(invalid_nizk.verify(&g, &h, &x_g, &x_h, dst).is_err());

        let other_g = g + G::generator();
        assert!(nizk.verify(&other_g, &h, &x_g, &x_h, dst).is_err());

        let other_h = h + G::generator();
        assert!(nizk.verify(&g, &other_h, &x_g, &x_h, dst).is_err());

        let other_x_g = x_g + G::generator();
        assert!(nizk.verify(&g, &h, &other_x_g, &x_h, dst).is_err());

        let other_x_h = x_h + G::generator();
        assert!(nizk.verify(&g, &h, &x_g, &other_x_h, dst).is_err());
    }

    #[test]
    fn challenge_regression_test() {
        let dst = b"test";
        let x = S::from(31u64);
        let g = G::generator() * S::from(71u64);
        let x_g = g * x;
        let x_h = g * S::from(7u64) * x;
        let r = S::from(91u64);
        let a = g * r;
        let b = (g * S::from(7u64)) * r;
        let c = DdhTupleNizk::<G>::challenge(&x_g, &x_h, &a, &b, dst);
        assert_eq!(
            &c.to_byte_array(),
            Hex::decode("0fcba8670c851477df01c27dcd01ba6b780eca4f7c2cb6cd168578430c8fff00")
                .unwrap()
                .as_slice()
        );
        // The challenge must depend on the DST.
        let other = DdhTupleNizk::<G>::challenge(&x_g, &x_h, &a, &b, b"other");
        assert_ne!(c.to_byte_array(), other.to_byte_array());
    }

    #[test]
    fn test_invalid_proofs() {
        // x_g/h_g/h=inf should be rejected
        let dst = b"test";
        let e = S::zero();
        let x = S::rand(&mut thread_rng());
        let g = G::generator() * S::rand(&mut thread_rng());
        let h = g * e;
        let x_g = g * x;
        let x_h = h * x;
        let nizk = DdhTupleNizk::create(&x, &g, &h, &x_g, &x_h, dst, &mut thread_rng());

        assert!(nizk.verify(&G::zero(), &h, &x_g, &x_h, dst).is_err());
        assert!(nizk.verify(&g, &G::zero(), &x_g, &x_h, dst).is_err());
        assert!(nizk.verify(&g, &h, &G::zero(), &x_h, dst).is_err());
        assert!(nizk.verify(&g, &h, &x_g, &G::zero(), dst).is_err());
    }

    #[test]
    fn test_serde() {
        let dst = b"test";
        let e = S::rand(&mut thread_rng());
        let x2 = S::rand(&mut thread_rng());
        let g = G::generator() * S::rand(&mut thread_rng());
        let h = g * e;
        let x_g = g * x2;
        let x_h = h * x2;
        let nizk = DdhTupleNizk::create(&x2, &g, &h, &x_g, &x_h, dst, &mut thread_rng());
        assert!(nizk.verify(&g, &h, &x_g, &x_h, dst).is_ok());

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
