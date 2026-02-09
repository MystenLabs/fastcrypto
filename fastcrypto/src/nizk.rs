// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::MultiScalarMul;
use crate::groups::{FiatShamirChallenge, GroupElement, Scalar};
use crate::hash::{HashFunction, Sha3_256};
use crate::traits::AllowedRng;
use serde::{Deserialize, Deserializer, Serialize};
use std::ops::Neg;

/// NIZKPoK for the DDH tuple [G, H=eG, xG, xH].
/// - Prover selects a random r and sends A=rG, B=rH.
/// - Prover computes challenge c and sends z=r+c*x.
/// - Verifier checks that zG=A+c(xG) and zH=B+c(xH).
///
/// The NIZK is (A, B, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DdhTupleNizk<G: GroupElement>(G, G, G::ScalarType);

impl<G> DdhTupleNizk<G>
where
    G: MultiScalarMul + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    /// Create a new NIZKPoK for the DDH tuple [G, H=eG, xG, xH] using the given RNG and random oracle.
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
            x_g,
            &G::generator(),
            &self.2, // z
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
