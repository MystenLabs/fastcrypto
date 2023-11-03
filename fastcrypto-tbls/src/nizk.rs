// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::random_oracle::RandomOracle;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// NIZKPoK for the DDH tuple [G, H=eG, xG, xH].
/// - Prover selects a random r and sends A=rG, B=rH.
/// - Prover computes challenge c and sends z=r+c*x.
/// - Verifier checks that zG=A+c(xG) and zeG=B+c(xH).
/// The NIZK is (A, B, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DdhTupleNizk<G: GroupElement>(G, G, G::ScalarType);

impl<G: GroupElement> DdhTupleNizk<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    pub fn create<R: AllowedRng>(
        x: &G::ScalarType,
        h: &G,
        x_g: &G,
        x_h: &G,
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = G::generator() * r;
        let b = *h * r;
        let challenge = Self::fiat_shamir_challenge(h, x_g, x_h, &a, &b, random_oracle);
        let z = challenge * x + r;
        DdhTupleNizk(a, b, z)
    }

    pub fn verify(
        &self,
        h: &G,
        x_g: &G,
        x_h: &G,
        random_oracle: &RandomOracle,
    ) -> Result<(), FastCryptoError> {
        let challenge = Self::fiat_shamir_challenge(h, x_g, x_h, &self.0, &self.1, random_oracle);
        if !Self::is_valid_relation(
            &self.0, // A
            x_g,
            &G::generator(),
            &self.2, // z
            &challenge,
        ) || !Self::is_valid_relation(
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
    fn fiat_shamir_challenge(
        h: &G,
        x_g: &G,
        x_h: &G,
        a: &G,
        b: &G,
        random_oracle: &RandomOracle,
    ) -> G::ScalarType {
        let output = random_oracle.evaluate(&(G::generator(), h, x_g, x_h, a, b));
        G::ScalarType::fiat_shamir_reduction_to_group_element(&output)
    }

    /// Checks if e1 + e2*c = z e3
    fn is_valid_relation(e1: &G, e2: &G, e3: &G, z: &G::ScalarType, c: &G::ScalarType) -> bool {
        let left = *e1 + *e2 * c;
        let right = *e3 * z;
        left == right
    }
}

/// NIZKPoK for the DL [G, xG].
/// - Prover selects a random r and sends A=rG.
/// - Prover computes challenge c and sends z=r+c*x.
/// - Verifier checks that zG=A+c(xG).
/// The NIZK is (A, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DLNizk<G: GroupElement>(G, G::ScalarType);

impl<G: GroupElement> DLNizk<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    pub fn create<R: AllowedRng>(
        x: &G::ScalarType,
        x_g: &G,
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = G::generator() * r;
        let challenge = Self::fiat_shamir_challenge(x_g, &a, random_oracle);
        let z = challenge * x + r;
        debug!("NIZK: Creating a proof for {x_g:?} with challenge {challenge:?}");
        DLNizk(a, z)
    }

    pub fn verify(&self, x_g: &G, random_oracle: &RandomOracle) -> Result<(), FastCryptoError> {
        let challenge = Self::fiat_shamir_challenge(x_g, &self.0, random_oracle);
        debug!("NIZK: Verifying a proof of {x_g:?} with challenge {challenge:?}");
        if (G::generator() * self.1) != (self.0 + *x_g * challenge) {
            Err(FastCryptoError::InvalidProof)
        } else {
            Ok(())
        }
    }

    /// Returns the challenge for Fiat-Shamir.
    fn fiat_shamir_challenge(x_g: &G, a: &G, random_oracle: &RandomOracle) -> G::ScalarType {
        let output = random_oracle.evaluate(&(G::generator(), x_g, a));
        G::ScalarType::fiat_shamir_reduction_to_group_element(&output)
    }
}
