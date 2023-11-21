// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::random_oracle::RandomOracle;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Deserializer, Serialize};
use tracing::debug;

/// NIZKPoK for the DDH tuple [G, H=eG, xG, xH].
/// - Prover selects a random r and sends A=rG, B=rH.
/// - Prover computes challenge c and sends z=r+c*x.
/// - Verifier checks that zG=A+c(xG) and zH=B+c(xH).
/// The NIZK is (A, B, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DdhTupleNizk<G: GroupElement>(G, G, G::ScalarType);

impl<G: GroupElement> DdhTupleNizk<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    /// Create a new NIZKPoK for the DDH tuple [G, H=eG, xG, xH] using the given RNG and random oracle.
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
        debug!("NIZK: Creating a proof for {h:?} {x_g:?} {x_h:?} with challenge {challenge:?}");
        DdhTupleNizk(a, b, z)
    }

    /// Verify this NIZKPoK.
    pub fn verify(
        &self,
        h: &G,
        x_g: &G,
        x_h: &G,
        random_oracle: &RandomOracle,
    ) -> FastCryptoResult<()> {
        if *h == G::zero() || *x_g == G::zero() || *x_h == G::zero() {
            // We should never see this, but just in case
            return Err(FastCryptoError::InvalidProof);
        }
        let challenge = Self::fiat_shamir_challenge(h, x_g, x_h, &self.0, &self.1, random_oracle);
        debug!("NIZK: Verifying a proof of {h:?} {x_g:?} {x_h:?} with challenge {challenge:?}");
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

/// NIZKPoK for the DL [G, xG].
/// - Prover selects a random r and sends A=rG.
/// - Prover computes challenge c and sends z=r+c*x.
/// - Verifier checks that zG=A+c(xG).
/// The NIZK is (A, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DLNizk<G: GroupElement>(G, G::ScalarType);

impl<G: GroupElement> DLNizk<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    /// Create a new NIZKPoK for the DL [G, xG] using the given RNG and random oracle.
    pub fn create<R: AllowedRng>(
        x: &G::ScalarType,
        x_g: &G,             // passed since probably already computed
        aux_ro_input: &[u8], // optional auxiliary input to the random oracle
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = G::generator() * r;
        let challenge = Self::fiat_shamir_challenge(x_g, &a, aux_ro_input, random_oracle);
        let z = challenge * x + r;
        debug!("NIZK: Creating a proof for {x_g:?} with challenge {challenge:?}");
        DLNizk(a, z)
    }

    pub fn verify(
        &self,
        x_g: &G,
        aux_ro_input: &[u8],
        random_oracle: &RandomOracle,
    ) -> FastCryptoResult<()> {
        if *x_g == G::zero() {
            // we should never see this, but just in case
            return Err(FastCryptoError::InvalidProof);
        }
        let challenge = Self::fiat_shamir_challenge(x_g, &self.0, aux_ro_input, random_oracle);
        debug!("NIZK: Verifying a proof of {x_g:?} with challenge {challenge:?}");
        if !is_valid_relation(&self.0, x_g, &G::generator(), &self.1, &challenge) {
            Err(FastCryptoError::InvalidProof)
        } else {
            Ok(())
        }
    }

    /// Returns the challenge for Fiat-Shamir.
    fn fiat_shamir_challenge(
        x_g: &G,
        a: &G,
        aux_ro_input: &[u8],
        random_oracle: &RandomOracle,
    ) -> G::ScalarType {
        let output = random_oracle.evaluate(&(G::generator(), x_g, a, aux_ro_input));
        G::ScalarType::fiat_shamir_reduction_to_group_element(&output)
    }
}

impl<'de, G> Deserialize<'de> for DLNizk<G>
where
    G: GroupElement + Deserialize<'de>,
    G::ScalarType: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tuple = <(G, G::ScalarType)>::deserialize(deserializer)?;
        if tuple.0 == G::zero() || tuple.1 == G::ScalarType::zero() {
            return Err(serde::de::Error::custom(
                "Invalid proof: one of the elements is inf/zero",
            ));
        }
        Ok(DLNizk(tuple.0, tuple.1))
    }
}

/// Checks if e1 + c e2 = z e3
fn is_valid_relation<G: GroupElement>(
    e1: &G,
    e2: &G,
    e3: &G,
    z: &G::ScalarType,
    c: &G::ScalarType,
) -> bool {
    let left = *e1 + *e2 * c;
    let right = *e3 * z;
    left == right
}
