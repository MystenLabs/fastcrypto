// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::random_oracle::RandomOracle;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};

/// NIZKPoK for the DDH tuple [G, eG, PK=sk*G, Key=sk*eG].
/// - Prover selects a random r and sends A=rG, B=reG.
/// - Prover computes challenge c and sends z=r+c*sk.
/// - Verifier checks that zG=A+cPK and zeG=B+cKey.
/// The NIZK is (A, B, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DdhTupleNizk<G: GroupElement>(G, G, G::ScalarType);

impl<G: GroupElement> DdhTupleNizk<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    pub fn create<R: AllowedRng>(
        sk: &G::ScalarType,
        e_g: &G,
        sk_g: &G,
        sk_e_g: &G,
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = G::generator() * r;
        let b = *e_g * r;
        let challenge = Self::fiat_shamir_challenge(e_g, sk_g, sk_e_g, &a, &b, random_oracle);
        let z = challenge * sk + r;
        DdhTupleNizk(a, b, z)
    }

    pub fn verify(
        &self,
        e_g: &G,
        sk_g: &G,
        sk_e_g: &G,
        random_oracle: &RandomOracle,
    ) -> Result<(), FastCryptoError> {
        let challenge =
            Self::fiat_shamir_challenge(e_g, sk_g, sk_e_g, &self.0, &self.1, random_oracle);
        if !Self::is_valid_relation(
            &self.0, // A
            sk_g,
            &G::generator(),
            &self.2, // z
            &challenge,
        ) || !Self::is_valid_relation(
            &self.1, // B
            sk_e_g, e_g, &self.2, // z
            &challenge,
        ) {
            Err(FastCryptoError::InvalidProof)
        } else {
            Ok(())
        }
    }

    /// Returns the challenge for Fiat-Shamir.
    fn fiat_shamir_challenge(
        e_g: &G,
        sk_g: &G,
        sk_e_g: &G,
        a: &G,
        b: &G,
        random_oracle: &RandomOracle,
    ) -> G::ScalarType {
        let output = random_oracle.evaluate(&(G::generator(), e_g, sk_g, sk_e_g, a, b));
        G::ScalarType::fiat_shamir_reduction_to_group_element(&output)
    }

    /// Checks if e1 + e2*c = z e3
    fn is_valid_relation(e1: &G, e2: &G, e3: &G, z: &G::ScalarType, c: &G::ScalarType) -> bool {
        let left = *e1 + *e2 * c;
        let right = *e3 * z;
        left == right
    }
}
