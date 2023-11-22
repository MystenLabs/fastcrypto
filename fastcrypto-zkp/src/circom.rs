// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine};
use fastcrypto::error::FastCryptoError;

pub type CircomG1 = Vec<String>;
pub type CircomG2 = Vec<Vec<String>>;

pub fn g1_affine_from_str_projective(s: &CircomG1) -> Result<G1Affine, FastCryptoError> {
    if s.len() != 3 {
        return Err(FastCryptoError::InvalidInput);
    }
    Ok(G1Projective::new_unchecked(
        s[0].parse::<Fq>()
            .map_err(|_| FastCryptoError::InvalidInput)?,
        s[1].parse::<Fq>()
            .map_err(|_| FastCryptoError::InvalidInput)?,
        s[2].parse::<Fq>()
            .map_err(|_| FastCryptoError::InvalidInput)?,
    )
    .into())
}

pub fn g2_affine_from_str_projective(s: &CircomG2) -> Result<G2Affine, FastCryptoError> {
    use ark_bn254::G2Projective;
    if s.len() != 3 {
        return Err(FastCryptoError::InvalidInput);
    }

    for x in s {
        if x.len() != 2 {
            return Err(FastCryptoError::InvalidInput);
        }
    }
    Ok(G2Projective::new_unchecked(
        Fq2::new(
            s[0][0]
                .parse::<Fq>()
                .map_err(|_| FastCryptoError::InvalidInput)?,
            s[0][1]
                .parse::<Fq>()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ),
        Fq2::new(
            s[1][0]
                .parse::<Fq>()
                .map_err(|_| FastCryptoError::InvalidInput)?,
            s[1][1]
                .parse::<Fq>()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ),
        Fq2::new(
            s[2][0].parse::<Fq>().unwrap(),
            s[2][1].parse::<Fq>().unwrap(),
        ),
    )
    .into())
}
