// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use fastcrypto::error::FastCryptoError;
use num_bigint::BigUint;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
/// A G1 point in BN254 serialized as a vector of three strings which is the canonical decimal
/// representation of the projective coordinates in Fq.
pub type CircomG1 = Vec<Bn254FqElement>;

/// A G2 point in BN254 serialized as a vector of three vectors each being a vector of two strings
/// which are the canonical decimal representation of the coefficients of the projective coordinates
/// in Fq2.
pub type CircomG2 = Vec<Vec<Bn254FqElement>>;

/// A struct that stores a Bn254 Fq field element as 32 bytes.
#[derive(Debug, Clone, JsonSchema, Eq, PartialEq)]
pub struct Bn254FqElement([u8; 32]);

impl std::str::FromStr for Bn254FqElement {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let big_int = Fq::from_str(s).map_err(|_| FastCryptoError::InvalidInput)?;
        let be_bytes = big_int.into_bigint().to_bytes_be();
        be_bytes
            .try_into()
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(Bn254FqElement)
    }
}

impl std::fmt::Display for Bn254FqElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let big_int = BigUint::from_bytes_be(&self.0);
        let radix10 = big_int.to_string();
        f.write_str(&radix10)
    }
}

// Bn254FqElement's serialized format is as a radix10 encoded string
impl Serialize for Bn254FqElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Bn254FqElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// A struct that stores a Bn254 Fr field element as 32 bytes.
#[derive(Debug, Clone, JsonSchema, Eq, PartialEq)]
pub struct Bn254FrElement([u8; 32]);

impl Bn254FrElement {
    /// Returns the unpadded version of the field element. This returns with leading zeros removed.
    pub fn unpadded(&self) -> &[u8] {
        let mut buf = self.0.as_slice();

        while !buf.is_empty() && buf[0] == 0 {
            buf = &buf[1..];
        }

        // If the value is '0' then just return a slice of length 1 of the final byte
        if buf.is_empty() {
            &self.0[31..]
        } else {
            buf
        }
    }

    /// Returns the padded version of the field element. This returns with leading zeros preserved to 32 bytes.
    pub fn padded(&self) -> &[u8] {
        &self.0
    }
}
impl std::str::FromStr for Bn254FrElement {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let big_int = Fr::from_str(s).map_err(|_| FastCryptoError::InvalidInput)?;
        let be_bytes = big_int.into_bigint().to_bytes_be();
        be_bytes
            .try_into()
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(Bn254FrElement)
    }
}

impl std::fmt::Display for Bn254FrElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let big_int = BigUint::from_bytes_be(&self.0);
        let radix10 = big_int.to_string();
        f.write_str(&radix10)
    }
}

// Bn254FrElement's serialized format is as a radix10 encoded string
impl Serialize for Bn254FrElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Bn254FrElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Convert Bn254FqElement type to arkworks' Fq.
impl From<&Bn254FqElement> for Fq {
    fn from(f: &Bn254FqElement) -> Self {
        Fq::from_be_bytes_mod_order(&f.0)
    }
}

/// Convert Bn254FrElement type to arkworks' Fr.
impl From<&Bn254FrElement> for Fr {
    fn from(f: &Bn254FrElement) -> Self {
        Fr::from_be_bytes_mod_order(&f.0)
    }
}

/// Deserialize a G1 projective point in BN254 serialized as a vector of three strings into an affine
/// G1 point in arkworks format. Return an error if the input is not a vector of three strings or if
/// any of the strings cannot be parsed as a field element.
pub(crate) fn g1_affine_from_str_projective(s: &CircomG1) -> Result<G1Affine, FastCryptoError> {
    if s.len() != 3 {
        return Err(FastCryptoError::InvalidInput);
    }

    let g1: G1Affine =
        G1Projective::new_unchecked((&s[0]).into(), (&s[1]).into(), (&s[2]).into()).into();

    if !g1.is_on_curve() || !g1.is_in_correct_subgroup_assuming_on_curve() {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(g1)
}

/// Deserialize a G2 projective point from the BN254 construction serialized as a vector of three
/// vectors each being a vector of two strings into an affine G2 point in arkworks format. Return an
/// error if the input is not a vector of the right format or if any of the strings cannot be parsed
/// as a field element.
pub(crate) fn g2_affine_from_str_projective(s: &CircomG2) -> Result<G2Affine, FastCryptoError> {
    if s.len() != 3 || s[0].len() != 2 || s[1].len() != 2 || s[2].len() != 2 {
        return Err(FastCryptoError::InvalidInput);
    }

    let g2: G2Affine = G2Projective::new_unchecked(
        Fq2::new((&s[0][0]).into(), (&s[0][1]).into()),
        Fq2::new((&s[1][0]).into(), (&s[1][1]).into()),
        Fq2::new((&s[2][0]).into(), (&s[2][1]).into()),
    )
    .into();

    if !g2.is_on_curve() || !g2.is_in_correct_subgroup_assuming_on_curve() {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(g2)
}

#[cfg(test)]
mod test {
    use crate::zk_login_utils::Bn254FqElement;
    use std::str::FromStr;

    use super::Bn254FrElement;
    use num_bigint::BigUint;
    use proptest::prelude::*;
    #[test]
    fn from_str_on_digits_only() {
        // do not allow non digit results.
        assert!(Bn254FrElement::from_str("10_________0").is_err());
        assert!(Bn254FqElement::from_str("10_________0").is_err());
        // do not allow leading zeros.
        assert!(Bn254FrElement::from_str("000001").is_err());
        assert!(Bn254FqElement::from_str("000001").is_err());
        assert!(Bn254FrElement::from_str("garbage").is_err());
        assert!(Bn254FqElement::from_str("garbage").is_err());
    }
    #[test]
    fn unpadded_slice() {
        let seed = Bn254FrElement([0; 32]);
        let zero: [u8; 1] = [0];
        assert_eq!(seed.unpadded(), zero.as_slice());

        let mut seed = Bn254FrElement([1; 32]);
        seed.0[0] = 0;
        assert_eq!(seed.unpadded(), [1; 31].as_slice());
    }

    proptest! {
        #[test]
        fn dont_crash_on_large_inputs(
            bytes in proptest::collection::vec(any::<u8>(), 33..1024)
        ) {
            let big_int = BigUint::from_bytes_be(&bytes);
            let radix10 = big_int.to_str_radix(10);

            // doesn't crash
            let _ = Bn254FrElement::from_str(&radix10);
            let _ = Bn254FqElement::from_str(&radix10);
        }
    }
}
