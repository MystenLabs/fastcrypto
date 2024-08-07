// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::bigint_serde;
use crate::math::hash_prime;
use crate::math::hash_prime::is_probable_prime;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use lazy_static::lazy_static;
use num_bigint::{BigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Signed};
use serde::{Deserialize, Serialize};
use std::ops::Neg;
use std::str::FromStr;

/// A discriminant for an imaginary class group. The discriminant is a negative integer congruent to
/// 1 mod 8.
#[derive(PartialEq, Eq, Debug, Clone, Serialize)]
pub struct Discriminant(#[serde(with = "crate::class_group::bigint_serde")] BigInt);

lazy_static! {
    /// Fixed 3072 bit discriminant. Generated from the seed `[1,2,3]` using [Discriminant::from_seed].
    // TODO: Generate this using a seed that we provably cannot influence.
    pub static ref DISCRIMINANT_3072: Discriminant = Discriminant(BigInt::from_str("-4080390101490206102067801750685552291425412528983716161454985565795560716833845004659207152503580931176637478422335625954692628868126419714053340412299850300602673802493259771830686596468801304317015718872352674945215883546019961626928140286675493693757393881479657605888983279619347902770789061953207866325747708864327315769009839190765716943013935708854055658243676903245686125751909996824976354309908771869043784640567352757672203749399825983258156684652782580603170228640173640869773628592618889352385821753919281706169861276929330689892675986265846043432389737049521845230769417696140636288030698887830215613149485135897148487896368642774768920061430225392365148291796645740474628778185683682893521776342856643134668770656709308404166182149870849376649591338267281149794078240401323227967073641261327798339424740171219484355109588337730742391198073121589465833677609362668436116144203312494461735357918360857667357985711").unwrap());
}

impl<'de> Deserialize<'de> for Discriminant {
    fn deserialize<D>(deserializer: D) -> Result<Discriminant, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Discriminant::try_from(bigint_serde::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    /// A valid discriminant should be a negative prime congruent to 1 mod 8. For large discriminants,
    /// this is very slow to check.
    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if !value.is_negative()
            || value.mod_floor(&BigInt::from(8)) != BigInt::one()
            || !is_probable_prime(value.abs().magnitude())
        {
            return Err(InvalidInput);
        }
        Ok(Self(value))
    }
}

impl Discriminant {
    /// Return the number of bits needed to represent this discriminant, not including the sign bit.
    pub fn bits(&self) -> u64 {
        self.0.bits()
    }

    /// Borrow a reference to the underlying big integer.
    pub(crate) fn as_bigint(&self) -> &BigInt {
        &self.0
    }

    /// Create a discriminant from the given value. It is assumed that the discriminant is a negative
    /// prime which is 1 mod 8. If this is not the case, some functions may panic, so this should only
    /// be used in tests.
    #[cfg(test)]
    pub(crate) fn from_trusted_bigint(value: BigInt) -> Self {
        Self(value)
    }

    /// Compute a valid discriminant (aka a negative prime equal to 1 mod 8) based on the given seed.
    /// The size_in_bits must be divisible by 8.
    pub fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Discriminant> {
        if size_in_bits % 8 != 0 {
            return Err(InvalidInput);
        }
        // Set the lower three bits to ensure that the prime is 7 mod 8 which makes the discriminant 1 mod 8.
        Ok(Self(
            hash_prime::hash_prime(seed, size_in_bits / 8, &[0, 1, 2, size_in_bits - 1])
                .to_bigint()
                .expect("Never fails")
                .neg(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminant() {
        let discriminant = Discriminant(-BigInt::from(223));
        assert_eq!(discriminant.bits(), 8);
        assert_eq!(discriminant.as_bigint(), &-BigInt::from(223));

        // Invalid modulus
        let candidate = BigInt::from(-29);
        assert!(candidate.is_negative());
        assert!(Discriminant::try_from(candidate).is_err());

        // Invalid sign
        let candidate = BigInt::from(17);
        assert_eq!(candidate.mod_floor(&BigInt::from(8)), BigInt::from(1));
        assert!(Discriminant::try_from(candidate).is_err());

        // Not prime
        let candidate = BigInt::from(-231);
        assert!(Discriminant::try_from(candidate).is_err());
    }

    #[test]
    fn test_discriminant_from_seed() {
        let seed = hex::decode("d911a54e3bf6f52b4111").unwrap();
        let target_size = 1024;
        let discriminant = Discriminant::from_seed(&seed, target_size).unwrap();
        assert_eq!(discriminant.bits() as usize, target_size);

        // Test vector from chiavdf computed using https://github.com/Chia-Network/chiavdf/blob/2844974ff81274060778a56dfefd2515bc567b90/tests/test_verifier.py.
        assert_eq!(discriminant.as_bigint().to_str_radix(16), "-95a0b0523b6c516e813d745e7e58b3c7223d511f6008a0ff2757c9a0f15cba8841293cc903af3a40654670c9dee17ec14da1457360aafe40a93831d90c3dd59738d8a24e415b6e33780224fa24171de1d4a1ca5fe4c877bf44361e7ba869126ac12367714eb4246a5e310515508ad35e170aee19cae371069d6d92e94c21d63f");
    }

    #[test]
    fn test_discriminant_to_from_bytes() {
        let discriminant = Discriminant(BigInt::from(-223));
        let bytes = bcs::to_bytes(&discriminant).unwrap();
        let discriminant2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, discriminant2);

        let discriminant = Discriminant::from_seed(&[0x01, 0x02, 0x03], 512).unwrap();
        let bytes = bcs::to_bytes(&discriminant).unwrap();
        let discriminant2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, discriminant2);

        // Test serde on invalid discriminants
        let invalid_discriminant_bytes =
            bcs::to_bytes(&BigInt::from(-221).to_signed_bytes_be()).unwrap();
        assert!(bcs::from_bytes::<Discriminant>(&invalid_discriminant_bytes).is_err());

        let invalid_discriminant_bytes =
            bcs::to_bytes(&BigInt::from(17).to_signed_bytes_be()).unwrap();
        assert!(bcs::from_bytes::<Discriminant>(&invalid_discriminant_bytes).is_err());
    }
}
