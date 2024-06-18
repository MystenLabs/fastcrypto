use std::ops::{Add, Mul, Neg};

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

use fastcrypto::groups::multiplier::ScalarMultiplier;
use fastcrypto::groups::Doubling;

use crate::groups::{Parameter, ParameterizedGroupElement};
use crate::vdf::wesolowski::fiat_shamir::StrongFiatShamir;
use crate::vdf::wesolowski::WesolowskisVDF;

mod biguint_serde;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAModulus {
    #[serde(with = "biguint_serde")]
    pub value: BigUint,
}

impl Parameter for RSAModulus {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAGroupElement {
    #[serde(with = "biguint_serde")]
    pub value: BigUint,
    pub modulus: RSAModulus,
}

impl Add<Self> for RSAGroupElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        self.add(&rhs)
    }
}

impl Add<&Self> for RSAGroupElement {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        Self {
            value: self.value.mul(&rhs.value).mod_floor(&self.modulus.value),
            modulus: self.modulus,
        }
    }
}

impl Doubling for RSAGroupElement {
    fn double(&self) -> Self {
        Self {
            value: self.value.modpow(&BigUint::from(2u8), &self.modulus.value),
            modulus: self.modulus.clone(),
        }
    }
}

impl Neg for RSAGroupElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            value: &self.modulus.value - &self.value,
            modulus: self.modulus,
        }
    }
}

impl ParameterizedGroupElement for RSAGroupElement {
    type ParameterType = RSAModulus;

    fn zero(parameter: &Self::ParameterType) -> Self {
        Self {
            value: BigUint::zero(),
            modulus: parameter.clone(),
        }
    }

    fn same_group_parameter(&self, other: &Self) -> bool {
        self.modulus == other.modulus
    }

    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool {
        self.modulus == *parameter
    }
}

/// A trivial scalar multiplier without precomputation
pub struct Multiplier {
    base_element: RSAGroupElement,
}

impl ScalarMultiplier<RSAGroupElement, BigUint> for Multiplier {
    fn new(base_element: RSAGroupElement, _zero: RSAGroupElement) -> Self {
        Self { base_element }
    }

    fn mul(&self, scalar: &BigUint) -> RSAGroupElement {
        RSAGroupElement {
            value: self
                .base_element
                .value
                .modpow(scalar, &self.base_element.modulus.value),
            modulus: self.base_element.modulus.clone(),
        }
    }

    fn two_scalar_mul(
        &self,
        base_scalar: &BigUint,
        other_element: &RSAGroupElement,
        other_scalar: &BigUint,
    ) -> RSAGroupElement {
        let base_mul = self.mul(base_scalar);
        let result = (base_mul.value
            * other_element
                .value
                .modpow(other_scalar, &other_element.modulus.value))
        .mod_floor(&other_element.modulus.value);
        RSAGroupElement {
            value: result,
            modulus: other_element.modulus.clone(),
        }
    }
}

pub type DefaultRSAVDF = WesolowskisVDF<RSAGroupElement, StrongFiatShamir, Multiplier>;

#[cfg(test)]
mod tests {
    use crate::groups::rsa_group::{DefaultRSAVDF, RSAGroupElement, RSAModulus};
    use crate::math::hash_prime::hash_prime;
    use crate::vdf::VDF;
    use fastcrypto::hash::{HashFunction, Sha256};
    use num_bigint::BigUint;
    use std::str::FromStr;

    impl RSAModulus {
        pub fn from_seed(seed: &[u8], size_in_bytes: usize) -> Self {
            let p = hash_prime(seed, size_in_bytes / 2, &[8 * size_in_bytes - 1]);
            let q = hash_prime(
                Sha256::digest(seed).as_ref(),
                size_in_bytes / 2,
                &[8 * size_in_bytes - 1],
            );
            Self { value: p * q }
        }
    }

    #[test]
    fn test_vdf() {
        let modulus = RSAModulus {
            value: BigUint::from_str("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357").unwrap(),
        };

        let vdf = DefaultRSAVDF::new(modulus.clone(), 1000);

        let input = RSAGroupElement {
            value: BigUint::from(2u64),
            modulus: modulus.clone(),
        };

        let (output, proof) = vdf.evaluate(&input).unwrap();
        assert!(vdf.verify(&input, &output, &proof).is_ok());
    }
}
