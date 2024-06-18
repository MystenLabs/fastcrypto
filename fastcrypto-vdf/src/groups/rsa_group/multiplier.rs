use crate::groups::rsa_group::RSAGroupElement;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use num_bigint::BigUint;
use num_integer::Integer;
use std::rc::Rc;

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
            modulus: Rc::clone(&self.base_element.modulus),
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
            modulus: Rc::clone(&self.base_element.modulus),
        }
    }
}
