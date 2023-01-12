// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::min_pk::DST_G2;
use crate::bls12381::min_sig::DST_G1;
use crate::error::FastCryptoError;
use crate::groups::{GroupElement, HashToGroupElement, Pairing, Scalar as ScalarType};
use crate::serde_helpers::BytesRepresentation;
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use crate::{generate_bytes_representation, serialize_deserialize_with_to_from_byte_array};
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_inverse, blst_fp12_mul, blst_fp12_one, blst_fp12_sqr,
    blst_fr, blst_fr_add, blst_fr_cneg, blst_fr_from_scalar, blst_fr_inverse, blst_fr_mul,
    blst_fr_rshift, blst_fr_sub, blst_hash_to_g1, blst_hash_to_g2, blst_lendian_from_scalar,
    blst_miller_loop, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_cneg,
    blst_p1_compress, blst_p1_deserialize, blst_p1_from_affine, blst_p1_in_g1, blst_p1_mult,
    blst_p1_to_affine, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_cneg,
    blst_p2_compress, blst_p2_deserialize, blst_p2_from_affine, blst_p2_in_g2, blst_p2_mult,
    blst_p2_to_affine, blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
    blst_scalar_from_lendian, Pairing as BlstPairing, BLS12_381_G1, BLS12_381_G2, BLST_ERROR,
};
use derive_more::From;
use fastcrypto_derive::GroupOpsExtend;
use serde::{de, Deserialize};
use std::ops::{Add, Div, Mul, Neg, Sub};
use std::ptr;

/// Elements of the group G_1 in BLS 12-381.
#[derive(Debug, From, Clone, Copy, Eq, PartialEq, GroupOpsExtend)]
pub struct G1Element(blst_p1);

/// Elements of the group G_2 in BLS 12-381.
#[derive(Debug, From, Clone, Copy, Eq, PartialEq, GroupOpsExtend)]
pub struct G2Element(blst_p2);

/// Elements of the subgroup G_T of F_q^{12} in BLS 12-381. Note that it is written in additive notation here.
#[derive(Debug, From, Clone, Copy, Eq, PartialEq, GroupOpsExtend)]
pub struct GTElement(blst_fp12);

/// This represents a scalar modulo r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
/// which is the order of the groups G1, G2 and GT. Note that r is a 255 bit prime.
#[derive(Debug, From, Clone, Copy, Eq, PartialEq, GroupOpsExtend)]
pub struct Scalar(blst_fr);

/// Length of [Scalar]s in bytes.
pub const SCALAR_LENGTH: usize = 32;
pub const G1_ELEMENT_BYTE_LENGTH: usize = 48;
pub const G2_ELEMENT_BYTE_LENGTH: usize = 96;

impl Add for G1Element {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = blst_p1::default();
        unsafe {
            blst_p1_add_or_double(&mut ret, &self.0, &rhs.0);
        }
        Self::from(ret)
    }
}

impl Sub for G1Element {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::add(self, Self::neg(rhs))
    }
}

impl Neg for G1Element {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ret = self.0;
        unsafe {
            blst_p1_cneg(&mut ret, true);
        }
        Self::from(ret)
    }
}

/// The size of this scalar in bytes.
fn size_in_bytes(scalar: &blst_scalar) -> usize {
    let mut i = scalar.b.len();
    while i != 0 && scalar.b[i - 1] == 0 {
        i -= 1;
    }
    i
}

/// Given a scalar and its size in bytes (computed using [size_in_bytes], this method returns the size
/// of the scalar in bits.
fn size_in_bits(scalar: &blst_scalar, size_in_bytes: usize) -> usize {
    8 * size_in_bytes - 7 + log_2_byte(scalar.b[size_in_bytes - 1])
}

impl Mul<Scalar> for G1Element {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let mut scalar: blst_scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
        }

        // Count the number of bytes to be multiplied.
        let bytes = size_in_bytes(&scalar);

        if bytes == 0 {
            return G1Element::zero();
        }

        // If rhs = 1, return self
        if bytes == 1 && scalar.b[0] == 1 {
            return self;
        }

        let mut result = blst_p1::default();
        unsafe {
            blst_p1_mult(
                &mut result,
                &self.0,
                &(scalar.b[0]),
                size_in_bits(&scalar, bytes),
            );
        }

        Self::from(result)
    }
}

impl GroupElement for G1Element {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self::from(blst_p1::default())
    }

    fn generator() -> Self {
        let mut ret = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut ret, &BLS12_381_G1);
        }
        Self::from(ret)
    }
}

impl Pairing for G1Element {
    type Other = G2Element;
    type Output = GTElement;

    fn pairing(&self, other: &Self::Other) -> <Self as Pairing>::Output {
        let mut self_affine = blst_p1_affine::default();
        let mut other_affine = blst_p2_affine::default();
        let mut res = blst_fp12::default();
        unsafe {
            blst_p1_to_affine(&mut self_affine, &self.0);
            blst_p2_to_affine(&mut other_affine, &other.0);
            blst_miller_loop(&mut res, &other_affine, &self_affine);
            blst_final_exp(&mut res, &res);
        }
        <Self as Pairing>::Output::from(res)
    }
}

impl HashToGroupElement for G1Element {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        let mut res = blst_p1::default();
        unsafe {
            blst_hash_to_g1(
                &mut res,
                msg.as_ptr(),
                msg.len(),
                DST_G1.as_ptr(),
                DST_G1.len(),
                ptr::null(),
                0,
            );
        }
        Self::from(res)
    }
}

impl ToFromByteArray<G1_ELEMENT_BYTE_LENGTH> for G1Element {
    fn from_byte_array(bytes: &[u8; G1_ELEMENT_BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        let mut ret = blst_p1::default();
        unsafe {
            let mut affine = blst_p1_affine::default();
            if blst_p1_deserialize(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(FastCryptoError::InvalidInput);
            }
            blst_p1_from_affine(&mut ret, &affine);
            // Verify that the deserialized element is in G1
            if !blst_p1_in_g1(&ret) {
                return Err(FastCryptoError::InvalidInput);
            }
        }
        Ok(G1Element::from(ret))
    }

    fn to_byte_array(&self) -> [u8; G1_ELEMENT_BYTE_LENGTH] {
        let mut bytes = [0u8; G1_ELEMENT_BYTE_LENGTH];
        unsafe {
            blst_p1_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(G1Element);
generate_bytes_representation!(G1Element, G1_ELEMENT_BYTE_LENGTH, G1ElementAsBytes);

impl Add for G2Element {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = blst_p2::default();
        unsafe {
            blst_p2_add_or_double(&mut ret, &self.0, &rhs.0);
        }
        Self::from(ret)
    }
}

impl Sub for G2Element {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::add(self, Self::neg(rhs))
    }
}

impl Neg for G2Element {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ret = self.0;
        unsafe {
            blst_p2_cneg(&mut ret, true);
        }
        Self::from(ret)
    }
}

impl Mul<Scalar> for G2Element {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let mut scalar: blst_scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
        }

        // Count the number of bytes to be multiplied.
        let bytes = size_in_bytes(&scalar);

        if bytes == 0 {
            return G2Element::zero();
        }

        // If rhs = 1, return self
        if bytes == 1 && scalar.b[0] == 1 {
            return self;
        }

        let mut result = blst_p2::default();
        unsafe {
            blst_p2_mult(
                &mut result,
                &self.0,
                &(scalar.b[0]),
                size_in_bits(&scalar, bytes),
            );
        }

        Self::from(result)
    }
}

impl GroupElement for G2Element {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self::from(blst_p2::default())
    }

    fn generator() -> Self {
        let mut ret = blst_p2::default();
        unsafe {
            blst_p2_from_affine(&mut ret, &BLS12_381_G2);
        }
        Self::from(ret)
    }
}

impl HashToGroupElement for G2Element {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        let mut res = blst_p2::default();
        unsafe {
            blst_hash_to_g2(
                &mut res,
                msg.as_ptr(),
                msg.len(),
                DST_G2.as_ptr(),
                DST_G2.len(),
                ptr::null(),
                0,
            );
        }
        Self::from(res)
    }
}

impl ToFromByteArray<G2_ELEMENT_BYTE_LENGTH> for G2Element {
    fn from_byte_array(bytes: &[u8; G2_ELEMENT_BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        let mut ret = blst_p2::default();
        unsafe {
            let mut affine = blst_p2_affine::default();
            if blst_p2_deserialize(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(FastCryptoError::InvalidInput);
            }
            blst_p2_from_affine(&mut ret, &affine);
            // Verify that the deserialized element is in G1
            if !blst_p2_in_g2(&ret) {
                return Err(FastCryptoError::InvalidInput);
            }
        }
        Ok(G2Element::from(ret))
    }

    fn to_byte_array(&self) -> [u8; G2_ELEMENT_BYTE_LENGTH] {
        let mut bytes = [0u8; G2_ELEMENT_BYTE_LENGTH];
        unsafe {
            blst_p2_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(G2Element);
generate_bytes_representation!(G2Element, G2_ELEMENT_BYTE_LENGTH, G2ElementAsBytes);

impl Add for GTElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = blst_fp12::default();
        unsafe {
            blst_fp12_mul(&mut ret, &self.0, &rhs.0);
        }
        Self::from(ret)
    }
}

impl Sub for GTElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::add(self, Self::neg(rhs))
    }
}

impl Neg for GTElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ret = self.0;
        unsafe {
            blst_fp12_inverse(&mut ret, &self.0);
        }
        Self::from(ret)
    }
}

impl Mul<Scalar> for GTElement {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        if rhs == Scalar::zero() {
            return Self::zero();
        }

        if rhs.0 == BLST_FR_ONE {
            return self;
        }

        let mut y: blst_fp12 = blst_fp12::default();
        let mut n = rhs.0;
        let mut x = self.0;

        // Compute n * x using repeated doubling (~ additive version of exponentiation by repeated squaring)
        unsafe {
            // Keep going while n > 1
            while n != blst_fr::default() && n != BLST_FR_ONE {
                if is_odd(&n) {
                    blst_fr_sub(&mut n, &n, &BLST_FR_ONE);
                    y *= x;
                }
                blst_fp12_sqr(&mut x, &x);
                blst_fr_rshift(&mut n, &n, 1);
            }
            y *= x;
            Self::from(y)
        }
    }
}

impl GroupElement for GTElement {
    type ScalarType = Scalar;

    fn zero() -> Self {
        unsafe { Self::from(*blst_fp12_one()) }
    }

    fn generator() -> Self {
        unsafe {
            // Compute the generator as e(G1, G2).
            // TODO: Should be precomputed.
            let dst = [0u8; 3];
            let mut pairing_blst = BlstPairing::new(false, &dst);
            pairing_blst.raw_aggregate(&BLS12_381_G2, &BLS12_381_G1);
            Self::from(pairing_blst.as_fp12())
        }
    }
}

impl GroupElement for Scalar {
    type ScalarType = Self;

    fn zero() -> Self {
        Self::from(blst_fr::default())
    }

    fn generator() -> Self {
        Self::from(BLST_FR_ONE)
    }
}

impl Add for Scalar {
    type Output = Scalar;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = blst_fr::default();
        unsafe {
            blst_fr_add(&mut ret, &self.0, &rhs.0);
        }
        Self::from(ret)
    }
}

impl Sub for Scalar {
    type Output = Scalar;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = blst_fr::default();
        unsafe {
            blst_fr_sub(&mut ret, &self.0, &rhs.0);
        }
        Self::from(ret)
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        let mut ret = blst_fr::default();
        unsafe {
            blst_fr_cneg(&mut ret, &self.0, true);
        }
        Self::from(ret)
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let mut ret = blst_fr::default();
        unsafe {
            blst_fr_mul(&mut ret, &self.0, &rhs.0);
        }
        Self::from(ret)
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        let low_bytes: [u8; 8] = u64::to_le_bytes(value);
        let mut bytes = [0u8; SCALAR_LENGTH];
        bytes[0..8].copy_from_slice(&low_bytes);

        let mut ret = blst_fr::default();
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_lendian(&mut scalar, bytes.as_ptr());
            blst_fr_from_scalar(&mut ret, &scalar);
        }
        Self::from(ret)
    }
}

impl Div<Scalar> for Scalar {
    type Output = Result<Self, FastCryptoError>;

    fn div(self, rhs: Self) -> Result<Self, FastCryptoError> {
        if rhs == Scalar::zero() {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut ret = blst_fr::default();
        unsafe {
            let mut inverse = blst_fr::default();
            blst_fr_inverse(&mut inverse, &rhs.0);
            blst_fr_mul(&mut ret, &self.0, &inverse);
        }
        Ok(Self::from(ret))
    }
}

impl ScalarType for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        let mut ret = blst_fr::default();
        let mut bytes = [0u8; SCALAR_LENGTH];
        rng.fill_bytes(&mut bytes);
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
            blst_fr_from_scalar(&mut ret, &scalar);
        }
        Scalar::from(ret)
    }
}

pub(crate) fn is_odd(value: &blst_fr) -> bool {
    let odd: bool;
    unsafe {
        let mut scalar = blst_scalar::default();
        blst_scalar_from_fr(&mut scalar, value);
        let mut bytes = [0u8; 32];
        blst_lendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        odd = bytes[0] % 2 == 1;
    }
    odd
}

/// This represents the multiplicative unit scalar
const BLST_FR_ONE: blst_fr = blst_fr {
    l: [
        8589934590,
        6378425256633387010,
        11064306276430008309,
        1739710354780652911,
    ],
};

/// Returns the log base 2 of b in O(lg(N)) time.
fn log_2_byte(b: u8) -> usize {
    let mut r = u8::from(b > 0xF) << 2;
    let mut b = b >> r;
    let shift = u8::from(b > 0x3) << 1;
    b >>= shift + 1;
    r |= shift | b;
    r.into()
}
