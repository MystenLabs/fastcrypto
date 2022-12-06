// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::GroupElement;
use crate::groups::Scalar as ScalarType;
use crate::traits::AllowedRng;
use blst::{
    blst_fp, blst_fp12, blst_fp12_inverse, blst_fp12_mul, blst_fp12_one, blst_fp12_sqr, blst_fr,
    blst_fr_add, blst_fr_cneg, blst_fr_from_scalar, blst_fr_from_uint64, blst_fr_inverse,
    blst_fr_mul, blst_fr_rshift, blst_fr_sub, blst_p1, blst_p1_add_or_double, blst_p1_cneg,
    blst_p1_from_affine, blst_p1_mult, blst_p2, blst_p2_add_or_double, blst_p2_cneg,
    blst_p2_from_affine, blst_p2_mult, blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
    blst_uint64_from_fr, Pairing, BLS12_381_G1, BLS12_381_G2,
};
use derive_more::From;
use fastcrypto_derive::GroupOpsExtend;
use std::ops::{Add, Div, Mul, Neg, Sub};

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

        let mut result = blst_p1::default();
        if bytes == 0 {
            return G1Element::zero();
        } else if bytes == 1 && scalar.b[0] == 1 {
            return self;
        } else {
            unsafe {
                blst_p1_mult(
                    &mut result,
                    &self.0,
                    &(scalar.b[0]),
                    size_in_bits(&scalar, bytes),
                );
            }
        }
        Self::from(result)
    }
}

impl GroupElement for G1Element {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self::from(G1_IDENTITY)
    }

    fn generator() -> Self {
        let mut ret = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut ret, &BLS12_381_G1);
        }
        Self::from(ret)
    }
}

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

        let mut result = blst_p2::default();
        if bytes == 0 {
            return G2Element::zero();
        } else if bytes == 1 && scalar.b[0] == 1 {
            return self;
        } else {
            unsafe {
                blst_p2_mult(
                    &mut result,
                    &self.0,
                    &(scalar.b[0]),
                    size_in_bits(&scalar, bytes),
                );
            }
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
            Self::zero()
        } else if rhs.0 == BLST_FR_ONE {
            self
        } else {
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
            let mut pairing_blst = Pairing::new(false, &dst);
            pairing_blst.raw_aggregate(&BLS12_381_G2, &BLS12_381_G1);
            Self::from(pairing_blst.as_fp12()) // this implies pairing_blst.commit()
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
        // blst_fr uses little-endian encoding of four 64 bit words
        // See https://github.com/supranational/blst/blob/05f896cda89a7f215aa718a3a98c3cb8791caa54/src/exports.c#L461-L479
        let mut ret = blst_fr::default();
        let mut words = [0u64; 4];
        words[0] = value;
        unsafe {
            blst_fr_from_uint64(&mut ret, &words[0]);
        }
        Self::from(ret)
    }
}

impl Div<Scalar> for Scalar {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let mut ret = blst_fr::default();
        unsafe {
            let mut inverse = blst_fr::default();
            blst_fr_inverse(&mut inverse, &rhs.0);
            blst_fr_mul(&mut ret, &self.0, &inverse);
        }
        Self::from(ret)
    }
}

impl ScalarType for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        let mut ret = blst_fr::default();
        let mut bytes = [0u8; 32];
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
        let mut ret = [0u64; 4];
        blst_uint64_from_fr(&mut ret[0], value);
        odd = ret[0] % 2 == 1;
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

/// This helper constant makes it easier to use compute the linear combination involved in the pairing inputs.
const G1_IDENTITY: blst_p1 = blst_p1 {
    x: blst_fp { l: [0; 6] },
    y: blst_fp { l: [0; 6] },
    z: blst_fp { l: [0; 6] },
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
