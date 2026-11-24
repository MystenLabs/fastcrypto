// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ristretto255 written directly from RFC 9496, with arkworks' field arithmetic. It shares no code
//! with curve25519-dalek, so it is an independent oracle for `groups::ristretto255`. It is slow and
//! not constant time.
//!
//! The fuzz target `ristretto255_group_ops` also includes this file, so it must not depend on the
//! rest of the crate.

// For the code that MontConfig derives.
#![allow(non_local_definitions, unexpected_cfgs)]

use ark_ff::{BigInteger, Field, Fp256, MontBackend, MontConfig, MontFp, One, PrimeField, Zero};
use hex_literal::hex;
use sha2::{Digest, Sha512};
use std::ops::{Add, Mul, Neg, Sub};

/// The field with p = 2^255 - 19 elements.
#[derive(MontConfig)]
#[modulus = "57896044618658097711785492504343953926634992332820282019728792003956564819949"]
#[generator = "2"]
pub struct FieldConfig;
pub type FieldElement = Fp256<MontBackend<FieldConfig, 4>>;

/// The field with l = 2^252 + 27742317777372353535851937790883648493 elements, the group order.
#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "2"]
pub struct ScalarConfig;
pub type Scalar = Fp256<MontBackend<ScalarConfig, 4>>;

/// The group order l and the field modulus p, little-endian.
pub const GROUP_ORDER: [u8; 32] =
    hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
pub const FIELD_MODULUS: [u8; 32] =
    hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

// The constants of RFC 9496, section 4.1.
const D: FieldElement =
    MontFp!("37095705934669439343138083508754565189542113879843219016388785533085940283555");
const SQRT_M1: FieldElement =
    MontFp!("19681161376707505956807079304988542015446066515923890162744021073123829784752");
const SQRT_AD_MINUS_ONE: FieldElement =
    MontFp!("25063068953384623474111414158702152701244531502492656460079210482610430750235");
const INVSQRT_A_MINUS_D: FieldElement =
    MontFp!("54469307008909316920995813868745141605393597292927456921205312896311721017578");
const ONE_MINUS_D_SQ: FieldElement =
    MontFp!("1159843021668779879193775521855586647937357759715417654439879720876111806838");
const D_MINUS_ONE_SQ: FieldElement =
    MontFp!("40440834346308536858101042469323190826248399146238708352240133220865137265952");

/// (p - 5) / 8 = 2^252 - 3, as little-endian 64-bit limbs.
const P_MINUS_5_DIV_8: [u64; 4] = [
    0xfffffffffffffffd,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x0fffffffffffffff,
];

fn field_to_bytes(x: &FieldElement) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().unwrap()
}

/// The field element with the given little-endian encoding, or `None` if it is not below p.
fn field_from_bytes(bytes: &[u8; 32]) -> Option<FieldElement> {
    let x = FieldElement::from_le_bytes_mod_order(bytes);
    (field_to_bytes(&x) == *bytes).then_some(x)
}

/// IS_NEGATIVE of RFC 9496, section 2.1.
fn is_negative(x: &FieldElement) -> bool {
    x.into_bigint().is_odd()
}

/// CT_ABS of RFC 9496, section 2.1.
fn abs(x: FieldElement) -> FieldElement {
    if is_negative(&x) {
        -x
    } else {
        x
    }
}

/// SQRT_RATIO_M1 of RFC 9496, section 4.2.
fn sqrt_ratio_m1(u: &FieldElement, v: &FieldElement) -> (bool, FieldElement) {
    let v3 = v.square() * v;
    let v7 = v3.square() * v;
    let r = (v3 * u) * (v7 * u).pow(P_MINUS_5_DIV_8);
    let check = r.square() * v;
    let correct_sign = check == *u;
    let flipped_sign = check == -*u;
    let flipped_sign_i = check == -*u * SQRT_M1;
    let r = if flipped_sign || flipped_sign_i {
        r * SQRT_M1
    } else {
        r
    };
    (correct_sign || flipped_sign, abs(r))
}

/// An element of the group, represented by a point on the curve -x^2 + y^2 = 1 + d x^2 y^2 in
/// extended coordinates (x = X / Z, y = Y / Z and x y = T / Z). Each element has four
/// representatives, which differ by the points of [torsion_points](Point::torsion_points).
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        Self {
            x,
            y,
            z: FieldElement::one(),
            t: x * y,
        }
    }

    pub fn identity() -> Self {
        Self::from_affine(FieldElement::zero(), FieldElement::one())
    }

    /// The base point of Ed25519, which has y = 4/5 and an even x.
    pub fn generator() -> Self {
        Self::from_affine(
            MontFp!(
                "15112221349535400772501151409588531511454012693041857206046113283949847762202"
            ),
            MontFp!(
                "46316835694926478169428394003475163141307993866256225615783033603165251855960"
            ),
        )
    }

    /// The four points of order dividing 4, which all represent the identity.
    pub fn torsion_points() -> [Self; 4] {
        let (zero, one) = (FieldElement::zero(), FieldElement::one());
        [(zero, one), (zero, -one), (SQRT_M1, zero), (-SQRT_M1, zero)]
            .map(|(x, y)| Self::from_affine(x, y))
    }

    /// Decode, section 4.3.1.
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        let s = field_from_bytes(bytes)?;
        if is_negative(&s) {
            return None;
        }
        let one = FieldElement::one();
        let ss = s.square();
        let u1 = one - ss;
        let u2 = one + ss;
        let u2_sqr = u2.square();
        let v = -(D * u1.square()) - u2_sqr;
        let (was_square, invsqrt) = sqrt_ratio_m1(&one, &(v * u2_sqr));
        let den_x = invsqrt * u2;
        let den_y = invsqrt * den_x * v;
        let x = abs(s.double() * den_x);
        let y = u1 * den_y;
        let t = x * y;
        if !was_square || is_negative(&t) || y.is_zero() {
            return None;
        }
        Some(Self { x, y, z: one, t })
    }

    /// Encode, section 4.3.2.
    pub fn encode(&self) -> [u8; 32] {
        let u1 = (self.z + self.y) * (self.z - self.y);
        let u2 = self.x * self.y;
        let (_, invsqrt) = sqrt_ratio_m1(&FieldElement::one(), &(u1 * u2.square()));
        let den1 = invsqrt * u1;
        let den2 = invsqrt * u2;
        let z_inv = den1 * den2 * self.t;
        let (x, y, den_inv) = if is_negative(&(self.t * z_inv)) {
            (self.y * SQRT_M1, self.x * SQRT_M1, den1 * INVSQRT_A_MINUS_D)
        } else {
            (self.x, self.y, den2)
        };
        let y = if is_negative(&(x * z_inv)) { -y } else { y };
        field_to_bytes(&abs(den_inv * (self.z - y)))
    }

    /// The function MAP of the element derivation, section 4.3.4.
    fn map(t: &FieldElement) -> Self {
        let one = FieldElement::one();
        let r = SQRT_M1 * t.square();
        let u = (r + one) * ONE_MINUS_D_SQ;
        let v = (-one - r * D) * (r + D);
        let (was_square, s) = sqrt_ratio_m1(&u, &v);
        let (s, c) = if was_square {
            (s, -one)
        } else {
            (-abs(s * t), r)
        };
        let n = c * (r - one) * D_MINUS_ONE_SQ - v;
        let w0 = s.double() * v;
        let w1 = n * SQRT_AD_MINUS_ONE;
        let w2 = one - s.square();
        let w3 = one + s.square();
        Self {
            x: w0 * w3,
            y: w2 * w1,
            z: w1 * w3,
            t: w0 * w2,
        }
    }

    /// The element derivation, section 4.3.4. The top bit of each half is ignored, and a half that
    /// is not below p is reduced.
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        let half = |half: &[u8]| {
            let mut half: [u8; 32] = half.try_into().unwrap();
            half[31] &= 0x7f;
            Self::map(&FieldElement::from_le_bytes_mod_order(&half))
        };
        half(&bytes[..32]) + half(&bytes[32..])
    }

    /// Whether the two points on the curve are equal, and not only the elements they represent.
    pub fn is_same_representative(&self, other: &Self) -> bool {
        self.x * other.z == other.x * self.z && self.y * other.z == other.y * self.z
    }
}

/// Equals, section 4.3.3.
impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.x * other.y == self.y * other.x || self.y * other.y == self.x * other.x
    }
}

/// The complete addition formulas for extended coordinates (Hisil et al., 2008, section 3.1).
impl Add for Point {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let a = self.x * other.x;
        let b = self.y * other.y;
        let c = D * self.t * other.t;
        let d = self.z * other.z;
        let e = (self.x + self.y) * (other.x + other.y) - a - b;
        let f = d - c;
        let g = d + c;
        let h = b + a;
        Self {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }
}

impl Neg for Point {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: -self.x,
            t: -self.t,
            ..self
        }
    }
}

impl Sub for Point {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + -other
    }
}

/// Double-and-add.
impl Mul<Scalar> for Point {
    type Output = Self;

    fn mul(self, scalar: Scalar) -> Self {
        scalar
            .into_bigint()
            .to_bits_be()
            .into_iter()
            .skip_while(|bit| !bit)
            .fold(Self::identity(), |acc, bit| {
                let doubled = acc + acc;
                if bit {
                    doubled + self
                } else {
                    doubled
                }
            })
    }
}

/// The little-endian integer of any length, reduced modulo the group order.
pub fn reduce_scalar(bytes: &[u8]) -> Scalar {
    Scalar::from_le_bytes_mod_order(bytes)
}

pub fn encode_scalar(scalar: &Scalar) -> [u8; 32] {
    scalar.into_bigint().to_bytes_le().try_into().unwrap()
}

/// The scalar with the given little-endian encoding, or `None` if it is not below the group order.
pub fn decode_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let scalar = reduce_scalar(bytes);
    (encode_scalar(&scalar) == *bytes).then_some(scalar)
}

/// The little-endian integer plus delta, modulo 2^256.
pub fn add_small(bytes: &[u8; 32], delta: i64) -> [u8; 32] {
    let mut carry = delta;
    bytes.map(|byte| {
        let digit = i64::from(byte) + carry;
        carry = digit.div_euclid(256);
        digit.rem_euclid(256) as u8
    })
}

pub fn concat(low: &[u8; 32], high: &[u8; 32]) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(low);
    bytes[32..].copy_from_slice(high);
    bytes
}

/// The encoding of p - s for the encoding of a field element s (or 0 for s = 0).
pub fn negate_field_element(bytes: &[u8; 32]) -> Option<[u8; 32]> {
    field_from_bytes(bytes).map(|s| field_to_bytes(&-s))
}

/// hash_to_ristretto255 of RFC 9380, appendix B, with expand_message_xmd (section 5.3.1) for
/// SHA-512 and 64 bytes. A domain separation tag longer than 255 bytes is hashed (section 5.3.3).
pub fn hash_to_point(msg: &[u8], dst: &[u8]) -> Point {
    let mut dst = dst.to_vec();
    if dst.len() > 255 {
        dst = Sha512::digest([b"H2C-OVERSIZE-DST-".as_slice(), &dst].concat()).to_vec();
    }
    dst.push(dst.len() as u8);
    // Z_pad is a block of zeros, l_i_b_str encodes the output length of 64 bytes, and one SHA-512
    // output is enough, so the result is b_1.
    let b_0 = Sha512::digest([&[0; 128], msg, &[0, 64, 0], &dst].concat());
    let b_1 = Sha512::digest([b_0.as_slice(), &[1], &dst].concat());
    Point::from_uniform_bytes(&b_1.into())
}
