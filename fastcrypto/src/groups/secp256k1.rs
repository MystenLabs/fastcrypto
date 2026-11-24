// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the Secp256k1 (aka K-256) curve, see [SEC 2, sec. 2.4.1](https://www.secg.org/sec2-v2.pdf).

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::{
    Doubling, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar as ScalarTrait,
};
use crate::serde_helpers::ToFromByteArray;
use crate::serialize_deserialize_with_to_from_byte_array;
use crate::traits::AllowedRng;
use ark_ec::{AffineRepr, CurveGroup, Group, ScalarMul, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derive_more::{Add, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use std::ops::{Div, Mul};

/// Size of a serialized scalar in bytes.
pub const SCALAR_SIZE_IN_BYTES: usize = 32;

/// Size of a serialized point in bytes. This uses compressed serialization.
pub const POINT_SIZE_IN_BYTES: usize = 33;

/// Size of a point in the SEC1 compressed encoding.
pub const SEC1_POINT_SIZE_IN_BYTES: usize = 33;

/// SEC1 tag for a compressed point with an even y-coordinate.
const SEC1_TAG_EVEN: u8 = 0x02;

/// SEC1 tag for a compressed point with an odd y-coordinate.
const SEC1_TAG_ODD: u8 = 0x03;

lazy_static! {
    pub static ref FQ_MODULUS: BigUint =
        BigUint::from_bytes_be(Fq::MODULUS.to_bytes_be().as_slice());
    pub static ref FR_MODULUS: BigUint =
        BigUint::from_bytes_be(Fr::MODULUS.to_bytes_be().as_slice());
}

/// A point on the Secp256k1 curve in projective coordinates.
///
/// Encoded as 33 bytes in the compressed format of
/// [arkworks](https://docs.rs/ark-ec/0.4.2/ark_ec/models/short_weierstrass/enum.SWFlags.html),
/// which is _not_ the SEC1 encoding. Bytes `0..32` hold the x-coordinate in little-endian order,
/// and byte `32` is a flag byte which is
/// * `0x00` if y <= (p - 1) / 2,
/// * `0x80` if y > (p - 1) / 2,
/// * `0x40` for the point at infinity, in which case bytes `0..32` are all zero.
///
/// Decoding only accepts this canonical encoding, so every point has exactly one encoding.
/// Use [ProjectivePoint::to_sec1_bytes] and [ProjectivePoint::from_sec1_bytes] for the SEC1
/// compressed encoding used by e.g. libsecp256k1 and Bitcoin, and the types in [schnorr] for the
/// encodings of [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct ProjectivePoint(pub(crate) Projective);

impl ProjectivePoint {
    /// Returns the x-coordinate of this point as a big-endian byte array.
    /// Returns an `InvalidInput` error if this is the identity point.
    pub fn x_as_be_bytes(&self) -> FastCryptoResult<[u8; 32]> {
        if self.0.is_zero() {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(self
            .0
            .into_affine()
            .x()
            .expect("Not zero")
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("Always 32 bytes"))
    }

    /// Lift an x-coordinate to a point on the curve with an even y-coordinate.
    /// Returns an error if x is not the x-coordinate of a point on the curve.
    pub fn with_even_y_from_x_be_bytes(x: &[u8; 32]) -> FastCryptoResult<Self> {
        Self::from_x_be_bytes_and_y_parity(x, false)
    }

    /// Lift an x-coordinate to the point on the curve whose y-coordinate is odd iff `odd_y` is
    /// true. Returns an error if x is not smaller than the field modulus or if it is not the
    /// x-coordinate of a point on the curve.
    fn from_x_be_bytes_and_y_parity(x: &[u8; 32], odd_y: bool) -> FastCryptoResult<Self> {
        let x = BigUint::from_bytes_be(x);
        if x >= *FQ_MODULUS {
            return Err(FastCryptoError::InvalidInput);
        }
        let x = Fq::from(x);
        let (y1, y2) = Affine::get_ys_from_x_unchecked(x).ok_or(FastCryptoError::InvalidInput)?;
        // y2 = p - y1 and p is odd, so exactly one of them is even.
        let y = if y1.into_bigint().is_odd() == odd_y {
            y1
        } else {
            y2
        };
        Ok(ProjectivePoint(Affine::new(x, y).into()))
    }

    /// Encode this point in the SEC1 compressed format,
    /// [SEC1, sec. 2.3.3](https://www.secg.org/sec1-v2.pdf): a tag byte, `0x02` if the
    /// y-coordinate is even and `0x03` if it is odd, followed by the x-coordinate as 32
    /// big-endian bytes. This is the format used by e.g. libsecp256k1 and Bitcoin for compressed
    /// public keys.
    ///
    /// Returns an `InvalidInput` error for the point at infinity, which SEC1 encodes as a single
    /// zero byte.
    pub fn to_sec1_bytes(&self) -> FastCryptoResult<[u8; SEC1_POINT_SIZE_IN_BYTES]> {
        let mut bytes = [0u8; SEC1_POINT_SIZE_IN_BYTES];
        bytes[0] = if self.has_even_y()? {
            SEC1_TAG_EVEN
        } else {
            SEC1_TAG_ODD
        };
        bytes[1..].copy_from_slice(&self.x_as_be_bytes()?);
        Ok(bytes)
    }

    /// Decode a point from the SEC1 compressed format, see [Self::to_sec1_bytes].
    ///
    /// Returns an `InvalidInput` error unless the tag is `0x02` or `0x03`, the x-coordinate is
    /// smaller than the field modulus and it is the x-coordinate of a point on the curve. So the
    /// uncompressed (`0x04`) and hybrid (`0x06`/`0x07`) formats and the point at infinity are
    /// rejected, and every point has exactly one accepted encoding.
    pub fn from_sec1_bytes(bytes: &[u8; SEC1_POINT_SIZE_IN_BYTES]) -> FastCryptoResult<Self> {
        let odd_y = match bytes[0] {
            SEC1_TAG_EVEN => false,
            SEC1_TAG_ODD => true,
            _ => return Err(FastCryptoError::InvalidInput),
        };
        let x = bytes[1..].try_into().expect("Always 32 bytes");
        Self::from_x_be_bytes_and_y_parity(x, odd_y)
    }

    /// Returns true iff the y-coordinate of this point is even.
    /// Returns an `InvalidInput` error if this is the identity point.
    pub fn has_even_y(&self) -> FastCryptoResult<bool> {
        if self.is_zero() {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(self
            .0
            .into_affine()
            .y()
            .expect("Not infinity")
            .into_bigint()
            .is_even())
    }

    /// Returns true iff this is the identity point aka the point at infinity.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl GroupElement for ProjectivePoint {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self(Projective::zero())
    }

    fn generator() -> Self {
        Self(Projective::generator())
    }
}

impl Doubling for ProjectivePoint {
    fn double(self) -> Self {
        ProjectivePoint::from(self.0.double())
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, rhs: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self.0 * rhs.0)
    }
}

impl Div<Scalar> for ProjectivePoint {
    type Output = Result<ProjectivePoint, FastCryptoError>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Scalar) -> Result<ProjectivePoint, FastCryptoError> {
        Ok(self * rhs.inverse()?)
    }
}

impl ToFromByteArray<POINT_SIZE_IN_BYTES> for ProjectivePoint {
    /// Decode a point. Returns an `InvalidInput` error unless `bytes` is the canonical encoding
    /// of a point on the curve.
    fn from_byte_array(bytes: &[u8; POINT_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
        // Arkworks checks that x is smaller than the field modulus and that the point is on the
        // curve, but it ignores the six lowest bits of the flag byte and the x-coordinate if the
        // infinity flag is set. Re-encoding and comparing rejects these non-canonical encodings.
        let point = Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)?;
        let mut canonical = [0u8; POINT_SIZE_IN_BYTES];
        point
            .serialize_compressed(&mut canonical[..])
            .expect("Is always 33 bytes");
        if canonical != *bytes {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(ProjectivePoint(point.into()))
    }

    fn to_byte_array(&self) -> [u8; POINT_SIZE_IN_BYTES] {
        let mut bytes = [0u8; POINT_SIZE_IN_BYTES];
        self.0
            .serialize_compressed(&mut bytes[..])
            .expect("Is always 33 bytes");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(ProjectivePoint);

impl MultiScalarMul for ProjectivePoint {
    fn multi_scalar_mul(
        scalars: &[Self::ScalarType],
        points: &[Self],
    ) -> Result<Self, FastCryptoError> {
        // Fail early if the lengths do not match
        if scalars.len() != points.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let scalars = scalars.iter().map(|s| s.0).collect::<Vec<_>>();
        Projective::msm(
            &Projective::batch_convert_to_mul_base(
                points.iter().map(|p| p.0).collect::<Vec<_>>().as_slice(),
            ),
            &scalars,
        )
        .map_err(|_| FastCryptoError::GeneralOpaqueError)
        .map(ProjectivePoint)
    }
}

/// A field element in the prime field of the same order as the curve.
///
/// Encoded as 32 bytes in big-endian order, like secret keys in
/// [SEC1, sec. 2.3.7](https://www.secg.org/sec1-v2.pdf) and libsecp256k1. Decoding rejects values
/// that are not smaller than the group order.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct Scalar(pub(crate) Fr);

impl Scalar {
    /// Create a scalar from a big-endian byte representation, reducing it modulo the group order if necessary.
    pub fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        Scalar(Fr::from_be_bytes_mod_order(bytes))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl GroupElement for Scalar {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Scalar(Fr::zero())
    }

    fn generator() -> Self {
        Scalar(Fr::one())
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0 * rhs.0)
    }
}

impl Div<Scalar> for Scalar {
    type Output = Result<Scalar, FastCryptoError>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Scalar) -> Result<Scalar, FastCryptoError> {
        Ok(self * rhs.inverse()?)
    }
}

impl From<u128> for Scalar {
    fn from(value: u128) -> Self {
        Scalar(Fr::from(value))
    }
}

impl ScalarTrait for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        Scalar(Fr::rand(rng))
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        Ok(Scalar(
            self.0.inverse().ok_or(FastCryptoError::InvalidInput)?,
        ))
    }
}

impl ToFromByteArray<SCALAR_SIZE_IN_BYTES> for Scalar {
    /// Decode a scalar. Returns an `InvalidInput` error if the value is not smaller than the
    /// group order.
    fn from_byte_array(bytes: &[u8; SCALAR_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
        // Align serialization with the k256 crate which follows the Bitcoin implementation
        let value = BigUint::from_bytes_be(bytes);
        if value >= *FR_MODULUS {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Scalar(Fr::from(value)))
    }

    fn to_byte_array(&self) -> [u8; SCALAR_SIZE_IN_BYTES] {
        self.0
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("Always 32 bytes")
    }
}

impl FiatShamirChallenge for Scalar {
    fn fiat_shamir_reduction_to_group_element(uniform_buffer: &[u8]) -> Self {
        // Ensure that we have enough bytes to avoid bias in the modular reduction.
        assert!(uniform_buffer.len() >= 48);
        Scalar::from(Fr::from_be_bytes_mod_order(uniform_buffer))
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);

/// A Schnorr signature scheme as defined in BIP-0340 (<https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>).
pub mod schnorr {
    use crate::error::{FastCryptoError, FastCryptoResult};
    use crate::groups::secp256k1::schnorr::Tag::{Aux, Challenge, Nonce};
    use crate::groups::secp256k1::{ProjectivePoint, Scalar};
    use crate::groups::{GroupElement, MultiScalarMul};
    use crate::hash::HashFunction;
    use crate::serde_helpers::ToFromByteArray;
    use crate::{hash, serialize_deserialize_with_to_from_byte_array};

    pub const SIGNATURE_SIZE_IN_BYTES: usize = 64;
    pub const PUBLIC_KEY_SIZE_IN_BYTES: usize = 32;
    pub const PRIVATE_KEY_SIZE_IN_BYTES: usize = 32;

    /// A Schnorr signature as defined in BIP-340. The r point must have an even y-coordinate and the s scalar cannot be zero.
    ///
    /// Encoded as 64 bytes as in BIP-340: the x-coordinate of r as 32 big-endian bytes followed by
    /// s as 32 big-endian bytes. Decoding rejects encodings where r is not the x-coordinate of a
    /// point on the curve or where s is zero or not smaller than the group order.
    pub struct SchnorrSignature {
        pub r: [u8; 32],
        pub s: Scalar,
    }

    impl TryFrom<(ProjectivePoint, Scalar)> for SchnorrSignature {
        type Error = FastCryptoError;

        fn try_from((r, s): (ProjectivePoint, Scalar)) -> FastCryptoResult<Self> {
            Ok(Self {
                r: r.x_as_be_bytes()?,
                s,
            })
        }
    }

    impl ToFromByteArray<SIGNATURE_SIZE_IN_BYTES> for SchnorrSignature {
        fn from_byte_array(bytes: &[u8; SIGNATURE_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
            let r: [u8; 32] = bytes[0..32].try_into().unwrap();
            let s_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();

            // Fails if not on curve
            let _ = ProjectivePoint::with_even_y_from_x_be_bytes(&r)?;

            let s = Scalar::from_byte_array(&s_bytes)?;
            if s.is_zero() {
                return Err(FastCryptoError::InvalidInput);
            }

            Ok(Self { r, s })
        }

        fn to_byte_array(&self) -> [u8; SIGNATURE_SIZE_IN_BYTES] {
            let mut bytes = [0u8; SIGNATURE_SIZE_IN_BYTES];
            bytes[..32].copy_from_slice(&self.r);
            bytes[32..].copy_from_slice(&self.s.to_byte_array());
            bytes
        }
    }

    serialize_deserialize_with_to_from_byte_array!(SchnorrSignature);

    /// A Schnorr public key as defined in BIP-340.
    /// The point cannot be the point at infinity and the y-coordinate must be even.
    ///
    /// Encoded as the 32-byte "x-only" format of BIP-340: the x-coordinate as 32 big-endian bytes,
    /// with the y-coordinate implicitly even. This is the SEC1 compressed encoding (see
    /// [ProjectivePoint::to_sec1_bytes]) without the leading `0x02` tag. Decoding rejects
    /// x-coordinates that are not smaller than the field modulus or not on the curve.
    pub struct SchnorrPublicKey(ProjectivePoint);

    impl TryFrom<&ProjectivePoint> for SchnorrPublicKey {
        type Error = FastCryptoError;

        fn try_from(value: &ProjectivePoint) -> Result<Self, Self::Error> {
            if value.is_zero() {
                return Err(FastCryptoError::InvalidInput);
            }
            if !value.has_even_y()? {
                return Ok(SchnorrPublicKey(-value));
            }
            Ok(SchnorrPublicKey(*value))
        }
    }

    impl From<&SchnorrPrivateKey> for SchnorrPublicKey {
        fn from(sk: &SchnorrPrivateKey) -> Self {
            // y is guaranteed to be even by construction of the private key
            SchnorrPublicKey(ProjectivePoint::generator() * sk.0)
        }
    }

    impl ToFromByteArray<PUBLIC_KEY_SIZE_IN_BYTES> for SchnorrPublicKey {
        fn from_byte_array(
            bytes: &[u8; PUBLIC_KEY_SIZE_IN_BYTES],
        ) -> Result<Self, FastCryptoError> {
            Ok(SchnorrPublicKey(
                ProjectivePoint::with_even_y_from_x_be_bytes(bytes)?,
            ))
        }

        fn to_byte_array(&self) -> [u8; PUBLIC_KEY_SIZE_IN_BYTES] {
            self.0.x_as_be_bytes().expect("Cannot be infinity")
        }
    }

    serialize_deserialize_with_to_from_byte_array!(SchnorrPublicKey);

    /// A Schnorr private key. The scalar cannot be zero.
    ///
    /// Encoded as 32 big-endian bytes like [Scalar]. As in BIP-340, a secret key d is replaced
    /// by n - d if d·G has an odd y-coordinate, so decoding and then encoding a key returns the
    /// bytes of n - d in that case. Both encodings give the same public key.
    pub struct SchnorrPrivateKey(Scalar);

    impl TryFrom<Scalar> for SchnorrPrivateKey {
        type Error = FastCryptoError;

        fn try_from(mut value: Scalar) -> Result<Self, Self::Error> {
            if value.is_zero() {
                return Err(FastCryptoError::InvalidInput);
            }

            // Ensure that the corresponding public key has an even y-coordinate. Otherwise, flip the sign of the scalar.
            if !(ProjectivePoint::generator() * value).has_even_y()? {
                value = -value
            };

            Ok(SchnorrPrivateKey(value))
        }
    }

    impl ToFromByteArray<PRIVATE_KEY_SIZE_IN_BYTES> for SchnorrPrivateKey {
        fn from_byte_array(
            bytes: &[u8; PRIVATE_KEY_SIZE_IN_BYTES],
        ) -> Result<Self, FastCryptoError> {
            SchnorrPrivateKey::try_from(Scalar::from_byte_array(bytes)?)
        }

        fn to_byte_array(&self) -> [u8; PRIVATE_KEY_SIZE_IN_BYTES] {
            self.0.to_byte_array()
        }
    }

    serialize_deserialize_with_to_from_byte_array!(SchnorrPrivateKey);

    pub enum Tag {
        Aux,
        Nonce,
        Challenge,
    }

    fn get_tag(tag: Tag) -> &'static str {
        match tag {
            Aux => "BIP0340/aux",
            Nonce => "BIP0340/nonce",
            Challenge => "BIP0340/challenge",
        }
    }

    fn hash<'a>(tag: Tag, data: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
        let name = get_tag(tag);
        let mut hasher = hash::Sha256::new();
        let tag_hash = hash::Sha256::digest(name.as_bytes());
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        data.into_iter().for_each(|d| hasher.update(d));
        hasher.finalize().into()
    }

    pub fn bip0340_hash_to_scalar<'a>(
        tag: Tag,
        data: impl IntoIterator<Item = &'a [u8]>,
    ) -> Scalar {
        Scalar::from_bytes_mod_order(&hash(tag, data))
    }

    fn xor<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
        let mut res = [0u8; N];
        for i in 0..N {
            res[i] = a[i] ^ b[i];
        }
        res
    }

    impl SchnorrPrivateKey {
        /// Sign a message with this private key and the given auxiliary random data.
        /// Follows the specifications from BIP-0340.
        pub fn sign(&self, msg: &[u8], aad: &[u8]) -> FastCryptoResult<SchnorrSignature> {
            let pk = SchnorrPublicKey::from(self);
            let pk_bytes = pk.to_byte_array();

            let t = xor(&self.to_byte_array(), &hash(Aux, [aad]));
            let k_prime = bip0340_hash_to_scalar(Nonce, [&t, &pk_bytes, msg]);
            if k_prime.is_zero() {
                return Err(FastCryptoError::InvalidInput);
            }

            let r = ProjectivePoint::generator() * k_prime;
            let k = if r.has_even_y().expect("r is not infinity") {
                k_prime
            } else {
                -k_prime
            };
            let r = r.x_as_be_bytes()?;

            let e = bip0340_hash_to_scalar(Challenge, [&r, &pk_bytes, msg]);
            let s = k + self.0 * e;

            let signature = SchnorrSignature { r, s };
            pk.verify(msg, &signature)?;

            Ok(signature)
        }
    }

    impl SchnorrPublicKey {
        /// Verify a signature on a message with this public key.
        pub fn verify(&self, msg: &[u8], sig: &SchnorrSignature) -> FastCryptoResult<()> {
            let SchnorrSignature { r, s } = sig;
            let e = bip0340_hash_to_scalar(Challenge, [r, &self.to_byte_array(), msg]);
            let expected = ProjectivePoint::multi_scalar_mul(
                &[*s, -e],
                &[ProjectivePoint::generator(), self.0],
            )
            .expect("Fixed size inputs");

            if expected.is_zero() || !expected.has_even_y()? || r != &expected.x_as_be_bytes()? {
                return Err(FastCryptoError::InvalidSignature);
            }
            Ok(())
        }

        pub fn as_point(&self) -> &ProjectivePoint {
            &self.0
        }
    }
}
