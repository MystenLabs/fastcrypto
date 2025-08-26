// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the Secp256k1 (aka K-256) curve.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::multiplier::ToLittleEndianBytes;
use crate::groups::{
    Doubling, GroupElement, HashToGroupElement, MultiScalarMul, Scalar as ScalarTrait,
};
use crate::serde_helpers::ToFromByteArray;
use crate::serialize_deserialize_with_to_from_byte_array;
use crate::traits::AllowedRng;
use ark_ec::{AffineRepr, CurveGroup, Group, ScalarMul, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derive_more::{Add, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use k256::elliptic_curve::bigint::{ArrayDecoding, ArrayEncoding};
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Group as GroupTrait;
use k256::Secp256k1;
use num_bigint::BigUint;
use serde::{de, Deserialize};
use std::ops::{Div, Mul};

/// Size of a serialized scalar in bytes.
pub const SCALAR_SIZE_IN_BYTES: usize = 32;

/// Size of a serialized point in bytes. This uses compressed serialization.
pub const POINT_SIZE_IN_BYTES: usize = 33;

/// A point on the Secp256k1 curve in projective coordinates.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct ProjectivePoint(pub(crate) Projective);

impl ProjectivePoint {
    /// Returns the x-coordinate of this point as a big-endian byte array.
    /// This is the encoding used in BIP-0340.
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
            .expect("Is always 32 bytes"))
    }

    /// Returns true iff the y-coordinate of this point is even.
    /// Returns an `InvalidInput` error if this is the identity point.
    pub fn has_even_y(&self) -> FastCryptoResult<bool> {
        if self.0.is_zero() {
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
    fn from_byte_array(bytes: &[u8; POINT_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
        Ok(ProjectivePoint(
            Projective::deserialize_compressed(bytes.as_slice())
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
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
impl From<&k256::ProjectivePoint> for ProjectivePoint {
    fn from(from: &k256::ProjectivePoint) -> Self {
        if from.is_identity().into() {
            return ProjectivePoint(Projective::zero());
        }

        let encoded_point = from.to_encoded_point(false);
        let x = convert_fq(encoded_point.x().expect("Uncompressed and not identity"));
        let y = convert_fq(encoded_point.y().expect("Uncompressed and not identity"));

        ProjectivePoint(Projective::from(Affine::new(x, y)))
    }
}

/// Convert a representation of a field element in the k256 crate to a field element [Fq] in the arkworks library.
fn convert_fq(fq: &k256::FieldBytes) -> Fq {
    // Invert endianness to match arkworks representation
    Fq::deserialize_uncompressed(fq.into_uint_le().to_be_byte_array().as_slice()).unwrap()
}

impl HashToGroupElement for ProjectivePoint {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        // This uses the hash-to-curve construction from https://datatracker.ietf.org/doc/rfc9380/
        // and the secp256k1_XMD:SHA-256_SSWU_RO_ suite defined in section 8.7.

        // The call to `hash_from_bytes` will panic if the expected output is too big (always two field elements in this case)
        // or if the output of the hash function (sha256) is too big. So since these are fixed, we can safely unwrap.
        ProjectivePoint::from(
            &Secp256k1::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(
                &[msg],
                b"secp256k1_XMD:SHA-256_SSWU_RO_",
            )
            .unwrap(),
        )
    }
}

/// A field element in the prime field of the same order as the curve.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct Scalar(pub(crate) Fr);

impl Scalar {
    /// Create a scalar from a big-endian byte representation, reducing it modulo the group order if necessary.
    pub fn from_bytes_mod_order(bytes: &[u8; SCALAR_SIZE_IN_BYTES]) -> Self {
        Scalar(Fr::from_be_bytes_mod_order(bytes.as_slice()))
    }

    pub fn as_big_int(&self) -> BigInt<4> {
        self.0.into_bigint()
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
    fn from_byte_array(bytes: &[u8; SCALAR_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
        // Align serialization with the k256 crate which follows the Bitcoin implementation
        let x = BigUint::from_bytes_be(bytes);
        match Fr::try_from(x) {
            Ok(x) => Ok(Scalar(x)),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }

    fn to_byte_array(&self) -> [u8; SCALAR_SIZE_IN_BYTES] {
        self.0.into_bigint().to_bytes_be().try_into().unwrap()
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);

pub mod schnorr {
    use crate::error::{FastCryptoError, FastCryptoResult};
    use crate::groups::secp256k1::schnorr::Tag::{Aux, Challenge, Nonce};
    use crate::groups::secp256k1::{ProjectivePoint, Scalar};
    use crate::groups::GroupElement;
    use crate::hash;
    use crate::hash::HashFunction;
    use crate::serde_helpers::ToFromByteArray;
    use ark_ec::CurveGroup;
    use ark_ff::{BigInteger, PrimeField};
    use ark_secp256k1::{Affine, Fq, Projective};
    use num_bigint::BigUint;

    pub struct SchnorrSignature(ProjectivePoint, Scalar);

    impl ToFromByteArray<64> for SchnorrSignature {
        fn from_byte_array(bytes: &[u8; 64]) -> Result<Self, FastCryptoError> {
            let r_bytes: [u8; 32] = bytes[0..32].try_into().unwrap();
            let s_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
            let r = lift_x(&r_bytes)?;
            let s = Scalar::from_byte_array(&s_bytes)?;
            Ok(SchnorrSignature(r, s))
        }

        fn to_byte_array(&self) -> [u8; 64] {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&self.0.x_as_be_bytes().expect("Not infinity"));
            bytes[32..].copy_from_slice(&self.1.to_byte_array());
            bytes
        }
    }

    /// A Schnorr public key as defined in BIP-340. The point cannot be the point at infinity.
    pub struct SchnorrPublicKey(ProjectivePoint);

    impl TryFrom<&ProjectivePoint> for SchnorrPublicKey {
        type Error = FastCryptoError;

        fn try_from(value: &ProjectivePoint) -> Result<Self, Self::Error> {
            if value.is_zero() {
                return Err(FastCryptoError::InvalidInput);
            }
            Ok(SchnorrPublicKey(*value))
        }
    }

    impl From<&SchnorrPrivateKey> for SchnorrPublicKey {
        fn from(sk: &SchnorrPrivateKey) -> Self {
            SchnorrPublicKey(ProjectivePoint::generator() * sk.0)
        }
    }

    impl ToFromByteArray<32> for SchnorrPublicKey {
        fn from_byte_array(bytes: &[u8; 32]) -> Result<Self, FastCryptoError> {
            Ok(SchnorrPublicKey(lift_x(bytes)?))
        }

        fn to_byte_array(&self) -> [u8; 32] {
            self.0.x_as_be_bytes().expect("Cannot be infinity")
        }
    }

    pub struct SchnorrPrivateKey(Scalar);

    impl ToFromByteArray<32> for SchnorrPrivateKey {
        fn from_byte_array(bytes: &[u8; 32]) -> Result<Self, FastCryptoError> {
            Ok(SchnorrPrivateKey(Scalar::from_byte_array(bytes)?))
        }

        fn to_byte_array(&self) -> [u8; 32] {
            self.0.to_byte_array()
        }
    }

    enum Tag {
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
        hasher.update(&tag_hash);
        hasher.update(&tag_hash);
        data.into_iter().for_each(|d| hasher.update(d));
        hasher.finalize().into()
    }

    fn hash_to_scalar<'a>(tag: Tag, data: impl IntoIterator<Item = &'a [u8]>) -> Scalar {
        Scalar::from_bytes_mod_order(&hash(tag, data))
    }

    /// Lift an x-coordinate to a point on the curve with an even y-coordinate.
    /// Returns an error if x is not the x-coordinate of a point on the curve.
    fn lift_x(x: &[u8; 32]) -> FastCryptoResult<ProjectivePoint> {
        let x = BigUint::from_bytes_be(x);
        match Fq::try_from(x) {
            Ok(x) => match Affine::get_ys_from_x_unchecked(x.clone()) {
                Some((y1, y2)) => {
                    // y2 = n - y1 so one of them must be even
                    let even_y = if y1.clone().into_bigint().is_even() {
                        y1
                    } else {
                        y2
                    };
                    Ok(ProjectivePoint(Projective::from(Affine::new(x, even_y))))
                }
                None => Err(FastCryptoError::InvalidInput),
            },
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }

    fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut res = [0u8; 32];
        for i in 0..32 {
            res[i] = a[i] ^ b[i];
        }
        res
    }

    fn sign(sk: &SchnorrPrivateKey, msg: &[u8], aad: &[u8]) -> FastCryptoResult<SchnorrSignature> {
        if sk.0.as_big_int().is_zero() {
            return Err(FastCryptoError::InvalidInput);
        }

        let p = ProjectivePoint::generator() * sk.0;
        let d = if p.has_even_y().expect("sk is not zero") {
            sk.0
        } else {
            -sk.0
        };

        let t = xor(&d.to_byte_array(), &hash(Aux, [aad]));
        let k_prime = hash_to_scalar(Nonce, [&t, &p.x_as_be_bytes()?, msg]);
        if k_prime.as_big_int().is_zero() {
            return Err(FastCryptoError::InvalidInput);
        }

        let r = ProjectivePoint::generator() * k_prime;
        let k = if r.has_even_y().expect("k_prime is not zero") {
            k_prime
        } else {
            -k_prime
        };
        let e = hash_to_scalar(Challenge, [&r.x_as_be_bytes()?, &p.x_as_be_bytes()?, msg]);
        let s = k + e * d;
        Ok(SchnorrSignature(r, s))
    }

    fn verify(pk: &SchnorrPublicKey, msg: &[u8], sig: &SchnorrSignature) -> FastCryptoResult<()> {
        let SchnorrSignature(r, s) = sig;
        if s.as_big_int().is_zero() {
            return Err(FastCryptoError::InvalidSignature);
        }
        if !r.has_even_y()? {
            return Err(FastCryptoError::InvalidSignature);
        }
        let e = hash_to_scalar(
            Challenge,
            [&r.x_as_be_bytes()?, &pk.0.x_as_be_bytes()?, msg],
        );
        let s_g = ProjectivePoint::generator() * *s;
        if s_g == *r + (pk.0 * e) {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidSignature)
        }
    }

    #[test]
    fn test_generator() {
        let x_bytes: [u8; 32] =
            hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap()
                .try_into()
                .unwrap();

        // Test that the generator is aligned with the specs.
        assert_eq!(
            x_bytes,
            ProjectivePoint::generator().x_as_be_bytes().unwrap()
        );
        assert!(ProjectivePoint::generator().has_even_y().unwrap());

        assert_eq!(lift_x(&x_bytes).unwrap(), ProjectivePoint::generator());
    }

    #[test]
    fn reference() {
        let sk = k256::schnorr::SigningKey::from_bytes(
            &hex::decode("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")
                .unwrap(),
        )
        .unwrap();
        let pk = k256::schnorr::VerifyingKey::from_bytes(
            &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                .unwrap(),
        )
        .unwrap();

        let aux_rand =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
            .unwrap()
            .try_into()
            .unwrap();
        let signature = sk.try_sign_prehashed(&msg, &aux_rand).unwrap();
        assert!(pk.verify_prehashed(&msg, &signature).is_ok());

        let expected_signature = hex::decode("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A").unwrap();
        assert_eq!(signature.as_bytes().to_vec(), expected_signature);
    }

    #[test]
    fn test_schnorr() {
        // Test vector 1 from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        let sk = SchnorrPrivateKey(
            Scalar::from_byte_array(
                &hex::decode("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        );
        let pk = SchnorrPublicKey(
            lift_x(
                &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        );
        let aux_rand =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
            .unwrap();
        let expected_signature = hex::decode("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A").unwrap();

        let signature = sign(&sk, &msg, &aux_rand).unwrap();
        let signature_bytes = signature.to_byte_array();
        assert_eq!(expected_signature, signature_bytes);

        assert!(verify(&pk, &msg, &signature).is_ok());
    }
}
