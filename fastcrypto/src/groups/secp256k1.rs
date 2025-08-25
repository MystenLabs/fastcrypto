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
use ark_ec::{Group, ScalarMul, VariableBaseMSM};
use ark_ff::{BigInt, Field, One, PrimeField, UniformRand, Zero};
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

    pub fn as_big_uint(&self) -> BigInt<4> {
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
        Ok(Scalar(
            Fr::deserialize_uncompressed(bytes.as_slice())
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    fn to_byte_array(&self) -> [u8; SCALAR_SIZE_IN_BYTES] {
        let mut bytes = [0u8; SCALAR_SIZE_IN_BYTES];
        self.0
            .serialize_uncompressed(&mut bytes[..])
            .expect("Byte array not large enough");
        bytes
    }
}

impl ToLittleEndianBytes for Scalar {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_byte_array().to_vec()
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);

mod schnorr {
    use crate::error::{FastCryptoError, FastCryptoResult};
    use crate::groups::secp256k1::{ProjectivePoint, Scalar};
    use crate::groups::GroupElement;
    use crate::hash::{HashFunction, Sha256};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_secp256k1::{Affine, Fq, Fr, Projective};
    use digest::Mac;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::signature::Verifier;
    use num_bigint::BigUint;

    fn hash(name: &str, data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let tag_hash = sha2::Sha256::digest(name.as_bytes());
        hasher.update(&tag_hash);
        hasher.update(&tag_hash);
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hash_to_scalar(name: &str, data: &[u8]) -> Scalar {
        Scalar::from_bytes_mod_order(&hash(name, data))
    }

    fn int(be_bytes: &[u8; 32]) -> Option<Scalar> {
        let x = BigUint::from_bytes_be(be_bytes);
        match Fr::try_from(x) {
            Ok(x) => Some(Scalar(x)),
            Err(_) => None,
        }
    }

    fn x(point: &ProjectivePoint) -> [u8; 32] {
        let affine = point.0.into_affine();
        affine
            .x()
            .unwrap()
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .unwrap()
    }

    fn y(point: &ProjectivePoint) -> [u8; 32] {
        let affine = point.0.into_affine();
        affine
            .y()
            .unwrap()
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .unwrap()
    }

    fn bytes_point(point: &ProjectivePoint) -> [u8; 32] {
        x(point)
    }

    fn bytes_scalar(scalar: &Scalar) -> [u8; 32] {
        scalar.0.into_bigint().to_bytes_be().try_into().unwrap()
    }

    fn has_even_y(point: &ProjectivePoint) -> bool {
        let affine = point.0.into_affine();
        affine.y().unwrap().into_bigint().is_even()
    }

    fn lift_x(x: &[u8; 32]) -> Option<ProjectivePoint> {
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
                    Some(ProjectivePoint(Projective::from(Affine::new(x, even_y))))
                }
                None => None,
            },
            Err(_) => None,
        }
    }

    fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut res = [0u8; 32];
        for i in 0..32 {
            res[i] = a[i] ^ b[i];
        }
        res
    }

    fn sign(sk: &Scalar, msg: &[u8], aad: &[u8]) -> Option<(ProjectivePoint, Scalar)> {
        let p = ProjectivePoint::generator() * *sk;
        let d = if has_even_y(&p) { *sk } else { -*sk };

        let t = xor(&bytes_scalar(&d), &hash("BIP0340/aux", aad));
        let k_prime = hash_to_scalar("BIP0340/nonce", &[&t, &bytes_point(&p), msg].concat());
        if k_prime.as_big_uint().is_zero() {
            return None;
        }

        let r = ProjectivePoint::generator() * k_prime;
        let k = if has_even_y(&r) { k_prime } else { -k_prime };
        let e = hash_to_scalar(
            "BIP0340/challenge",
            &[&bytes_point(&r), &bytes_point(&p), msg].concat(),
        );
        let s = k + e * d;
        Some((r, s))
    }

    fn signature_bytes((r, s): &(ProjectivePoint, Scalar)) -> [u8; 64] {
        [bytes_point(r), bytes_scalar(s)]
            .concat()
            .try_into()
            .unwrap()
    }

    fn verify(
        pk: &ProjectivePoint,
        msg: &[u8],
        signature: &(ProjectivePoint, Scalar),
    ) -> FastCryptoResult<()> {
        let (r, s) = signature;
        if s.as_big_uint().is_zero() || s.as_big_uint() >= Fr::MODULUS.into() {
            return Err(FastCryptoError::InvalidSignature);
        }
        if !has_even_y(r) {
            return Err(FastCryptoError::InvalidSignature);
        }
        let e = hash_to_scalar(
            "BIP0340/challenge",
            &[&bytes_point(r), &bytes_point(pk), msg].concat(),
        );
        let s_g = ProjectivePoint::generator() * *s;
        if s_g == *r + (*pk * e) {
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
        let y_bytes: [u8; 32] =
            hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap()
                .try_into()
                .unwrap();

        // Test that the generator is aligned with the specs.
        assert_eq!(x_bytes, x(&ProjectivePoint::generator()));
        assert_eq!(y_bytes, y(&ProjectivePoint::generator()));
        assert!(has_even_y(&ProjectivePoint::generator()));

        assert_eq!(lift_x(&x_bytes), Some(ProjectivePoint::generator()));
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
        let sk = int(&hex::decode(
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        )
        .unwrap()
        .try_into()
        .unwrap())
        .unwrap();
        let pk = lift_x(
            &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let aux_rand =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let msg = hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
            .unwrap();
        let expected_signature = hex::decode("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A").unwrap();

        let signature = sign(&sk, &msg, &aux_rand).unwrap();
        let signature_bytes = signature_bytes(&signature);
        assert_eq!(expected_signature, signature_bytes);

        assert!(verify(&pk, &msg, &signature).is_ok());
    }
}
