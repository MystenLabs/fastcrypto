// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the Secp256k1 (aka K-256) curve.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::{
    Doubling, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar as ScalarTrait,
};
use crate::hash::{HashFunction, Sha3_512};
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

lazy_static! {
    pub static ref FQ_MODULUS: BigUint =
        BigUint::from_bytes_be(Fq::MODULUS.to_bytes_be().as_slice());
    pub static ref FR_MODULUS: BigUint =
        BigUint::from_bytes_be(Fr::MODULUS.to_bytes_be().as_slice());
}

/// A point on the Secp256k1 curve in projective coordinates.
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
        let x = BigUint::from_bytes_be(x);
        if x >= *FQ_MODULUS {
            return Err(FastCryptoError::InvalidInput);
        }
        let x = Fq::from(x);
        match Affine::get_ys_from_x_unchecked(x) {
            Some((y1, y2)) => {
                // y2 = n - y1 so one of them must be even
                let even_y = if y1.into_bigint().is_even() {
                    y1.into_bigint()
                } else {
                    y2.into_bigint()
                };
                Ok(ProjectivePoint(Affine::new(x, Fq::from(even_y)).into()))
            }
            None => Err(FastCryptoError::InvalidInput),
        }
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

/// A field element in the prime field of the same order as the curve.
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
        Scalar::from(Fr::from_be_bytes_mod_order(
            &Sha3_512::digest(uniform_buffer).digest,
        ))
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);

/// A Schnorr signature scheme as defined in BIP-0340 (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
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
    pub struct SchnorrPrivateKey(Scalar);

    impl TryFrom<Scalar> for SchnorrPrivateKey {
        type Error = FastCryptoError;

        fn try_from(value: Scalar) -> Result<Self, Self::Error> {
            if value.is_zero() {
                return Err(FastCryptoError::InvalidInput);
            }

            // Ensure that the corresponding public key has an even y-coordinate. Otherwise, flip the sign of the scalar.
            let value = if (ProjectivePoint::generator() * value).has_even_y()? {
                value
            } else {
                -value
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

            self.sign_with_nonce(msg, &k_prime)
        }

        pub fn sign_with_nonce(
            &self,
            msg: &[u8],
            nonce: &Scalar,
        ) -> FastCryptoResult<SchnorrSignature> {
            let pk = SchnorrPublicKey::from(self);
            let pk_bytes = pk.to_byte_array();

            let r = ProjectivePoint::generator() * nonce;
            let nonce = if r.has_even_y().expect("r is not infinity") {
                *nonce
            } else {
                -nonce
            };
            let r = r.x_as_be_bytes()?;

            let e = bip0340_hash_to_scalar(Challenge, [&r, &pk_bytes, msg]);
            let s = nonce + self.0 * e;

            let signature = SchnorrSignature { r, s };
            pk.verify(msg, &signature)?;

            Ok(signature)
        }

        pub fn as_scalar(&self) -> &Scalar {
            &self.0
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

            if expected.is_zero()
                || !expected.has_even_y()?
                || r != &expected.x_as_be_bytes().expect("Not infinity")
            {
                return Err(FastCryptoError::InvalidSignature);
            }
            Ok(())
        }

        pub fn as_point(&self) -> &ProjectivePoint {
            &self.0
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

        assert_eq!(
            ProjectivePoint::with_even_y_from_x_be_bytes(&x_bytes).unwrap(),
            ProjectivePoint::generator()
        );
    }

    #[cfg(test)]
    mod tests {
        use crate::groups::secp256k1::schnorr::{
            SchnorrPrivateKey, SchnorrPublicKey, SchnorrSignature,
        };
        use crate::serde_helpers::ToFromByteArray;

        struct SigningTestVector {
            sk: &'static str,
            pk: &'static str,
            aux_rand: &'static str,
            msg: &'static str,
            signature: &'static str,
        }

        fn test_signing_test_vector(v: SigningTestVector) {
            let sk =
                SchnorrPrivateKey::from_byte_array(&hex::decode(v.sk).unwrap().try_into().unwrap())
                    .unwrap();
            let pk =
                SchnorrPublicKey::from_byte_array(&hex::decode(v.pk).unwrap().try_into().unwrap())
                    .unwrap();
            let aux_rand = hex::decode(v.aux_rand).unwrap();
            let msg = hex::decode(v.msg).unwrap();
            let expected_signature = hex::decode(v.signature).unwrap();
            let signature = sk.sign(&msg, &aux_rand).unwrap();
            let signature_bytes = signature.to_byte_array();
            assert_eq!(
                expected_signature, signature_bytes,
                "Signature does not match expected signature"
            );
            assert!(pk.verify(&msg, &signature).is_ok());
        }

        #[test]
        fn valid_test_vectors() {
            // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
            let test_vectors = [
                SigningTestVector {
                    sk: "0000000000000000000000000000000000000000000000000000000000000003",
                    pk: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
                    msg: "0000000000000000000000000000000000000000000000000000000000000000",
                    signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
                },
            SigningTestVector {
                    sk: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                    pk: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    aux_rand: "0000000000000000000000000000000000000000000000000000000000000001",
                    msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                    signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
                },
                SigningTestVector {
                    sk: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
                    pk: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                    aux_rand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
                    msg: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                    signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
                },
                SigningTestVector {
                    sk: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
                    pk: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
                    aux_rand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    msg: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
                },
                SigningTestVector {
                    sk: "0340034003400340034003400340034003400340034003400340034003400340",
                    pk: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
                    aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
                    msg: "",
                    signature: "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
                },
                SigningTestVector {
                    sk: "0340034003400340034003400340034003400340034003400340034003400340",
                    pk: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
                    aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
                    msg: "11",
                    signature: "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
                },
                SigningTestVector {
                    sk: "0340034003400340034003400340034003400340034003400340034003400340",
                    pk: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
                    aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
                    msg: "0102030405060708090A0B0C0D0E0F1011",
                    signature: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
                },
                SigningTestVector {
                    sk: "0340034003400340034003400340034003400340034003400340034003400340",
                    pk: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
                    aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
                    msg: "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
                    signature: "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
                },
            ];

            for v in test_vectors {
                test_signing_test_vector(v);
            }
        }

        #[test]
        fn test_invalid_pk() {
            let invalid_pk = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34";
            assert!(SchnorrPublicKey::from_byte_array(
                &hex::decode(invalid_pk).unwrap().try_into().unwrap()
            )
            .is_err());

            let other_invalid_pk =
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30";
            assert!(SchnorrPublicKey::from_byte_array(
                &hex::decode(other_invalid_pk).unwrap().try_into().unwrap()
            )
            .is_err());
        }

        #[test]
        fn test_invalid_signature() {
            let invalid_signature_1 = "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B";
            assert!(SchnorrSignature::from_byte_array(
                &hex::decode(invalid_signature_1)
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
            .is_err());

            let invalid_signature_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B";
            assert!(SchnorrSignature::from_byte_array(
                &hex::decode(invalid_signature_2)
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
            .is_err());

            let invalid_signature_3 = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
            assert!(SchnorrSignature::from_byte_array(
                &hex::decode(invalid_signature_3)
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
            .is_err());
        }

        struct VerifyTestVector {
            verifies: bool,
            pk: &'static str,
            msg: &'static str,
            signature: &'static str,
        }

        fn verify_test_vector(v: VerifyTestVector) {
            let pk =
                SchnorrPublicKey::from_byte_array(&hex::decode(v.pk).unwrap().try_into().unwrap())
                    .unwrap();
            let msg = hex::decode(v.msg).unwrap();
            let expected_signature = hex::decode(v.signature).unwrap();
            let signature =
                SchnorrSignature::from_byte_array(&expected_signature.try_into().unwrap()).unwrap();
            assert_eq!(pk.verify(&msg, &signature).is_ok(), v.verifies);
        }

        #[test]
        fn test_verify_test_vectors() {
            // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
            let test_vectors = [
                VerifyTestVector {
                    verifies: true,
                    pk: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
                    msg: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
                    signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
                },
                // has_even_y(R) is false
                VerifyTestVector {
                    verifies: false,
                    pk: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                    signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
                },
                // negated message
                VerifyTestVector {
                    verifies: false,
                    pk: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                    signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
                },
                // Negated s value
                VerifyTestVector {
                    verifies: false,
                    pk: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                    signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
                },
            ];

            for v in test_vectors {
                verify_test_vector(v);
            }
        }
    }
}
