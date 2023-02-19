// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::random_oracle::RandomOracle;
use fastcrypto::aes::{Aes256Ctr, AesKey, Cipher, InitializationVector};
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::{GroupElement, HashToGroupElement, Scalar};
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::traits::{AllowedRng, ToFromBytes};
use serde::{Deserialize, Serialize};
use typenum::consts::{U16, U32};

///
/// Simple ECIES encryption using a generic group and AES-256-counter.
///
/// - Secret key x is a scalar.
/// - Public key is xG.
/// - Encryption of message m for public key xG is: (rG, AES(key=hkdf(rxG), message));
///
/// APIs that use a random oracle must receive one as an argument. That RO must be unique and thus
/// the caller should initialize/derive it using a unique prefix.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey<G: GroupElement>(G::ScalarType);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey<G: GroupElement>(G);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encryption<G: GroupElement>(G, Vec<u8>);

/// A recovery package that allows decrypting a *specific* ECIES Encryption.
/// It also includes a NIZK proof of correctness.
// TODO: add Serialize, Deserialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPackage<G: GroupElement> {
    ephemeral_key: G,
    proof: DdhTupleNizk<G>,
}

const AES_KEY_LENGTH: usize = 32;

/// NIZKPoK for the DDH tuple [G, eG, PK=sk*G, Key=sk*eG].
/// - Prover selects a random r and sends A=rG, B=reG.
/// - Prover computes challenge c and sends z=r+c*sk.
/// - Verifier checks that zG=A+cPK and zeG=B+cKey.
/// The NIZK is (A, B, z) where c is implicitly computed using a random oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhTupleNizk<G: GroupElement>(G, G, G::ScalarType);

impl<G> PrivateKey<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: HashToGroupElement,
{
    pub fn new<R: AllowedRng>(rng: &mut R) -> Self {
        Self(G::ScalarType::rand(rng))
    }

    pub fn decrypt(&self, enc: &Encryption<G>) -> Vec<u8> {
        enc.decrypt(&self.0)
    }

    pub fn create_recovery_package<R: AllowedRng>(
        &self,
        enc: &Encryption<G>,
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> RecoveryPackage<G> {
        let ephemeral_key = enc.0 * self.0;
        let pk = G::generator() * self.0;
        let proof =
            DdhTupleNizk::<G>::create(&self.0, &enc.0, &pk, &ephemeral_key, random_oracle, rng);
        RecoveryPackage {
            ephemeral_key,
            proof,
        }
    }
}

impl<G> PublicKey<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: HashToGroupElement,
{
    pub fn from_private_key(sk: &PrivateKey<G>) -> Self {
        Self(G::generator() * sk.0)
    }

    pub fn encrypt<R: AllowedRng>(&self, msg: &[u8], rng: &mut R) -> Encryption<G> {
        Encryption::<G>::encrypt(&self.0, msg, rng)
    }

    pub fn decrypt_with_recovery_package(
        &self,
        pkg: &RecoveryPackage<G>,
        random_oracle: &RandomOracle,
        enc: &Encryption<G>,
    ) -> Result<Vec<u8>, FastCryptoError> {
        pkg.proof
            .verify(&enc.0, &self.0, &pkg.ephemeral_key, random_oracle)?;
        Ok(enc.decrypt_from_partial_decryption(&pkg.ephemeral_key))
    }
}

impl<G: GroupElement + Serialize> Encryption<G> {
    fn encrypt<R: AllowedRng>(x_g: &G, msg: &[u8], rng: &mut R) -> Self {
        let r = G::ScalarType::rand(rng);
        let r_g = G::generator() * r;
        let r_x_g = *x_g * r;
        let hkdf_result = Self::hkdf(&r_x_g);
        let cipher = Aes256Ctr::new(
            AesKey::<U32>::from_bytes(&hkdf_result)
                .expect("New shouldn't fail as use fixed size key is used"),
        );
        let encrypted_message = cipher.encrypt(&Self::fixed_zero_nonce(), msg);
        Self(r_g, encrypted_message)
    }

    fn decrypt(&self, sk: &G::ScalarType) -> Vec<u8> {
        let partial_key = self.0 * sk;
        self.decrypt_from_partial_decryption(&partial_key)
    }

    fn decrypt_from_partial_decryption(&self, partial_key: &G) -> Vec<u8> {
        let hkdf_result = Self::hkdf(partial_key);
        let cipher = Aes256Ctr::new(
            AesKey::<U32>::from_bytes(&hkdf_result)
                .expect("New shouldn't fail as use fixed size key is used"),
        );
        cipher
            .decrypt(&Self::fixed_zero_nonce(), &self.1)
            .expect("Decrypt should never fail for CTR mode")
    }

    fn hkdf(e: &G) -> Vec<u8> {
        let serialized = bincode::serialize(&e).expect("serialize should never fail");
        hkdf_sha3_256(
            &HkdfIkm::from_bytes(serialized.as_slice())
                .expect("hkdf_sha3_256 should work with any input"),
            &[],
            &[],
            AES_KEY_LENGTH,
        )
        .expect("hkdf_sha3_256 should never fail for an AES_KEY_LENGTH long output")
    }

    fn fixed_zero_nonce() -> InitializationVector<U16> {
        InitializationVector::<U16>::from_bytes(&[0u8; 16])
            .expect("U16 could always be set from a 16 bytes array of zeros")
    }
}

impl<G: GroupElement> DdhTupleNizk<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: HashToGroupElement,
{
    pub fn create<R: AllowedRng>(
        sk: &G::ScalarType,
        e_g: &G,
        sk_g: &G,
        sk_e_g: &G,
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> Self {
        let r = G::ScalarType::rand(rng);
        let a = G::generator() * r;
        let b = *e_g * r;
        let challenge = Self::fiat_shamir_challenge(e_g, sk_g, sk_e_g, &a, &b, random_oracle);
        let z = challenge * sk + r;
        DdhTupleNizk(a, b, z)
    }

    pub fn verify(
        &self,
        e_g: &G,
        sk_g: &G,
        sk_e_g: &G,
        random_oracle: &RandomOracle,
    ) -> Result<(), FastCryptoError> {
        let challenge =
            Self::fiat_shamir_challenge(e_g, sk_g, sk_e_g, &self.0, &self.1, random_oracle);
        if !Self::is_valid_relation(
            &self.0, // A
            sk_g,
            &G::generator(),
            &self.2, // z
            &challenge,
        ) || !Self::is_valid_relation(
            &self.1, // B
            sk_e_g, e_g, &self.2, // z
            &challenge,
        ) {
            Err(FastCryptoError::InvalidProof)
        } else {
            Ok(())
        }
    }

    /// Returns the challenge for Fiat-Shamir.
    fn fiat_shamir_challenge(
        e_g: &G,
        sk_g: &G,
        sk_e_g: &G,
        a: &G,
        b: &G,
        random_oracle: &RandomOracle,
    ) -> G::ScalarType {
        let output = random_oracle.evaluate(&(G1Element::generator(), e_g, sk_g, sk_e_g, a, b));
        G::ScalarType::hash_to_group_element(&output)
    }

    /// Checks if e1 + e2*c = z e3
    fn is_valid_relation(e1: &G, e2: &G, e3: &G, z: &G::ScalarType, c: &G::ScalarType) -> bool {
        let left = *e1 + *e2 * c;
        let right = *e3 * z;
        left == right
    }
}
