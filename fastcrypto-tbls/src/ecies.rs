// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nizk::{DLNizk, DdhTupleNizk};
use crate::random_oracle::RandomOracle;
use fastcrypto::aes::{Aes256Ctr, AesKey, Cipher, InitializationVector};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::traits::{AllowedRng, ToFromBytes};
use serde::de::DeserializeOwned;
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
///
/// The encryption uses AES Counter mode and is not CCA secure as is.

// TODO: Use ZeroizeOnDrop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey<G: GroupElement>(G::ScalarType);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey<G: GroupElement>(G);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encryption<G: GroupElement>(G, Vec<u8>);

/// Multi-recipient encryption with a proof-of-knowledge of the plaintexts (when the encryption is
/// valid).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRecipientEncryption<G: GroupElement>(G, Vec<Vec<u8>>, DLNizk<G>);

/// A recovery package that allows decrypting a *specific* ECIES Encryption.
/// It also includes a NIZK proof of correctness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPackage<G: GroupElement> {
    ephemeral_key: G,
    proof: DdhTupleNizk<G>,
}

const AES_KEY_LENGTH: usize = 32;

impl<G> PrivateKey<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    pub fn new<R: AllowedRng>(rng: &mut R) -> Self {
        Self(G::ScalarType::rand(rng))
    }

    pub fn from(sc: G::ScalarType) -> Self {
        Self(sc)
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
    G: GroupElement + Serialize + DeserializeOwned,
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    pub fn from_private_key(sk: &PrivateKey<G>) -> Self {
        Self(G::generator() * sk.0)
    }

    pub fn encrypt<R: AllowedRng>(&self, msg: &[u8], rng: &mut R) -> Encryption<G> {
        Encryption::<G>::encrypt(&self.0, msg, rng)
    }

    pub fn deterministic_encrypt(msg: &[u8], r_g: &G, r_x_g: &G) -> Encryption<G> {
        Encryption::<G>::deterministic_encrypt(msg, r_g, r_x_g)
    }

    pub fn decrypt_with_recovery_package(
        &self,
        pkg: &RecoveryPackage<G>,
        random_oracle: &RandomOracle,
        enc: &Encryption<G>,
    ) -> FastCryptoResult<Vec<u8>> {
        pkg.proof
            .verify(&enc.0, &self.0, &pkg.ephemeral_key, random_oracle)?;
        Ok(enc.decrypt_from_partial_decryption(&pkg.ephemeral_key))
    }

    pub fn as_element(&self) -> &G {
        &self.0
    }
}

impl<G: GroupElement> From<G> for PublicKey<G> {
    fn from(p: G) -> Self {
        Self(p)
    }
}

impl<G: GroupElement + Serialize> Encryption<G> {
    fn deterministic_encrypt(msg: &[u8], r_g: &G, r_x_g: &G) -> Self {
        let hkdf_result = Self::hkdf(r_x_g);
        // TODO: Should we just xor with the hkdf output and append with hmac?
        let cipher = Aes256Ctr::new(
            AesKey::<U32>::from_bytes(&hkdf_result)
                .expect("New shouldn't fail as use fixed size key is used"),
        );
        let encrypted_message = cipher.encrypt(&Self::fixed_zero_nonce(), msg);
        Self(*r_g, encrypted_message)
    }

    fn encrypt<R: AllowedRng>(x_g: &G, msg: &[u8], rng: &mut R) -> Self {
        let r = G::ScalarType::rand(rng);
        let r_g = G::generator() * r;
        let r_x_g = *x_g * r;
        Self::deterministic_encrypt(msg, &r_g, &r_x_g)
    }

    fn decrypt(&self, sk: &G::ScalarType) -> Vec<u8> {
        let partial_key = self.0 * sk;
        self.decrypt_from_partial_decryption(&partial_key)
    }

    pub fn decrypt_from_partial_decryption(&self, partial_key: &G) -> Vec<u8> {
        let hkdf_result = Self::hkdf(partial_key);
        let cipher = Aes256Ctr::new(
            AesKey::<U32>::from_bytes(&hkdf_result)
                .expect("New shouldn't fail as use fixed size key is used"),
        );
        cipher
            .decrypt(&Self::fixed_zero_nonce(), &self.1)
            .expect("Decrypt should never fail for CTR mode")
    }

    pub fn ephemeral_key(&self) -> &G {
        &self.0
    }

    fn hkdf(e: &G) -> Vec<u8> {
        let serialized = bcs::to_bytes(e).expect("serialize should never fail");
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

impl<G: GroupElement + Serialize> MultiRecipientEncryption<G>
where
    <G as GroupElement>::ScalarType: FiatShamirChallenge,
{
    pub fn encrypt<R: AllowedRng>(
        pk_and_msgs: &[(PublicKey<G>, Vec<u8>)],
        random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> MultiRecipientEncryption<G> {
        let r = G::ScalarType::rand(rng);
        let r_g = G::generator() * r;
        let encs = pk_and_msgs
            .iter()
            .map(|(pk, msg)| {
                let r_x_g = pk.0 * r;
                Encryption::<G>::deterministic_encrypt(msg, &r_g, &r_x_g).1
            })
            .collect::<Vec<_>>();
        // Bind the NIZK to the encrypted messages by adding them as inputs to the RO.
        let encs_bytes = bcs::to_bytes(&encs).expect("serialize should never fail");
        let nizk = DLNizk::<G>::create(&r, &r_g, &encs_bytes, random_oracle, rng);
        Self(r_g, encs, nizk)
    }

    pub fn get_encryption(&self, i: usize) -> FastCryptoResult<Encryption<G>> {
        let buffer = self.1.get(i).ok_or(FastCryptoError::InvalidInput)?;
        Ok(Encryption(self.0, buffer.clone()))
    }

    pub fn len(&self) -> usize {
        self.1.len()
    }
    pub fn is_empty(&self) -> bool {
        self.1.is_empty()
    }

    pub fn verify(&self, random_oracle: &RandomOracle) -> FastCryptoResult<()> {
        let encs_bytes = bcs::to_bytes(&self.1).expect("serialize should never fail");
        self.2.verify(&self.0, &encs_bytes, random_oracle)?;
        // Encryptions cannot be empty.
        self.1
            .iter()
            .all(|e| !e.is_empty())
            .then_some(())
            .ok_or(FastCryptoError::InvalidInput)
    }

    pub fn ephemeral_key(&self) -> &G {
        &self.0
    }
    pub fn proof(&self) -> &DLNizk<G> {
        &self.2
    }

    #[cfg(test)]
    pub fn swap_for_testing(&mut self, i: usize, j: usize) {
        self.1.swap(i, j);
    }

    #[cfg(test)]
    pub fn copy_for_testing(&mut self, src: usize, dst: usize) {
        self.1[dst] = self.1[src].clone();
    }
}
