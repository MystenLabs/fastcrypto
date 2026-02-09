// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nizk::DdhTupleNizk;
use crate::random_oracle::RandomOracle;
use fastcrypto::aes::{Aes256Ctr, AesKey, Cipher, InitializationVector};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement, Scalar};
use fastcrypto::traits::{AllowedRng, ToFromBytes};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use typenum::consts::{U16, U32};
use typenum::Unsigned;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Simple ECIES encryption using a generic group and AES-256-counter.
///
/// Random oracles are extended from two oracles provided by the caller, one for
/// encryptions/decryptions and one for recovery packages. We assume that the
/// caller extended the random oracles with the relevant tags and omit them here.
///
/// The encryption uses AES Counter mode and is not CCA secure as is.
///

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct PrivateKey<G: GroupElement>(pub(crate) G::ScalarType)
where
    G::ScalarType: Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey<G: GroupElement>(pub(crate) G);

/// A recovery package that allows decrypting a *specific* ECIES Encryption.
/// It also includes a NIZK proof of correctness (DDH-NIZK).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPackage<G: GroupElement> {
    pub(crate) ephemeral_key: G,
    pub(crate) proof: DdhTupleNizk<G>,
}

pub const AES_KEY_LENGTH: usize = 32;

/// Multi-recipient encryption with a proof-of-possession of the ephemeral key.
/// (rG, r RO1(rG), {AES(k=RO2(rPK_i), m_i)}_i, DDH-NIZK(G, RO1(rG), rG, r RO1(rG)) )
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRecipientEncryption<G: GroupElement> {
    c: G,
    c_hat: G,
    encs: Vec<Vec<u8>>,
    proof: DdhTupleNizk<G>,
}

impl<G: GroupElement + Serialize> MultiRecipientEncryption<G>
where
    <G as GroupElement>::ScalarType: FiatShamirChallenge + Zeroize,
    G: HashToGroupElement,
{
    pub fn encrypt<R: AllowedRng>(
        pk_and_msgs: &[(PublicKey<G>, Vec<u8>)],
        encryption_random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> MultiRecipientEncryption<G> {
        let r = G::ScalarType::rand(rng);
        let c = G::generator() * r;
        let g_hat = G::hash_to_group_element(
            &Self::g_hat_random_oracle(encryption_random_oracle).evaluate(&c),
        );
        let c_hat = g_hat * r;
        let proof = DdhTupleNizk::<G>::create(
            &r,
            &g_hat,
            &c,
            &c_hat,
            &Self::zk_random_oracle(encryption_random_oracle),
            rng,
        );

        let encs_ro = Self::encs_random_oracle(encryption_random_oracle);
        let encs = pk_and_msgs
            .iter()
            .enumerate()
            .map(|(receiver_index, (receiver_pk, msg))| {
                let pk_r = receiver_pk.0 * r;
                let k = encs_ro.evaluate(&(receiver_index, pk_r));
                let cipher = sym_cipher(&k);
                // Since k is fresh per encryption, we can safely use a fixed nonce.
                cipher.encrypt(&fixed_zero_nonce(), msg)
            })
            .collect::<Vec<_>>();

        MultiRecipientEncryption {
            c,
            c_hat,
            encs,
            proof,
        }
    }

    pub fn verify(&self, encryption_random_oracle: &RandomOracle) -> FastCryptoResult<()> {
        let g_hat = G::hash_to_group_element(
            &Self::g_hat_random_oracle(encryption_random_oracle).evaluate(&self.c),
        );
        self.proof.verify(
            &g_hat,
            &self.c,
            &self.c_hat,
            &Self::zk_random_oracle(encryption_random_oracle),
        )?;
        // Encryptions should not be empty.
        self.encs
            .iter()
            .all(|e| !e.is_empty())
            .then_some(())
            .ok_or(FastCryptoError::InvalidInput)
    }

    /// Assumption: Verify is called before decrypt and do not call it again here to avoid redundant
    /// checks.
    pub fn decrypt(
        &self,
        sk: &PrivateKey<G>,
        encryption_random_oracle: &RandomOracle,
        receiver_index: usize,
    ) -> Vec<u8> {
        let enc_ro = Self::encs_random_oracle(encryption_random_oracle);
        let ephemeral_key = self.c * sk.0;
        let k = enc_ro.evaluate(&(receiver_index, ephemeral_key));
        let cipher = sym_cipher(&k);
        cipher
            .decrypt(&fixed_zero_nonce(), &self.encs[receiver_index])
            .expect("Decrypt should never fail for CTR mode")
    }

    /// Assumption: Verify is called before create_recovery_package and do not call it again here to
    /// avoid redundant checks.
    pub fn create_recovery_package<R: AllowedRng>(
        &self,
        sk: &PrivateKey<G>,
        recovery_random_oracle: &RandomOracle,
        rng: &mut R,
    ) -> RecoveryPackage<G> {
        let pk = G::generator() * sk.0;
        let ephemeral_key = self.c * sk.0;

        let proof = DdhTupleNizk::<G>::create(
            &sk.0,
            &self.c,
            &pk,
            &ephemeral_key,
            recovery_random_oracle,
            rng,
        );

        RecoveryPackage {
            ephemeral_key,
            proof,
        }
    }

    pub fn decrypt_with_recovery_package(
        &self,
        pkg: &RecoveryPackage<G>,
        recovery_random_oracle: &RandomOracle,
        encryption_random_oracle: &RandomOracle,
        receiver_pk: &PublicKey<G>,
        receiver_index: usize,
    ) -> FastCryptoResult<Vec<u8>> {
        assert!(receiver_index < self.encs.len());
        pkg.proof.verify(
            &self.c,
            &receiver_pk.0,
            &pkg.ephemeral_key,
            recovery_random_oracle,
        )?;
        let encs_ro = Self::encs_random_oracle(encryption_random_oracle);
        let k = encs_ro.evaluate(&(receiver_index, pkg.ephemeral_key));
        let cipher = sym_cipher(&k);
        Ok(cipher
            .decrypt(&fixed_zero_nonce(), &self.encs[receiver_index])
            .expect("Decrypt should never fail for CTR mode"))
    }

    pub fn len(&self) -> usize {
        self.encs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.encs.is_empty()
    }

    pub fn ephemeral_key(&self) -> &G {
        &self.c
    }

    pub fn proof(&self) -> &DdhTupleNizk<G> {
        &self.proof
    }

    fn encs_random_oracle(encryption_random_oracle: &RandomOracle) -> RandomOracle {
        encryption_random_oracle.extend("encs")
    }

    fn zk_random_oracle(encryption_random_oracle: &RandomOracle) -> RandomOracle {
        encryption_random_oracle.extend("zk")
    }

    fn g_hat_random_oracle(encryption_random_oracle: &RandomOracle) -> RandomOracle {
        encryption_random_oracle.extend("g_hat")
    }

    #[cfg(test)]
    pub fn modify_c_hat_for_testing(&mut self, c_hat: G) {
        self.c_hat = c_hat;
    }

    #[cfg(test)]
    pub fn copy_for_testing(&mut self, src: usize, dst: usize) {
        self.encs[dst] = self.encs[src].clone();
    }
}

fn fixed_zero_nonce() -> InitializationVector<U16> {
    InitializationVector::<U16>::from_bytes(&[0u8; 16])
        .expect("U16 could always be set from a 16 bytes array of zeros")
}

fn sym_cipher(k: &[u8; 64]) -> Aes256Ctr {
    Aes256Ctr::new(
        AesKey::<U32>::from_bytes(&k[0..U32::USIZE])
            .expect("New shouldn't fail as use fixed size key is used"),
    )
}

impl<G> PrivateKey<G>
where
    G: GroupElement + Serialize,
    <G as GroupElement>::ScalarType: FiatShamirChallenge + Zeroize,
{
    pub fn new<R: AllowedRng>(rng: &mut R) -> Self {
        Self(G::ScalarType::rand(rng))
    }

    pub fn from(sc: G::ScalarType) -> Self {
        Self(sc)
    }
}

impl<G> PublicKey<G>
where
    G: GroupElement + Serialize + DeserializeOwned,
    <G as GroupElement>::ScalarType: FiatShamirChallenge + Zeroize,
{
    pub fn from_private_key(sk: &PrivateKey<G>) -> Self {
        Self(G::generator() * sk.0)
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
