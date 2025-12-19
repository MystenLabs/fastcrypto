// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains implementations of various AES modes.
//!
//! # Example
//! ```
//! # use fastcrypto::aes::*;
//! # use crate::fastcrypto::traits::Generate;
//! use rand::thread_rng;
//! let plaintext = b"Hello, world!";
//! let key = AesKey::generate(&mut thread_rng());
//! let iv = InitializationVector::generate(&mut thread_rng());
//! let cipher = Aes256Ctr::new(key);
//! let ciphertext = cipher.encrypt(&iv, plaintext);
//! let decrypted = cipher.decrypt(&iv, &ciphertext).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

use crate::{
    error::FastCryptoError,
    traits::{AllowedRng, Generate, ToFromBytes},
};
use aes::cipher::{
    BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, BlockSizeUser,
    KeyInit, KeyIvInit, KeySizeUser, StreamCipher,
};
use aes_gcm::{AeadCore, AeadInPlace};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use generic_array::{ArrayLength, GenericArray};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use typenum::U16;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait impl'd by encryption keys in symmetric cryptography
///
pub trait EncryptionKey:
    ToFromBytes + Serialize + DeserializeOwned + Send + Sync + Sized + Generate
{
}

/// Trait impl'd by nonces and IV's used in symmetric cryptography
///
pub trait Nonce:
    ToFromBytes + Serialize + DeserializeOwned + Send + Sync + Sized + Generate
{
}

/// Trait impl'd by symmetric ciphers.
///
pub trait Cipher {
    type IVType: Nonce;

    /// Encrypt `plaintext` using the given IV and return the result.
    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Vec<u8>;

    /// Decrypt `ciphertext` using the given IV and return the result. An error may be returned in
    /// CBC-mode if the ciphertext is not correctly padded, but in other modes this method always
    /// return Ok.
    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError>;
}

/// Trait impl'd by symmetric ciphers for authenticated encryption.
///
pub trait AuthenticatedCipher {
    type IVType: Nonce;

    /// Encrypt `plaintext` using the given IV and authentication data and return the result.
    fn encrypt_authenticated(&self, iv: &Self::IVType, aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Decrypt `ciphertext` using the given IV and authentication data and return the result.
    /// An error is returned if the authentication data does not match the supplied ciphertext.
    fn decrypt_authenticated(
        &self,
        iv: &Self::IVType,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, FastCryptoError>;
}

impl<AC: AuthenticatedCipher> Cipher for AC {
    type IVType = AC::IVType;

    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt_authenticated(iv, &[], plaintext)
    }

    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError> {
        self.decrypt_authenticated(iv, &[], ciphertext)
    }
}

/// Struct wrapping an instance of a `generic_array::GenericArray<u8, N>`.
#[derive(Clone, Serialize, Deserialize, SilentDebug, SilentDisplay, ZeroizeOnDrop)]
#[serde(bound = "N: ArrayLength<u8>")]
pub struct GenericByteArray<N: ArrayLength<u8>> {
    // We use GenericArrays because they are used by the underlying crates.
    bytes: GenericArray<u8, N>,
}

impl<N: ArrayLength<u8>> AsRef<[u8]> for GenericByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<N> ToFromBytes for GenericByteArray<N>
where
    N: ArrayLength<u8> + Debug,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match bytes.len() == N::USIZE {
            true => Ok(GenericByteArray {
                bytes: GenericArray::clone_from_slice(bytes),
            }),
            false => Err(FastCryptoError::InputLengthWrong(N::USIZE)),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<N> Generate for GenericByteArray<N>
where
    N: ArrayLength<u8> + Debug,
{
    fn generate<R: AllowedRng>(rng: &mut R) -> AesKey<N> {
        let mut bytes = GenericArray::<u8, N>::default();
        rng.fill_bytes(&mut bytes);
        GenericByteArray { bytes }
    }
}

impl<N> Zeroize for GenericByteArray<N>
where
    N: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

/// A key of `N` bytes used with AES ciphers.
pub type AesKey<N> = GenericByteArray<N>;
impl<N> EncryptionKey for AesKey<N> where N: ArrayLength<u8> + Debug {}

/// An `N` byte initialization vector used with AES ciphers.
pub type InitializationVector<N> = GenericByteArray<N>;
impl<N> Nonce for InitializationVector<N> where N: ArrayLength<u8> + Debug {}

///
/// Aes in CTR mode
///
pub struct AesCtr<Aes: KeySizeUser>(AesKey<Aes::KeySize>);

impl<Aes: KeySizeUser> AesCtr<Aes> {
    pub fn new(key: AesKey<Aes::KeySize>) -> Self {
        Self(key)
    }
}

impl<Aes> Cipher for AesCtr<Aes>
where
    Aes: KeySizeUser
        + KeyInit
        + BlockCipher
        + BlockSizeUser<BlockSize = U16>
        + BlockEncrypt
        + BlockDecrypt,
{
    type IVType = InitializationVector<U16>;

    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; plaintext.len()];
        let mut cipher = ctr::Ctr128BE::<Aes>::new(&self.0.bytes, &iv.bytes);
        cipher.apply_keystream_b2b(plaintext, &mut buffer).unwrap();
        buffer
    }

    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError> {
        let mut buffer: Vec<u8> = vec![0; ciphertext.len()];
        let mut cipher = ctr::Ctr128BE::<Aes>::new(&self.0.bytes, &iv.bytes);
        cipher.apply_keystream_b2b(ciphertext, &mut buffer).unwrap();
        Ok(buffer)
    }
}

/// AES128 in CTR-mode.
pub type Aes128Ctr = AesCtr<aes::Aes128>;

/// AES192 in CTR-mode.
pub type Aes192Ctr = AesCtr<aes::Aes192>;

/// AES256 in CTR-mode.
pub type Aes256Ctr = AesCtr<aes::Aes256>;

///
/// Aes in CBC mode
///
pub struct AesCbc<Aes: KeySizeUser, Padding> {
    key: AesKey<Aes::KeySize>,
    padding: PhantomData<Padding>,
}

impl<Aes: KeySizeUser, Padding> AesCbc<Aes, Padding> {
    pub fn new(key: AesKey<Aes::KeySize>) -> Self {
        Self {
            key,
            padding: PhantomData,
        }
    }
}

impl<Aes, Padding> Cipher for AesCbc<Aes, Padding>
where
    Aes: KeySizeUser
        + KeyInit
        + BlockCipher
        + BlockSizeUser<BlockSize = U16>
        + BlockEncrypt
        + BlockDecrypt,
    Padding: aes::cipher::block_padding::Padding<U16>,
{
    type IVType = InitializationVector<U16>;

    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Vec<u8> {
        let cipher = cbc::Encryptor::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher.encrypt_padded_vec_mut::<Padding>(plaintext)
    }

    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError> {
        let cipher = cbc::Decryptor::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher
            .decrypt_padded_vec_mut::<Padding>(ciphertext)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

/// AES128 in CBC-mode using PKCS #7 padding.
pub type Aes128CbcPkcs7 = AesCbc<aes::Aes128, aes::cipher::block_padding::Pkcs7>;

/// AES256 in CBC-mode using PKCS #7 padding.
pub type Aes256CbcPkcs7 = AesCbc<aes::Aes256, aes::cipher::block_padding::Pkcs7>;

/// AES128 in CBC-mode using ISO 10126 padding.
pub type Aes128CbcIso10126 = AesCbc<aes::Aes128, aes::cipher::block_padding::Iso10126>;

/// AES256 in CBC-mode using ISO 10126 padding.
pub type Aes256CbcIso10126 = AesCbc<aes::Aes256, aes::cipher::block_padding::Iso10126>;

/// AES128 in CBC-mode using ANSI X9.23 padding.
pub type Aes128CbcAnsiX923 = AesCbc<aes::Aes128, aes::cipher::block_padding::AnsiX923>;

/// AES256 in CBC-mode using ANSI X9.23 padding.
pub type Aes256CbcAnsiX923 = AesCbc<aes::Aes256, aes::cipher::block_padding::AnsiX923>;

/// AES in GCM mode (authenticated).
pub struct AeadWrapper<A: AeadInPlace>(A);

impl<A: KeyInit + AeadInPlace> AeadWrapper<A> {
    pub fn new(key: AesKey<A::KeySize>) -> Self {
        Self(A::new(&key.bytes))
    }
}

impl<A: AeadInPlace> AuthenticatedCipher for AeadWrapper<A>
where
    <A as AeadCore>::NonceSize: Debug,
{
    type IVType = InitializationVector<<A as AeadCore>::NonceSize>;

    fn encrypt_authenticated(&self, iv: &Self::IVType, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buffer: Vec<u8> = plaintext.to_vec();
        self.0
            .encrypt_in_place(&iv.bytes, aad, &mut buffer)
            .unwrap();
        buffer
    }

    fn decrypt_authenticated(
        &self,
        iv: &Self::IVType,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, FastCryptoError> {
        if iv.as_bytes().is_empty() {
            return Err(FastCryptoError::InputTooShort(1));
        }
        let mut buffer: Vec<u8> = ciphertext.to_vec();
        self.0
            .decrypt_in_place(&iv.bytes, aad, &mut buffer)
            .map_err(|_| FastCryptoError::GeneralOpaqueError)?;
        Ok(buffer)
    }
}

/// AES128 in GCM-mode (authenticated) using the given nonce size.
pub type Aes128Gcm<NonceSize> = AeadWrapper<aes_gcm::AesGcm<aes::Aes128, NonceSize>>;

/// AES256 in GCM-mode (authenticated) using the given nonce size.
pub type Aes256Gcm<NonceSize> = AeadWrapper<aes_gcm::AesGcm<aes::Aes256, NonceSize>>;

/// AES256 in GCM-SIV (authenticated) mode with 96 bit nonces.
pub type Aes256GcmSiv = AeadWrapper<aes_gcm_siv::Aes256GcmSiv>;
