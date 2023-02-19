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
use aes_gcm::AeadInPlace;
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use generic_array::{ArrayLength, GenericArray};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use typenum::{U16, U24, U32};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait impl'd by encryption keys in symmetric cryptography
///
pub trait EncryptionKey:
    ToFromBytes + 'static + Serialize + DeserializeOwned + Send + Sync + Sized + Generate
{
}

/// Trait impl'd by nonces and IV's used in symmetric cryptography
///
pub trait Nonce:
    ToFromBytes + 'static + Serialize + DeserializeOwned + Send + Sync + Sized + Generate
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

/// Struct wrapping an instance of a `generic_array::GenericArray<u8, N>`.
#[derive(Clone, Serialize, Deserialize, SilentDebug, SilentDisplay)]
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
                bytes: GenericArray::from_slice(bytes).to_owned(),
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

impl<N> Drop for GenericByteArray<N>
where
    N: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<N> ZeroizeOnDrop for GenericByteArray<N> where N: ArrayLength<u8> + Debug {}

/// A key of `N` bytes used with AES ciphers.
pub type AesKey<N> = GenericByteArray<N>;
impl<N> EncryptionKey for AesKey<N> where N: ArrayLength<u8> + Debug {}

/// An `N` byte initialization vector used with AES ciphers.
pub type InitializationVector<N> = GenericByteArray<N>;
impl<N> Nonce for InitializationVector<N> where N: ArrayLength<u8> + Debug {}

///
/// Aes in CTR mode
///
pub struct AesCtr<KeySize: ArrayLength<u8>, Aes> {
    key: AesKey<KeySize>,
    algorithm: PhantomData<Aes>,
}

impl<KeySize: ArrayLength<u8>, Aes> AesCtr<KeySize, Aes> {
    pub fn new(key: AesKey<KeySize>) -> Self {
        Self {
            key,
            algorithm: PhantomData,
        }
    }
}

impl<KeySize: ArrayLength<u8>, Aes> Cipher for AesCtr<KeySize, Aes>
where
    Aes: KeySizeUser<KeySize = KeySize>
        + KeyInit
        + BlockCipher
        + BlockSizeUser<BlockSize = U16>
        + BlockEncrypt
        + BlockDecrypt,
{
    type IVType = InitializationVector<U16>;

    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; plaintext.len()];
        let mut cipher = ctr::Ctr128BE::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher.apply_keystream_b2b(plaintext, &mut buffer).unwrap();
        buffer
    }

    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError> {
        let mut buffer: Vec<u8> = vec![0; ciphertext.len()];
        let mut cipher = ctr::Ctr128BE::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher.apply_keystream_b2b(ciphertext, &mut buffer).unwrap();
        Ok(buffer)
    }
}

/// AES128 in CTR-mode.
pub type Aes128Ctr = AesCtr<U16, aes::Aes128>;

/// AES192 in CTR-mode.
pub type Aes192Ctr = AesCtr<U24, aes::Aes192>;

/// AES256 in CTR-mode.
pub type Aes256Ctr = AesCtr<U32, aes::Aes256>;

///
/// Aes in CBC mode
///
pub struct AesCbc<KeySize: ArrayLength<u8>, Aes, Padding> {
    key: AesKey<KeySize>,
    algorithm: PhantomData<Aes>,
    padding: PhantomData<Padding>,
}

impl<KeySize: ArrayLength<u8>, Aes, Padding> AesCbc<KeySize, Aes, Padding> {
    pub fn new(key: AesKey<KeySize>) -> Self {
        Self {
            key,
            algorithm: PhantomData,
            padding: PhantomData,
        }
    }
}

impl<KeySize: ArrayLength<u8>, Aes, Padding> Cipher for AesCbc<KeySize, Aes, Padding>
where
    Aes: KeySizeUser<KeySize = KeySize>
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
pub type Aes128CbcPkcs7 = AesCbc<U16, aes::Aes128, aes::cipher::block_padding::Pkcs7>;

/// AES256 in CBC-mode using PKCS #7 padding.
pub type Aes256CbcPkcs7 = AesCbc<U32, aes::Aes256, aes::cipher::block_padding::Pkcs7>;

/// AES128 in CBC-mode using ISO 10126 padding.
pub type Aes128CbcIso10126 = AesCbc<U16, aes::Aes128, aes::cipher::block_padding::Iso10126>;

/// AES256 in CBC-mode using ISO 10126 padding.
pub type Aes256CbcIso10126 = AesCbc<U32, aes::Aes256, aes::cipher::block_padding::Iso10126>;

/// AES128 in CBC-mode using ANSI X9.23 padding.
pub type Aes128CbcAnsiX923 = AesCbc<U16, aes::Aes128, aes::cipher::block_padding::AnsiX923>;

/// AES256 in CBC-mode using ANSI X9.23 padding.
pub type Aes256CbcAnsiX923 = AesCbc<U32, aes::Aes256, aes::cipher::block_padding::AnsiX923>;

/// AES in GCM mode (authenticated).
pub struct AesGcm<KeySize: ArrayLength<u8>, Aes, NonceSize> {
    key: AesKey<KeySize>,
    algorithm: PhantomData<Aes>,
    nonce_size: PhantomData<NonceSize>,
}

impl<KeySize: ArrayLength<u8>, Aes, NonceSize> AesGcm<KeySize, Aes, NonceSize> {
    pub fn new(key: AesKey<KeySize>) -> Self {
        Self {
            key,
            algorithm: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

impl<KeySize: ArrayLength<u8>, Aes, NonceSize> AuthenticatedCipher
    for AesGcm<KeySize, Aes, NonceSize>
where
    Aes: KeySizeUser<KeySize = KeySize>
        + KeyInit
        + BlockCipher
        + BlockSizeUser<BlockSize = U16>
        + BlockEncrypt,
    NonceSize: ArrayLength<u8> + Debug,
{
    type IVType = InitializationVector<NonceSize>;

    fn encrypt_authenticated(&self, iv: &Self::IVType, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = aes_gcm::AesGcm::<Aes, NonceSize>::new(&self.key.bytes);
        let mut buffer: Vec<u8> = plaintext.to_vec();
        cipher
            .encrypt_in_place(iv.as_bytes().into(), aad, &mut buffer)
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
        let cipher = aes_gcm::AesGcm::<Aes, NonceSize>::new(&self.key.bytes);
        let mut buffer: Vec<u8> = ciphertext.to_vec();
        cipher
            .decrypt_in_place(iv.as_bytes().into(), aad, &mut buffer)
            .map_err(|_| FastCryptoError::GeneralOpaqueError)?;
        Ok(buffer)
    }
}

impl<KeySize: ArrayLength<u8>, Aes, NonceSize> Cipher for AesGcm<KeySize, Aes, NonceSize>
where
    Aes: KeySizeUser<KeySize = KeySize>
        + KeyInit
        + BlockCipher
        + BlockSizeUser<BlockSize = U16>
        + BlockEncrypt,
    NonceSize: ArrayLength<u8> + Debug,
{
    type IVType = InitializationVector<NonceSize>;

    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt_authenticated(iv, b"", plaintext)
    }

    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError> {
        self.decrypt_authenticated(iv, b"", ciphertext)
    }
}

/// AES128 in GCM-mode (authenticated) using the given nonce size.
pub type Aes128Gcm<NonceSize> = AesGcm<U16, aes::Aes128, NonceSize>;

/// AES256 in GCM-mode (authenticated) using the given nonce size.
pub type Aes256Gcm<NonceSize> = AesGcm<U32, aes::Aes256, NonceSize>;
