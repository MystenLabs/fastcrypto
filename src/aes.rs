// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::traits::{AuthenticatedCipher, Cipher, EncryptionKey, Generate, ToFromBytes};

use crate::traits::Nonce;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::AeadInPlace;
use core::fmt::Debug;
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use typenum::{U16, U24, U32};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "N: ArrayLength<u8>")]
pub struct GenericByteArray<N: ArrayLength<u8>> {
    // This is needed to derive Serialize and Deserialize since serde does not support derive for arrays
    // longer than 32 or of generic size. We do not really need it since N currently is either 16 or 32
    // but it allows generifying the code.
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
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(GenericByteArray {
            bytes: GenericArray::from_slice(bytes).to_owned(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<N> Generate for GenericByteArray<N>
where
    N: ArrayLength<u8> + Debug,
{
    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> AesKey<N> {
        let mut bytes = GenericArray::<u8, N>::default();
        rng.fill_bytes(&mut bytes);
        GenericByteArray { bytes }
    }
}

/// A key of `N` bytes. Used with AES ciphers.
pub type AesKey<N> = GenericByteArray<N>;
impl<N> EncryptionKey for AesKey<N> where N: ArrayLength<u8> + Debug {}

/// A `N` byte nonce.
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
    Aes: aes::cipher::KeySizeUser<KeySize = KeySize>
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt
        + aes::cipher::BlockDecrypt,
{
    type NonceType = InitializationVector<U16>;

    fn encrypt(&self, iv: &Self::NonceType, plaintext: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let mut buffer: Vec<u8> = vec![0; plaintext.len()];
        let mut cipher = ctr::Ctr128BE::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher
            .apply_keystream_b2b(plaintext, &mut buffer)
            .map_err(|_| signature::Error::new())?;
        Ok(buffer)
    }

    fn decrypt(
        &self,
        iv: &Self::NonceType,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, signature::Error> {
        let mut buffer: Vec<u8> = vec![0; ciphertext.len()];
        let mut cipher = ctr::Ctr128BE::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher
            .apply_keystream_b2b(ciphertext, &mut buffer)
            .map_err(|_| signature::Error::new())?;
        Ok(buffer)
    }
}

pub type Aes128Ctr = AesCtr<U16, aes::Aes128>;

pub type Aes192Ctr = AesCtr<U24, aes::Aes192>;

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
    Aes: aes::cipher::KeySizeUser<KeySize = KeySize>
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt
        + aes::cipher::BlockDecrypt,
    Padding: aes::cipher::block_padding::Padding<U16>,
{
    type NonceType = InitializationVector<U16>;

    fn encrypt(&self, iv: &Self::NonceType, plaintext: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let cipher = cbc::Encryptor::<Aes>::new(&self.key.bytes, &iv.bytes);
        Ok(cipher.encrypt_padded_vec_mut::<Padding>(plaintext))
    }

    fn decrypt(
        &self,
        iv: &Self::NonceType,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, signature::Error> {
        let cipher = cbc::Decryptor::<Aes>::new(&self.key.bytes, &iv.bytes);
        cipher
            .decrypt_padded_vec_mut::<Padding>(ciphertext)
            .map_err(|_| signature::Error::new())
    }
}

pub type Aes128CbcPkcs7 = AesCbc<U16, aes::Aes128, aes::cipher::block_padding::Pkcs7>;

pub type Aes256CbcPkcs7 = AesCbc<U32, aes::Aes256, aes::cipher::block_padding::Pkcs7>;

pub type Aes128CbcIso10126 = AesCbc<U16, aes::Aes128, aes::cipher::block_padding::Iso10126>;

pub type Aes256CbcIso10126 = AesCbc<U32, aes::Aes256, aes::cipher::block_padding::Iso10126>;

pub type Aes128CbcAnsiX923 = AesCbc<U16, aes::Aes128, aes::cipher::block_padding::AnsiX923>;

pub type Aes256CbcAnsiX923 = AesCbc<U32, aes::Aes256, aes::cipher::block_padding::AnsiX923>;

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
    Aes: aes::cipher::KeySizeUser<KeySize = KeySize>
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt,
    NonceSize: ArrayLength<u8> + Debug,
{
    type NonceType = InitializationVector<NonceSize>;

    fn encrypt_authenticated(
        &self,
        iv: &Self::NonceType,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, signature::Error> {
        if iv.as_bytes().is_empty() {
            return Err(signature::Error::new());
        }
        let cipher = aes_gcm::AesGcm::<Aes, NonceSize>::new(&self.key.bytes);
        let mut buffer: Vec<u8> = plaintext.to_vec();
        cipher
            .encrypt_in_place(iv.as_bytes().into(), aad, &mut buffer)
            .map_err(|_| signature::Error::new())?;
        Ok(buffer)
    }

    fn decrypt_authenticated(
        &self,
        iv: &Self::NonceType,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, signature::Error> {
        if iv.as_bytes().is_empty() {
            return Err(signature::Error::new());
        }
        let cipher = aes_gcm::AesGcm::<Aes, NonceSize>::new(&self.key.bytes);
        let mut buffer: Vec<u8> = ciphertext.to_vec();
        cipher
            .decrypt_in_place(iv.as_bytes().into(), aad, &mut buffer)
            .map_err(|_| signature::Error::new())?;
        Ok(buffer)
    }
}

impl<KeySize: ArrayLength<u8>, Aes, NonceSize> Cipher for AesGcm<KeySize, Aes, NonceSize>
where
    Aes: aes::cipher::KeySizeUser<KeySize = KeySize>
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt,
    NonceSize: ArrayLength<u8> + Debug,
{
    type NonceType = InitializationVector<NonceSize>;

    fn encrypt(&self, iv: &Self::NonceType, plaintext: &[u8]) -> Result<Vec<u8>, signature::Error> {
        self.encrypt_authenticated(iv, b"", plaintext)
    }

    fn decrypt(
        &self,
        iv: &Self::NonceType,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, signature::Error> {
        self.decrypt_authenticated(iv, b"", ciphertext)
    }
}

pub type Aes128Gcm<NonceSize> = AesGcm<U16, aes::Aes128, NonceSize>;

pub type Aes256Gcm<NonceSize> = AesGcm<U32, aes::Aes256, NonceSize>;
