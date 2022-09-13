// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::traits::{AuthenticatedCipher, Cipher, EncryptionKey, ToFromBytes};

use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes_gcm::{AeadInPlace, KeyInit};
use ctr::cipher::StreamCipher;
use digest::{crypto_common::KeyIvInit, generic_array::ArrayLength, typenum::U16};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

///
/// An encryption key for a symmetric cipher consisting of `N` bytes.
///
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key<const N: usize> {
    // This is needed to derive Serialize and Deserialize since serde does not support derive for arrays
    // longer than 32 or of generic size. We do not really need it since N currently is either 16 or 32
    // but it allows generifying the code.
    #[serde_as(as = "[_; N]")]
    pub bytes: [u8; N],
}

impl<const N: usize> AsRef<[u8]> for Key<N> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<const N: usize> ToFromBytes for Key<N> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Key {
            bytes: bytes.try_into().expect("wrong length"),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> EncryptionKey for Key<N> {
    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        Key { bytes }
    }
}

///
/// Aes in CTR mode
///
pub struct AesCtr<const KEY_SIZE: usize, Aes> {
    key: Key<KEY_SIZE>,
    algorithm: PhantomData<Aes>,
}

impl<const KEY_SIZE: usize, Aes> AesCtr<KEY_SIZE, Aes> {
    pub fn new(key: Key<KEY_SIZE>) -> Self {
        Self {
            key,
            algorithm: PhantomData,
        }
    }
}

impl<const KEY_SIZE: usize, Aes> Cipher for AesCtr<KEY_SIZE, Aes>
where
    Aes: aes::cipher::KeySizeUser
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt
        + aes::cipher::BlockDecrypt,
{
    fn encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<Aes>::new(self.key.as_bytes().into(), iv.into());
        cipher.apply_keystream_b2b(plaintext, buffer).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<Aes>::new(self.key.as_bytes().into(), iv.into());
        cipher.apply_keystream_b2b(ciphertext, buffer).unwrap();
        Ok(())
    }
}

pub type Aes128Ctr = AesCtr<16, aes::Aes128>;

pub type Aes256Ctr = AesCtr<32, aes::Aes256>;

///
/// Aes in CBC mode
///
pub struct AesCbc<const KEY_SIZE: usize, Aes, Padding> {
    key: Key<KEY_SIZE>,
    algorithm: PhantomData<Aes>,
    padding: PhantomData<Padding>,
}

impl<const KEY_SIZE: usize, Aes, Padding> AesCbc<KEY_SIZE, Aes, Padding> {
    pub fn new(key: Key<KEY_SIZE>) -> Self {
        Self {
            key,
            algorithm: PhantomData,
            padding: PhantomData,
        }
    }
}

impl<const KEY_SIZE: usize, Aes, Padding> Cipher for AesCbc<KEY_SIZE, Aes, Padding>
where
    Aes: aes::cipher::KeySizeUser
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt
        + aes::cipher::BlockDecrypt,
    Padding: aes::cipher::block_padding::Padding<U16>,
{
    fn encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        let cipher = cbc::Encryptor::<Aes>::new(self.key.bytes.as_slice().into(), iv.into());
        cipher
            .encrypt_padded_b2b_mut::<Padding>(plaintext, buffer)
            .unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        let cipher = cbc::Decryptor::<Aes>::new(self.key.bytes.as_slice().into(), iv.into());
        cipher
            .decrypt_padded_b2b_mut::<Padding>(ciphertext, buffer)
            .unwrap();
        Ok(())
    }
}

pub type Aes128CbcPkcs7 = AesCbc<16, aes::Aes128, aes::cipher::block_padding::Pkcs7>;

pub type Aes256CbcPkcs7 = AesCbc<32, aes::Aes256, aes::cipher::block_padding::Pkcs7>;

pub type Aes128CbcIso10126 = AesCbc<16, aes::Aes128, aes::cipher::block_padding::Iso10126>;

pub type Aes256CbcIso10126 = AesCbc<32, aes::Aes256, aes::cipher::block_padding::Iso10126>;

pub type Aes128CbcAnsiX923 = AesCbc<16, aes::Aes128, aes::cipher::block_padding::AnsiX923>;

pub type Aes256CbcAnsiX923 = AesCbc<32, aes::Aes256, aes::cipher::block_padding::AnsiX923>;

pub struct AesGcm<const KEY_SIZE: usize, Aes, NonceSize> {
    key: Key<KEY_SIZE>,
    algorithm: PhantomData<Aes>,
    nonce_size: PhantomData<NonceSize>,
}

impl<const KEY_SIZE: usize, Aes, NonceSize> AesGcm<KEY_SIZE, Aes, NonceSize> {
    pub fn new(key: Key<KEY_SIZE>) -> Self {
        Self {
            key,
            algorithm: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

impl<const KEY_SIZE: usize, Aes, NonceSize> AuthenticatedCipher for AesGcm<KEY_SIZE, Aes, NonceSize>
where
    Aes: aes::cipher::KeySizeUser
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt_authenticated(
        &self,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        if iv.is_empty() {
            return Err(signature::Error::new());
        }
        let mut tmp: Vec<u8> = Vec::<u8>::from(plaintext);
        let cipher =
            aes_gcm::AesGcm::<Aes, NonceSize>::new_from_slice(self.key.as_bytes()).unwrap();
        cipher.encrypt_in_place(iv.into(), aad, &mut tmp).unwrap();
        buffer[..tmp.len()].copy_from_slice(&tmp);
        Ok(())
    }

    fn decrypt_authenticated(
        &self,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        if iv.is_empty() {
            return Err(signature::Error::new());
        }
        let mut tmp: Vec<u8> = Vec::<u8>::from(ciphertext);
        let cipher =
            aes_gcm::AesGcm::<Aes, NonceSize>::new_from_slice(self.key.as_bytes()).unwrap();
        cipher.decrypt_in_place(iv.into(), aad, &mut tmp).unwrap();
        buffer[..tmp.len()].copy_from_slice(&tmp);
        Ok(())
    }
}

impl<const KEY_SIZE: usize, Aes, NonceSize> Cipher for AesGcm<KEY_SIZE, Aes, NonceSize>
where
    Aes: aes::cipher::KeySizeUser
        + aes::cipher::KeyInit
        + aes::cipher::BlockCipher
        + aes::cipher::BlockSizeUser<BlockSize = U16>
        + aes::cipher::BlockEncrypt,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        self.encrypt_authenticated(iv, b"", plaintext, buffer)
    }

    fn decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), signature::Error> {
        self.decrypt_authenticated(iv, b"", ciphertext, buffer)
    }
}

pub type Aes128Gcm<NonceSize> = AesGcm<16, aes::Aes128, NonceSize>;

pub type Aes256Gcm<NonceSize> = AesGcm<32, aes::Aes256, NonceSize>;
