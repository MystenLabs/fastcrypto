// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::{Cipher, EncryptionKey, ToFromBytes};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut};
use aes_gcm::{AeadInPlace, KeyInit};
use ctr::cipher::StreamCipher;
use digest::{
    crypto_common::KeyIvInit,
    generic_array::{ArrayLength, GenericArray},
};
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
/// Aes128 in CTR mode
///
pub struct Aes128Ctr {
    pub iv: [u8; 16],
    pub key: Key<16>,
}

impl Cipher for Aes128Ctr {
    fn encrypt(&self, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new(&self.key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(plaintext, buffer).unwrap();
        Ok(())
    }

    fn decrypt(&self, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new(&self.key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(ciphertext, buffer).unwrap();
        Ok(())
    }
}

///
/// Aes256 in CTR mode
///
pub struct Aes256Ctr {
    pub iv: [u8; 16],
    pub key: Key<32>,
}

impl Cipher for Aes256Ctr {
    fn encrypt(&self, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(&self.key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(plaintext, buffer).unwrap();
        Ok(())
    }

    fn decrypt(&self, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(&self.key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(ciphertext, buffer).unwrap();
        Ok(())
    }
}

///
/// Aes128 in CBC mode with PKCS#7 padding
///
pub struct Aes128CbcPkcs7 {
    pub iv: [u8; 16],
    pub key: Key<16>,
}

impl Cipher for Aes128CbcPkcs7 {
    fn encrypt(&self, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let cipher = cbc::Encryptor::<aes::Aes128>::new(&self.key.bytes.into(), &self.iv.into());
        cipher
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, buffer)
            .unwrap();
        Ok(())
    }

    fn decrypt(&self, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let cipher = cbc::Decryptor::<aes::Aes128>::new(&self.key.bytes.into(), &self.iv.into());
        cipher
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, buffer)
            .unwrap();
        Ok(())
    }
}

///
/// Aes256 in CBC mode using PKCS#7 padding
///
pub struct Aes256CbcPkcs7 {
    pub iv: [u8; 16],
    pub key: Key<32>,
}

impl Cipher for Aes256CbcPkcs7 {
    fn encrypt(&self, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let cipher = cbc::Encryptor::<aes::Aes256>::new(&self.key.bytes.into(), &self.iv.into());
        cipher
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, buffer)
            .unwrap();
        Ok(())
    }

    fn decrypt(&self, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let cipher = cbc::Decryptor::<aes::Aes256>::new(&self.key.bytes.into(), &self.iv.into());
        cipher
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, buffer)
            .unwrap();
        Ok(())
    }
}

///
/// Aes128 in GCM mode (Authenticated)
///
pub struct Aes128Gcm<'a, NonceSize: ArrayLength<u8>> {
    pub iv: &'a GenericArray<u8, NonceSize>,
    pub key: Key<16>,
    pub aad: &'a [u8],
}

impl<'a, NonceSize: ArrayLength<u8>> Cipher for Aes128Gcm<'a, NonceSize> {
    fn encrypt(&self, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        if self.iv.is_empty() {
            return Err(signature::Error::new());
        }
        let mut tmp: Vec<u8> = Vec::<u8>::from(plaintext);
        let cipher =
            aes_gcm::AesGcm::<aes::Aes128, NonceSize>::new_from_slice(self.key.as_bytes()).unwrap();
        cipher
            .encrypt_in_place(self.iv.as_slice().into(), self.aad, &mut tmp)
            .unwrap();
        buffer[..tmp.len()].copy_from_slice(&tmp);
        Ok(())
    }

    fn decrypt(&self, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        if self.iv.is_empty() {
            return Err(signature::Error::new());
        }
        let mut tmp: Vec<u8> = Vec::<u8>::from(ciphertext);
        let cipher =
            aes_gcm::AesGcm::<aes::Aes128, NonceSize>::new_from_slice(self.key.as_bytes()).unwrap();
        cipher
            .decrypt_in_place(self.iv.as_slice().into(), self.aad, &mut tmp)
            .unwrap();
        buffer[..tmp.len()].copy_from_slice(&tmp);
        Ok(())
    }
}

///
/// Aes256 in GCM mode (Authenticated)
///
pub struct Aes256Gcm<'a, NonceSize: ArrayLength<u8>> {
    pub iv: &'a GenericArray<u8, NonceSize>,
    pub key: Key<32>,
    pub aad: &'a [u8],
}

impl<'a, NonceSize: ArrayLength<u8>> Cipher for Aes256Gcm<'a, NonceSize> {
    fn encrypt(&self, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        if self.iv.is_empty() {
            return Err(signature::Error::new());
        }
        let mut tmp: Vec<u8> = Vec::<u8>::from(plaintext);
        let cipher =
            aes_gcm::AesGcm::<aes::Aes256, NonceSize>::new_from_slice(self.key.as_bytes()).unwrap();
        cipher
            .encrypt_in_place(self.iv.as_slice().into(), self.aad, &mut tmp)
            .unwrap();
        buffer[..tmp.len()].copy_from_slice(&tmp);
        Ok(())
    }

    fn decrypt(&self, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        if self.iv.is_empty() {
            return Err(signature::Error::new());
        }
        let mut tmp: Vec<u8> = Vec::<u8>::from(ciphertext);
        let cipher =
            aes_gcm::AesGcm::<aes::Aes256, NonceSize>::new_from_slice(self.key.as_bytes()).unwrap();
        cipher
            .decrypt_in_place(self.iv.as_slice().into(), self.aad, &mut tmp)
            .unwrap();
        buffer[..tmp.len()].copy_from_slice(&tmp);
        Ok(())
    }
}
