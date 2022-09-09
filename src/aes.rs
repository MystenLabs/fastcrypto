// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::{EncryptionKey, ToFromBytes, Cipher};

use aes::cipher::{BlockEncryptMut, block_padding::Pkcs7, BlockDecryptMut, AsyncStreamCipher};
use digest::{crypto_common::KeyIvInit};
use ctr::cipher::StreamCipher;
use serde::{Serialize, Deserialize};
use serde_with::serde_as;

///
/// An encryption key for a symmetric cipher consisting of `N` bytes.
/// 
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key<const N: usize>  {

    // This is needed to derive Serialize and Deserialize since serde does not support derive for arrays 
    // longer than 32 or of generic size. We do not really need it since N currently is either 16 or 32
    // but it allows generifying the code.
    #[serde_as(as = "[_; N]")]
    pub bytes: [u8; N]
}

impl <const N: usize> AsRef<[u8]> for Key<N> {
    fn as_ref(&self) -> &[u8] {
        todo!()
    }
}

impl <const N: usize> ToFromBytes for Key<N> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Key {bytes: bytes.try_into().expect("wrong length")})
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl <const N: usize> EncryptionKey for Key<N> {
    const LENGTH: usize = N;

    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        return Key { bytes }
    }
}

///
/// Aes128 in CTR mode
/// 
pub struct Aes128Ctr {
    pub iv: [u8; 16]
}

impl Cipher for Aes128Ctr {
    type K = Key<16>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new(&key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(plaintext, buffer).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new(&key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(ciphertext, buffer).unwrap();
        Ok(())
    }
}

///
/// Aes256 in CTR mode
/// 
pub struct Aes256Ctr {
    pub iv: [u8; 16]
}

impl Cipher for Aes256Ctr {
    type K = Key<32>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(&key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(plaintext, buffer).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(&key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(ciphertext, buffer).unwrap();
        Ok(())
    }
}

///
/// Aes128 in CBC mode with PKCS#7 padding
/// 
pub struct Aes128CbcPkcs7 {
    pub iv: [u8; 16]
}

impl Cipher for Aes128CbcPkcs7 {
    type K = Key<16>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cbc::Encryptor::<aes::Aes128>::new(&key.bytes.into(), &self.iv.into());
        cipher.encrypt_padded_b2b_mut::<Pkcs7>(plaintext.into(), buffer.into()).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cbc::Decryptor::<aes::Aes128>::new(&key.bytes.into(), &self.iv.into());
        cipher.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext.into(), buffer.into()).unwrap();
        Ok(())
    }
}

///
/// Aes256 in CBC mode using PKCS#7 padding
/// 
pub struct Aes256CbcPkcs7 {
    pub iv: [u8; 16]
}

impl Cipher for Aes256CbcPkcs7 {
    type K = Key<32>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cbc::Encryptor::<aes::Aes256>::new(&key.bytes.into(), &self.iv.into());
        cipher.encrypt_padded_b2b_mut::<Pkcs7>(plaintext.into(), buffer.into()).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cbc::Decryptor::<aes::Aes256>::new(&key.bytes.into(), &self.iv.into());
        cipher.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext.into(), buffer.into()).unwrap();
        Ok(())
    }
}

///
/// Aes128 in CFB mode
/// 
pub struct Aes128Cfb {
    pub iv: [u8; 16]
}

impl Cipher for Aes128Cfb {
    type K = Key<16>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb_mode::Encryptor::<aes::Aes128>::new(key.as_bytes().into(), &self.iv.into());
        cipher.encrypt_b2b(plaintext.into(), buffer.into()).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb_mode::Decryptor::<aes::Aes128>::new(key.as_bytes().into(), &self.iv.into());
        cipher.decrypt_b2b(ciphertext.into(), buffer.into()).unwrap();
        Ok(())
    }
}

///
/// Aes256 in CFB mode
/// 
pub struct Aes256Cfb {
    pub iv: [u8; 16]
}

impl Cipher for Aes256Cfb {
    type K = Key<32>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb_mode::Encryptor::<aes::Aes256>::new(key.as_bytes().into(), &self.iv.into());
        cipher.encrypt_b2b(plaintext.into(), buffer.into()).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb_mode::Decryptor::<aes::Aes256>::new(key.as_bytes().into(), &self.iv.into());
        cipher.decrypt_b2b(ciphertext.into(), buffer.into()).unwrap();
        Ok(())
    }
}

///
/// Aes128 in CFB-8 mode
/// 
pub struct Aes128Cfb8 {
    pub iv: [u8; 16]
}

impl Cipher for Aes128Cfb8 {
    type K = Key<16>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb8::Encryptor::<aes::Aes128>::new(key.as_bytes().into(), &self.iv.into());
        cipher.encrypt_b2b(plaintext.into(), buffer.into()).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb8::Decryptor::<aes::Aes128>::new(key.as_bytes().into(), &self.iv.into());
        cipher.decrypt_b2b(ciphertext.into(), buffer.into()).unwrap();
        Ok(())
    }
}

///
/// Aes256 in CFB-8 mode
/// 
pub struct Aes256Cfb8 {
    pub iv: [u8; 16]
}

impl Cipher for Aes256Cfb8 {
    type K = Key<32>;

    fn encrypt(
        &self, 
        key: &Self::K, 
        plaintext: &[u8], 
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb_mode::Encryptor::<aes::Aes256>::new(key.as_bytes().into(), &self.iv.into());
        cipher.encrypt_b2b(plaintext.into(), buffer.into()).unwrap();
        Ok(())
    }

    fn decrypt(
        &self,
        key: &Self::K,
        ciphertext: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), signature::Error> {
        let cipher = cfb_mode::Decryptor::<aes::Aes256>::new(key.as_bytes().into(), &self.iv.into());
        cipher.decrypt_b2b(ciphertext.into(), buffer.into()).unwrap();
        Ok(())
    }
}