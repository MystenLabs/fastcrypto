// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::{EncryptionKey, ToFromBytes, Encryptor, Decryptor};

use digest::crypto_common::KeyIvInit;
use ctr::cipher::StreamCipher;

#[derive(Debug, Clone)]
pub struct Aes128Key {
    pub bytes: [u8; 16]
}

pub struct Aes128CtrEncryptor {
    pub iv: [u8; 16]
}

pub struct Aes128CtrDecryptor {
    pub iv: [u8; 16]
}

impl AsRef<[u8]> for Aes128Key {
    fn as_ref(&self) -> &[u8] {
        todo!()
    }
}

impl ToFromBytes for Aes128Key {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Aes128Key {bytes: bytes.try_into().expect("wrong length")})
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl EncryptionKey for Aes128Key {
    const LENGTH: usize = 16;

    fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut buffer = [0u8; 16];
        rng.fill_bytes(&mut buffer);
        return Aes128Key { bytes: buffer }
    }
}

impl Encryptor for Aes128CtrEncryptor {
    type K = Aes128Key;

    fn encrypt(&self, key: &Self::K, plaintext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new(&key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(plaintext, buffer).unwrap();
        Ok(())
    }
}

impl Decryptor for Aes128CtrDecryptor {
    type K = Aes128Key;

    fn decrypt(&self, key: &Aes128Key, ciphertext: &[u8], buffer: &mut [u8]) -> Result<(), signature::Error> {
        let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new(&key.bytes.into(), &self.iv.into());
        cipher.apply_keystream_b2b(ciphertext, buffer).unwrap();
        Ok(())
    }
}