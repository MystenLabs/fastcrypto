// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    aes::{Key, Aes128Ctr, Aes256Ctr, Aes128CbcPkcs7, Aes256CbcPkcs7, Aes128Cfb, Aes256Cfb, Aes128Cfb8, Aes256Cfb8}, 
    traits::{Cipher, EncryptionKey}
};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_aes128ctr_encrypt_and_decrypt() {
    test_cipher(Aes128Ctr {iv: [0x24; 16]});
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt() {
    test_cipher(Aes256Ctr {iv: [0x24; 16]});
}

#[test]
fn test_aes128cbc_encrypt_and_decrypt() {
    test_cipher_padded(Aes128CbcPkcs7 {iv: [0x24; 16]});
}

#[test]
fn test_aes256cbc_encrypt_and_decrypt() {
    test_cipher_padded(Aes256CbcPkcs7 {iv: [0x24; 16]});
}

#[test]
fn test_aes128cfb_encrypt_and_decrypt() {
    test_cipher(Aes128Cfb {iv: [0x24; 16]});
}

#[test]
fn test_aes256cfb_encrypt_and_decrypt() {
    test_cipher(Aes256Cfb {iv: [0x24; 16]});
}

#[test]
fn test_aes128cfb8_encrypt_and_decrypt() {
    test_cipher(Aes128Cfb8 {iv: [0x24; 16]});
}

#[test]
fn test_aes256cfb8_encrypt_and_decrypt() {
    test_cipher(Aes256Cfb8 {iv: [0x24; 16]});
}

#[test]
fn test_aes128ctr_encrypt_and_decrypt_negative() {
    test_cipher_negative(Aes128Ctr {iv: [0x24; 16]});
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt_negative() {
    test_cipher(Aes256Ctr {iv: [0x24; 16]});
}

#[test]
fn test_aes128cfb_encrypt_and_decrypt_negative() {
    test_cipher_negative(Aes128Cfb {iv: [0x24; 16]});
}

#[test]
fn test_aes256cfb_encrypt_and_decrypt_negative() {
    test_cipher_negative(Aes256Cfb {iv: [0x24; 16]});
}

#[test]
fn test_aes128cfb8_encrypt_and_decrypt_negative() {
    test_cipher_negative(Aes128Cfb8 {iv: [0x24; 16]});
}

#[test]
fn test_aes256cfb8_encrypt_and_decrypt_negative() {
    test_cipher_negative(Aes256Cfb8 {iv: [0x24; 16]});
}

fn test_cipher<const KEY_SIZE: usize, C: Cipher<K = Key<KEY_SIZE>>> (cipher: C) {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<KEY_SIZE> = Key::generate(&mut rng);

    // Encrypt into buffer1
    let mut buffer1 = [0u8; PLAINTEXT.len()];
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = [0u8; PLAINTEXT.len()];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2, PLAINTEXT);
}

fn test_cipher_padded<const KEY_SIZE: usize, C: Cipher<K = Key<KEY_SIZE>>> (cipher: C) {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Because of the padding, the buffer needs to have length which is a muliple of 16
    const BUFFER_SIZE: usize = ((PLAINTEXT.len() / 16) + 1) * 16;
    
    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<KEY_SIZE> = Key::generate(&mut rng);

    // Encrypt into buffer1
    let mut buffer1 = [0u8; BUFFER_SIZE];
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = [0u8; BUFFER_SIZE];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2[..PLAINTEXT.len()], PLAINTEXT);
}

fn test_cipher_negative<const KEY_SIZE: usize, C: Cipher<K = Key<KEY_SIZE>>> (cipher: C) {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<KEY_SIZE> = Key::generate(&mut rng);

    // Encrypt into buffer1
    let mut buffer1 = [0u8; PLAINTEXT.len()];
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Change the cipher text
    buffer1[0] += 1;
    
    // Decrypt into buffer2
    let mut buffer2 = [0u8; PLAINTEXT.len()];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text does not equal the plaintext
    assert_ne!(buffer2, PLAINTEXT);
}