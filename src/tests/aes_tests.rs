// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    aes::{Key, Aes128Ctr, Aes256Ctr, Aes128CbcPkcs7, Aes256CbcPkcs7}, traits::{Cipher, EncryptionKey}
};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_aes128ctr_encrypt_and_decrypt() {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<16> = Key::generate(&mut rng);

    // Set IV
    let iv = [0x24; 16];

    // Encrypt into buffer1
    let mut buffer1 = [0u8; PLAINTEXT.len()];
    let cipher = Aes128Ctr {iv};
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = [0u8; PLAINTEXT.len()];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2, PLAINTEXT);
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt() {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<32> = Key::generate(&mut rng);

    // Set IV
    let iv = [0x24; 16];

    // Encrypt into buffer1
    let mut buffer1 = [0u8; PLAINTEXT.len()];
    let cipher = Aes256Ctr {iv};
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = [0u8; PLAINTEXT.len()];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2, PLAINTEXT);
}

#[test]
fn test_aes128cbc_encrypt_and_decrypt() {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<16> = Key::generate(&mut rng);

    // Set IV
    let iv = [0x24; 16];

    // Encrypt into buffer1 with extra space for padding
    let mut buffer1 = [0u8; 16];
    let cipher = Aes128CbcPkcs7 {iv};
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = [0u8; 16];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2[0..13], PLAINTEXT);
}

#[test]
fn test_aes256cbc_encrypt_and_decrypt() {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<32> = Key::generate(&mut rng);

    // Set IV
    let iv = [0x24; 16];

    // Encrypt into buffer1 with extra space for padding
    let mut buffer1 = [0u8; 16];
    let cipher = Aes256CbcPkcs7 {iv};
    cipher.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = [0u8; 16];
    cipher.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2[0..13], PLAINTEXT);
}