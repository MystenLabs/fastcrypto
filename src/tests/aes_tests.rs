// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    aes::{Aes128Key, Aes128CtrDecryptor, Aes128CtrEncryptor}, traits::{Encryptor, Decryptor, EncryptionKey}
};
use rand::{rngs::StdRng, SeedableRng};
use hex_literal::hex;

#[test]
fn test_encrypt_and_decrypt() {

    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key = Aes128Key::generate(&mut rng);

    // Set IV
    let iv = hex!("000102030405060708090a0b0c0d0e0f");

    // Encrypt into buffer1
    let mut buffer1 = [0u8; PLAINTEXT.len()];
    let encryptor = Aes128CtrEncryptor {iv};
    encryptor.encrypt(&key, &PLAINTEXT, &mut buffer1).unwrap();

    print!("{}", hex::encode(&buffer1));

    // Decrypt into buffer2
    let mut buffer2 = [0u8; PLAINTEXT.len()];
    let decryptor = Aes128CtrDecryptor {iv};
    decryptor.decrypt(&key, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2, PLAINTEXT);
}

