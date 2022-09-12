// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    aes::{
        Aes128CbcPkcs7, Aes128Ctr, Aes256CbcPkcs7, Aes256Ctr, Key, Aes128Gcm, Aes256Gcm,
    },
    traits::{Cipher, EncryptionKey},
};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_aes128ctr_encrypt_and_decrypt() {
    test_cipher(|key, iv| Aes128Ctr { key, iv: *iv });
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt() {
    test_cipher(|key, iv| Aes256Ctr { key, iv: *iv });
}

#[test]
fn test_aes128cbc_encrypt_and_decrypt() {
    test_cipher_padded(|key, iv| Aes128CbcPkcs7 { key, iv: *iv }, |s| ((s / 16) + 1) * 16);
}

#[test]
fn test_aes256cbc_encrypt_and_decrypt() {
    test_cipher_padded(|key, iv| Aes256CbcPkcs7 { key, iv: *iv }, |s| ((s / 16) + 1) * 16);
}

#[test]
fn test_aes128gcm_encrypt_and_decrypt() {
    test_cipher_padded(|key, iv| Aes128Gcm { key, iv: *iv, aad: b"Additional data" }, |s| s + 16);
}

#[test]
fn test_aes256gcm_encrypt_and_decrypt() {
    test_cipher_padded(|key, iv| Aes256Gcm { key, iv: *iv, aad: b"Additional data" }, |s| s + 16);
}

#[test]
fn test_aes128ctr_encrypt_and_decrypt_negative() {
    test_cipher_negative(|key, iv| Aes128Ctr { key, iv: *iv });
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt_negative() {
    test_cipher_negative(|key, iv| Aes256Ctr { key, iv: *iv });
}

fn test_cipher<const KEY_SIZE: usize, const IV_SIZE : usize, C: Cipher, F: Fn(Key<KEY_SIZE>, &[u8; IV_SIZE]) -> C>(
    cipher_builder: F,
) {
    test_cipher_padded(
        cipher_builder,
        |s| s
    );

}

fn test_cipher_padded<const KEY_SIZE: usize, const IV_SIZE: usize, P: FnOnce(usize) -> usize, C: Cipher, F: Fn(Key<KEY_SIZE>, &[u8; IV_SIZE]) -> C>(
    cipher_builder: F, padding_length: P
) {
    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Because of the padding, the buffer needs to have length which is a muliple of 16
    let buffer_size: usize = padding_length(PLAINTEXT.len()); //(PLAINTEXT.len() / 16) + 1) * 16;

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<KEY_SIZE> = Key::generate(&mut rng);

    let iv = [0x24; IV_SIZE];

    let cipher = cipher_builder(key, &iv);

    // Encrypt into buffer1
    let mut buffer1 = vec![0u8; buffer_size];
    cipher.encrypt(&PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = vec![0u8; buffer_size];
    cipher.decrypt(&buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2[..PLAINTEXT.len()], PLAINTEXT);
}

fn test_cipher_negative<const KEY_SIZE: usize, const IV_SIZE: usize, C: Cipher, F: Fn(Key<KEY_SIZE>, &[u8; IV_SIZE]) -> C>(
    cipher_builder: F,
) {
    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<KEY_SIZE> = Key::generate(&mut rng);

    let iv = [0x24; IV_SIZE];

    let cipher = cipher_builder(key, &iv);

    // Encrypt into buffer1
    let mut buffer1 = [0u8; PLAINTEXT.len()];
    cipher.encrypt(&PLAINTEXT, &mut buffer1).unwrap();

    // Change the ciphertext
    buffer1[0] += 1;

    // Decrypt into buffer2
    let mut buffer2 = [0u8; PLAINTEXT.len()];
    cipher.decrypt(&buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text does NOT equal the plaintext
    assert_ne!(buffer2, PLAINTEXT);
}

// fn wycheproof_test() {
//     let test_set = TestSet::load(wycheproof::aead::TestName::Aes).unwrap();
//     for test_group in test_set.test_groups {
//         let pk = Ed25519PublicKey::from_bytes(&test_group.key.pk).unwrap();
//         for test in test_group.tests {
//             let sig = match <Ed25519Signature as ToFromBytes>::from_bytes(&test.sig) {
//                 Ok(s) => s,
//                 Err(_) => {
//                     assert_eq!(test.result, TestResult::Invalid);
//                     continue;
//                 }
//             };
//             match pk.verify(&test.msg, &sig) {
//                 Ok(_) => assert_eq!(test.result, TestResult::Valid),
//                 Err(_) => assert_eq!(test.result, TestResult::Invalid),
//             }
//         }
//     }
// }