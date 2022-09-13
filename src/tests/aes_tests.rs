// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    aes::{Aes128CbcPkcs7, Aes128Ctr, Aes128Gcm, Aes256CbcPkcs7, Aes256Ctr, Aes256Gcm, Key},
    traits::{AuthenticatedCipher, Cipher, EncryptionKey, ToFromBytes},
};
use digest::consts::*;
use digest::generic_array::ArrayLength;
use rand::{rngs::StdRng, SeedableRng};
use wycheproof::aead::Test;

#[test]
fn test_aes128ctr_encrypt_and_decrypt() {
    test_cipher::<16, 16, _, _>(Aes128Ctr::new);
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt() {
    test_cipher::<32, 16, _, _>(Aes256Ctr::new);
}

#[test]
fn test_aes128cbc_encrypt_and_decrypt() {
    test_cipher_padded::<16, 16, _, _>(Aes128CbcPkcs7::new, &|s| ((s / 16) + 1) * 16);
}

#[test]
fn test_aes256cbc_encrypt_and_decrypt() {
    test_cipher_padded::<32, 16, _, _>(Aes256CbcPkcs7::new, &|s| ((s / 16) + 1) * 16);
}

#[test]
fn test_aes128gcm_encrypt_and_decrypt() {
    test_cipher_padded::<16, 12, _, _>(Aes128Gcm::<U12>::new, &|s| s + 16);
}

#[test]
fn test_aes256gcm_encrypt_and_decrypt() {
    test_cipher_padded::<32, 12, _, _>(Aes256Gcm::<U12>::new, &|s| s + 16);
}

fn test_cipher<
    const KEY_SIZE: usize,
    const IV_SIZE: usize,
    C: Cipher,
    F: Fn(Key<KEY_SIZE>) -> C,
>(
    cipher_builder: F,
) {
    test_cipher_padded::<KEY_SIZE, IV_SIZE, C, F>(cipher_builder, &|s| *s);
}

fn test_cipher_padded<
    const KEY_SIZE: usize,
    const IV_SIZE: usize,
    C: Cipher,
    F: Fn(Key<KEY_SIZE>) -> C,
>(
    cipher_builder: F,
    padding_length: &dyn Fn(&usize) -> usize,
) {
    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // If this cipher uses padding or adds a tag, the buffer may need to be larger than the plain text
    let buffer_size: usize = padding_length(&PLAINTEXT.len());

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key: Key<KEY_SIZE> = Key::generate(&mut rng);

    let iv = [0x24; IV_SIZE];

    let cipher = cipher_builder(key);

    // Encrypt into buffer1
    let mut buffer1 = vec![0u8; buffer_size];
    cipher.encrypt(&iv, &PLAINTEXT, &mut buffer1).unwrap();

    // Decrypt into buffer2
    let mut buffer2 = vec![0u8; buffer_size];
    cipher.decrypt(&iv, &buffer1, &mut buffer2).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(buffer2[..PLAINTEXT.len()], PLAINTEXT);
}

fn single_wycheproof_test_128<NonceSize: ArrayLength<u8>>(test: &Test) -> bool {
    let cipher = Aes128Gcm::new(Key::<16>::from_bytes(&test.key).unwrap());
    single_wycheproof_test::<NonceSize, Aes128Gcm<NonceSize>>(test, cipher)
}

fn single_wycheproof_test_256<NonceSize: ArrayLength<u8>>(test: &Test) -> bool {
    let cipher = Aes256Gcm::new(Key::<32>::from_bytes(&test.key).unwrap());
    single_wycheproof_test::<NonceSize, Aes256Gcm<NonceSize>>(test, cipher)
}

/// Verify a single wycheproof test with the given cipher
fn single_wycheproof_test<NonceSize: ArrayLength<u8>, C: AuthenticatedCipher>(
    test: &Test,
    cipher: C,
) -> bool {
    let mut ct_buffer = vec![0u8; test.pt.len() + 16];
    if cipher
        .encrypt_authenticated(&test.nonce, &test.aad, &test.pt, &mut ct_buffer)
        .is_err()
    {
        return false;
    }

    // Verify that the cipher text is
    if test.ct != ct_buffer[..test.pt.len()] {
        return false;
    }

    if test.tag != ct_buffer[test.pt.len()..] {
        return false;
    }

    let mut pt_buffer = vec![0u8; test.pt.len()];
    if cipher
        .decrypt_authenticated(&test.nonce, &test.aad, &ct_buffer, &mut pt_buffer)
        .is_err()
    {
        return false;
    }

    if test.pt != pt_buffer {
        return false;
    }

    true
}

#[test]
fn wycheproof_test() {
    let test_set = wycheproof::aead::TestSet::load(wycheproof::aead::TestName::AesGcm).unwrap();

    for test_group in test_set.test_groups {
        // The underlying crate only supports 128 and 256 bit key sizes
        if test_group.key_size == 192 {
            continue;
        }

        for test in test_group.tests {
            let result = match (test_group.key_size, test_group.nonce_size) {
                (128, 0) => single_wycheproof_test_128::<U0>(&test),
                (128, 8) => single_wycheproof_test_128::<U1>(&test),
                (128, 16) => single_wycheproof_test_128::<U2>(&test),
                (128, 32) => single_wycheproof_test_128::<U4>(&test),
                (128, 48) => single_wycheproof_test_128::<U6>(&test),
                (128, 64) => single_wycheproof_test_128::<U8>(&test),
                (128, 96) => single_wycheproof_test_128::<U12>(&test),
                (128, 120) => single_wycheproof_test_128::<U15>(&test),
                (128, 128) => single_wycheproof_test_128::<U16>(&test),
                (128, 160) => single_wycheproof_test_128::<U20>(&test),
                (128, 256) => single_wycheproof_test_128::<U32>(&test),
                (128, 512) => single_wycheproof_test_128::<U64>(&test),
                (128, 1024) => single_wycheproof_test_128::<U128>(&test),
                (128, 2056) => single_wycheproof_test_128::<U257>(&test),

                (256, 0) => single_wycheproof_test_256::<U0>(&test),
                (256, 8) => single_wycheproof_test_256::<U1>(&test),
                (256, 16) => single_wycheproof_test_256::<U2>(&test),
                (256, 32) => single_wycheproof_test_256::<U4>(&test),
                (256, 48) => single_wycheproof_test_256::<U6>(&test),
                (256, 64) => single_wycheproof_test_256::<U8>(&test),
                (256, 96) => single_wycheproof_test_256::<U12>(&test),
                (256, 120) => single_wycheproof_test_256::<U15>(&test),
                (256, 128) => single_wycheproof_test_256::<U16>(&test),
                (256, 160) => single_wycheproof_test_256::<U20>(&test),
                (256, 256) => single_wycheproof_test_256::<U32>(&test),
                (256, 512) => single_wycheproof_test_256::<U64>(&test),
                (256, 1024) => single_wycheproof_test_256::<U128>(&test),
                (256, 2056) => single_wycheproof_test_256::<U257>(&test),

                (_, _) => panic!(), // Unhandled error
            };

            // Test returns true if it succeeded
            assert_eq!(result, !test.result.must_fail());
        }
    }
}
