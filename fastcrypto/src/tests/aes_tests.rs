// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::aes::{AuthenticatedCipher, Cipher};
use crate::{
    aes::{
        Aes128CbcPkcs7, Aes128Ctr, Aes128Gcm, Aes192Ctr, Aes256CbcPkcs7, Aes256Ctr, Aes256Gcm,
        AesKey, GenericByteArray, InitializationVector,
    },
    error::FastCryptoError,
    traits::{Generate, ToFromBytes},
};
use core::fmt::Debug;
use generic_array::ArrayLength;
use rand::{rngs::StdRng, SeedableRng};
use typenum::consts::{U0, U1, U12, U128, U15, U16, U2, U20, U24, U257, U32, U4, U6, U64, U8};
use typenum::U10;
use wycheproof::aead::Test;

#[test]
fn serialize_deserialize_key() {
    let mut rng = StdRng::from_seed([9; 32]);
    let key = AesKey::<U16>::generate(&mut rng);
    let bytes = bincode::serialize(&key).unwrap();
    let key2 = bincode::deserialize::<AesKey<U16>>(&bytes).unwrap();
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

#[test]
fn serialize_deserialize_iv() {
    let mut rng = StdRng::from_seed([9; 32]);
    let iv = InitializationVector::<U16>::generate(&mut rng);
    let bytes = bincode::serialize(&iv).unwrap();
    let iv2 = bincode::deserialize::<InitializationVector<U16>>(&bytes).unwrap();
    assert_eq!(iv.as_bytes(), iv2.as_bytes());
}

#[test]
fn test_aes128ctr_encrypt_and_decrypt() {
    test_cipher::<U16, U16, _, _>(Aes128Ctr::new);
}

#[test]
fn test_aes192ctr_encrypt_and_decrypt() {
    test_cipher::<U24, U16, _, _>(Aes192Ctr::new);
}

#[test]
fn test_aes256ctr_encrypt_and_decrypt() {
    test_cipher::<U32, U16, _, _>(Aes256Ctr::new);
}

#[test]
fn test_aes128cbc_encrypt_and_decrypt() {
    test_cipher::<U16, U16, _, _>(Aes128CbcPkcs7::new);
}

#[test]
fn test_aes256cbc_encrypt_and_decrypt() {
    test_cipher::<U32, U16, _, _>(Aes256CbcPkcs7::new);
}

#[test]
fn test_aes128gcm_encrypt_and_decrypt() {
    test_cipher::<U16, U12, _, _>(Aes128Gcm::<U12>::new);
}

#[test]
fn test_aes256gcm_encrypt_and_decrypt() {
    test_cipher::<U32, U12, _, _>(Aes256Gcm::<U12>::new);
}

fn test_cipher<
    KeySize: ArrayLength<u8> + Debug,
    IvSize: ArrayLength<u8> + Debug,
    C: Cipher<IVType = InitializationVector<IvSize>>,
    F: Fn(AesKey<KeySize>) -> C,
>(
    cipher_builder: F,
) {
    const PLAINTEXT: [u8; 13] = *b"Hello, world!";

    // Generate key
    let mut rng = StdRng::from_seed([9; 32]);
    let key = AesKey::generate(&mut rng);
    let iv = InitializationVector::generate(&mut rng);

    let cipher = cipher_builder(key);

    // Encrypt into buffer1
    let ciphertext = cipher.encrypt(&iv, &PLAINTEXT);

    // Decrypt into buffer2
    let plaintext = cipher.decrypt(&iv, &ciphertext).unwrap();

    // Verify that the decrypted text equals the plaintext
    assert_eq!(plaintext[..PLAINTEXT.len()], PLAINTEXT);
}

fn single_wycheproof_test_128<NonceSize: ArrayLength<u8> + Debug>(
    test: &Test,
) -> Result<(), FastCryptoError> {
    let cipher = Aes128Gcm::new(AesKey::<U16>::from_bytes(&test.key).unwrap());
    single_wycheproof_test::<NonceSize, Aes128Gcm<NonceSize>>(test, cipher)
}

fn single_wycheproof_test_256<NonceSize: ArrayLength<u8> + Debug>(
    test: &Test,
) -> Result<(), FastCryptoError> {
    let cipher = Aes256Gcm::new(AesKey::<U32>::from_bytes(&test.key).unwrap());
    single_wycheproof_test::<NonceSize, Aes256Gcm<NonceSize>>(test, cipher)
}

/// Verify a single wycheproof test with the given cipher
fn single_wycheproof_test<
    NonceSize: ArrayLength<u8> + Debug,
    C: AuthenticatedCipher<IVType = InitializationVector<NonceSize>>,
>(
    test: &Test,
    cipher: C,
) -> Result<(), FastCryptoError> {
    let iv = InitializationVector::from_bytes(test.nonce.as_slice()).expect("Failed to parse IV");

    let ciphertext = cipher.encrypt_authenticated(&iv, &test.aad, &test.pt);

    if test.ct.to_vec() != ciphertext[..test.pt.len()] {
        return Err(FastCryptoError::GeneralOpaqueError);
    }

    if test.tag.to_vec() != ciphertext[test.pt.len()..] {
        return Err(FastCryptoError::GeneralOpaqueError);
    }

    let plaintext = cipher.decrypt_authenticated(&iv, &test.aad, &ciphertext)?;

    if test.pt.to_vec() != plaintext {
        return Err(FastCryptoError::GeneralOpaqueError);
    }
    Ok(())
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
                (128, 80) => single_wycheproof_test_128::<U10>(&test),
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
                (256, 80) => single_wycheproof_test_256::<U10>(&test),
                (256, 96) => single_wycheproof_test_256::<U12>(&test),
                (256, 120) => single_wycheproof_test_256::<U15>(&test),
                (256, 128) => single_wycheproof_test_256::<U16>(&test),
                (256, 160) => single_wycheproof_test_256::<U20>(&test),
                (256, 256) => single_wycheproof_test_256::<U32>(&test),
                (256, 512) => single_wycheproof_test_256::<U64>(&test),
                (256, 1024) => single_wycheproof_test_256::<U128>(&test),
                (256, 2056) => single_wycheproof_test_256::<U257>(&test),

                (_, _) => panic!(), // Unhandled case
            };

            // Test returns Ok if successful and Err if it fails
            assert_eq!(result.is_err(), test.result.must_fail());
        }
    }
}

#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let mut sk_bytes = Vec::new();
    {
        let mut rng = StdRng::from_seed([9; 32]);

        // Both keys and nonces are GenericByteArrays
        let sk = GenericByteArray::<U32>::generate(&mut rng);
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk) as *const u8;

        let sk_memory: &[u8] = unsafe { std::slice::from_raw_parts(ptr, 32) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that sk is zeroized
    unsafe {
        for i in 0..32 {
            assert_eq!(*ptr.add(i), 0);
        }
    }
}
