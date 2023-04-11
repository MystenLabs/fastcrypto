// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError;
use crate::hash::{Keccak256, ReverseWrapper, Sha3_256};
use crate::hmac::{hkdf_sha3_256, hmac_sha3_256, HkdfIkm, HmacKey};
use crate::traits::{FromUniformBytes, ToFromBytes};
use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero},
    HashMarker,
};
use hkdf::hmac::Hmac;
use rand::{rngs::StdRng, SeedableRng};
use wycheproof::TestResult;

fn hkdf_wrapper<H>(salt: Option<&[u8]>) -> Vec<u8>
where
    H: ReverseWrapper,
    <<H as ReverseWrapper>::Variant as CoreProxy>::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <<<H as ReverseWrapper>::Variant as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<<H as ReverseWrapper>::Variant as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>:
        NonZero,
{
    let ikm = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];

    let hk = hkdf::Hkdf::<H::Variant, Hmac<H::Variant>>::new(salt, ikm);
    let mut okm = vec![0u8; 1024];
    hk.expand(&[], &mut okm).unwrap();
    okm
}

struct HmacTestVector {
    key: &'static str,
    message: &'static str,
    expected_output: &'static str,
}

struct HkdfTestVector {
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    expected_output: &'static str,
}

#[test]
fn test_regression_of_salt_padding() {
    // When HMAC is called, salt is padded with zeros to the internal block size.
    assert_eq!(
        hkdf_wrapper::<Sha3_256>(None),
        hkdf_wrapper::<Sha3_256>(Some(&[]))
    );
    assert_eq!(
        hkdf_wrapper::<Keccak256>(None),
        hkdf_wrapper::<Keccak256>(Some(&[]))
    );
    assert_eq!(
        hkdf_wrapper::<Sha3_256>(None),
        hkdf_wrapper::<Sha3_256>(Some(&[0]))
    );
    // Sha3_256's internal block size is 136.
    assert_eq!(
        hkdf_wrapper::<Sha3_256>(None),
        hkdf_wrapper::<Sha3_256>(Some(&[0u8; 136]))
    );
    assert_ne!(
        hkdf_wrapper::<Sha3_256>(None),
        hkdf_wrapper::<Sha3_256>(Some(&[0u8; 137]))
    );
}

#[test]
fn test_hmac_regression() {
    let test1 = HmacTestVector {
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        message: "4869205468657265",
        expected_output: "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
    };
    let test2 = HmacTestVector {
        key: "4a656665",
        message: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        expected_output: "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5",
    };
    let test3 = HmacTestVector{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", message: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", expected_output: "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207"};
    let test4 = HmacTestVector{key: "0102030405060708090a0b0c0d0e0f10111213141516171819", message: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", expected_output: "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7"};
    let test5 = HmacTestVector{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", message: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", expected_output: "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b"};
    let test6 = HmacTestVector{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", message: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", expected_output: "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123"};

    for t in [test1, test2, test3, test4, test5, test6] {
        let k = HmacKey::from_bytes(hex::decode(t.key).unwrap().as_ref()).unwrap();
        let m = hex::decode(t.message).unwrap();
        let d = hmac_sha3_256(&k, m.as_ref());
        let expected = hex::decode(t.expected_output).unwrap();
        assert_eq!(d.to_vec(), expected);
    }
}

#[test]
fn test_sanity_hmac_key() {
    // Empty/short keys are padded.
    let message = [1u8; 30];
    let r = hmac_sha3_256(&HmacKey::from_bytes(&[]).unwrap(), &message);
    assert_eq!(
        r,
        hmac_sha3_256(&HmacKey::from_bytes(&[0; 32]).unwrap(), &message)
    );
    assert_eq!(
        r,
        hmac_sha3_256(&HmacKey::from_bytes(&[0]).unwrap(), &message)
    );
    assert_ne!(
        r,
        hmac_sha3_256(&HmacKey::from_bytes(&[0; 200]).unwrap(), &message)
    ); // Large keys are hashed.
}

#[test]
fn test_sanity_hmac_message() {
    // Message is not padded, thus any change is significant.
    let key = [11u8; 30];
    assert_ne!(
        hmac_sha3_256(&HmacKey::from_bytes(&key).unwrap(), &[0]),
        hmac_sha3_256(&HmacKey::from_bytes(&key).unwrap(), &[])
    );
    // Also with an empty key.
    let _ = hmac_sha3_256(&HmacKey::from_bytes(&[]).unwrap(), &[]);
    // And with a long message.
    let _ = hmac_sha3_256(&HmacKey::from_bytes(&[0]).unwrap(), &[11u8; 1000000]);
}

#[test]
fn test_regression_of_hkdf() {
    let test1 = HkdfTestVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        expected_output:
            "0c5160501d65021deaf2c14f5abce04c5bd2635abceeba61c2edb6e8ed72674900557728f2c9f2c4c179",
    };
    let test2 = HkdfTestVector {
        ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        expected_output:
        "3dc251e66c75da6560405ec5ac10e17d851eedfbfdc13feafbec16964c25d021bd971465a3e9c615f27769019e3f0407d84986fb0ba24e729c99834624baa21cb623dc0098f430d52e18bbdf694df4edd8b2",
    };
    let test3 = HkdfTestVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        expected_output:
            "bc1342cdd75c05e8b0c3ae609ce4410684d197232875073499b30cdfe2de2853c1c1bed63d725e885e78",
    };

    for t in [test1, test2, test3] {
        let ikm = hex::decode(t.ikm).unwrap();
        let salt = hex::decode(t.salt).unwrap();
        let info = hex::decode(t.info).unwrap();
        let expected = hex::decode(t.expected_output).unwrap();
        let okm = hkdf_sha3_256(
            &HkdfIkm::from_bytes(ikm.as_ref()).unwrap(),
            salt.as_ref(),
            info.as_ref(),
            expected.len(),
        )
        .unwrap();
        println!("{}", hex::encode(&okm));
        assert_eq!(okm, expected);
    }
}

#[test]
fn test_sanity_hkdf() {
    // Short salt should be padded with zeros.
    assert_eq!(
        hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 100).unwrap(),
        hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[0], &[], 100).unwrap()
    );
    assert_eq!(
        hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 100).unwrap(),
        hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[0; 10], &[], 100).unwrap()
    );

    // All inputs are being used.
    let okm = hkdf_sha3_256(
        &HkdfIkm::from_bytes(&[1, 2, 3]).unwrap(),
        &[4, 5, 6],
        &[7, 8, 9],
        100,
    )
    .unwrap();
    assert_ne!(
        okm,
        hkdf_sha3_256(
            &HkdfIkm::from_bytes(&[1, 2, 0]).unwrap(),
            &[4, 5, 6],
            &[7, 8, 9],
            100
        )
        .unwrap()
    );
    assert_ne!(
        okm,
        hkdf_sha3_256(
            &HkdfIkm::from_bytes(&[1, 2, 3]).unwrap(),
            &[4, 5, 0],
            &[7, 8, 9],
            100
        )
        .unwrap()
    );
    assert_ne!(
        okm,
        hkdf_sha3_256(
            &HkdfIkm::from_bytes(&[1, 2, 3]).unwrap(),
            &[4, 5, 6],
            &[7, 8, 0],
            100
        )
        .unwrap()
    );

    // Edge cases
    let _ = hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 100).unwrap();
    let _ = hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 0).unwrap();
    assert_eq!(
        hkdf_sha3_256(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 255 * 1000),
        Err(FastCryptoError::InputTooLong(255 * 32))
    );
}

#[test]
fn test_sanity_seed_generation() {
    let mut rng = StdRng::from_seed([11; 32]);
    let hmac_key = HmacKey::generate(&mut rng);
    let hkdf_key = HkdfIkm::generate(&mut rng);
    assert_eq!(hmac_key.as_ref().len(), 32);
    assert_eq!(hkdf_key.as_ref().len(), 32);
}

#[test]
fn hmac_wycheproof_test() {
    let test_set = wycheproof::mac::TestSet::load(wycheproof::mac::TestName::HmacSha3_256).unwrap();
    for test_group in test_set.test_groups {
        for test in test_group.tests {
            let d = hmac_sha3_256(&HmacKey::from_bytes(&test.key).unwrap(), &test.msg);
            assert_eq!(
                d.to_vec()[0..test_group.tag_size / 8] == test.tag.to_vec(),
                test.result == TestResult::Valid
            );
        }
    }
}
