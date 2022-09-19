// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError;
use crate::hmac::{hkdf, hmac, HkdfIkm, HmacKey};
use crate::traits::{FromUniformBytes, ToFromBytes};
use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero},
    HashMarker, OutputSizeUser,
};
use hkdf::hmac::Hmac;
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Keccak256, Sha3_256};

fn hkdf_wrapper<H>(salt: Option<&[u8]>) -> Vec<u8>
where
    H: CoreProxy + OutputSizeUser,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let ikm = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];

    let hk = hkdf::Hkdf::<H, Hmac<H>>::new(salt, ikm);
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
fn test_regression_of_hmac() {
    // Using test vectors from https://datatracker.ietf.org/doc/html/rfc4231#page-3
    let test1 = HmacTestVector {
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        message: "4869205468657265",
        expected_output: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    };
    let test2 = HmacTestVector {
        key: "4a656665",
        message: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        expected_output: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    };
    let test3 = HmacTestVector{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", message: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", expected_output: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"};
    let test4 = HmacTestVector{key: "0102030405060708090a0b0c0d0e0f10111213141516171819", message: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", expected_output: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"};
    let test5 = HmacTestVector{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", message: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", expected_output: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"};
    let test6 = HmacTestVector{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", message: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", expected_output: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"};

    for t in [test1, test2, test3, test4, test5, test6] {
        let k = HmacKey::from_bytes(hex::decode(t.key).unwrap().as_ref()).unwrap();
        let m = hex::decode(t.message).unwrap();
        let d = hmac(&k, m.as_ref());
        let expected = hex::decode(t.expected_output).unwrap();
        assert_eq!(d.to_vec(), expected);
    }
}

#[test]
fn test_sanity_hmac_key() {
    // Empty/short keys are be padded.
    let message = [1u8; 30];
    let r = hmac(&HmacKey::from_bytes(&[]).unwrap(), &message);
    assert_eq!(r, hmac(&HmacKey::from_bytes(&[0; 32]).unwrap(), &message));
    assert_eq!(r, hmac(&HmacKey::from_bytes(&[0]).unwrap(), &message));
    assert_ne!(r, hmac(&HmacKey::from_bytes(&[0; 100]).unwrap(), &message)); // Large keys are hashed.
}

#[test]
fn test_sanity_hmac_message() {
    // Message is not padded, thus any change is significant.
    let key = [11u8; 30];
    assert_ne!(
        hmac(&HmacKey::from_bytes(&key).unwrap(), &[0]),
        hmac(&HmacKey::from_bytes(&key).unwrap(), &[])
    );
    // Also with an empty key.
    let _ = hmac(&HmacKey::from_bytes(&[]).unwrap(), &[]);
    // And with a long message.
    let _ = hmac(&HmacKey::from_bytes(&[0]).unwrap(), &[11u8; 1000000]);
}

#[test]
fn test_regression_of_hkdf() {
    // Using test vectors from https://www.rfc-editor.org/rfc/rfc5869
    let test1 = HkdfTestVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        expected_output:
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    };
    let test2 = HkdfTestVector {
        ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        expected_output:
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    };
    let test3 = HkdfTestVector {
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        expected_output:
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    };

    for t in [test1, test2, test3] {
        let ikm = hex::decode(t.ikm).unwrap();
        let salt = hex::decode(t.salt).unwrap();
        let info = hex::decode(t.info).unwrap();
        let expected = hex::decode(t.expected_output).unwrap();
        let okm = hkdf(
            &HkdfIkm::from_bytes(ikm.as_ref()).unwrap(),
            salt.as_ref(),
            info.as_ref(),
            expected.len(),
        )
        .unwrap();
        assert_eq!(okm, expected);
    }
}

#[test]
fn test_sanity_hkdf() {
    // Short salt should be padded with zeros.
    assert_eq!(
        hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 100).unwrap(),
        hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[0], &[], 100).unwrap()
    );
    assert_eq!(
        hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 100).unwrap(),
        hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[0; 10], &[], 100).unwrap()
    );

    // All inputs are being used.
    let okm = hkdf(
        &HkdfIkm::from_bytes(&[1, 2, 3]).unwrap(),
        &[4, 5, 6],
        &[7, 8, 9],
        100,
    )
    .unwrap();
    assert_ne!(
        okm,
        hkdf(
            &HkdfIkm::from_bytes(&[1, 2, 0]).unwrap(),
            &[4, 5, 6],
            &[7, 8, 9],
            100
        )
        .unwrap()
    );
    assert_ne!(
        okm,
        hkdf(
            &HkdfIkm::from_bytes(&[1, 2, 3]).unwrap(),
            &[4, 5, 0],
            &[7, 8, 9],
            100
        )
        .unwrap()
    );
    assert_ne!(
        okm,
        hkdf(
            &HkdfIkm::from_bytes(&[1, 2, 3]).unwrap(),
            &[4, 5, 6],
            &[7, 8, 0],
            100
        )
        .unwrap()
    );

    // Edge cases
    let _ = hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 100).unwrap();
    let _ = hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 0).unwrap();
    assert_eq!(
        hkdf(&HkdfIkm::from_bytes(&[]).unwrap(), &[], &[], 255 * 1000),
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
