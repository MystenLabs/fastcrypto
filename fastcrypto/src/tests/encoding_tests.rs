// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{encode_with_format, Base64, Encoding, Hex};
use proptest::{arbitrary::Arbitrary, prop_assert_eq};
#[test]
fn test_hex_roundtrip() {
    let bytes = &[1, 10, 100];
    let encoded = Hex::from_bytes(bytes);
    let decoded = encoded.to_vec().unwrap();
    assert_eq!(decoded, bytes);
}

#[test]
fn test_hex_decode_err() {
    assert!(Hex::from_string("A").to_vec().is_err());
    assert!(Hex::from_string("8").to_vec().is_err());
}

#[test]
fn test_hex_encode_format() {
    assert_eq!(encode_with_format(&[1]), "0x01");
    assert_eq!(encode_with_format(Hex::decode("0x01").unwrap()), "0x01");
}

#[test]
fn test_serde() {
    let bytes = &[1];
    let encoded = Hex::from_bytes(bytes);

    let encoded_str = serde_json::to_string(&encoded).unwrap();
    let decoded: Hex = serde_json::from_str(&encoded_str).unwrap();
    assert_eq!("\"0x01\"", encoded_str);
    assert_eq!(
        decoded.to_vec().as_ref().unwrap(),
        encoded.to_vec().as_ref().unwrap()
    );
}

#[test]
fn test_rfc4648_base64() {
    // Test vectors from https://www.rfc-editor.org/rfc/rfc4648
    assert_eq!(Base64::encode(""), "");
    assert_eq!(Base64::encode("f"), "Zg==");
    assert_eq!(Base64::encode("fo"), "Zm8=");
    assert_eq!(Base64::encode("foo"), "Zm9v");
    assert_eq!(Base64::encode("foob"), "Zm9vYg==");
    assert_eq!(Base64::encode("fooba"), "Zm9vYmE=");
    assert_eq!(Base64::encode("foobar"), "Zm9vYmFy");
}

#[test]
fn test_base64_err() {
    // Test vectors from https://eprint.iacr.org/2022/361.pdf
    assert!(Base64::try_from("SGVsbG9=".to_string()).is_err());
    assert!(Base64::try_from("SGVsbG9".to_string()).is_err());
    assert!(Base64::try_from("SGVsbA=".to_string()).is_err());
    assert!(Base64::try_from("SGVsbA=".to_string()).is_err());
    assert!(Base64::try_from("SGVsbA====".to_string()).is_err());
}

proptest::proptest! {
    #[test]
    fn roundtrip_hex(bytes in <[u8; 20]>::arbitrary()) {
        let encoded = Hex::from_bytes(&bytes);
        let decoded = encoded.to_vec().unwrap();
        prop_assert_eq!(bytes, decoded.as_slice());
    }

    #[test]
    fn roundtrip_base64(bytes in <[u8; 20]>::arbitrary()) {
        let encoded = Base64::from_bytes(&bytes);
        let decoded = encoded.to_vec().unwrap();
        prop_assert_eq!(bytes, decoded.as_slice());
    }
}
