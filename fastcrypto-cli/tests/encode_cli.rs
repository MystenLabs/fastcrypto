// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;

#[test]
fn integration_test_encode_base64_to_hex() {
    let mut cmd = Command::cargo_bin("encode-cli").unwrap();

    let base64 = "SGVsbG8gV29ybGQh";
    let hex = "48656c6c6f20576f726c6421";
    let bytes = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];

    let result = cmd.arg("base64-to-hex").arg("--value").arg(base64).ok();
    assert!(result.is_ok());
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!(
        format!("Decoded bytes: {:?}\nHex: {:?}\n", bytes, hex),
        output
    );
}

#[test]
fn integration_test_encode_hex_to_base64() {
    let mut cmd = Command::cargo_bin("encode-cli").unwrap();

    let base64 = "SGVsbG8gV29ybGQh";
    let hex = "48656c6c6f20576f726c6421";
    let bytes = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];

    let result = cmd.arg("hex-to-base64").arg("--value").arg(hex).ok();
    assert!(result.is_ok());
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!(
        format!("Decoded bytes: {:?}\nBase64: {:?}\n", bytes, base64),
        output
    );
}
