// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;
use fastcrypto_cli::sigs_cli_test_vectors::{MSG, SEED, TEST_CASES};
use regex::Regex;

fn valid_keygen(scheme: &str, seed: &str, expected_secret_key: &str, expected_public_key: &str) {
    let result = Command::cargo_bin("sigs-cli")
        .unwrap()
        .arg("keygen")
        .arg("--scheme")
        .arg(scheme)
        .arg("--seed")
        .arg(seed)
        .ok();
    assert!(result.is_ok());
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    let pattern = Regex::new(
        "Private key in hex: \"([0-9a-fA-F]*)\"\nPublic key in hex: \"([0-9a-fA-F]*)\"\n",
    )
    .unwrap();

    let captures = pattern.captures(&output).unwrap();
    let secret_key = captures.get(1).unwrap().as_str();
    let public_key = captures.get(2).unwrap().as_str();

    assert_eq!(secret_key, expected_secret_key);
    assert_eq!(public_key, expected_public_key);
}

fn invalid_keygen(scheme: &str, seed: &str) {
    let result = Command::cargo_bin("sigs-cli")
        .unwrap()
        .arg("keygen")
        .arg("--scheme")
        .arg(scheme)
        .arg("--seed")
        .arg(seed)
        .ok();
    assert!(result.is_err());
}

#[test]
fn integration_test_keygen() {
    for test_case in TEST_CASES {
        valid_keygen(test_case.name, SEED, test_case.private, test_case.public);
    }

    let invalid_seed = "invalid seed";
    for test_case in TEST_CASES {
        invalid_keygen(test_case.name, invalid_seed);
    }

    invalid_keygen("invalid_scheme", SEED);
}

fn valid_sign(
    scheme: &str,
    secret_key: &str,
    msg: &str,
    public_key: &str,
    expected_signature: &str,
) {
    let result = Command::cargo_bin("sigs-cli")
        .unwrap()
        .arg("sign")
        .arg("--scheme")
        .arg(scheme)
        .arg("--secret-key")
        .arg(secret_key)
        .arg("--msg")
        .arg(msg)
        .ok();
    assert!(result.is_ok());
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    println!("{}", output);
    let pattern =
        Regex::new("Signature in hex: \"([0-9a-fA-F]*)\"\nPublic key in hex: \"([0-9a-fA-F]*)\"\n")
            .unwrap();

    let captures = pattern.captures(&output).unwrap();
    let signature = captures.get(1).unwrap().as_str();
    let actual_public_key = captures.get(2).unwrap().as_str();

    assert_eq!(expected_signature, signature);
    assert_eq!(public_key, actual_public_key);
}

#[test]
fn integration_test_sign() {
    for test_case in TEST_CASES {
        valid_sign(
            test_case.name,
            test_case.private,
            MSG,
            test_case.public,
            test_case.sig,
        )
    }
}

fn valid_verify(scheme: &str, msg: &str, public_key: &str, signature: &str) {
    let result = Command::cargo_bin("sigs-cli")
        .unwrap()
        .arg("verify")
        .arg("--scheme")
        .arg(scheme)
        .arg("--public-key")
        .arg(public_key)
        .arg("--signature")
        .arg(signature)
        .arg("--msg")
        .arg(msg)
        .ok();
    assert!(result.is_ok());
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!("Verify result: Ok(())\n", output);
}

#[test]
fn integration_test_verify() {
    for test_case in TEST_CASES {
        valid_verify(test_case.name, MSG, test_case.public, test_case.sig)
    }
}
