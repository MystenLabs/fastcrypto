// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;
use regex::Regex;

#[test]
fn integration_test_ecvrf_keygen() {
    let result = Command::cargo_bin("ecvrf-cli").unwrap().arg("keygen").ok();
    assert!(result.is_ok());

    let expected =
        Regex::new(r"Secret key: ([0-9a-fA-F]{64})\nPublic key: ([0-9a-fA-F]{64})").unwrap();
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert!(expected.is_match(&output));
}

#[test]
fn integration_test_ecvrf_prove() {
    let input = "01020304";
    let secret_key = "b057530c45b7b0f4b96f9b21b011072b2a513f45dd9537ad796acf571055550f";
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .arg("prove")
        .arg("--input")
        .arg(input)
        .arg("--secret-key")
        .arg(secret_key)
        .ok();
    assert!(result.is_ok());

    let expected = "Proof:  2640d12c11a372c726348d60ec74ac80320960ba541fb3e66af0a21590c0a75bf5ccf408d5070c5de77f87c733512f575b4a03511d0031dc2e78ab1582fbbef919b52732c8cb1f44b27ad1d1293dec0f\nOutput: 84588b918a6c9f5b8b74e56a305bb1c2d44e73f68457e991a1dc8defd51672c36b07a2fa95b9f1e701d0152b35d373ab8c48468f0de4bb5abfe84504319fd00c\n";
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!(expected, output);
}

#[test]
fn integration_test_ecvrf_verify() {
    let input = "01020304";
    let public_key = "42250302396453b168c42d5b91e162b848b1b4f90f37818cb4798944095de557";
    let proof = "2640d12c11a372c726348d60ec74ac80320960ba541fb3e66af0a21590c0a75bf5ccf408d5070c5de77f87c733512f575b4a03511d0031dc2e78ab1582fbbef919b52732c8cb1f44b27ad1d1293dec0f";
    let output = "84588b918a6c9f5b8b74e56a305bb1c2d44e73f68457e991a1dc8defd51672c36b07a2fa95b9f1e701d0152b35d373ab8c48468f0de4bb5abfe84504319fd00c";

    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .arg("verify")
        .arg("--output")
        .arg(output)
        .arg("--proof")
        .arg(proof)
        .arg("--input")
        .arg(input)
        .arg("--public-key")
        .arg(public_key)
        .ok();
    assert!(result.is_ok());

    let expected = "Proof verified correctly!\n";
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!(expected, output);
}

#[test]
fn integration_test_ecvrf_e2e() {
    // Keygen
    let result = Command::cargo_bin("ecvrf-cli").unwrap().arg("keygen").ok();
    assert!(result.is_ok());
    let pattern =
        Regex::new(r"Secret key: ([0-9a-fA-F]{64})\nPublic key: ([0-9a-fA-F]{64})").unwrap();
    let stdout = String::from_utf8(result.unwrap().stdout).unwrap();
    assert!(pattern.is_match(&stdout));
    let captures = pattern.captures(&stdout).unwrap();
    let secret_key = captures.get(1).unwrap().as_str();
    let public_key = captures.get(2).unwrap().as_str();

    // Prove
    let input = "01020304";
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .arg("prove")
        .arg("--input")
        .arg(input)
        .arg("--secret-key")
        .arg(secret_key)
        .ok();
    assert!(result.is_ok());
    let pattern = Regex::new(r"Proof:  ([0-9a-fA-F]{160})\nOutput: ([0-9a-fA-F]{128})").unwrap();
    let stdout = String::from_utf8(result.unwrap().stdout).unwrap();
    assert!(pattern.is_match(&stdout));
    let captures = pattern.captures(&stdout).unwrap();
    let proof = captures.get(1).unwrap().as_str();
    let output = captures.get(2).unwrap().as_str();

    // Verify
    let result = Command::cargo_bin("ecvrf-cli")
        .unwrap()
        .arg("verify")
        .arg("--output")
        .arg(output)
        .arg("--proof")
        .arg(proof)
        .arg("--input")
        .arg(input)
        .arg("--public-key")
        .arg(public_key)
        .ok();
    assert!(result.is_ok());
    let expected = "Proof verified correctly!\n";
    let output = String::from_utf8(result.unwrap().stdout).unwrap();
    assert_eq!(expected, output);
}
