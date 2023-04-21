// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;
use regex::Regex;

// Test vectors
const MSG: &str = "00010203";
const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const ED25519: &str = "ed25519";
const ED25519_SECRET_KEY: &str = "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d";
const ED25519_PUBLIC_KEY: &str = "8c553335eee80b9bfa0c544a45fe63474a09dff9c4b0b33db2b662f934ea46c4";
const ED25519_SIGNATURE: &str = "e929370aa36bef3a6b51594b6d96e0f389f09f28807e6b3a25d0ea93f56dd4659e15995f87545ab8f7f924bc18e0502fa689a57e57e931620b79a6c9ec7b3208";
const SECP256K1: &str = "secp256k1";
const SECP256K1_SECRET_KEY: &str =
    "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d";
const SECP256K1_PUBLIC_KEY: &str =
    "033e99a541db69bd32040dfe5037fbf5210dafa8151a71e21c5204b05d95ce0a62";
const SECP256K1_SIGNATURE: &str = "416a21d50b3c838328d4f03213f8ef0c3776389a972ba1ecd37b56243734eba208ea6aaa6fc076ad7accd71d355f693a6fe54fe69b3c168eace9803827bc9046";
const SECP256K1_RECOVERABLE: &str = "secp256k1-rec";
const SECP256K1_RECOVERABLE_SIGNATURE: &str = "416a21d50b3c838328d4f03213f8ef0c3776389a972ba1ecd37b56243734eba208ea6aaa6fc076ad7accd71d355f693a6fe54fe69b3c168eace9803827bc904601";
const SECP256R1: &str = "secp256r1";
const SECP256R1_SECRET_KEY: &str =
    "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d";
const SECP256R1_PUBLIC_KEY: &str =
    "035a8b075508c75f4a124749982a7d21f80d9a5f6893e41a9e955fe4c821e0debe";
const SECP256R1_SIGNATURE: &str = "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd";
const SECP256R1_RECOVERABLE: &str = "secp256r1-rec";
const SECP256R1_RECOVERABLE_SIGNATURE: &str = "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd01";
const BLS12381: &str = "bls12381";
const BLS12381_SECRET_KEY: &str =
    "5fbaab9bd5ed88305581c2926a67ac56fd987ade7658335b1fa1acd258a6f337";
const BLS12381_PUBLIC_KEY: &str = "a57feae28362201f657ccf6cdaba629758beb0214942804d2c084967d76908fe46ce355e0e735bdde2705620c7cf4b3903177f62ba43ba39277d952d80afee4fdc439a3ce2ce6fd113196d7de7aff7d1683ed507a21e6920119c91980329925b";
const BLS12381_SIGNATURE: &str = "a09f9b16ac4cfeadfd4d69b940cf9ead098a7d9f0df0a11d07820cb1dbacda6e1d0631529b1070ec1d8eb29fbc76a807";

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
    valid_keygen(ED25519, SEED, ED25519_SECRET_KEY, ED25519_PUBLIC_KEY);
    valid_keygen(SECP256K1, SEED, SECP256K1_SECRET_KEY, SECP256K1_PUBLIC_KEY);
    valid_keygen(
        SECP256K1_RECOVERABLE,
        SEED,
        SECP256K1_SECRET_KEY,
        SECP256K1_PUBLIC_KEY,
    );
    valid_keygen(SECP256R1, SEED, SECP256R1_SECRET_KEY, SECP256R1_PUBLIC_KEY);
    valid_keygen(
        SECP256R1_RECOVERABLE,
        SEED,
        SECP256R1_SECRET_KEY,
        SECP256R1_PUBLIC_KEY,
    );
    valid_keygen(BLS12381, SEED, BLS12381_SECRET_KEY, BLS12381_PUBLIC_KEY);

    let invalid_seed = "invalid seed";
    invalid_keygen(ED25519, invalid_seed);
    invalid_keygen(SECP256K1, invalid_seed);
    invalid_keygen(SECP256K1_RECOVERABLE, invalid_seed);
    invalid_keygen(SECP256R1, invalid_seed);
    invalid_keygen(SECP256R1_RECOVERABLE, invalid_seed);
    invalid_keygen(BLS12381, invalid_seed);

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
    valid_sign(
        ED25519,
        ED25519_SECRET_KEY,
        MSG,
        ED25519_PUBLIC_KEY,
        ED25519_SIGNATURE,
    );
    valid_sign(
        SECP256R1,
        SECP256R1_SECRET_KEY,
        MSG,
        SECP256R1_PUBLIC_KEY,
        SECP256R1_SIGNATURE,
    );
    valid_sign(
        SECP256R1_RECOVERABLE,
        SECP256R1_SECRET_KEY,
        MSG,
        SECP256R1_PUBLIC_KEY,
        SECP256R1_RECOVERABLE_SIGNATURE,
    );
    valid_sign(
        SECP256K1,
        SECP256K1_SECRET_KEY,
        MSG,
        SECP256K1_PUBLIC_KEY,
        SECP256K1_SIGNATURE,
    );
    valid_sign(
        SECP256K1_RECOVERABLE,
        SECP256K1_SECRET_KEY,
        MSG,
        SECP256K1_PUBLIC_KEY,
        SECP256K1_RECOVERABLE_SIGNATURE,
    );
    valid_sign(
        BLS12381,
        BLS12381_SECRET_KEY,
        MSG,
        BLS12381_PUBLIC_KEY,
        BLS12381_SIGNATURE,
    );
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
    valid_verify(ED25519, MSG, ED25519_PUBLIC_KEY, ED25519_SIGNATURE);
    valid_verify(SECP256K1, MSG, SECP256K1_PUBLIC_KEY, SECP256K1_SIGNATURE);
    valid_verify(
        SECP256K1_RECOVERABLE,
        MSG,
        SECP256K1_PUBLIC_KEY,
        SECP256K1_RECOVERABLE_SIGNATURE,
    );
    valid_verify(SECP256R1, MSG, SECP256R1_PUBLIC_KEY, SECP256R1_SIGNATURE);
    valid_verify(
        SECP256R1_RECOVERABLE,
        MSG,
        SECP256R1_PUBLIC_KEY,
        SECP256R1_RECOVERABLE_SIGNATURE,
    );
    valid_verify(BLS12381, MSG, BLS12381_PUBLIC_KEY, BLS12381_SIGNATURE);
}
