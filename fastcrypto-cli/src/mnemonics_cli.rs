// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use clap::Parser;
use fastcrypto::{
    ed25519::Ed25519KeyPair,
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::{KeyPair, ToFromBytes},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde_json::Value;
use slip10_ed25519::derive_ed25519_private_key;
use std::io::Read;
use std::{fs::File, time::Instant};

#[derive(Parser)]
#[command(name = "mnemonics-cli")]
#[command(about = "Try to derive the 12-word mnemonics from 8-word", long_about = None)]
enum Command {
    RecoverFullMnemonics(PartialMnemonics),
    Generate,
}

#[derive(Parser, Clone)]
struct PartialMnemonics {
    #[clap(long)]
    short: String,
    #[clap(long)]
    target_pk: String,
}

fn main() {
    match execute(Command::parse()) {
        Ok(_) => {
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

fn execute(cmd: Command) -> Result<(), FastCryptoError> {
    match cmd {
        Command::Generate => {
            // uncomment to define a deterministic entropy.
            // let entropy = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            // let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
            let seed = Seed::new(&mnemonic, "");
            let derived = derive_ed25519_private_key(seed.as_bytes(), &[44, 784, 0, 0, 0]);
            let kp = Ed25519KeyPair::from_bytes(&derived).unwrap();
            println!("12 word mnemonic: {:?}", mnemonic.phrase());
            println!("Public key: {:?}", kp.public());

            let wordlist = load();
            let arr = mnemonic.entropy();
            let mut sized = [0u8; 16];
            sized.copy_from_slice(arr);
            println!("Entropy: {:?}", hex::encode(sized));
            println!("Seed: {:?}", hex::encode(seed.as_bytes()));

            let bitarray_str = to_bitarray_string(&sized);
            println!("Bit array: {:?}", bitarray_str);

            let input = u128::from_be_bytes(sized);
            let mut words = Vec::new();

            // Output every 13 bits as a word, total 8 words.
            for i in 1..9 {
                let start_bit = 128 - i * 13;
                let number = (input >> start_bit) & 0x1FFF;
                let word = wordlist[number as usize].clone();
                words.push(word);
            }

            // Output every 3 bits as a number, total 8 digits.
            let mut digits = Vec::new();
            for i in 1..9 {
                let start_bit = 24 - i * 3;
                let number = (input >> start_bit) & 0b111;
                digits.push(number);
            }

            let full = words
                .iter()
                .zip(digits.iter())
                .map(|(w, d)| format!("{}{}", w, d))
                .collect::<Vec<_>>();
            println!("8 word mnemonic: {:?}", full.join(" "));
            println!("8 word partial mnemonic: {:?}", words.join(" "));
            println!(
                "target/release/mnemonics-cli recover-full-mnemonics --short {:?} --target-pk {:?}",
                words.join(" "),
                kp.public()
            );

            Ok(())
        }

        Command::RecoverFullMnemonics(arg) => {
            let wordlist = load();
            let mut indices = Vec::new();

            for m in arg.short.split(' ') {
                if let Some(index) = wordlist.iter().position(|word| word == m) {
                    indices.push(index);
                } else {
                    return Err(FastCryptoError::GeneralError(format!(
                        "Invalid word {:?}",
                        m
                    )));
                }
            }
            let mut target: u128 = 0;
            for (i, v) in indices.into_iter().enumerate() {
                target += (v as u128) << (13 * (7 - i) + 24);
            }
            let bytes = target.to_be_bytes();
            let bitarray_str = to_bitarray_string(&bytes);
            println!(
                "Partial bit array (missing last 24 bit): {:?}",
                bitarray_str
            );

            let total_combinations: u32 = 1 << 24;
            let start_time = Instant::now();

            let res = (0..total_combinations).into_par_iter().find_any(|i| {
                let mut bytes = bytes[..13].to_vec().clone();
                let digit_bytes = i.to_be_bytes();
                bytes.extend_from_slice(&digit_bytes[1..]);

                let mnemonic = Mnemonic::from_entropy(&bytes, Language::English).unwrap();
                let seed = Seed::new(&mnemonic, "");
                let derived = derive_ed25519_private_key(seed.as_bytes(), &[44, 784, 0, 0, 0]);

                if let Ok(kp) = Ed25519KeyPair::from_bytes(&derived) {
                    if kp.public().as_bytes() == Base64::decode(&arg.target_pk).unwrap() {
                        println!(
                            "Private key found, 12-word legacy mnemonics: {:?}",
                            mnemonic.phrase()
                        );
                        return true;
                    }
                }
                false
            });
            println!("Target digit found: {:?}", res);
            match res {
                Some(val) => {
                    let mut digits = Vec::new();
                    for i in 1..9 {
                        let start_bit = 24 - i * 3;
                        let number = (val >> start_bit) & 0b111;
                        digits.push(number);
                    }
                    println!("Last 8 digits: {:?}", digits);
                    let words: Vec<String> = digits
                        .iter()
                        .zip(arg.short.split(' '))
                        .map(|(d, w)| format!("{}{}", w, d))
                        .collect();
                    println!("Full 8-word mnemonics: {:?}", words.join(" "));
                }
                None => {
                    println!("Private key not found");
                }
            }
            println!("Time elapsed: {:?}", start_time.elapsed());
            Ok(())
        }
    }
}

/// Print the byte array into a human readable bit array.
fn to_bitarray_string(bytes: &[u8]) -> String {
    let mut bit_array = Vec::new();
    for &byte in bytes.iter() {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            bit_array.push(bit);
        }
    }

    let mut res = String::new();
    for (index, &bit) in bit_array.iter().enumerate() {
        res.push_str(&bit.to_string());

        if (index + 1) % 13 == 0 {
            res.push(' ');
        }
    }
    res
}

/// Load the wordlist from the json file.
fn load() -> Vec<String> {
    let mut file = File::open("fastcrypto-cli/src/english_8192.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let json_value: Value = serde_json::from_str(&contents).unwrap();
    let mut wordlist: Vec<String> = Vec::new();

    if let Value::Array(arr) = json_value {
        for element in arr {
            if let Value::String(s) = element {
                wordlist.push(s);
            }
        }
    }
    wordlist
}
