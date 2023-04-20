// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use std::io::{Error, ErrorKind};

#[derive(Parser)]
#[command(name = "encode-cli")]
#[command(about = "Convert between base64 and hex encoding of a string", long_about = None)]
enum Command {
    /// Decode a base64 string into hex string.
    Base64ToHex(Arg),

    /// Decode a hex string into base64 string.
    HexToBase64(Arg),
}

#[derive(Parser, Clone)]
struct Arg {
    #[clap(short, long)]
    value: String,
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

fn execute(cmd: Command) -> Result<(), std::io::Error> {
    match cmd {
        Command::Base64ToHex(args) => {
            let val = Base64::decode(&args.value)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid base64 string"))?;
            println!("Decoded bytes: {:?}", val);
            println!("Hex: {:?}", Hex::encode(val));
            Ok(())
        }
        Command::HexToBase64(args) => {
            let val = Hex::decode(&args.value)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid hex string"))?;
            println!("Decoded bytes: {:?}", val);
            println!("Base64: {:?}", Base64::encode(val));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {

    use assert_cmd::Command;
    use lazy_static::lazy_static;
    use std::path::PathBuf;

    // Cache the binary to avoid building it for every test. See https://docs.rs/assert_cmd/2.0.11/assert_cmd/cargo/index.html.
    lazy_static! {
        static ref BINARY: PathBuf = {
            escargot::CargoBuild::new()
                .bin("encode-cli")
                .current_release()
                .current_target()
                .run()
                .unwrap()
                .path()
                .to_path_buf()
        };
    }

    #[test]
    fn test_base64_to_hex() {
        let mut cmd = Command::new(BINARY.as_path());

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
    fn test_hex_to_base64() {
        let mut cmd = Command::new(BINARY.as_path());

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
}
