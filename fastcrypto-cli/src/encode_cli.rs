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
    use crate::{execute, Arg, Command};

    #[test]
    fn test_encode_base64_to_hex() {
        // The correctness of the output is tested in the integration tests in fastcrypto-cli/tests/encode_cli.rs.
        let base64 = "SGVsbG8gV29ybGQh";
        assert!(execute(Command::Base64ToHex(Arg {
            value: base64.to_string(),
        }))
        .is_ok());

        let invalid_base64 = "SGVsbG8gV29ybGQ";
        assert!(execute(Command::Base64ToHex(Arg {
            value: invalid_base64.to_string(),
        }))
        .is_err());
    }

    #[test]
    fn test_encode_hex_to_base64() {
        // The correctness of the output is tested in the integration tests in fastcrypto-cli/tests/encode_cli.rs.
        let hex = "48656c6c6f20576f726c6421";
        assert!(execute(Command::HexToBase64(Arg {
            value: hex.to_string(),
        }))
        .is_ok());

        let invalid_hex = "48656c6c6f20576f726c642";
        assert!(execute(Command::HexToBase64(Arg {
            value: invalid_hex.to_string(),
        }))
        .is_err());
    }
}
