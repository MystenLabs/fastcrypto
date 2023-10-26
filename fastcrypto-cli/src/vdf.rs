// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::{Discriminant, QuadraticForm};
use fastcrypto_vdf::vdf::wesolowski::ClassGroupVDF;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::ParameterizedGroupElement;
use std::io::{Error, ErrorKind};

#[derive(Parser)]
#[command(name = "vdf-cli")]
#[command(about = "Verifiable delay function using Wesolowski's construction over imaginary class groups", long_about = None)]
enum Command {
    /// Compute VDF output and proof.
    Prove(ProveArguments),

    /// Verify an output .
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct ProveArguments {
    /// The hex encoded seed string used to sample the discriminant.
    #[clap(short, long)]
    seed: String,

    /// The number of iterations.
    #[clap(short, long)]
    iterations: u64,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// The public key corresponding to the secret key used to generate the proof.
    #[clap(short, long)]
    seed: String,

    /// Iterations
    #[clap(short, long)]
    iterations: u64,

    /// The output of the VDF.
    #[clap(short, long)]
    output: String,

    /// The proof of the correctness of the VDF output.
    #[clap(short, long)]
    proof: String,
}

fn main() {
    match execute(Command::parse()) {
        Ok(res) => {
            println!("{}", res);
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

const DISCRIMINANT_BIT_LENGTH: usize = 1024;

fn execute(cmd: Command) -> Result<String, std::io::Error> {
    match cmd {
        Command::Prove(arguments) => {
            let seed = hex::decode(arguments.seed)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid seed."))?;
            let discriminant = Discriminant::from_seed(&seed, DISCRIMINANT_BIT_LENGTH).unwrap();

            let g = QuadraticForm::generator(&discriminant);

            let vdf = ClassGroupVDF::new(discriminant, arguments.iterations);
            let (output, proof) = vdf
                .evaluate(&g)
                .map_err(|_| Error::new(ErrorKind::Other, "VDF evaluation failed"))?;

            let output_string = hex::encode(output.as_bytes());
            let proof_string = hex::encode(proof.as_bytes());

            let mut result = "Output: ".to_string();
            result.push_str(&output_string);
            result.push_str("\nProof:  ");
            result.push_str(&proof_string);
            Ok(result)
        }

        Command::Verify(arguments) => {
            let seed = hex::decode(arguments.seed)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid seed."))?;
            let discriminant = Discriminant::from_seed(&seed, DISCRIMINANT_BIT_LENGTH).unwrap();

            let output = QuadraticForm::from_bytes(
                &hex::decode(arguments.output).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?,
                &discriminant,
            )
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output."))?;
            let proof = QuadraticForm::from_bytes(
                &hex::decode(arguments.proof).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid proof hex string.")
                })?,
                &discriminant,
            )
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid proof."))?;

            let g = QuadraticForm::generator(&discriminant);

            let vdf = ClassGroupVDF::new(discriminant, arguments.iterations);
            let verifies = vdf.verify(&g, &output, &proof).is_ok();

            let mut result = "Verified: ".to_string();
            result.push_str(&verifies.to_string());
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{execute, Command, ProveArguments, VerifyArguments};

    #[test]
    fn test_prove() {
        let seed = "abcd".to_string();
        let iterations = 1000u64;
        let result = execute(Command::Prove(ProveArguments { seed, iterations })).unwrap();
        let expected = "Output: 010027d513249bf8d6ad8cc854052080111a420b2771fab2ac566e63cb6a389cfe42c7920b90871fd1ea0b85e80d157d48e6759546cdcfef4a25b3f013b982c2970dfaa8d67e5f87564a91698ffd1407c505372fc52b0313f444937991c63b6b00040401\nProof:  0300999cca180ec6e2e51b5fb42b9d9b95e9c8b3407ee08f181d8a2699513d4d5d543c9918df4f7e9e9c476191e85a2a7bfdb5b7706c2866daafd9194c741c3f345aa9ab9731fca61eb863401a76966e9deecf5c79112351e99d27cfcdd108a41d1a0100";
        assert_eq!(expected, result);

        let invalid_seed = "abcx".to_string();
        assert!(execute(Command::Prove(ProveArguments {
            seed: invalid_seed,
            iterations,
        }))
        .is_err());
    }

    #[test]
    fn test_verify() {
        let seed = "abcd".to_string();
        let iterations = 1000u64;
        let output = "010027d513249bf8d6ad8cc854052080111a420b2771fab2ac566e63cb6a389cfe42c7920b90871fd1ea0b85e80d157d48e6759546cdcfef4a25b3f013b982c2970dfaa8d67e5f87564a91698ffd1407c505372fc52b0313f444937991c63b6b00040401".to_string();
        let proof = "0300999cca180ec6e2e51b5fb42b9d9b95e9c8b3407ee08f181d8a2699513d4d5d543c9918df4f7e9e9c476191e85a2a7bfdb5b7706c2866daafd9194c741c3f345aa9ab9731fca61eb863401a76966e9deecf5c79112351e99d27cfcdd108a41d1a0100".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            seed,
            iterations,
            output: output.clone(),
            proof: proof.clone(),
        }))
        .unwrap();
        let expected = "Verified: true";
        assert_eq!(expected, result);

        let invalid_seed = "abcx".to_string();
        assert!(execute(Command::Verify(VerifyArguments {
            seed: invalid_seed,
            iterations,
            output,
            proof,
        }))
        .is_err());
    }

    #[test]
    fn test_invalid_proof() {
        let seed = "abcd".to_string();
        let iterations = 2000u64;
        let output = "010027d513249bf8d6ad8cc854052080111a420b2771fab2ac566e63cb6a389cfe42c7920b90871fd1ea0b85e80d157d48e6759546cdcfef4a25b3f013b982c2970dfaa8d67e5f87564a91698ffd1407c505372fc52b0313f444937991c63b6b00040401".to_string();
        let proof = "0300999cca180ec6e2e51b5fb42b9d9b95e9c8b3407ee08f181d8a2699513d4d5d543c9918df4f7e9e9c476191e85a2a7bfdb5b7706c2866daafd9194c741c3f345aa9ab9731fca61eb863401a76966e9deecf5c79112351e99d27cfcdd108a41d1a0100".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            seed,
            iterations,
            output,
            proof,
        }))
        .unwrap();
        let expected = "Verified: false";
        assert_eq!(expected, result);
    }
}
