// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::{Discriminant, QuadraticForm};
use fastcrypto_vdf::vdf::wesolowski::ClassGroupVDF;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::ParameterizedGroupElement;
use std::io::{Error, ErrorKind};

const DEFAULT_DISCRIMINANT_BIT_LENGTH: u64 = 1024;

#[derive(Parser)]
#[command(name = "vdf-cli")]
#[command(about = "Verifiable delay function using Wesolowski's construction over imaginary class groups", long_about = None)]
enum Command {
    /// Sample a random discriminant from a seed.
    Discriminant(DiscriminantArguments),

    /// Compute VDF output and proof.
    Prove(ProveArguments),

    /// Verify an output .
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct DiscriminantArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    seed: String,

    /// Bit length of the discriminant (default is 1024).
    #[clap(short, long, default_value_t = DEFAULT_DISCRIMINANT_BIT_LENGTH)]
    bit_length: u64,
}

#[derive(Parser, Clone)]
struct ProveArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

    /// The number of iterations.
    #[clap(short, long)]
    iterations: u64,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

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

fn execute(cmd: Command) -> Result<String, Error> {
    match cmd {
        Command::Discriminant(arguments) => {
            let seed = hex::decode(arguments.seed)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid seed."))?;
            let discriminant =
                Discriminant::from_seed(&seed, arguments.bit_length as usize).unwrap();
            let discriminant_string = hex::encode(discriminant.to_bytes());
            let mut result = "Discriminant: ".to_string();
            result.push_str(&discriminant_string);
            Ok(result)
        }

        Command::Prove(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = Discriminant::try_from_be_bytes(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

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
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = Discriminant::try_from_be_bytes(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

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

    use crate::{execute, Command, DiscriminantArguments, ProveArguments, VerifyArguments};

    #[test]
    fn test_discriminant() {
        let seed = "abcd".to_string();
        let result = execute(Command::Discriminant(DiscriminantArguments {
            seed,
            bit_length: 1024,
        }))
        .unwrap();
        let expected = "Discriminant: ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_prove() {
        let discriminant = "ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        let iterations = 1000u64;
        let result = execute(Command::Prove(ProveArguments {
            discriminant,
            iterations,
        }))
        .unwrap();
        let expected = "Output: 010027d513249bf8d6ad8cc854052080111a420b2771fab2ac566e63cb6a389cfe42c7920b90871fd1ea0b85e80d157d48e6759546cdcfef4a25b3f013b982c2970dfaa8d67e5f87564a91698ffd1407c505372fc52b0313f444937991c63b6b00040401\nProof:  0300999cca180ec6e2e51b5fb42b9d9b95e9c8b3407ee08f181d8a2699513d4d5d543c9918df4f7e9e9c476191e85a2a7bfdb5b7706c2866daafd9194c741c3f345aa9ab9731fca61eb863401a76966e9deecf5c79112351e99d27cfcdd108a41d1a0100";
        assert_eq!(expected, result);

        let invalid_discriminant = "abcx".to_string();
        assert!(execute(Command::Prove(ProveArguments {
            discriminant: invalid_discriminant,
            iterations,
        }))
        .is_err());
    }

    #[test]
    fn test_verify() {
        let discriminant = "ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        let iterations = 1000u64;
        let output = "010027d513249bf8d6ad8cc854052080111a420b2771fab2ac566e63cb6a389cfe42c7920b90871fd1ea0b85e80d157d48e6759546cdcfef4a25b3f013b982c2970dfaa8d67e5f87564a91698ffd1407c505372fc52b0313f444937991c63b6b00040401".to_string();
        let proof = "0300999cca180ec6e2e51b5fb42b9d9b95e9c8b3407ee08f181d8a2699513d4d5d543c9918df4f7e9e9c476191e85a2a7bfdb5b7706c2866daafd9194c741c3f345aa9ab9731fca61eb863401a76966e9deecf5c79112351e99d27cfcdd108a41d1a0100".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            discriminant,
            iterations,
            output: output.clone(),
            proof: proof.clone(),
        }))
        .unwrap();
        let expected = "Verified: true";
        assert_eq!(expected, result);

        let invalid_discriminant = "abcx".to_string();
        assert!(execute(Command::Verify(VerifyArguments {
            discriminant: invalid_discriminant,
            iterations,
            output,
            proof,
        }))
        .is_err());
    }

    #[test]
    fn test_invalid_proof() {
        let discriminant = "ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        let iterations = 2000u64;
        let output = "010027d513249bf8d6ad8cc854052080111a420b2771fab2ac566e63cb6a389cfe42c7920b90871fd1ea0b85e80d157d48e6759546cdcfef4a25b3f013b982c2970dfaa8d67e5f87564a91698ffd1407c505372fc52b0313f444937991c63b6b00040401".to_string();
        let proof = "0300999cca180ec6e2e51b5fb42b9d9b95e9c8b3407ee08f181d8a2699513d4d5d543c9918df4f7e9e9c476191e85a2a7bfdb5b7706c2866daafd9194c741c3f345aa9ab9731fca61eb863401a76966e9deecf5c79112351e99d27cfcdd108a41d1a0100".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            discriminant,
            iterations,
            output,
            proof,
        }))
        .unwrap();
        let expected = "Verified: false";
        assert_eq!(expected, result);
    }
}
