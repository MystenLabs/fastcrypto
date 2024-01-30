// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::QuadraticForm;
use fastcrypto_vdf::vdf::wesolowski::StrongVDF;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::Parameter;
use fastcrypto_vdf::ToBytes;
use std::io::{Error, ErrorKind};
use fastcrypto_vdf::class_group::discriminant::Discriminant;

const DEFAULT_DISCRIMINANT_BIT_LENGTH: u64 = 2400;

#[derive(Parser)]
#[command(name = "vdf-cli")]
#[command(about = "Verifiable delay function using Wesolowski's construction over imaginary class groups", long_about = None)]
enum Command {
    /// Sample a random discriminant from a seed.
    Discriminant(DiscriminantArguments),

    /// Compute VDF output and proof.
    Evaluate(EvaluateArguments),

    /// Verify an output .
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct DiscriminantArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    seed: String,

    /// Bit length of the discriminant (default is 2400).
    #[clap(short, long, default_value_t = DEFAULT_DISCRIMINANT_BIT_LENGTH)]
    bit_length: u64,
}

#[derive(Parser, Clone)]
struct EvaluateArguments {
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

        Command::Evaluate(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = Discriminant::try_from_be_bytes(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let g = QuadraticForm::generator(&discriminant);

            let vdf = StrongVDF::new(discriminant, arguments.iterations);
            let (output, proof) = vdf
                .evaluate(&g)
                .map_err(|_| Error::new(ErrorKind::Other, "VDF evaluation failed"))?;

            let output_string = hex::encode(output.to_bytes());
            let proof_string = hex::encode(proof.to_bytes());

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

            let vdf = StrongVDF::new(discriminant, arguments.iterations);
            let verifies = vdf.verify(&g, &output, &proof).is_ok();

            let mut result = "Verified: ".to_string();
            result.push_str(&verifies.to_string());
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{Command, DiscriminantArguments, EvaluateArguments, execute, VerifyArguments};

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
    fn test_evaluate() {
        let discriminant = "ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        let iterations = 1000u64;
        let result = execute(Command::Evaluate(EvaluateArguments {
            discriminant,
            iterations,
        }))
        .unwrap();
        let expected = "Output: 0040365f0a0ae44fc2cc952bbf3f351a55d79921f45437a2142fab447e1e402e4b1d0bfa70e1ab2d8db95ab2cbe9c49c2d086846008015532232b75be26c904f549c0040efdd7e38615ef6dbe5dc6202755cd634943e7f0b6e3b9701cc84fc5d41d4064440ed27fc5c16ff95a9c9527a6b037a8c2992c7ce40bf192e7518756050b41875\nProof:  00405f86e2ea77d24d63080f5bd6c4fd978904a7af1534c167d3cc6d00e32b700dfa76900c505c0d33b28b7e209254714f3825165170225ed70bff867434c3083b3f0040aaba221a7671183fdbfa132c15d381273003a98d7a221ace226bb6f8f0b751845fbc2d29dabb051d15dfecdc4ec3f69f065fb7192d0f09da48ad688fe023f921";
        assert_eq!(expected, result);

        let invalid_discriminant = "abcx".to_string();
        assert!(execute(Command::Evaluate(EvaluateArguments {
            discriminant: invalid_discriminant,
            iterations,
        }))
        .is_err());
    }

    #[test]
    fn test_verify() {
        let discriminant = "ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        let iterations = 1000u64;
        let output = "0040365f0a0ae44fc2cc952bbf3f351a55d79921f45437a2142fab447e1e402e4b1d0bfa70e1ab2d8db95ab2cbe9c49c2d086846008015532232b75be26c904f549c0040efdd7e38615ef6dbe5dc6202755cd634943e7f0b6e3b9701cc84fc5d41d4064440ed27fc5c16ff95a9c9527a6b037a8c2992c7ce40bf192e7518756050b41875".to_string();
        let proof = "00405f86e2ea77d24d63080f5bd6c4fd978904a7af1534c167d3cc6d00e32b700dfa76900c505c0d33b28b7e209254714f3825165170225ed70bff867434c3083b3f0040aaba221a7671183fdbfa132c15d381273003a98d7a221ace226bb6f8f0b751845fbc2d29dabb051d15dfecdc4ec3f69f065fb7192d0f09da48ad688fe023f921".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            discriminant: discriminant.clone(),
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
            output: output.clone(),
            proof: proof.clone(),
        }))
        .is_err());

        let other_iterations = 2000u64;
        let result = execute(Command::Verify(VerifyArguments {
            discriminant,
            iterations: other_iterations,
            output,
            proof,
        }))
            .unwrap();
        let expected = "Verified: false";
        assert_eq!(expected, result);
    }
}
