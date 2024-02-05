// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::discriminant::Discriminant;
use fastcrypto_vdf::class_group::QuadraticForm;
use fastcrypto_vdf::vdf::wesolowski::StrongVDF;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::Parameter;
use fastcrypto_vdf::ToBytes;
use std::io::{Error, ErrorKind};

/// This discriminant size is based on a lower bound from "Trustless unkown-order groups" by Dobson et al.
/// (https://inria.hal.science/hal-02882161/file/unknown-order.pdf)
///
/// A discriminant size of 3072 bits ensures that the computational hardness of computing the group order of a group
/// with a randomly chosen discriminant is at least 128 bits with probability at least 1 - 2^{-40}.
const DEFAULT_DISCRIMINANT_BIT_LENGTH: u64 = 3072;

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

    /// Hash a binary message to a quadratic form.
    Hash(HashArguments),
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

    /// The hex encoded input to the VDF.
    #[clap(long)]
    input: String,

    /// The number of iterations.
    #[clap(long)]
    iterations: u64,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

    /// Iterations
    #[clap(long)]
    iterations: u64,

    /// The input to the VDF.
    #[clap(long)]
    input: String,

    /// The output of the VDF.
    #[clap(short, long)]
    output: String,

    /// The proof of the correctness of the VDF output.
    #[clap(short, long)]
    proof: String,
}

#[derive(Parser, Clone)]
struct HashArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

    /// The hex encoded input to the hash function.
    #[clap(short, long)]
    message: String,

    /// Number of parallel prime samplings in the hash function.
    #[clap(short, long, default_value_t = 64)]
    k: u16,
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

            let input_bytes = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input point."))?;
            let g = QuadraticForm::from_bytes(&input_bytes, &discriminant).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid input point or discriminant.",
                )
            })?;

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

            let input = QuadraticForm::from_bytes(
                &hex::decode(arguments.input).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?,
                &discriminant,
            )
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output."))?;

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

            let vdf = StrongVDF::new(discriminant, arguments.iterations);
            let verifies = vdf.verify(&input, &output, &proof).is_ok();

            let mut result = "Verified: ".to_string();
            result.push_str(&verifies.to_string());
            Ok(result)
        }
        Command::Hash(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = Discriminant::try_from_be_bytes(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input = hex::decode(arguments.message)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid message."))?;
            let output = QuadraticForm::hash_to_group(&input, &discriminant, arguments.k)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "The k parameter was too big"))?;

            let output_bytes = hex::encode(output.to_bytes());

            let mut result = "Output: ".to_string();
            result.push_str(&output_bytes);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{execute, Command, DiscriminantArguments, EvaluateArguments, VerifyArguments};

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
        let input = "003e011627d4dd594f1292809daa77877d6f86f9ec116925889e7c32e7e81a0b32d2209b6f2a14968708366a277b92f81ba95227813ca8ead6dbaadd73ea47730073f5b91ae629a7cfdc7865ec1a3584e62be28b8313d0c82878e9ed9584c8f76526937d6a5e1cd94fedb3dbb2f7a2c5cf32be003e098eb4f5d20ded5d7818e8e6477d68198059df223fe173e37f3da6b9e5296861da0b5f92787aeaca9f627fdeacc66e3e247ed6ce0652b9192f7c864a96397a79".to_string();
        let iterations = 1000u64;
        let result = execute(Command::Evaluate(EvaluateArguments {
            discriminant,
            input: input.clone(),
            iterations,
        }))
        .unwrap();
        let expected = "Output: 004040c4a50e492fe6e62ec8e62b5604b0635ceb1e85af5375503adcef21065cb4bedf0145e8fe26f0fde050fef647b6a1a3290dc675ee7d541509e7e199a45ac5c60040d6fdd70d4957f8e959bee9d2e825cb9fa7f0eec51b412b78da2d3fe5b07b29a1d548725653ac7d5537a72ff2c2789b07241a3ca9700575200f94ddad9cb2b611\nProof:  0040667413c7ff4f5f7d8fef0b4cd2f035b81b7771b9071dcbff62663a26f3be0d5456be08c019f6655186362036c6022a3144646014be815fda9550c3a03d816ceb0040c08f22aa35bbf0c23a86d49eee0d8fef6736391608e1d7d66b9c0bfbb4cf0c82f5e1158a68246bbfae7c10951af3e8deade2c0b2aa4e8c440a6770ae1e3c1143";
        assert_eq!(expected, result);

        let invalid_discriminant = "abcx".to_string();
        assert!(execute(Command::Evaluate(EvaluateArguments {
            discriminant: invalid_discriminant,
            input,
            iterations,
        }))
        .is_err());
    }

    #[test]
    fn test_verify() {
        let discriminant = "ff6cb04c161319209d438b6f016a9c3703b69fef3bb701550eb556a7b2dfec8676677282f2dd06c5688c51439c59e5e1f9efe8305df1957d6b7bf3433493668680e8b8bb05262cbdf4d020dafa8d5a3433199b8b53f6d487b3f37a4ab59493f050d1e2b535b7e9be19c0201055c0d7a07db3aaa67fe0eed63b63d86558668a27".to_string();
        let iterations = 1000u64;
        let input = "003e011627d4dd594f1292809daa77877d6f86f9ec116925889e7c32e7e81a0b32d2209b6f2a14968708366a277b92f81ba95227813ca8ead6dbaadd73ea47730073f5b91ae629a7cfdc7865ec1a3584e62be28b8313d0c82878e9ed9584c8f76526937d6a5e1cd94fedb3dbb2f7a2c5cf32be003e098eb4f5d20ded5d7818e8e6477d68198059df223fe173e37f3da6b9e5296861da0b5f92787aeaca9f627fdeacc66e3e247ed6ce0652b9192f7c864a96397a79".to_string();
        let output = "004040c4a50e492fe6e62ec8e62b5604b0635ceb1e85af5375503adcef21065cb4bedf0145e8fe26f0fde050fef647b6a1a3290dc675ee7d541509e7e199a45ac5c60040d6fdd70d4957f8e959bee9d2e825cb9fa7f0eec51b412b78da2d3fe5b07b29a1d548725653ac7d5537a72ff2c2789b07241a3ca9700575200f94ddad9cb2b611".to_string();
        let proof = "0040667413c7ff4f5f7d8fef0b4cd2f035b81b7771b9071dcbff62663a26f3be0d5456be08c019f6655186362036c6022a3144646014be815fda9550c3a03d816ceb0040c08f22aa35bbf0c23a86d49eee0d8fef6736391608e1d7d66b9c0bfbb4cf0c82f5e1158a68246bbfae7c10951af3e8deade2c0b2aa4e8c440a6770ae1e3c1143".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            discriminant: discriminant.clone(),
            iterations,
            input: input.clone(),
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
            input: input.clone(),
            output: output.clone(),
            proof: proof.clone(),
        }))
        .is_err());

        let other_iterations = 2000u64;
        let result = execute(Command::Verify(VerifyArguments {
            discriminant,
            iterations: other_iterations,
            input,
            output,
            proof,
        }))
        .unwrap();
        let expected = "Verified: false";
        assert_eq!(expected, result);
    }
}
