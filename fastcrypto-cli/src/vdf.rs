// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::discriminant::Discriminant;
use fastcrypto_vdf::class_group::QuadraticForm;
use fastcrypto_vdf::vdf::wesolowski::DefaultVDF;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::Parameter;
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

    /// Bit length of the discriminant (default is 3072).
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
            let discriminant_string = hex::encode(bcs::to_bytes(&discriminant).unwrap());
            let mut result = "Discriminant: ".to_string();
            result.push_str(&discriminant_string);
            Ok(result)
        }

        Command::Evaluate(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = bcs::from_bytes::<Discriminant>(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input_bytes = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input point."))?;
            let g = bcs::from_bytes::<QuadraticForm>(&input_bytes).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid input point or discriminant.",
                )
            })?;
            if g.discriminant() != discriminant {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Input point does not match discriminant.",
                ));
            }

            let vdf = DefaultVDF::new(discriminant, arguments.iterations);
            let (output, proof) = vdf
                .evaluate(&g)
                .map_err(|_| Error::new(ErrorKind::Other, "VDF evaluation failed"))?;

            let output_string = hex::encode(bcs::to_bytes(&output).unwrap());
            let proof_string = hex::encode(bcs::to_bytes(&proof).unwrap());

            let mut result = "Output: ".to_string();
            result.push_str(&output_string);
            result.push_str("\nProof:  ");
            result.push_str(&proof_string);
            Ok(result)
        }

        Command::Verify(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = bcs::from_bytes::<Discriminant>(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.input).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output."))?;
            if input.discriminant() != discriminant {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Input has wrong discriminant.",
                ));
            }

            let output =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.output).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output."))?;
            if output.discriminant() != discriminant {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Output has wrong discriminant.",
                ));
            }

            let proof =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.proof).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid proof hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid proof."))?;
            if proof.discriminant() != discriminant {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Proof has wrong discriminant.",
                ));
            }

            let vdf = DefaultVDF::new(discriminant, arguments.iterations);
            let verifies = vdf.verify(&input, &output, &proof).is_ok();

            let mut result = "Verified: ".to_string();
            result.push_str(&verifies.to_string());
            Ok(result)
        }
        Command::Hash(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = bcs::from_bytes(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input = hex::decode(arguments.message)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid message."))?;
            let output =
                QuadraticForm::hash_to_group_with_default_parameters(&input, &discriminant)
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidInput, "The k parameter was too big")
                    })?;

            let output_bytes = hex::encode(bcs::to_bytes(&output).unwrap());

            let mut result = "Output: ".to_string();
            result.push_str(&output_bytes);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        execute, Command, DiscriminantArguments, EvaluateArguments, HashArguments, VerifyArguments,
    };

    #[test]
    fn test_discriminant() {
        let seed = "abcd".to_string();
        let result = execute(Command::Discriminant(DiscriminantArguments {
            seed,
            bit_length: 1024,
        }))
        .unwrap();
        let expected = "Discriminant: ff20278a665865d8633bd6eee07fa6aab37da0d7c0551020c019bee9b735b5e2d150f09394b54a7af3b387d4f6538b9b1933345a8dfada20d0f4bd2c2605bbb8e8808666933443f37b6b7d95f15d30e8eff9e1e5599c43518c68c506ddf28272677686ecdfb2a756b50e5501b73bef9fb603379c6a016f8b439d201913164cb06cff".to_string();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_evaluate() {
        let discriminant = "ff20278a665865d8633bd6eee07fa6aab37da0d7c0551020c019bee9b735b5e2d150f09394b54a7af3b387d4f6538b9b1933345a8dfada20d0f4bd2c2605bbb8e8808666933443f37b6b7d95f15d30e8eff9e1e5599c43518c68c506ddf28272677686ecdfb2a756b50e5501b73bef9fb603379c6a016f8b439d201913164cb06cff".to_string();
        let input = "01107347ea73ddaadbd6eaa83c812752a91bf8927b276a36088796142a6f9b20d2320b1ae8e7327c9e88256911ecf9866f7d8777aa9d8092124f59ddd42716010000ff1d8785c669b57983d0e646adf9312981dbc191395321809d60351585876da0f4259e97d61a4659c2801c8c1ec0dd20a67fe69782b81917e787a212f22d0a4b71f6c1ff41cd303a5d084d244c12b026e3a195826cd99a08377b6a121687d7372fec7c741dd4197bcae5139a87233058d619e5460a00012a529137ff7e92f0d9eeedb39007b17a0b0a8eb20fae8650a6609016287de91f286c8f058f63fc7779b8897a7ff42a9b5e83ed8bf1f18d95caec65d4921b24959732443b14cb3b8c77e46cc8279a44f1a1330711acbe72821f8e3390b708935d18fce7a9afbaf3a796a50cb567e7b7ec619af2bb71eeab31750e26e9509412e153a3e80f52e068b90b9c33ada6d31119d71b61e0bb535b4337b46e5b45f4893296252615ea66fc4c18".to_string();
        let iterations = 1000u64;
        let result = execute(Command::Evaluate(EvaluateArguments {
            discriminant,
            input: input.clone(),
            iterations,
        }))
        .unwrap();
        let expected = "Output: 0110c6c55aa499e1e70915547dee75c60d29a3a1b647f6fe50e0fdf026fee84501dfbeb45c0621efdc3a507553af851eeb5c63b004562be6c82ee6e62f490ea5c440ff10ef494d6352226bf0df8afa8f56c3e5dbf864873d0dd058c8aa8253aca98db72a5ed6844f1ac0d22587d4bee43a110f586034da172d1641a61607a8b6f22802290111c3ac7acb4925b5dac4c4cfcd73c6b9ff00d2f70a6744d013177716354d4ecaf22cd35abf54ebc2fe0a3467ae0a03b7297bd9d4fdaa39ad2ede29f95fc8eee20201000000\nProof:  0110126b982a21de0a3e40a2482dc7fda92dcc701daf92f14a15c9a6b021527102a8e2aef9cdc9321ff117dfc72a0b67b2440d115bd490a74d655cad78b1b5c4cf3eff10bb0dee4be77a0cdd6423fc9a6f9bfd954ad71bc1170ca90188f83ef5d7dabffcb917cef7844e0db3373818c04d693ed596fb1e2383ecf8c1aad58a8da2a29d05011158e3306707d66fa243487cafdc3b14be74333c30592ddd4ce5ab3c83eea42424a0c0fa63574f3b1fa03873bd48f3cf44c94bb13040effb5e076ab1b95efc610401000000";
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
        let discriminant = "ff20278a665865d8633bd6eee07fa6aab37da0d7c0551020c019bee9b735b5e2d150f09394b54a7af3b387d4f6538b9b1933345a8dfada20d0f4bd2c2605bbb8e8808666933443f37b6b7d95f15d30e8eff9e1e5599c43518c68c506ddf28272677686ecdfb2a756b50e5501b73bef9fb603379c6a016f8b439d201913164cb06cff".to_string();
        let iterations = 1000u64;
        let input = "01107347ea73ddaadbd6eaa83c812752a91bf8927b276a36088796142a6f9b20d2320b1ae8e7327c9e88256911ecf9866f7d8777aa9d8092124f59ddd42716010000ff1d8785c669b57983d0e646adf9312981dbc191395321809d60351585876da0f4259e97d61a4659c2801c8c1ec0dd20a67fe69782b81917e787a212f22d0a4b71f6c1ff41cd303a5d084d244c12b026e3a195826cd99a08377b6a121687d7372fec7c741dd4197bcae5139a87233058d619e5460a00012a529137ff7e92f0d9eeedb39007b17a0b0a8eb20fae8650a6609016287de91f286c8f058f63fc7779b8897a7ff42a9b5e83ed8bf1f18d95caec65d4921b24959732443b14cb3b8c77e46cc8279a44f1a1330711acbe72821f8e3390b708935d18fce7a9afbaf3a796a50cb567e7b7ec619af2bb71eeab31750e26e9509412e153a3e80f52e068b90b9c33ada6d31119d71b61e0bb535b4337b46e5b45f4893296252615ea66fc4c18".to_string();
        let output = "0110c6c55aa499e1e70915547dee75c60d29a3a1b647f6fe50e0fdf026fee84501dfbeb45c0621efdc3a507553af851eeb5c63b004562be6c82ee6e62f490ea5c440ff10ef494d6352226bf0df8afa8f56c3e5dbf864873d0dd058c8aa8253aca98db72a5ed6844f1ac0d22587d4bee43a110f586034da172d1641a61607a8b6f22802290111c3ac7acb4925b5dac4c4cfcd73c6b9ff00d2f70a6744d013177716354d4ecaf22cd35abf54ebc2fe0a3467ae0a03b7297bd9d4fdaa39ad2ede29f95fc8eee20201000000".to_string();
        let proof = "0110126b982a21de0a3e40a2482dc7fda92dcc701daf92f14a15c9a6b021527102a8e2aef9cdc9321ff117dfc72a0b67b2440d115bd490a74d655cad78b1b5c4cf3eff10bb0dee4be77a0cdd6423fc9a6f9bfd954ad71bc1170ca90188f83ef5d7dabffcb917cef7844e0db3373818c04d693ed596fb1e2383ecf8c1aad58a8da2a29d05011158e3306707d66fa243487cafdc3b14be74333c30592ddd4ce5ab3c83eea42424a0c0fa63574f3b1fa03873bd48f3cf44c94bb13040effb5e076ab1b95efc610401000000".to_string();
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

    #[test]
    fn test_hash() {
        let discriminant = "ff20278a665865d8633bd6eee07fa6aab37da0d7c0551020c019bee9b735b5e2d150f09394b54a7af3b387d4f6538b9b1933345a8dfada20d0f4bd2c2605bbb8e8808666933443f37b6b7d95f15d30e8eff9e1e5599c43518c68c506ddf28272677686ecdfb2a756b50e5501b73bef9fb603379c6a016f8b439d201913164cb06cff".to_string();
        let seed = "abcd".to_string();
        let result = execute(Command::Hash(HashArguments {
            discriminant: discriminant.clone(),
            message: seed.clone(),
        }))
        .unwrap();
        let expected = "Output: 01107347ea73ddaadbd6eaa83c812752a91bf8927b276a36088796142a6f9b20d2320b1ae8e7327c9e88256911ecf9866f7d8777aa9d8092124f59ddd42716010000ff1d8785c669b57983d0e646adf9312981dbc191395321809d60351585876da0f4259e97d61a4659c2801c8c1ec0dd20a67fe69782b81917e787a212f22d0a4b71f6c1ff41cd303a5d084d244c12b026e3a195826cd99a08377b6a121687d7372fec7c741dd4197bcae5139a87233058d619e5460a00012a529137ff7e92f0d9eeedb39007b17a0b0a8eb20fae8650a6609016287de91f286c8f058f63fc7779b8897a7ff42a9b5e83ed8bf1f18d95caec65d4921b24959732443b14cb3b8c77e46cc8279a44f1a1330711acbe72821f8e3390b708935d18fce7a9afbaf3a796a50cb567e7b7ec619af2bb71eeab31750e26e9509412e153a3e80f52e068b90b9c33ada6d31119d71b61e0bb535b4337b46e5b45f4893296252615ea66fc4c18";
        assert_eq!(expected, result);
    }
}
