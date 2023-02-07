// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto::vrf::ecvrf::{ECVRFKeyPair, ECVRFPrivateKey, ECVRFProof, ECVRFPublicKey};
use fastcrypto::vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;
use std::io::{Error, ErrorKind};

#[derive(Parser)]
#[command(name = "ecvrf-cli")]
#[command(about = "Elliptic Curve Verifiable Random Function (ECVRF) over Ristretto255 according to draft-irtf-cfrg-vrf-15.", long_about = None)]
enum Command {
    /// Generate a key pair for proving and verification.
    Keygen,

    /// Create an output/hash and a proof.
    Prove(ProveArguments),

    /// Verify an output/hash and a proof.
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct ProveArguments {
    /// The hex encoded input string. May be of arbitrary length but should ideally be at least 16 bytes.
    #[clap(short, long)]
    input: String,

    /// A hex encoding of the secret key. Corresponds to a scalar in Ristretto255 and must be 32 bytes.
    #[clap(short, long)]
    secret_key: String,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// Hex-encoded Sha512 hash of the proof. Must be 64 bytes.
    #[clap(short, long)]
    output: String,

    /// Encoding of the proof to verify. Must be 80 bytes.
    #[clap(short, long)]
    proof: String,

    /// Hex encoding of the input string used to generate the proof. May be of arbitrary length but
    /// should ideally be at least 16 bytes.
    #[clap(short, long)]
    input: String,

    /// The public key corresponding to the secret key used to generate the proof.
    #[clap(short, long)]
    verification_key: String,
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

fn execute(cmd: Command) -> Result<String, std::io::Error> {
    match cmd {
        Command::Keygen => {
            let keypair = ECVRFKeyPair::generate(&mut thread_rng());
            let sk_string =
                hex::encode(bincode::serialize(&keypair.sk).map_err(|_| {
                    Error::new(ErrorKind::Other, "Failed to serialize secret key.")
                })?);
            let pk_string =
                hex::encode(bincode::serialize(&keypair.pk).map_err(|_| {
                    Error::new(ErrorKind::Other, "Failed to serialize public key.")
                })?);

            let mut result = "Secret key: ".to_string();
            result.push_str(&sk_string);
            result.push_str("\nPublic key: ");
            result.push_str(&pk_string);
            Ok(result)
        }

        Command::Prove(arguments) => {
            // Parse inputs
            let secret_key_bytes = hex::decode(arguments.secret_key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid private key."))?;
            let alpha_string = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input string."))?;

            if alpha_string.len() < 16 {
                println!("Warning: Input string should preferably be at least 16 bytes");
            }

            // Create keypair from the secret key bytes
            let secret_key = bincode::deserialize::<ECVRFPrivateKey>(&secret_key_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Failed to parse private key."))?;
            let kp = ECVRFKeyPair::from(secret_key);

            // Generate proof
            let proof = kp.prove(&alpha_string);
            let proof_string = hex::encode(bincode::serialize(&proof).unwrap());
            let proof_hash = hex::encode(proof.to_hash());

            let mut result = "Proof:  ".to_string();
            result.push_str(&proof_string);
            result.push_str("\nOutput: ");
            result.push_str(&proof_hash);
            Ok(result)
        }

        Command::Verify(arguments) => {
            // Parse inputs
            let public_key_bytes = hex::decode(arguments.verification_key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid public key."))?;
            let alpha_string = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input string."))?;
            let proof_bytes = hex::decode(arguments.proof)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid proof string."))?;
            let output_bytes = hex::decode(arguments.output)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output string."))?;
            let output: [u8; 64] = output_bytes
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Output must be 64 bytes."))?;

            // Create public key and proof from parsed bytes
            let public_key: ECVRFPublicKey =
                bincode::deserialize::<ECVRFPublicKey>(&public_key_bytes)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid public key."))?;
            let proof: ECVRFProof = bincode::deserialize::<ECVRFProof>(&proof_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Unable to parse proof."))?;

            if proof
                .verify_output(&alpha_string, &public_key, &output)
                .is_ok()
            {
                return Ok("Proof verified correctly!".to_string());
            }
            Err(Error::new(ErrorKind::Other, "Proof is not correct."))
        }
    }
}
