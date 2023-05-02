// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto::traits::Signer;
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    encoding::{Encoding, Hex},
    error::FastCryptoError,
    secp256k1::{
        recoverable::Secp256k1RecoverableSignature, Secp256k1KeyPair, Secp256k1PrivateKey,
        Secp256k1PublicKey, Secp256k1Signature,
    },
    secp256r1::{
        recoverable::Secp256r1RecoverableSignature, Secp256r1KeyPair, Secp256r1PrivateKey,
        Secp256r1PublicKey, Secp256r1Signature,
    },
    traits::{KeyPair, RecoverableSigner, ToFromBytes, VerifyRecoverable, VerifyingKey},
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::{
    io::{Error, ErrorKind},
    str::FromStr,
};
#[derive(Parser)]
#[command(name = "sig-cli")]
#[command(about = "Sign or verify a signature using a signature scheme", long_about = None)]
enum Command {
    /// Generate a keypair using the signature scheme with a deterministic seed.
    Keygen(KeygenArguments),

    /// Sign a message using a secret key using the signature scheme.
    Sign(SigningArguments),

    /// Verify the signature against the message and public key using the signature scheme.
    Verify(VerifiyingArguments),
}

#[derive(Parser, Clone)]
struct KeygenArguments {
    /// Name of the signature scheme.
    #[clap(long)]
    scheme: String,
    /// Hex encoded 32-byte seed for deterministic key generation. e.g. 0000000000000000000000000000000000000000000000000000000000000000.
    #[clap(long)]
    seed: String,
}

enum SignatureScheme {
    Ed25519,
    Secp256k1,
    Secp256k1Recoverable,
    Secp256r1,
    Secp256r1Recoverable,
    BLS12381MinSig,
    BLS12381MinPk,
}

impl FromStr for SignatureScheme {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(SignatureScheme::Ed25519),
            "secp256k1" => Ok(SignatureScheme::Secp256k1),
            "secp256k1-rec" => Ok(SignatureScheme::Secp256k1Recoverable),
            "secp256r1" => Ok(SignatureScheme::Secp256r1),
            "secp256r1-rec" => Ok(SignatureScheme::Secp256r1Recoverable),
            "bls12381-minsig" => Ok(SignatureScheme::BLS12381MinSig),
            "bls12381-minpk" => Ok(SignatureScheme::BLS12381MinPk),
            _ => Err(Error::new(ErrorKind::Other, "Invalid signature scheme.")),
        }
    }
}
#[derive(Parser, Clone)]
struct SigningArguments {
    /// The raw message to be signed.
    #[clap(long)]
    msg: String,

    /// Hex encoded secret key string used to sign.
    #[clap(long)]
    secret_key: String,

    /// Name of the signature scheme.
    #[clap(long)]
    scheme: String,
}

#[derive(Parser, Clone)]
struct VerifiyingArguments {
    /// The raw message signed.
    #[clap(short, long)]
    msg: String,

    /// Hex encoded signature to be verified.
    #[clap(long)]
    signature: String,

    /// Public key to verify the signature.
    #[clap(short, long)]
    public_key: String,

    /// Name of the signature scheme.
    #[clap(long)]
    scheme: String,
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
        Command::Keygen(arg) => {
            let arr = Hex::decode(&arg.seed).map_err(|_| FastCryptoError::InvalidInput)?;
            let seed: [u8; 32] = arr.try_into().map_err(|_| FastCryptoError::InvalidInput)?;
            let rng = &mut StdRng::from_seed(seed);

            let (sk, pk) = match SignatureScheme::from_str(&arg.scheme) {
                Ok(SignatureScheme::Ed25519) => {
                    let kp = Ed25519KeyPair::generate(rng);
                    (
                        Hex::encode(kp.copy().private().as_ref()),
                        Hex::encode(kp.public().as_ref()),
                    )
                }
                Ok(SignatureScheme::Secp256k1) | Ok(SignatureScheme::Secp256k1Recoverable) => {
                    let kp = Secp256k1KeyPair::generate(rng);
                    (
                        Hex::encode(kp.copy().private().as_ref()),
                        Hex::encode(kp.public().as_ref()),
                    )
                }
                Ok(SignatureScheme::Secp256r1) | Ok(SignatureScheme::Secp256r1Recoverable) => {
                    let kp = Secp256r1KeyPair::generate(rng);
                    (
                        Hex::encode(kp.copy().private().as_ref()),
                        Hex::encode(kp.public().as_ref()),
                    )
                }
                Ok(SignatureScheme::BLS12381MinSig) => {
                    let kp = fastcrypto::bls12381::min_sig::BLS12381KeyPair::generate(rng);
                    (
                        Hex::encode(kp.copy().private().as_ref()),
                        Hex::encode(kp.public().as_ref()),
                    )
                }
                Ok(SignatureScheme::BLS12381MinPk) => {
                    let kp = fastcrypto::bls12381::min_pk::BLS12381KeyPair::generate(rng);
                    (
                        Hex::encode(kp.copy().private().as_ref()),
                        Hex::encode(kp.public().as_ref()),
                    )
                }
                Err(_) => return Err(FastCryptoError::InvalidInput),
            };
            println!("Private key in hex: {:?}", sk);
            println!("Public key in hex: {:?}", pk);

            Ok(())
        }

        Command::Sign(arg) => {
            let sk = Hex::decode(&arg.secret_key).map_err(|_| FastCryptoError::InvalidInput)?;
            let msg = Hex::decode(&arg.msg).map_err(|_| FastCryptoError::InvalidInput)?;

            let (pk, sig) = match SignatureScheme::from_str(&arg.scheme) {
                Ok(SignatureScheme::Ed25519) => {
                    let kp = Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&sk)?);
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign(&msg).as_ref()),
                    )
                }
                Ok(SignatureScheme::Secp256k1) => {
                    let kp = Secp256k1KeyPair::from(Secp256k1PrivateKey::from_bytes(&sk)?);
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign(&msg).as_ref()),
                    )
                }
                Ok(SignatureScheme::Secp256k1Recoverable) => {
                    let kp = Secp256k1KeyPair::from(Secp256k1PrivateKey::from_bytes(&sk)?);
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign_recoverable(&msg).as_ref()),
                    )
                }
                Ok(SignatureScheme::Secp256r1) => {
                    let kp = Secp256r1KeyPair::from(Secp256r1PrivateKey::from_bytes(&sk)?);
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign(&msg).as_ref()),
                    )
                }
                Ok(SignatureScheme::Secp256r1Recoverable) => {
                    let kp = Secp256r1KeyPair::from(Secp256r1PrivateKey::from_bytes(&sk)?);
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign_recoverable(&msg).as_ref()),
                    )
                }
                Ok(SignatureScheme::BLS12381MinSig) => {
                    let kp = fastcrypto::bls12381::min_sig::BLS12381KeyPair::from(
                        fastcrypto::bls12381::min_sig::BLS12381PrivateKey::from_bytes(&sk)?,
                    );
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign(&msg).as_ref()),
                    )
                }
                Ok(SignatureScheme::BLS12381MinPk) => {
                    let kp = fastcrypto::bls12381::min_pk::BLS12381KeyPair::from(
                        fastcrypto::bls12381::min_pk::BLS12381PrivateKey::from_bytes(&sk)?,
                    );
                    (
                        Hex::encode(kp.public()),
                        Hex::encode(kp.sign(&msg).as_ref()),
                    )
                }
                Err(_) => return Err(FastCryptoError::InvalidInput),
            };
            println!("Signature in hex: {:?}", sig);
            println!("Public key in hex: {:?}", pk);
            Ok(())
        }

        Command::Verify(arg) => {
            let pk = Hex::decode(&arg.public_key).map_err(|_| FastCryptoError::InvalidInput)?;
            let msg = Hex::decode(&arg.msg).map_err(|_| FastCryptoError::InvalidInput)?;
            let sig = Hex::decode(&arg.signature).map_err(|_| FastCryptoError::InvalidInput)?;

            let res = match SignatureScheme::from_str(&arg.scheme) {
                Ok(SignatureScheme::Ed25519) => {
                    let pk = Ed25519PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify(&msg, &Ed25519Signature::from_bytes(&sig)?)
                }
                Ok(SignatureScheme::Secp256k1) => {
                    let pk = Secp256k1PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify(&msg, &Secp256k1Signature::from_bytes(&sig)?)
                }
                Ok(SignatureScheme::Secp256k1Recoverable) => {
                    let pk = Secp256k1PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify_recoverable(&msg, &Secp256k1RecoverableSignature::from_bytes(&sig)?)
                }
                Ok(SignatureScheme::Secp256r1) => {
                    let pk = Secp256r1PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify(&msg, &Secp256r1Signature::from_bytes(&sig)?)
                }
                Ok(SignatureScheme::Secp256r1Recoverable) => {
                    let pk = Secp256r1PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify_recoverable(&msg, &Secp256r1RecoverableSignature::from_bytes(&sig)?)
                }
                Ok(SignatureScheme::BLS12381MinSig) => {
                    let pk = fastcrypto::bls12381::min_sig::BLS12381PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify(
                        &msg,
                        &fastcrypto::bls12381::min_sig::BLS12381Signature::from_bytes(&sig)?,
                    )
                }
                Ok(SignatureScheme::BLS12381MinPk) => {
                    let pk = fastcrypto::bls12381::min_pk::BLS12381PublicKey::from_bytes(&pk)
                        .map_err(|_| FastCryptoError::InvalidInput)?;
                    pk.verify(
                        &msg,
                        &fastcrypto::bls12381::min_pk::BLS12381Signature::from_bytes(&sig)?,
                    )
                }
                Err(_) => return Err(FastCryptoError::InvalidInput),
            };
            println!("Verify result: {:?}", res);
            Ok(())
        }
    }
}
