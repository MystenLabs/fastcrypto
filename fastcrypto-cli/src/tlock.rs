// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{bls12381, GroupElement, HashToGroupElement, Pairing};
use fastcrypto::hash::{Blake2b256, HashFunction, Sha256};
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};

#[derive(Parser)]
#[command(name = "tlock-cli")]
#[command(about = "Basic tlock interface (for quicknet).", long_about = None)]
enum Command {
    Encrypt(EncryptArguments),
    Decrypt(DecryptArguments),
    Verify(VerifyArguments),
}

/// Encrypt a plaintext. Returns a ciphertext (hex).
#[derive(Parser, Clone)]
struct EncryptArguments {
    /// drand round number
    #[clap(short, long)]
    round: u64,

    /// Plaintext to encrypt (hex, 32 bytes)
    #[clap(short, long)]
    plaintext: String,
}

/// Decrypt a ciphertext. Returns a plaintext (hex).
#[derive(Parser, Clone)]
struct DecryptArguments {
    /// Ciphertext to decrypt (hex)
    #[clap(short, long)]
    ciphertext: String,

    /// drand signature for the required round (hex, 48 bytes)
    #[clap(short, long)]
    round_signature: String,
}

/// Verify a drand signature for a given round.
#[derive(Parser, Clone)]
struct VerifyArguments {
    /// drand round number
    #[clap(short, long)]
    round: u64,

    /// drand signature (hex, 48 bytes)
    #[clap(short, long)]
    signature: String,
}

/// An encryption of 32 bytes message following https://eprint.iacr.org/2023/189.pdf.
#[derive(Serialize, Deserialize, Debug)]
struct Encryption {
    u: bls12381::G2Element,
    v: [u8; 32],
    w: [u8; 32],
}

fn drand_pk() -> bls12381::G2Element {
    // The public key from 'curl https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info'
    let pk = hex::decode("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a").unwrap().try_into().unwrap();
    bls12381::G2Element::from_byte_array(&pk).unwrap()
}

fn encode_round(round: &u64) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(round.to_be_bytes());
    sha.finalize().digest
}

fn xor_arrays(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

fn encrypt(round: u64, msg: &[u8]) -> Encryption {
    assert_eq!(msg.len(), 32);
    let pk = drand_pk();
    let target = encode_round(&round);

    // pk_rho = e(H1(target), pk)
    let target_hash = bls12381::G1Element::hash_to_group_element(&target);
    let pk_rho = target_hash.pairing(&pk);

    // r = H3(sigma | m) as a scalar
    let mut sigma: [u8; 32];
    let r: bls12381::Scalar;
    loop {
        sigma = thread_rng().gen();
        let mut hash_function = Blake2b256::default();
        hash_function.update(b"HASH3 - ");
        hash_function.update(&sigma);
        hash_function.update(&msg);
        let hash = hash_function.finalize().digest;
        let r_as_res = bls12381::Scalar::from_byte_array(&hash);
        // rejection sampling until we find a sigma that results in a valid r
        if r_as_res.is_ok() {
            r = r_as_res.unwrap();
            break;
        }
    }

    // U = r*g2
    let u = bls12381::G2Element::generator() * r;

    // V = sigma xor H2(pk_rho^r)
    let pk_rho_r = pk_rho * r;
    let mut hash_function = Blake2b256::default();
    hash_function.update(b"HASH2 - ");
    hash_function.update(&pk_rho_r.to_byte_array());
    let hash = hash_function.finalize().digest;
    let v = xor_arrays(&sigma, &hash).try_into().unwrap();

    // W = m xor H4(sigma)
    let mut hash_function = Blake2b256::default();
    hash_function.update(b"HASH4 - ");
    hash_function.update(&sigma);
    let hash = hash_function.finalize().digest;
    let w = xor_arrays(&msg, &hash).try_into().unwrap();

    Encryption { u, v, w }
}

fn decrypt(enc: Encryption, target_key: bls12381::G1Element) -> Option<Vec<u8>> {
    // sigma_prime = V xor H2(e(target_key, u))
    let e = target_key.pairing(&enc.u);
    let mut hash_function = Blake2b256::default();
    hash_function.update(b"HASH2 - ");
    hash_function.update(&e.to_byte_array());
    let hash = hash_function.finalize().digest;
    let sigma_prime = xor_arrays(&enc.v, &hash);

    // m_prime = W xor H4(sigma_prime)
    let mut hash_function = Blake2b256::default();
    hash_function.update(b"HASH4 - ");
    hash_function.update(&sigma_prime);
    let hash = hash_function.finalize().digest;
    let m_prime = xor_arrays(&enc.w, &hash);

    // r = H3(sigma_prime | m_prime) as a scalar (the paper has a typo)
    let mut hash_function = Blake2b256::default();
    hash_function.update(b"HASH3 - ");
    hash_function.update(&sigma_prime);
    hash_function.update(&m_prime);
    let hash = hash_function.finalize().digest;
    let r =
        bls12381::Scalar::from_byte_array(&hash).expect("sigma was chosen above to guarantee this");

    // U ?= r*g2
    let g2_r = bls12381::G2Element::generator() * r;
    if enc.u == g2_r {
        Some(m_prime)
    } else {
        None
    }
}

fn verify_signature(sig: bls12381::G1Element, round: u64) -> FastCryptoResult<()> {
    let pk = drand_pk();
    let target = encode_round(&round);
    let lhs = bls12381::G1Element::hash_to_group_element(&target).pairing(&pk);
    let rhs = sig.pairing(&bls12381::G2Element::generator());
    if lhs == rhs {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidSignature)
    }
}

fn execute(cmd: Command) -> Result<String, std::io::Error> {
    match cmd {
        Command::Encrypt(arguments) => {
            let round = arguments.round;
            let plaintext = hex::decode(arguments.plaintext)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid plaintext string."))?;
            if plaintext.len() != 32 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Plaintext must be 32 bytes (hex).",
                ));
            }

            let enc = encrypt(round, &plaintext);
            let enc = bcs::to_bytes(&enc).unwrap();

            let mut result = "Encryption: ".to_string();
            result.push_str(&hex::encode(&enc));
            Ok(result)
        }

        Command::Decrypt(arguments) => {
            let ciphertext = hex::decode(arguments.ciphertext)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid ciphertext string."))?;
            let enc = bcs::from_bytes(&ciphertext).unwrap();
            let round_signature: [u8; 48] = hex::decode(arguments.round_signature)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid round_signature (hex)."))?
                .try_into()
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid round_signature (length).")
                })?;
            let round_signature =
                bls12381::G1Element::from_byte_array(&round_signature).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid round_signature (value).")
                })?;

            let decrypted_msg = decrypt(enc, round_signature);

            match decrypted_msg {
                Some(msg) => {
                    let msg = hex::encode(msg);
                    let mut result = "Decrypted message: ".to_string();
                    result.push_str(&msg);
                    Ok(result)
                }
                None => Err(Error::new(ErrorKind::Other, "Decryption failed.")),
            }
        }
        Command::Verify(arguments) => {
            let round = arguments.round;
            let sig = hex::decode(arguments.signature)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid signature (hex)."))?
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid signature (length)."))?;

            let sig = bls12381::G1Element::from_byte_array(&sig)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid signature (value)."))?;

            match verify_signature(sig, round) {
                Ok(_) => Ok("Valid signature.".to_string()),
                Err(_) => Ok("Invalid signature.".to_string()),
            }
        }
    }
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

#[test]
fn test_e2e() {
    // Retreived with 'curl https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/1234'.
    let sig ="a81d4aad15461a0a02b43da857be1d782a2232a3c7bb370a2763e95ce1f2628460b24de2cee7453cd12e43c197ea2f23".to_string();
    let msg = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string();
    let round = 1234;

    let enc = execute(Command::Encrypt(EncryptArguments {
        round,
        plaintext: msg.clone(),
    }))
    .unwrap()["Encryption: ".len()..]
        .to_string();

    execute(Command::Verify(VerifyArguments {
        round,
        signature: sig.clone(),
    }))
    .unwrap();

    let dec = execute(Command::Decrypt(DecryptArguments {
        ciphertext: enc,
        round_signature: sig,
    }))
    .unwrap()["Decrypted message: ".len()..]
        .to_string()
        .to_uppercase();

    assert_eq!(msg, dec);
}
