// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::snark::SNARK;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};
use im::hashmap::HashMap as ImHashMap;

use super::verifier::process_vk_special;
use super::zk_login::{OAuthProviderContent, ZkLoginInputs};
use crate::bn254::VerifyingKey as Bn254VerifyingKey;
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;
use once_cell::sync::Lazy;

/// Enum to specify the environment to use for verifying keys.
#[derive(Debug)]
pub enum Environment {
    /// Use the secure global verifying key derived from ceremony.
    Production,
    /// Use the insecure global verifying key.
    Test,
}

// TODO: Replace after ceremony.
static GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(global_pvk);
static INSECURE_GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(global_pvk);

/// Load a fixed verifying key from zklogin.vkey output. This is based on a local setup and should not use in production.
fn global_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(vec![
        "20491192805390485299153009773594534940189261866228447918068658471970481763042".to_string(),
        "9383485363053290200918347156157836566562967994039712273449902621266178545958".to_string(),
        "1".to_string(),
    ]);
    let vk_beta_2 = g2_affine_from_str_projective(vec![
        vec![
            "6375614351688725206403948262868962793625744043794305715222011528459656738731"
                .to_string(),
            "4252822878758300859123897981450591353533073413197771768651442665752259397132"
                .to_string(),
        ],
        vec![
            "10505242626370262277552901082094356697409835680220590971873171140371331206856"
                .to_string(),
            "21847035105528745403288232691147584728191162732299865338377159692350059136679"
                .to_string(),
        ],
        vec!["1".to_string(), "0".to_string()],
    ]);
    let vk_gamma_2 = g2_affine_from_str_projective(vec![
        vec![
            "10857046999023057135944570762232829481370756359578518086990519993285655852781"
                .to_string(),
            "11559732032986387107991004021392285783925812861821192530917403151452391805634"
                .to_string(),
        ],
        vec![
            "8495653923123431417604973247489272438418190587263600148770280649306958101930"
                .to_string(),
            "4082367875863433681332203403145435568316851327593401208105741076214120093531"
                .to_string(),
        ],
        vec!["1".to_string(), "0".to_string()],
    ]);
    let vk_delta_2 = g2_affine_from_str_projective(vec![
        vec![
            "10857046999023057135944570762232829481370756359578518086990519993285655852781"
                .to_string(),
            "11559732032986387107991004021392285783925812861821192530917403151452391805634"
                .to_string(),
        ],
        vec![
            "8495653923123431417604973247489272438418190587263600148770280649306958101930"
                .to_string(),
            "4082367875863433681332203403145435568316851327593401208105741076214120093531"
                .to_string(),
        ],
        vec!["1".to_string(), "0".to_string()],
    ]);

    // Create a vector of G1Affine elements from the IC
    let mut vk_gamma_abc_g1 = Vec::new();
    for e in vec![
        vec![
            "7601221783497382045435100727010102844416767995017297605284115099608422303035"
                .to_string(),
            "8749785198598536603958085261928419291825402152367782685067088145065090991309"
                .to_string(),
            "1".to_string(),
        ],
        vec![
            "2844107402968053321142842260538249836495213364133637503989930436252095154777"
                .to_string(),
            "6671443994502368977962577284247390754840595243304510253358092664535353826787"
                .to_string(),
            "1".to_string(),
        ],
    ] {
        let g1 = g1_affine_from_str_projective(e);
        vk_gamma_abc_g1.push(g1);
    }

    let vk = VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    };

    // Conver thte verifying key into the prepared form.
    process_vk_special(&Bn254VerifyingKey(vk)).as_arkworks_pvk()
}

/// Entry point for the ZkLogin API.
pub fn verify_zk_login(
    input: &ZkLoginInputs,
    max_epoch: u64,
    eph_pubkey_bytes: &[u8],
    all_jwk: &ImHashMap<(String, String), OAuthProviderContent>,
    usage: Environment,
) -> Result<(), FastCryptoError> {
    // Load the expected JWK based on (kid, iss).
    let jwk = all_jwk
        .get(&(input.get_kid().to_string(), input.get_iss().to_string()))
        .ok_or_else(|| FastCryptoError::GeneralError("JWK not found".to_string()))?;

    // Decode modulus to bytes.
    let modulus = Base64UrlUnpadded::decode_vec(&jwk.n).map_err(|_| {
        FastCryptoError::GeneralError("Invalid Base64 encoded jwk modulus".to_string())
    })?;

    // Calculat all inputs hash and passed to the verification function.
    match verify_zk_login_proof_with_fixed_vk(
        usage,
        input.get_proof().as_arkworks(),
        &input.calculate_all_inputs_hash(eph_pubkey_bytes, &modulus, max_epoch)?,
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(FastCryptoError::GeneralError(
            "Groth16 proof verify failed".to_string(),
        )),
    }
}

/// Verify a proof against its public inputs using the fixed verifying key.
fn verify_zk_login_proof_with_fixed_vk(
    usage: Environment,
    proof: Proof<Bn254>,
    public_inputs: &[Bn254Fr],
) -> Result<bool, FastCryptoError> {
    let pvk = match usage {
        Environment::Production => &GLOBAL_VERIFYING_KEY,
        Environment::Test => &INSECURE_GLOBAL_VERIFYING_KEY,
    };
    Groth16::<Bn254>::verify_with_processed_vk(pvk, public_inputs, &proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}
