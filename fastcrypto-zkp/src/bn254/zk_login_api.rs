// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::snark::SNARK;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};
use im::hashmap::HashMap as ImHashMap;
use num_bigint::BigUint;

use super::verifier::process_vk_special;
use super::zk_login::{
    AuxInputs, OAuthProviderContent, PublicInputs, SupportedKeyClaim, ZkLoginProof,
};
use crate::bn254::VerifyingKey as Bn254VerifyingKey;
use crate::{
    bn254::verifier::PreparedVerifyingKey,
    circom::{g1_affine_from_str_projective, g2_affine_from_str_projective},
};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;
use once_cell::sync::Lazy;

static GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey> = Lazy::new(global_pvk);

/// Load a fixed verifying key from zklogin.vkey output from trusted setup
fn global_pvk() -> PreparedVerifyingKey {
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
            "4646159977885290315333074199003995943497097760119603432786031341328349612779"
                .to_string(),
            "16883660321018397536550988255072623983427868378088223250291094422460916984531"
                .to_string(),
            "1".to_string(),
        ],
        vec![
            "6837327174314649334165592796561910467712597348860761363984054398343874430321"
                .to_string(),
            "8986010922336065169810776007712346238931454905016238478271450397492184507492"
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
    process_vk_special(&Bn254VerifyingKey(vk))
}

/// Entry point for the ZkLogin API.
pub fn verify_zk_login(
    proof: &ZkLoginProof,
    public_inputs: &PublicInputs,
    aux_inputs: &AuxInputs,
    eph_pubkey_bytes: &[u8],
    all_jwk: &ImHashMap<(String, String), OAuthProviderContent>,
) -> Result<(), FastCryptoError> {
    if !is_claim_supported(aux_inputs.get_key_claim_name()) {
        return Err(FastCryptoError::GeneralError(
            "Unsupported claim found".to_string(),
        ));
    }

    let jwk = all_jwk
        .get(&(
            aux_inputs.get_kid().to_string(),
            aux_inputs.get_iss().to_string(),
        ))
        .ok_or_else(|| FastCryptoError::GeneralError("JWK not found".to_string()))?;
    let jwk_modulus =
        BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(&jwk.n).map_err(|_| {
            FastCryptoError::GeneralError("Invalid Base64 encoded jwk.n".to_string())
        })?);

    if jwk_modulus.to_string() != aux_inputs.get_mod() || jwk.validate().is_err() {
        return Err(FastCryptoError::GeneralError("Invalid modulus".to_string()));
    }

    if aux_inputs.calculate_all_inputs_hash(eph_pubkey_bytes)?
        != public_inputs.get_all_inputs_hash()?
    {
        return Err(FastCryptoError::GeneralError(
            "Invalid all inputs hash".to_string(),
        ));
    }

    match verify_zk_login_proof_with_fixed_vk(proof, public_inputs) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(FastCryptoError::GeneralError(
            "Groth16 proof verify failed".to_string(),
        )),
    }
}

/// Verify a zk login proof using the fixed verifying key.
fn verify_zk_login_proof_with_fixed_vk(
    proof: &ZkLoginProof,
    public_inputs: &PublicInputs,
) -> Result<bool, FastCryptoError> {
    Groth16::<Bn254>::verify_with_processed_vk(
        &GLOBAL_VERIFYING_KEY.as_arkworks_pvk(),
        &public_inputs.as_arkworks()?,
        &proof.as_arkworks(),
    )
    .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}

/// Return whether the claim string is supported for zk login. Currently only "sub" is supported.
pub fn is_claim_supported(claim_name: &str) -> bool {
    vec![SupportedKeyClaim::Sub.to_string()].contains(&claim_name.to_owned())
}
