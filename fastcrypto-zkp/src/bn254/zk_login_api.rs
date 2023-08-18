// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::snark::SNARK;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};

use super::verifier::process_vk_special;
use super::zk_login::{JwkId, ZkLoginInputs, JWK};
use crate::bn254::VerifyingKey as Bn254VerifyingKey;
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;
use im::hashmap::HashMap as ImHashMap;
use once_cell::sync::Lazy;

/// Enum to specify the environment to use for verifying keys.
#[derive(Debug, Clone)]
pub enum ZkLoginEnv {
    /// Use the secure global verifying key derived from ceremony.
    Prod,
    /// Use the insecure global verifying key.
    Test,
}

impl Default for ZkLoginEnv {
    fn default() -> Self {
        Self::Prod
    }
}

/// Produced from ceremony. Secure to use for mainnet.
static GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(random_pvk);
/// Produced from a local trusted setup. Insecure to use for mainnet.
static INSECURE_GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(global_pvk);

// TODO: Replace after ceremony.
fn random_pvk() -> PreparedVerifyingKey<Bn254> {
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
            "18931764958316061396537365316410279129357566768168194299771466990652581507745"
                .to_string(),
            "19589594864158083697499253358172374190940731232487666687594341722397321059767"
                .to_string(),
            "1".to_string(),
        ],
        vec![
            "6267760579143073538587735682191258967573139158461221609828687320377758856284"
                .to_string(),
            "18672820669757254021555424652581702101071897282778751499312181111578447239911"
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

    // Convert the verifying key into the prepared form.
    process_vk_special(&Bn254VerifyingKey(vk)).as_arkworks_pvk()
}

/// Load a fixed verifying key from zkLogin.vkey output. This is based on a local setup and should not use in production.
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
            "7867381425847202568112484563431973323103411930691887303954018406238548242435"
                .to_string(),
            "9248741518501530047280522988482444540196070811288498251337804330766153222468"
                .to_string(),
            "1".to_string(),
        ],
        vec![
            "6921103582886817463237640768843495630434715149818209746147837519636936148422"
                .to_string(),
            "322734211400980047302715221807873863996954295847288894748430574151699272036"
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

    // Convert the verifying key into the prepared form.
    process_vk_special(&Bn254VerifyingKey(vk)).as_arkworks_pvk()
}

/// Entry point for the ZkLogin API.
pub fn verify_zk_login(
    input: &ZkLoginInputs,
    max_epoch: u64,
    eph_pubkey_bytes: &[u8],
    all_jwk: &ImHashMap<JwkId, JWK>,
    env: &ZkLoginEnv,
) -> Result<(), FastCryptoError> {
    // Load the expected JWK based on (iss, kid).
    let (iss, kid) = (input.get_iss().to_string(), input.get_kid().to_string());
    let jwk = all_jwk
        .get(&JwkId::new(iss.clone(), kid.clone()))
        .ok_or_else(|| {
            FastCryptoError::GeneralError(format!("JWK not found ({} - {})", iss, kid))
        })?;

    // Decode modulus to bytes.
    let modulus = Base64UrlUnpadded::decode_vec(&jwk.n).map_err(|_| {
        FastCryptoError::GeneralError("Invalid Base64 encoded jwk modulus".to_string())
    })?;

    // Calculat all inputs hash and passed to the verification function.
    match verify_zk_login_proof_with_fixed_vk(
        env,
        &input.get_proof().as_arkworks(),
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
    usage: &ZkLoginEnv,
    proof: &Proof<Bn254>,
    public_inputs: &[Bn254Fr],
) -> Result<bool, FastCryptoError> {
    let pvk = match usage {
        ZkLoginEnv::Prod => &GLOBAL_VERIFYING_KEY,
        ZkLoginEnv::Test => &INSECURE_GLOBAL_VERIFYING_KEY,
    };
    Groth16::<Bn254>::verify_with_processed_vk(pvk, public_inputs, proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}
