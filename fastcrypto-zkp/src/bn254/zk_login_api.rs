// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_snark::SNARK;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};

use super::zk_login::{JwkId, ZkLoginInputs, JWK};
use crate::bn254::utils::{gen_address_seed_with_salt_hash, get_zk_login_address};
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
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

/// Corresponding to proofs generated from prover (prod). Produced from ceremony. Secure to use for mainnet.
static GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(global_pvk);

/// Corresponding to proofs generated from prover-dev. Used in devnet/testnet.
static INSECURE_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(insecure_pvk);

/// Load a fixed verifying key from zkLogin.vkey output. This is based on a local setup and should not use in production.
fn insecure_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(&vec![
        "20491192805390485299153009773594534940189261866228447918068658471970481763042".to_string(),
        "9383485363053290200918347156157836566562967994039712273449902621266178545958".to_string(),
        "1".to_string(),
    ])
    .unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&vec![
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
    ])
    .unwrap();
    let vk_gamma_2 = g2_affine_from_str_projective(&vec![
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
    ])
    .unwrap();
    let vk_delta_2 = g2_affine_from_str_projective(&vec![
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
    ])
    .unwrap();

    // Create a vector of G1Affine elements from the IC
    let mut vk_gamma_abc_g1 = Vec::new();
    for e in [
        vec![
            "20701306374481714853949730154526815782802808896228594855451770849676897643964"
                .to_string(),
            "2766989084754673216772682210231588284954002353414778477810174100808747060165"
                .to_string(),
            "1".to_string(),
        ],
        vec![
            "501195541410525737371980194958674422793469475773065719916327137354779402600"
                .to_string(),
            "13527631693157515024233848630878973193664410306029731429350155106228769355415"
                .to_string(),
            "1".to_string(),
        ],
    ] {
        let g1 = g1_affine_from_str_projective(&e).unwrap();
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
    PreparedVerifyingKey::from(vk)
}

/// Load a fixed verifying key from zkLogin.vkey output. This is based on a local setup and should not use in production.
fn global_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(&vec![
        "21529901943976716921335152104180790524318946701278905588288070441048877064089".to_string(),
        "7775817982019986089115946956794180159548389285968353014325286374017358010641".to_string(),
        "1".to_string(),
    ])
    .unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&vec![
        vec![
            "6600437987682835329040464538375790690815756241121776438004683031791078085074"
                .to_string(),
            "16207344858883952201936462217289725998755030546200154201671892670464461194903"
                .to_string(),
        ],
        vec![
            "17943105074568074607580970189766801116106680981075272363121544016828311544390"
                .to_string(),
            "18339640667362802607939727433487930605412455701857832124655129852540230493587"
                .to_string(),
        ],
        vec!["1".to_string(), "0".to_string()],
    ])
    .unwrap();
    let vk_gamma_2 = g2_affine_from_str_projective(&vec![
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
    ])
    .unwrap();
    let vk_delta_2 = g2_affine_from_str_projective(&vec![
        vec![
            "19260309516619721648285279557078789954438346514188902804737557357941293711874"
                .to_string(),
            "2480422554560175324649200374556411861037961022026590718777465211464278308900"
                .to_string(),
        ],
        vec![
            "14489104692423540990601374549557603533921811847080812036788172274404299703364"
                .to_string(),
            "12564378633583954025611992187142343628816140907276948128970903673042690269191"
                .to_string(),
        ],
        vec!["1".to_string(), "0".to_string()],
    ])
    .unwrap();

    // Create a vector of G1Affine elements from the IC
    let mut vk_gamma_abc_g1 = Vec::new();
    for e in [
        vec![
            "1607694606386445293170795095076356565829000940041894770459712091642365695804"
                .to_string(),
            "18066827569413962196795937356879694709963206118612267170825707780758040578649"
                .to_string(),
            "1".to_string(),
        ],
        vec![
            "20653794344898475822834426774542692225449366952113790098812854265588083247207"
                .to_string(),
            "3296759704176575765409730962060698204792513807296274014163938591826372646699"
                .to_string(),
            "1".to_string(),
        ],
    ] {
        let g1 = g1_affine_from_str_projective(&e).unwrap();
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
    PreparedVerifyingKey::from(vk)
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
        &input.get_proof().as_arkworks()?,
        &[input.calculate_all_inputs_hash(eph_pubkey_bytes, &modulus, max_epoch)?],
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(FastCryptoError::GeneralError(
            "Groth16 proof verify failed".to_string(),
        )),
    }
}

/// Verify a proof against its public inputs using the fixed verifying key.
pub fn verify_zk_login_proof_with_fixed_vk(
    usage: &ZkLoginEnv,
    proof: &Proof<Bn254>,
    public_inputs: &[Bn254Fr],
) -> Result<bool, FastCryptoError> {
    let vk = match usage {
        ZkLoginEnv::Prod => &GLOBAL_VERIFYING_KEY,
        ZkLoginEnv::Test => &INSECURE_VERIFYING_KEY,
    };
    Groth16::<Bn254>::verify_with_processed_vk(vk, public_inputs, proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}

/// Verify that the given parameters (name, value, aud, iss and salt_hash) were used to generate the
/// given address.
pub fn verify_zk_login_id(
    address: &[u8],
    name: &str,
    value: &str,
    aud: &str,
    iss: &str,
    salt_hash: &str,
) -> FastCryptoResult<()> {
    let address_seed = gen_address_seed_with_salt_hash(salt_hash, name, value, aud)?;
    verify_zk_login_iss(address, &address_seed, iss)
}

/// Verify that the given parameters (address_seed and iss) were used to generate the given address.
pub fn verify_zk_login_iss(address: &[u8], address_seed: &str, iss: &str) -> FastCryptoResult<()> {
    let reconstructed_address = get_zk_login_address(address_seed, iss)?;
    match reconstructed_address == address {
        true => Ok(()),
        false => Err(FastCryptoError::InvalidProof),
    }
}
