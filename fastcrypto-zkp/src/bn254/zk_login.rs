// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::snark::SNARK;
use std::collections::HashMap;
use std::fmt;

use super::{poseidon::PoseidonWrapper, verifier::process_vk_special};
use crate::bn254::VerifyingKey as Bn254VerifyingKey;
use crate::circom::CircomPublicInputs;
use crate::{
    bn254::verifier::PreparedVerifyingKey,
    circom::{g1_affine_from_str_projective, g2_affine_from_str_projective},
};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::{
    error::FastCryptoError,
    rsa::{Base64UrlUnpadded, Encoding},
};
use num_bigint::{BigInt, BigUint};
use once_cell::sync::Lazy;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

#[cfg(test)]
#[path = "unit_tests/zk_login_tests.rs"]
mod zk_login_tests;

static GLOBAL_VERIFYING_KEY: Lazy<PreparedVerifyingKey> = Lazy::new(global_pvk);

/// Hardcoded mapping from the provider and its supported key claim name to its map-to-field Big Int in string.
/// The field value is computed from the max key claim length and its provider.
static SUPPORTED_KEY_CLAIM_TO_FIELD: Lazy<HashMap<(&str, String), &str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        (
            OAuthProvider::Google.get_config().0,
            SupportedKeyClaim::Sub.to_string(),
        ),
        "18523124550523841778801820019979000409432455608728354507022210389496924497355",
    );
    map.insert(
        (
            OAuthProvider::Google.get_config().0,
            SupportedKeyClaim::Email.to_string(),
        ),
        "",
    );
    map.insert(
        (
            OAuthProvider::Twitch.get_config().0,
            SupportedKeyClaim::Sub.to_string(),
        ),
        "",
    );
    map.insert(
        (
            OAuthProvider::Twitch.get_config().0,
            SupportedKeyClaim::Email.to_string(),
        ),
        "",
    );
    map
});

/// Supported OAuth providers. Must contain "openid" in "scopes_supported"
/// and "public" for "subject_types_supported" instead of "pairwise".
#[derive(Debug)]
pub enum OAuthProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
}

impl OAuthProvider {
    /// Returns a tuple of iss string and JWK endpoint string for the given provider.
    pub fn get_config(&self) -> (&str, &str) {
        match self {
            OAuthProvider::Google => (
                "https://accounts.google.com",
                "https://www.googleapis.com/oauth2/v2/certs",
            ),
            OAuthProvider::Twitch => (
                "https://id.twitch.tv/oauth2",
                "https://id.twitch.tv/oauth2/keys",
            ),
        }
    }

    /// Returns the provider for the given iss string.
    pub fn from_iss(iss: &str) -> Result<Self, FastCryptoError> {
        match iss {
            "https://accounts.google.com" => Ok(Self::Google),
            "https://id.twitch.tv/oauth2" => Ok(Self::Twitch),
            _ => Err(FastCryptoError::InvalidInput),
        }
    }
}

/// The claims in the body signed by OAuth provider that must
/// be locally unique to the provider and cannot be reassigned.
#[derive(Debug)]
pub enum SupportedKeyClaim {
    /// Subject id representing an unique account.
    Sub,
    /// Email string representing an unique account.
    Email,
}

impl fmt::Display for SupportedKeyClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupportedKeyClaim::Email => write!(f, "email"),
            SupportedKeyClaim::Sub => write!(f, "sub"),
        }
    }
}

/// Return whether the claim string is supported for zk login.
pub fn is_claim_supported(claim_name: &str) -> bool {
    vec![SupportedKeyClaim::Sub.to_string()].contains(&claim_name.to_owned())
}

/// Verify a zk login proof using the fixed verifying key.
pub fn verify_zk_login_proof_with_fixed_vk(
    proof: &ZkLoginProof,
    public_inputs: &PublicInputs,
) -> Result<bool, FastCryptoError> {
    Groth16::<Bn254>::verify_with_processed_vk(
        &GLOBAL_VERIFYING_KEY.as_arkworks_pvk(),
        &public_inputs.as_arkworks(),
        &proof.as_arkworks(),
    )
    .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}

/// Load a fixed verifying key from zklogin.vkey output from setup
/// https://github.com/MystenLabs/fastcrypto/blob/2a704431e4d2685625c0cc06d19fd7d08a4aafa4/openid-zkp-auth/README.md
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
    process_vk_special(&Bn254VerifyingKey(vk))
}

/// A parsed result of all aux inputs.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub struct AuxInputs {
    addr_seed: String,
    eph_public_key: Vec<String>,
    jwt_sha2_hash: Vec<String>,
    jwt_signature: String,
    key_claim_name: String,
    masked_content: Vec<u8>,
    max_epoch: u64,
    num_sha2_blocks: u8,
    payload_len: u16,
    payload_start_index: u16,
    #[serde(skip)]
    parsed_masked_content: ParsedMaskedContent,
}

impl AuxInputs {
    /// Validate and parse masked content bytes into the struct and other json strings into the struct.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let mut inputs: AuxInputs =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidInput)?;
        inputs.parsed_masked_content = ParsedMaskedContent::new(
            &inputs.masked_content,
            inputs.payload_start_index,
            inputs.payload_len,
            inputs.num_sha2_blocks,
        )?;
        Ok(inputs)
    }

    /// Init ParsedMaskedContent
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
        self.parsed_masked_content = ParsedMaskedContent::new(
            &self.masked_content,
            self.payload_start_index,
            self.payload_len,
            self.num_sha2_blocks,
        )?;
        Ok(self.to_owned())
    }
    /// Get the jwt hash in byte array format.
    pub fn get_jwt_hash(&self) -> Vec<u8> {
        self.jwt_sha2_hash
            .iter()
            .flat_map(|x| big_int_str_to_bytes(x))
            .collect()
    }

    /// Get the ephemeral pubkey in bytes.
    pub fn get_eph_pub_key(&self) -> Vec<u8> {
        self.eph_public_key
            .iter()
            .flat_map(|x| big_int_str_to_bytes(x))
            .collect()
    }

    /// Get the max epoch value.
    pub fn get_max_epoch(&self) -> u64 {
        self.max_epoch
    }

    /// Get jwt signature in bytes.
    pub fn get_jwt_signature(&self) -> Result<Vec<u8>, FastCryptoError> {
        Base64UrlUnpadded::decode_vec(&self.jwt_signature)
            .map_err(|_| FastCryptoError::InvalidInput)
    }

    /// Get the address seed in string.
    pub fn get_address_seed(&self) -> &str {
        &self.addr_seed
    }

    /// Get the iss string.
    pub fn get_iss(&self) -> &str {
        self.parsed_masked_content.get_iss()
    }

    /// Get the client id string.
    pub fn get_client_id(&self) -> &str {
        self.parsed_masked_content.get_client_id()
    }

    /// Get the kid string.
    pub fn get_kid(&self) -> &str {
        self.parsed_masked_content.get_kid()
    }

    /// Get the key claim name string.
    pub fn get_claim_name(&self) -> &str {
        &self.key_claim_name
    }

    /// Calculate the poseidon hash from 10 selected fields in the aux inputs.
    pub fn calculate_all_inputs_hash(&self) -> Result<String, FastCryptoError> {
        // TODO(joyqvq): check each string for bigint is valid.
        let mut poseidon = PoseidonWrapper::new();
        let jwt_sha2_hash_0 = Bn254Fr::from_str(&self.jwt_sha2_hash[0]).unwrap();
        let jwt_sha2_hash_1 = Bn254Fr::from_str(&self.jwt_sha2_hash[1]).unwrap();
        let masked_content_hash = Bn254Fr::from_str(&self.parsed_masked_content.hash).unwrap();
        let payload_start_index = Bn254Fr::from_str(&self.payload_start_index.to_string()).unwrap();
        let payload_len = Bn254Fr::from_str(&self.payload_len.to_string()).unwrap();
        let eph_public_key_0 = Bn254Fr::from_str(&self.eph_public_key[0]).unwrap();
        let eph_public_key_1 = Bn254Fr::from_str(&self.eph_public_key[1]).unwrap();
        let max_epoch = Bn254Fr::from_str(&self.max_epoch.to_string()).unwrap();
        let num_sha2_blocks = Bn254Fr::from_str(&self.num_sha2_blocks.to_string()).unwrap();
        let addr_seed = Bn254Fr::from_str(&self.addr_seed.to_string()).unwrap();
        let key_claim_name_f = Bn254Fr::from_str(
            SUPPORTED_KEY_CLAIM_TO_FIELD
                .get(&(self.get_iss(), self.get_claim_name().to_owned()))
                .unwrap(),
        )
        .unwrap();
        Ok(poseidon
            .hash(vec![
                jwt_sha2_hash_0,
                jwt_sha2_hash_1,
                masked_content_hash,
                payload_start_index,
                payload_len,
                eph_public_key_0,
                eph_public_key_1,
                max_epoch,
                num_sha2_blocks,
                key_claim_name_f,
                addr_seed,
            ])?
            .to_string())
    }
}

/// A structed of all parsed and validated values from the masked content bytes.
#[derive(Default, Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct ParsedMaskedContent {
    header: JWTHeader,
    iss: String,
    client_id: String,
    hash: String,
}

/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Default, Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct JWTHeader {
    alg: String,
    kid: String,
    typ: String,
}

impl ParsedMaskedContent {
    /// Parse the masked content bytes into a [struct ParsedMaskedContent].
    /// payload_start_index, payload_len, num_sha2_blocks are used for
    /// validation and parsing.
    pub fn new(
        masked_content: &[u8],
        payload_start_index: u16,
        payload_len: u16,
        num_sha2_blocks: u8,
    ) -> Result<Self, FastCryptoError> {
        // Verify the bytes after 64 * num_sha2_blocks should be all 0s.
        if !masked_content
            .get(64 * num_sha2_blocks as usize..)
            .ok_or(FastCryptoError::InvalidInput)?
            .iter()
            .all(|&x| x == 0)
        {
            return Err(FastCryptoError::GeneralError(
                "Incorrect payload padding".to_string(),
            ));
        }

        let masked_content_tmp = masked_content
            .get(..64 * num_sha2_blocks as usize)
            .ok_or(FastCryptoError::InvalidInput)?;

        // Verify the byte at payload start index is indeed b'.'.
        if payload_start_index < 1
            || masked_content_tmp.get(payload_start_index as usize - 1) != Some(&b'.')
        {
            return Err(FastCryptoError::GeneralError(
                "Incorrect payload index for separator".to_string(),
            ));
        }

        let header = parse_and_validate_header(
            masked_content_tmp
                .get(0..payload_start_index as usize - 1)
                .ok_or_else(|| {
                    FastCryptoError::GeneralError(
                        "Invalid payload index to parse header".to_string(),
                    )
                })?,
        )?;

        // Parse the jwt length from the last 8 bytes of the masked content.
        let jwt_length_bytes = masked_content_tmp
            .get(masked_content_tmp.len() - 8..)
            .ok_or_else(|| FastCryptoError::GeneralError("Invalid last 8 bytes".to_string()))?;
        let jwt_length = calculate_value_from_bytearray(jwt_length_bytes);

        // Verify the jwt length equals to 8*(payload_start_index + payload_len).
        if jwt_length != 8 * (payload_start_index as usize + payload_len as usize) {
            return Err(FastCryptoError::GeneralError(
                "Incorrect jwt length".to_string(),
            ));
        }

        // Parse sha2 pad into a bit array.
        let sha_2_pad = bytearray_to_bits(
            &masked_content_tmp[payload_start_index as usize + payload_len as usize..],
        );

        // Verify that the first bit of the bit array of sha2 pad is 1.
        if !sha_2_pad[0] {
            return Err(FastCryptoError::GeneralError(
                "Incorrect sha2 padding".to_string(),
            ));
        }

        // Verify the count of 0s in the sha2 pad bit array satifies the condition
        // with the jwt length.
        validate_zeros_count(&sha_2_pad, jwt_length)?;

        // Splits the masked payload into 3 parts (that reveals iss, aud, nonce respectively)
        // separated by a delimiter of "=" of any length. With padding etc
        let parts = find_parts_and_indices(
            &masked_content_tmp
                [payload_start_index as usize..payload_start_index as usize + payload_len as usize],
        )?;

        Ok(Self {
            header,
            iss: parts[0].to_string(),
            client_id: parts[1].to_string(),
            hash: calculate_merklized_hash(masked_content)?,
        })
    }

    /// Get the iss string value.
    pub fn get_iss(&self) -> &str {
        &self.iss
    }

    /// Get the kid string value.
    pub fn get_kid(&self) -> &str {
        &self.header.kid
    }

    /// Get the client id string value.
    pub fn get_client_id(&self) -> &str {
        &self.client_id
    }
}

/// The zk login proof.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    protocol: String,
}

impl ZkLoginProof {
    /// Parse the proof from a json string.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let proof: ZkLoginProof =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidProof)?;
        match proof.protocol == "groth16" {
            true => Ok(proof),
            false => Err(FastCryptoError::InvalidProof),
        }
    }

    /// Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    pub fn as_arkworks(&self) -> Proof<Bn254> {
        let a = g1_affine_from_str_projective(self.pi_a.clone());
        let b = g2_affine_from_str_projective(self.pi_b.clone());
        let c = g1_affine_from_str_projective(self.pi_c.clone());
        Proof { a, b, c }
    }
}

/// The public inputs containing an array of string that is the all inputs hash.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct PublicInputs {
    inputs: Vec<String>, // Represented the public inputs in canonical serialized form.
}

impl PublicInputs {
    /// Parse the public inputs from a json string.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let inputs: CircomPublicInputs =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidProof)?;
        Ok(Self { inputs })
    }

    /// Convert the public inputs into arkworks format.
    pub fn as_arkworks(&self) -> Vec<Bn254Fr> {
        // TODO(joyqvq): check safety for valid bigint string.
        self.inputs
            .iter()
            .map(|x| Bn254Fr::from_str(x).unwrap())
            .collect()
    }

    /// Get the all_inputs_hash as big int string.
    pub fn get_all_inputs_hash(&self) -> &str {
        &self.inputs[0]
    }
}

/// Parse the ascii string from the input bytearray and split it by delimiter "=" of any
/// length. Return a list of the split parts and a list of start indices of each part.
fn find_parts_and_indices(input: &[u8]) -> Result<Vec<String>, FastCryptoError> {
    let input_str = std::str::from_utf8(input)
        .map_err(|_| FastCryptoError::GeneralError("Invalid masked content".to_string()))?;
    let re = Regex::new("=+").expect("Regex string should be valid");

    let mut chunks = Vec::new();
    let mut start_idx = 0;

    for mat in re.find_iter(input_str) {
        let end_idx = mat.start();
        if start_idx < end_idx {
            if start_idx % 4 == 3 || end_idx % 4 == 0 {
                return Err(FastCryptoError::GeneralError(
                    "Invalid start or end index".to_string(),
                ));
            }
            let mut chunk_in_bits: Vec<bool> = base64_to_bitarray(&input_str[start_idx..end_idx]);
            let original_len = chunk_in_bits.len();
            if start_idx % 4 == 1 {
                chunk_in_bits.drain(..2);
            } else if start_idx % 4 == 2 {
                chunk_in_bits.drain(..4);
            }

            if end_idx % 4 == 1 {
                chunk_in_bits.drain(original_len - 4..);
            } else if end_idx % 4 == 2 {
                chunk_in_bits.drain(original_len - 2..);
            };

            let bytearray = bits_to_bytes(&chunk_in_bits);
            let input_str = std::str::from_utf8(&bytearray).map_err(|_| {
                FastCryptoError::GeneralError("Invalid bytearray from tweaked bits".to_string())
            })?;
            chunks.push(input_str.to_string());
        }
        start_idx = mat.end();
    }
    Ok(vec![
        find_value(&chunks[0], "\"iss\":\"", "\",")?,
        find_value(&chunks[1], "\"aud\":\"", "\",")?,
    ])
}

/// Given a part in string, find the value between the prefix and suffix.
/// The index value is used to decide the number of '0' needed to pad to
/// make the parts an valid Base64 encoding.
fn find_value(ascii_string: &str, prefix: &str, suffix: &str) -> Result<String, FastCryptoError> {
    let start = ascii_string
        .find(prefix)
        .ok_or_else(|| FastCryptoError::GeneralError("Invalid parts prefix".to_string()))?
        + prefix.len();
    let end = ascii_string[start..]
        .find(suffix)
        .ok_or_else(|| FastCryptoError::GeneralError("Invalid ascii suffix".to_string()))?
        + start;
    Ok(ascii_string[start..end].to_string())
}

/// Count the number of 0s in the bit array and check if the count satifies as the
/// smallest, non-negative solution to equation jwt_length + 1 + K = 448 (mod 512).
/// See more at 4.1(b) https://datatracker.ietf.org/doc/html/rfc4634#section-4.1
fn validate_zeros_count(arr: &[bool], jwt_length: usize) -> Result<(), FastCryptoError> {
    // Count the number of 0s in the bitarray excluding the last 8 bytes (64 bits).
    let count = arr.iter().take(arr.len() - 64).filter(|&bit| !bit).count();
    if (jwt_length + 1 + count) % 512 == 448 && count < 512 {
        Ok(())
    } else {
        Err(FastCryptoError::GeneralError(
            "Invalid bitarray".to_string(),
        ))
    }
}

/// Map a base64 string to a bit array by taking each char's index and covert it to binary form.
fn base64_to_bitarray(input: &str) -> Vec<bool> {
    let base64_url_character_set =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    input
        .chars()
        .flat_map(|c| {
            let index = base64_url_character_set.find(c).unwrap();
            let mut bits = Vec::new();
            for i in 0..6 {
                bits.push((index >> (5 - i)) & 1 == 1);
            }
            bits
        })
        .collect()
}

/// Convert a bitarray to a bytearray.
fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut current_byte: u8 = 0;
    let mut bits_remaining: u8 = 8;

    for bit in bits.iter() {
        if *bit {
            current_byte |= 1 << (bits_remaining - 1);
        }
        bits_remaining -= 1;
        if bits_remaining == 0 {
            bytes.push(current_byte);
            current_byte = 0;
            bits_remaining = 8;
        }
    }

    if bits_remaining < 8 {
        bytes.push(current_byte);
    }

    bytes
}

/// Convert a big int string to a big endian bytearray.
pub fn big_int_str_to_bytes(value: &str) -> Vec<u8> {
    BigInt::from_str(value)
        .expect("Invalid big int string")
        .to_bytes_be()
        .1
}

/// Calculate the integer value from the bytearray.
fn calculate_value_from_bytearray(arr: &[u8]) -> usize {
    let sized: [u8; 8] = arr.try_into().expect("Invalid byte array");
    ((sized[7] as u16) | (sized[6] as u16) << 8).into()
}

/// Given a chunk of bytearray, parse it as an ascii string and decode as a JWTHeader.
/// Return the JWTHeader if its fields are valid.
fn parse_and_validate_header(chunk: &[u8]) -> Result<JWTHeader, FastCryptoError> {
    let header_str = std::str::from_utf8(chunk)
        .map_err(|_| FastCryptoError::GeneralError("Cannot parse header string".to_string()))?;
    let decoded_header = Base64UrlUnpadded::decode_vec(header_str)
        .map_err(|_| FastCryptoError::GeneralError("Invalid jwt header".to_string()))?;
    let json_header: Value = serde_json::from_slice(&decoded_header)
        .map_err(|_| FastCryptoError::GeneralError("Invalid json".to_string()))?;
    let header: JWTHeader = serde_json::from_value(json_header)
        .map_err(|_| FastCryptoError::GeneralError("Cannot parse jwt header".to_string()))?;
    if header.alg != "RS256" || header.typ != "JWT" {
        Err(FastCryptoError::GeneralError("Invalid header".to_string()))
    } else {
        Ok(header)
    }
}

/// Calculate the merklized hash of the given bytes after 0 paddings.
pub fn calculate_merklized_hash(bytes: &[u8]) -> Result<String, FastCryptoError> {
    let mut bitarray = bytearray_to_bits(bytes);
    pad_bitarray(&mut bitarray, 248);
    let bigints = convert_to_bigints(&bitarray, 248);
    to_poseidon_hash(bigints)
}

/// Calculate the hash of the inputs.
pub fn to_poseidon_hash(inputs: Vec<Bn254Fr>) -> Result<String, FastCryptoError> {
    if inputs.len() <= 15 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        Ok(poseidon1.hash(inputs)?.to_string())
    } else if inputs.len() <= 30 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        let hash1 = poseidon1.hash(inputs[0..15].to_vec())?;

        let mut poseidon2 = PoseidonWrapper::new();
        let hash2 = poseidon2.hash(inputs[15..].to_vec())?;

        let mut poseidon3 = PoseidonWrapper::new();
        let hash_final = poseidon3.hash([hash1, hash2].to_vec());

        Ok(hash_final?.to_string())
    } else {
        Err(FastCryptoError::InvalidInput)
    }
}
/// Convert a bytearray to a bitarray.
fn bytearray_to_bits(bytearray: &[u8]) -> Vec<bool> {
    bytearray
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect()
}

/// Convert a bitarray to a bytearray.
fn bitarray_to_string(bitarray: &[bool]) -> Vec<u8> {
    bitarray.iter().map(|&b| u8::from(b)).collect()
}

/// Pad the bitarray some number of 0s so that its length is a multiple of the segment size.
fn pad_bitarray(bitarray: &mut Vec<bool>, segment_size: usize) {
    let remainder = bitarray.len() % segment_size;
    if remainder != 0 {
        bitarray.extend(std::iter::repeat(false).take(segment_size - remainder));
    }
}

/// Convert a bitarray to a vector of field elements, padded using segment size.
fn convert_to_bigints(bitarray: &[bool], segment_size: usize) -> Vec<Bn254Fr> {
    let chunks = bitarray.chunks(segment_size);
    chunks
        .map(|chunk| {
            let mut bytes = vec![0; (segment_size + 7) / 8];
            for (i, &bit) in chunk.iter().enumerate() {
                bytes[i / 8] |= (bit as u8) << (7 - i % 8);
            }
            let f = bitarray_to_string(chunk);
            let st = BigUint::from_radix_be(&f, 2).unwrap().to_string();
            Bn254Fr::from_str(&st).unwrap()
        })
        .collect()
}
