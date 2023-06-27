// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

use super::poseidon::PoseidonWrapper;
use crate::circom::CircomPublicInputs;
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::Proof;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::{
    error::FastCryptoError,
    rsa::{Base64UrlUnpadded, Encoding},
};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(test)]
#[path = "unit_tests/zk_login_tests.rs"]
mod zk_login_tests;

const MAX_EXTENDED_ISS_LEN: u8 = 99;
const MAX_EXTENDED_ISS_LEN_B64: u8 = 1 + (4 * (MAX_EXTENDED_ISS_LEN / 3));
const MAX_EXTENDED_AUD_LEN: u8 = 99;
const MAX_EXTENDED_AUD_LEN_B64: u8 = 1 + (4 * (MAX_EXTENDED_AUD_LEN / 3));
const MAX_HEADER_LEN: u8 = 150;
const PACK_WIDTH: u8 = 248;

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
            OAuthProvider::Twitch.get_config().0,
            SupportedKeyClaim::Sub.to_string(),
        ),
        "18523124550523841778801820019979000409432455608728354507022210389496924497355",
    );
    map
});

/// Supported OAuth providers. Must contain "openid" in "scopes_supported"
/// and "public" for "subject_types_supported" instead of "pairwise".
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum OAuthProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
}

/// Struct that contains all the OAuth provider information. A list of them can
/// be retrieved from the JWK endpoint (e.g. <https://www.googleapis.com/oauth2/v3/certs>)
/// and published on the bulletin along with a trusted party's signature.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OAuthProviderContent {
    /// Key type parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
    pub kty: String,
    /// RSA public exponent, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub e: String,
    /// RSA modulus, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub n: String,
    /// Algorithm parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    pub alg: String,
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
}

/// The claims in the body signed by OAuth provider that must
/// be locally unique to the provider and cannot be reassigned.
#[derive(Debug)]
pub enum SupportedKeyClaim {
    /// Subject id representing an unique account for provider.
    Sub,
    /// Email string representing an unique account for provider.
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

/// Necessary value for claim.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub struct Claim {
    name: String,
    value_base64: String,
    index_mod_4: u8,
}

/// A parsed result of all aux inputs.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub struct AuxInputs {
    claims: Vec<Claim>,
    header_base64: String,
    addr_seed: String,
    eph_public_key: Vec<String>,
    max_epoch: u64,
    key_claim_name: String,
    modulus: String,
    #[serde(skip)]
    parsed_masked_content: ParsedMaskedContent,
}

impl AuxInputs {
    /// Validate and parse masked content bytes into the struct and other json strings into the struct.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let inputs: AuxInputs =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(inputs)
    }

    /// Initialize ParsedMaskedContent
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
        self.parsed_masked_content = ParsedMaskedContent::new(&self.header_base64, &self.claims)?;
        Ok(self.to_owned())
    }

    /// Get the max epoch value.
    pub fn get_max_epoch(&self) -> u64 {
        self.max_epoch
    }

    /// Get the address seed in string.
    pub fn get_address_seed(&self) -> &str {
        &self.addr_seed
    }

    /// Get the parsed iss string.
    pub fn get_iss(&self) -> &str {
        &self.parsed_masked_content.iss
    }

    /// Get the parsed aud string.
    pub fn get_aud(&self) -> &str {
        &self.parsed_masked_content.aud
    }

    /// Get the key claim name used.
    pub fn get_key_claim_name(&self) -> &str {
        &self.key_claim_name
    }

    /// Get the parsed kid string.
    pub fn get_kid(&self) -> &str {
        &self.parsed_masked_content.kid
    }

    /// Get the modulus.
    pub fn get_mod(&self) -> &str {
        &self.modulus
    }

    /// Calculate the poseidon hash from 10 selected fields in the aux inputs.
    pub fn calculate_all_inputs_hash(&self) -> Result<String, FastCryptoError> {
        let mut poseidon = PoseidonWrapper::new();
        let addr_seed = to_field(&self.addr_seed)?;
        let eph_public_key_0 = to_field(&self.eph_public_key[0])?;
        let eph_public_key_1 = to_field(&self.eph_public_key[1])?;
        let max_epoch = to_field(&self.max_epoch.to_string())?;
        let key_claim_name_f = to_field(
            SUPPORTED_KEY_CLAIM_TO_FIELD
                .get(&(self.get_iss(), self.get_key_claim_name().to_owned()))
                .ok_or(FastCryptoError::InvalidInput)?,
        )?;
        let iss_f = map_to_field(
            &self.parsed_masked_content.iss_str,
            MAX_EXTENDED_ISS_LEN_B64,
        )?;
        let aud_f = map_to_field(
            &self.parsed_masked_content.aud_str,
            MAX_EXTENDED_AUD_LEN_B64,
        )?;
        let header_f = map_to_field(&self.parsed_masked_content.header, MAX_HEADER_LEN)?;
        let iss_index = to_field(&self.parsed_masked_content.iss_index.to_string())?;
        let aud_index = to_field(&self.parsed_masked_content.aud_index.to_string())?;

        Ok(poseidon
            .hash(vec![
                addr_seed,
                eph_public_key_0,
                eph_public_key_1,
                max_epoch,
                key_claim_name_f,
                iss_f,
                iss_index,
                aud_f,
                aud_index,
                header_f,
            ])?
            .to_string())
    }
}
/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Default, Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct JWTHeader {
    alg: String,
    kid: String,
    typ: String,
}

impl JWTHeader {
    /// Parse the header base64 string into a [struct JWTHeader].
    pub fn new(header_base64: &str) -> Result<Self, FastCryptoError> {
        let header_bytes = Base64UrlUnpadded::decode_vec(header_base64)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        let header_str =
            std::str::from_utf8(&header_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        let header: JWTHeader =
            serde_json::from_str(header_str).map_err(|_| FastCryptoError::InvalidInput)?;
        if header.alg != "RS256" || header.typ != "JWT" {
            return Err(FastCryptoError::GeneralError("Invalid header".to_string()));
        }
        Ok(header)
    }
}

/// A structed of all parsed and validated values from the masked content bytes.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ParsedMaskedContent {
    kid: String,
    header: String,
    iss: String,
    aud: String,
    iss_str: String,
    aud_str: String,
    iss_index: u8,
    aud_index: u8,
}

impl ParsedMaskedContent {
    /// Read a list of Claims and header string and parse them into fields
    /// header, iss, iss_index, aud, aud_index.
    pub fn new(header_base64: &str, claims: &[Claim]) -> Result<Self, FastCryptoError> {
        let header = JWTHeader::new(header_base64)?;
        let mut iss = None;
        let mut aud = None;
        for claim in claims {
            match claim.name.as_str() {
                "iss" => {
                    iss = Some((
                        decode_base64_url(&claim.value_base64, &claim.index_mod_4)?,
                        claim.value_base64.clone(),
                        claim.index_mod_4,
                    ));
                }
                "aud" => {
                    aud = Some((
                        decode_base64_url(&claim.value_base64, &claim.index_mod_4)?,
                        claim.value_base64.clone(),
                        claim.index_mod_4,
                    ));
                }
                _ => {
                    return Err(FastCryptoError::GeneralError(
                        "Invalid claim name".to_string(),
                    ));
                }
            }
        }
        let iss_val = iss
            .ok_or_else(|| FastCryptoError::GeneralError("iss not found in claims".to_string()))?;
        let aud_val = aud
            .ok_or_else(|| FastCryptoError::GeneralError("aud not found in claims".to_string()))?;
        Ok(ParsedMaskedContent {
            kid: header.kid,
            header: header_base64.to_string(),
            iss: verify_extended_claim(&iss_val.0.to_string(), "iss")?,
            aud: verify_extended_claim(&aud_val.0.to_string(), "aud")?,
            iss_str: iss_val.1,
            aud_str: aud_val.1,
            iss_index: iss_val.2,
            aud_index: aud_val.2,
        })
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
    pub fn as_arkworks(&self) -> Result<Vec<Bn254Fr>, FastCryptoError> {
        let mut result = Vec::new();
        for input in &self.inputs {
            match Bn254Fr::from_str(input) {
                Ok(value) => result.push(value),
                Err(_) => return Err(FastCryptoError::InvalidInput),
            }
        }
        Ok(result)
    }

    /// Get the all_inputs_hash as big int string.
    pub fn get_all_inputs_hash(&self) -> Result<&str, FastCryptoError> {
        if self.inputs.len() != 1 {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(&self.inputs[0])
    }
}

/// Parse the extended claim json value to its claim value, using the expected claim key.
fn verify_extended_claim(
    extended_claim: &str,
    expected_key: &str,
) -> Result<String, FastCryptoError> {
    // Last character of each extracted_claim must be '}' or ','
    if !(extended_claim.ends_with('}') || extended_claim.ends_with(',')) {
        return Err(FastCryptoError::GeneralError(
            "Invalid extended claim".to_string(),
        ));
    }

    let json_str = format!("{{{}}}", &extended_claim[..extended_claim.len() - 1]);
    let json: Value = serde_json::from_str(&json_str).map_err(|_| FastCryptoError::InvalidInput)?;
    let value = json
        .as_object()
        .ok_or(FastCryptoError::InvalidInput)?
        .get(expected_key)
        .ok_or(FastCryptoError::InvalidInput)?
        .as_str()
        .ok_or(FastCryptoError::InvalidInput)?;
    Ok(value.to_string())
}

/// Parse the base64 string, add paddings based on offset, and convert to a bytearray.
fn decode_base64_url(s: &str, i: &u8) -> Result<String, FastCryptoError> {
    if s.len() < 2 {
        return Err(FastCryptoError::GeneralError(
            "Base64 string smaller than 2".to_string(),
        ));
    }
    let mut bits = base64_to_bitarray(s);
    let first_char_offset = i % 4;
    match first_char_offset {
        0 => {}
        1 => {
            bits.drain(..2);
        }
        2 => {
            bits.drain(..4);
        }
        _ => {
            return Err(FastCryptoError::GeneralError(
                "Invalid first_char_offset".to_string(),
            ));
        }
    }

    let last_char_offset = (i + s.len() as u8 - 1) % 4;
    match last_char_offset {
        3 => {}
        2 => {
            bits.drain(bits.len() - 2..);
        }
        1 => {
            bits.drain(bits.len() - 4..);
        }
        _ => {
            return Err(FastCryptoError::GeneralError(
                "Invalid last_char_offset".to_string(),
            ));
        }
    }

    if bits.len() % 8 != 0 {
        return Err(FastCryptoError::GeneralError(
            "Invalid bits length".to_string(),
        ));
    }

    Ok(std::str::from_utf8(&bitarray_to_bytearray(&bits))
        .map_err(|_| FastCryptoError::GeneralError("Invalid masked content".to_string()))?
        .to_owned())
}

/// Map a base64 string to a bit array by taking each char's index and covert it to binary form.
fn base64_to_bitarray(input: &str) -> Vec<u8> {
    let base64_url_character_set =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    input
        .chars()
        .flat_map(|c| {
            let index = base64_url_character_set.find(c).unwrap();
            let mut bits = Vec::new();
            for i in 0..6 {
                bits.push(u8::from((index >> (5 - i)) & 1 == 1));
            }
            bits
        })
        .collect()
}

/// Convert a bitarray to a bytearray by taking each 8 bits as a byte.
fn bitarray_to_bytearray(bits: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut current_byte: u8 = 0;
    let mut bits_remaining: u8 = 8;

    for bit in bits.iter() {
        if bit == &1 {
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

/// Calculate the poseidon hash of the field element inputs.
pub fn to_poseidon_hash(inputs: Vec<Bn254Fr>) -> Result<Bn254Fr, FastCryptoError> {
    if inputs.len() <= 15 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        poseidon1.hash(inputs)
    } else if inputs.len() <= 30 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        let hash1 = poseidon1.hash(inputs[0..15].to_vec())?;

        let mut poseidon2 = PoseidonWrapper::new();
        let hash2 = poseidon2.hash(inputs[15..].to_vec())?;

        let mut poseidon3 = PoseidonWrapper::new();
        poseidon3.hash([hash1, hash2].to_vec())
    } else {
        Err(FastCryptoError::GeneralError(
            "Invalid input length for poseidon hash".to_string(),
        ))
    }
}

/// Convert a bigint string to a field element.
fn to_field(val: &str) -> Result<Bn254Fr, FastCryptoError> {
    Bn254Fr::from_str(val).map_err(|_| FastCryptoError::InvalidInput)
}

/// Parse the input to a big int array and calculate the poseidon hash after packing.
fn map_to_field(input: &str, max_size: u8) -> Result<Bn254Fr, FastCryptoError> {
    if input.len() > max_size as usize {
        return Err(FastCryptoError::InvalidInput);
    }
    let num_elements = max_size / (PACK_WIDTH / 8) + 1;
    let in_arr: Vec<BigUint> = input
        .chars()
        .map(|c| BigUint::from_slice(&([c as u32])))
        .collect();
    let packed = pack2(&in_arr, 8, PACK_WIDTH, num_elements)?;
    to_poseidon_hash(packed)
}

/// Helper function to pack field elements from big ints.
fn pack2(
    in_arr: &[BigUint],
    in_width: u8,
    out_width: u8,
    out_count: u8,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    let packed = pack(in_arr, in_width as usize, out_width as usize)?;
    if packed.len() > out_count as usize {
        return Err(FastCryptoError::InvalidInput);
    }
    let mut padded = packed.clone();
    padded.extend(vec![
        to_field("0")?;
        out_count as usize - packed.len() as usize
    ]);
    Ok(padded)
}

/// Helper function to pack field elements from big ints.
fn pack(
    in_arr: &[BigUint],
    in_width: usize,
    out_width: usize,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    let bits = big_int_array_to_bits(in_arr, in_width);
    let extra_bits = if bits.len() % out_width == 0 {
        0
    } else {
        out_width - (bits.len() % out_width)
    };
    let mut bits_padded = bits;
    bits_padded.extend(vec![0; extra_bits]);

    if bits_padded.len() % out_width != 0 {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(bits_padded
        .chunks(out_width)
        .map(|chunk| {
            let st = BigUint::from_radix_be(chunk, 2).unwrap().to_string();
            Bn254Fr::from_str(&st).unwrap()
        })
        .collect())
}

/// Convert a big int array to a bit array with 0 paddings.
fn big_int_array_to_bits(arr: &[BigUint], int_size: usize) -> Vec<u8> {
    let mut bitarray: Vec<u8> = Vec::new();
    for num in arr {
        let mut padded = Vec::new();
        let val = num.to_radix_be(2);

        let extra_bits = if val.len() < int_size {
            int_size - val.len()
        } else {
            0
        };

        padded.extend(vec![0; extra_bits]);
        padded.extend(val);
        bitarray.extend(padded)
    }
    bitarray
}
