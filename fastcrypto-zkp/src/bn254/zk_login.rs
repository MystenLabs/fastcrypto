// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::{error::FastCryptoResult, jwt_utils::JWTHeader};
use reqwest::Client;
use serde_json::Value;

use super::utils::split_to_two_frs;
use crate::bn254::poseidon::poseidon_zk_login;
use crate::circom::{
    g1_affine_from_str_projective, g2_affine_from_str_projective, CircomG1, CircomG2,
};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_ff::Zero;
use ark_groth16::Proof;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;
use num_bigint::BigUint;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(test)]
#[path = "unit_tests/zk_login_tests.rs"]
mod zk_login_tests;

#[cfg(feature = "e2e")]
#[cfg(test)]
#[path = "unit_tests/zk_login_e2e_tests.rs"]
mod zk_login_e2e_tests;

const MAX_HEADER_LEN: u8 = 248;
const PACK_WIDTH: u8 = 248;
const ISS: &str = "iss";
const BASE64_URL_CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const MAX_EXT_ISS_LEN: u8 = 165;
const MAX_ISS_LEN_B64: u8 = 4 * (1 + MAX_EXT_ISS_LEN / 3);

/// Key to identify a JWK, consists of iss and kid.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct JwkId {
    /// iss string that identifies the OIDC provider.
    pub iss: String,
    /// kid string that identifies the JWK.
    pub kid: String,
}

impl JwkId {
    /// Create a new JwkId.
    pub fn new(iss: String, kid: String) -> Self {
        Self { iss, kid }
    }
}

/// The provider config consists of iss string and jwk endpoint.
#[derive(Debug)]
pub struct ProviderConfig {
    /// iss string that identifies the OIDC provider.
    pub iss: String,
    /// The JWK url string for the given provider.
    pub jwk_endpoint: String,
}

impl ProviderConfig {
    /// Create a new provider config.
    pub fn new(iss: &str, jwk_endpoint: &str) -> Self {
        Self {
            iss: iss.to_string(),
            jwk_endpoint: jwk_endpoint.to_string(),
        }
    }
}

/// Supported OIDC providers.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum OIDCProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
    /// See https://www.facebook.com/.well-known/openid-configuration/
    Facebook,
    /// See https://kauth.kakao.com/.well-known/openid-configuration
    Kakao,
    /// See https://appleid.apple.com/.well-known/openid-configuration
    Apple,
    /// See https://slack.com/.well-known/openid-configuration
    Slack,
}

impl FromStr for OIDCProvider {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Google" => Ok(Self::Google),
            "Twitch" => Ok(Self::Twitch),
            "Facebook" => Ok(Self::Facebook),
            "Kakao" => Ok(Self::Kakao),
            "Apple" => Ok(Self::Apple),
            "Slack" => Ok(Self::Slack),
            _ => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl ToString for OIDCProvider {
    fn to_string(&self) -> String {
        match self {
            Self::Google => "Google".to_string(),
            Self::Twitch => "Twitch".to_string(),
            Self::Facebook => "Facebook".to_string(),
            Self::Kakao => "Kakao".to_string(),
            Self::Apple => "Apple".to_string(),
            Self::Slack => "Slack".to_string(),
        }
    }
}

impl OIDCProvider {
    /// Returns the provider config consisting of iss and jwk endpoint.
    pub fn get_config(&self) -> ProviderConfig {
        match self {
            OIDCProvider::Google => ProviderConfig::new(
                "https://accounts.google.com",
                "https://www.googleapis.com/oauth2/v2/certs",
            ),
            OIDCProvider::Twitch => ProviderConfig::new(
                "https://id.twitch.tv/oauth2",
                "https://id.twitch.tv/oauth2/keys",
            ),
            OIDCProvider::Facebook => ProviderConfig::new(
                "https://www.facebook.com",
                "https://www.facebook.com/.well-known/oauth/openid/jwks/",
            ),
            OIDCProvider::Kakao => ProviderConfig::new(
                "https://kauth.kakao.com",
                "https://kauth.kakao.com/.well-known/jwks.json",
            ),
            OIDCProvider::Apple => ProviderConfig::new(
                "https://appleid.apple.com",
                "https://appleid.apple.com/auth/keys",
            ),
            OIDCProvider::Slack => {
                ProviderConfig::new("https://slack.com", "https://slack.com/openid/connect/keys")
            }
        }
    }

    /// Returns the OIDCProvider for the given iss string.
    pub fn from_iss(iss: &str) -> Result<Self, FastCryptoError> {
        match iss {
            "https://accounts.google.com" => Ok(Self::Google),
            "https://id.twitch.tv/oauth2" => Ok(Self::Twitch),
            "https://www.facebook.com" => Ok(Self::Facebook),
            "https://kauth.kakao.com" => Ok(Self::Kakao),
            "https://appleid.apple.com" => Ok(Self::Apple),
            "https://slack.com" => Ok(Self::Slack),
            _ => Err(FastCryptoError::InvalidInput),
        }
    }
}

/// Struct that contains info for a JWK. A list of them for different kids can
/// be retrieved from the JWK endpoint (e.g. <https://www.googleapis.com/oauth2/v3/certs>).
/// The JWK is used to verify the JWT token.
#[derive(PartialEq, Eq, Hash, Debug, Clone, Serialize, Deserialize, PartialOrd, Ord)]
pub struct JWK {
    /// Key type parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
    pub kty: String,
    /// RSA public exponent, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub e: String,
    /// RSA modulus, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub n: String,
    /// Algorithm parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    pub alg: String,
}

/// Reader struct to parse all fields in a JWK from JSON.
#[derive(Debug, Serialize, Deserialize)]
pub struct JWKReader {
    e: String,
    n: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    my_use: Option<String>,
    kid: String,
    kty: String,
    alg: String,
}

impl JWK {
    /// Parse JWK from the reader struct.
    pub fn from_reader(reader: JWKReader) -> FastCryptoResult<Self> {
        let trimmed_e = trim(reader.e);
        if reader.alg != "RS256" || reader.kty != "RSA" || trimmed_e != "AQAB" {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self {
            kty: reader.kty,
            e: trimmed_e,
            n: trim(reader.n),
            alg: reader.alg,
        })
    }
}

/// Trim trailing '=' so that it is considered a valid base64 url encoding string by base64ct library.
fn trim(str: String) -> String {
    str.trim_end_matches('=').to_owned()
}

/// Fetch JWKs from the given provider and return a list of JwkId -> JWK.
pub async fn fetch_jwks(
    provider: &OIDCProvider,
    client: &Client,
) -> Result<Vec<(JwkId, JWK)>, FastCryptoError> {
    let response = client
        .get(provider.get_config().jwk_endpoint)
        .send()
        .await
        .map_err(|e| {
            FastCryptoError::GeneralError(format!(
                "Failed to get JWK {:?} {:?}",
                e.to_string(),
                provider
            ))
        })?;
    let bytes = response.bytes().await.map_err(|e| {
        FastCryptoError::GeneralError(format!(
            "Failed to get bytes {:?} {:?}",
            e.to_string(),
            provider
        ))
    })?;
    parse_jwks(&bytes, provider)
}

/// Parse the JWK bytes received from the given provider and return a list of JwkId -> JWK.
pub fn parse_jwks(
    json_bytes: &[u8],
    provider: &OIDCProvider,
) -> Result<Vec<(JwkId, JWK)>, FastCryptoError> {
    let json_str = String::from_utf8_lossy(json_bytes);
    let parsed_list: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&json_str);
    if let Ok(parsed_list) = parsed_list {
        if let Some(keys) = parsed_list["keys"].as_array() {
            let mut ret = Vec::new();
            for k in keys {
                let parsed: JWKReader = serde_json::from_value(k.clone())
                    .map_err(|_| FastCryptoError::GeneralError("Parse error".to_string()))?;

                ret.push((
                    JwkId::new(provider.get_config().iss, parsed.kid.clone()),
                    JWK::from_reader(parsed)?,
                ));
            }
            return Ok(ret);
        }
    }
    Err(FastCryptoError::GeneralError(
        "Invalid JWK response".to_string(),
    ))
}

/// A claim consists of value and index_mod_4.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    value: String,
    index_mod_4: u8,
}

/// A structed of parsed JWT details, consists of kid, header, iss.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct JWTDetails {
    kid: String,
    header: String,
    iss: String,
}

impl JWTDetails {
    /// Read in the Claim and header string. Parse and validate kid, header, iss as JWT details.
    pub fn new(header_base64: &str, claim: &Claim) -> Result<Self, FastCryptoError> {
        let header = JWTHeader::new(header_base64)?;
        let ext_claim = decode_base64_url(&claim.value, &claim.index_mod_4)?;
        Ok(JWTDetails {
            kid: header.kid,
            header: header_base64.to_string(),
            iss: verify_extended_claim(&ext_claim, ISS)?,
        })
    }
}

/// All inputs required for the zk login proof verification and other public inputs.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]

pub struct ZkLoginInputs {
    proof_points: ZkLoginProof,
    iss_base64_details: Claim,
    header_base64: String,
    address_seed: String,
    #[serde(skip)]
    jwt_details: JWTDetails,
}

/// The reader struct for the proving service response.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkLoginInputsReader {
    proof_points: ZkLoginProof,
    iss_base64_details: Claim,
    header_base64: String,
    #[serde(skip)]
    jwt_details: JWTDetails,
}

impl ZkLoginInputs {
    /// Parse the proving service response and pass in the address seed. Initialize the jwt details struct.
    pub fn from_json(value: &str, address_seed: &str) -> Result<Self, FastCryptoError> {
        let reader: ZkLoginInputsReader =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidInput)?;
        Self::from_reader(reader, address_seed)
    }

    /// Initialize ZkLoginInputs from the
    pub fn from_reader(
        reader: ZkLoginInputsReader,
        address_seed: &str,
    ) -> Result<Self, FastCryptoError> {
        ZkLoginInputs {
            proof_points: reader.proof_points,
            iss_base64_details: reader.iss_base64_details,
            header_base64: reader.header_base64,
            address_seed: address_seed.to_owned(),
            jwt_details: reader.jwt_details,
        }
        .init()
    }

    /// Initialize JWTDetails by parsing header_base64 and iss_base64_details.
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
        if BigUint::from_str(&self.address_seed).is_err() {
            return Err(FastCryptoError::InvalidInput);
        }
        self.jwt_details = JWTDetails::new(&self.header_base64, &self.iss_base64_details)?;
        Ok(self.to_owned())
    }

    /// Get the parsed kid string.
    pub fn get_kid(&self) -> &str {
        &self.jwt_details.kid
    }

    /// Get the parsed iss string.
    pub fn get_iss(&self) -> &str {
        &self.jwt_details.iss
    }

    /// Get the zk login proof.
    pub fn get_proof(&self) -> &ZkLoginProof {
        &self.proof_points
    }

    /// Get the address seed string.
    pub fn get_address_seed(&self) -> &str {
        &self.address_seed
    }

    /// Calculate the poseidon hash from selected fields from inputs, along with the ephemeral pubkey.
    pub fn calculate_all_inputs_hash(
        &self,
        eph_pk_bytes: &[u8],
        modulus: &[u8],
        max_epoch: u64,
    ) -> Result<Bn254Fr, FastCryptoError> {
        if self.header_base64.len() > MAX_HEADER_LEN as usize {
            return Err(FastCryptoError::GeneralError("Header too long".to_string()));
        }

        let addr_seed = to_field(&self.address_seed)?;
        let (first, second) = split_to_two_frs(eph_pk_bytes)?;

        let max_epoch_f = to_field(&max_epoch.to_string())?;
        let index_mod_4_f = to_field(&self.iss_base64_details.index_mod_4.to_string())?;

        let iss_base64_f =
            hash_ascii_str_to_field(&self.iss_base64_details.value, MAX_ISS_LEN_B64)?;
        let header_f = hash_ascii_str_to_field(&self.header_base64, MAX_HEADER_LEN)?;
        let modulus_f = hash_to_field(&[BigUint::from_bytes_be(modulus)], 2048, PACK_WIDTH)?;
        poseidon_zk_login(vec![
            first,
            second,
            addr_seed,
            max_epoch_f,
            iss_base64_f,
            index_mod_4_f,
            header_f,
            modulus_f,
        ])
    }
}
/// The struct for zk login proof.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginProof {
    a: CircomG1,
    b: CircomG2,
    c: CircomG1,
}

impl ZkLoginProof {
    /// Parse the proof from a json string.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let proof: ZkLoginProof =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidProof)?;
        Ok(proof)
    }

    /// Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    pub fn as_arkworks(&self) -> Result<Proof<Bn254>, FastCryptoError> {
        Ok(Proof {
            a: g1_affine_from_str_projective(&self.a)?,
            b: g2_affine_from_str_projective(&self.b)?,
            c: g1_affine_from_str_projective(&self.c)?,
        })
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
    match i {
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
        .map_err(|_| FastCryptoError::GeneralError("Invalid UTF8 string".to_string()))?
        .to_owned())
}

/// Map a base64 string to a bit array by taking each char's index and covert it to binary form.
fn base64_to_bitarray(input: &str) -> Vec<u8> {
    input
        .chars()
        .flat_map(|c| {
            let index = BASE64_URL_CHARSET.find(c).unwrap() as u8; // TODO: could panic
            (0..6).rev().map(move |i| index >> i & 1)
        })
        .collect()
}

/// Convert a bitarray (each bit is represented by u8) to a byte array by taking each 8 bits as a
/// byte in big-endian format.
fn bitarray_to_bytearray(bits: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for bits in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, bit) in bits.iter().rev().enumerate() {
            byte |= bit << i;
        }
        bytes.push(byte);
    }
    bytes
}

/// Convert a bigint string to a field element.
pub fn to_field(val: &str) -> Result<Bn254Fr, FastCryptoError> {
    Bn254Fr::from_str(val)
        .map_err(|_| FastCryptoError::GeneralError("Convert to field error".to_string()))
}

/// Pads a stream of bytes and maps it to a field element
pub fn hash_ascii_str_to_field(str: &str, max_size: u8) -> Result<Bn254Fr, FastCryptoError> {
    let str_padded = str_to_padded_char_codes(str, max_size)?;
    hash_to_field(&str_padded, 8, PACK_WIDTH)
}

fn str_to_padded_char_codes(str: &str, max_len: u8) -> Result<Vec<BigUint>, FastCryptoError> {
    let arr: Vec<BigUint> = str
        .chars()
        .map(|c| BigUint::from_slice(&([c as u32])))
        .collect();
    pad_with_zeroes(arr, max_len)
}

fn pad_with_zeroes(in_arr: Vec<BigUint>, out_count: u8) -> Result<Vec<BigUint>, FastCryptoError> {
    if in_arr.len() > out_count as usize {
        return Err(FastCryptoError::GeneralError("in_arr too long".to_string()));
    }
    let mut padded = in_arr;
    padded.resize(out_count as usize, BigUint::zero());
    Ok(padded)
}

/// Maps a stream of bigints to a single field element. First we convert the base from
/// inWidth to packWidth. Then we compute the poseidon hash of the "packed" input.
/// input is the input vector containing equal-width big ints. inWidth is the width of
/// each input element.
fn hash_to_field(
    input: &[BigUint],
    in_width: u16,
    pack_width: u8,
) -> Result<Bn254Fr, FastCryptoError> {
    let packed = convert_base(input, in_width, pack_width)?;
    poseidon_zk_login(packed)
}

fn div_ceil(dividend: usize, divisor: usize) -> Result<usize, FastCryptoError> {
    if divisor == 0 {
        // Handle division by zero as needed for your application.
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(1 + ((dividend - 1) / divisor))
}

/// Helper function to pack field elements from big ints.
fn convert_base(
    in_arr: &[BigUint],
    in_width: u16,
    out_width: u8,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    let bits = big_int_array_to_bits(in_arr, in_width as usize);
    let mut packed: Vec<Bn254Fr> = bits
        .rchunks(out_width as usize)
        .map(|chunk| Bn254Fr::from(BigUint::from_radix_be(chunk, 2).unwrap()))
        .collect();
    packed.reverse();
    match packed.len() != div_ceil(in_arr.len() * in_width as usize, out_width as usize).unwrap() {
        true => Err(FastCryptoError::InvalidInput),
        false => Ok(packed),
    }
}

/// Convert a big int array to a bit array with 0 paddings.
fn big_int_array_to_bits(arr: &[BigUint], int_size: usize) -> Vec<u8> {
    let mut bitarray: Vec<u8> = Vec::new();
    for num in arr {
        let val = num.to_radix_be(2);
        let extra_bits = if val.len() < int_size {
            int_size - val.len()
        } else {
            0
        };

        let mut padded = vec![0; extra_bits];
        padded.extend(val);
        bitarray.extend(padded)
    }
    bitarray
}
