// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoResult;
use serde_json::Value;

use super::{
    poseidon::{to_poseidon_hash, PoseidonWrapper},
    utils::split_to_two_frs,
};
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_ff::Zero;
use ark_groth16::Proof;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::{
    error::FastCryptoError,
    rsa::{Base64UrlUnpadded, Encoding},
};
use num_bigint::BigUint;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

type ParsedJWKs = Vec<((String, String), JWK)>;
#[cfg(test)]
#[path = "unit_tests/zk_login_tests.rs"]
mod zk_login_tests;

const MAX_HEADER_LEN: u16 = 500;
const PACK_WIDTH: u16 = 248;
const ISS: &str = "iss";
const AUD: &str = "aud";
const NUM_EXTRACTABLE_STRINGS: u8 = 5;
const MAX_EXTRACTABLE_STR_LEN: u16 = 150;
const MAX_EXTRACTABLE_STR_LEN_B64: u16 = 4 * (1 + MAX_EXTRACTABLE_STR_LEN / 3);

/// Supported OAuth providers.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum OIDCProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
    /// See https://www.facebook.com/.well-known/openid-configuration/
    Facebook,
}

/// Struct that contains all the OAuth provider information. A list of them can
/// be retrieved from the JWK endpoint (e.g. <https://www.googleapis.com/oauth2/v3/certs>)
/// and published on the bulletin along with a trusted party's signature.
// #[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
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

/// Reader struct to parse all fields.
// #[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct JWKReader {
    e: String,
    n: String,
    #[serde(rename = "use")]
    my_use: String,
    kid: String,
    kty: String,
    alg: String,
}

impl JWK {
    /// Parse JWK from the reader struct.
    pub fn from_reader(reader: JWKReader) -> FastCryptoResult<Self> {
        let trimmed_e = trim(reader.e);
        if reader.alg != "RS256"
            || reader.my_use != "sig"
            || reader.kty != "RSA"
            || trimmed_e != "AQAB"
        {
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

/// Fetch JWKs from all supported OAuth providers and return the list as ((iss, kid), JWK)
pub async fn fetch_jwks() -> Result<ParsedJWKs, FastCryptoError> {
    let client = reqwest::Client::new();
    let mut res = Vec::new();
    // We currently support three providers: Google, Facebook, and Twitch.
    for provider in [
        OIDCProvider::Google,
        OIDCProvider::Facebook,
        OIDCProvider::Twitch,
    ] {
        let response = client
            .get(provider.get_config().1)
            .send()
            .await
            .map_err(|_| FastCryptoError::GeneralError("Failed to get JWK".to_string()))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|_| FastCryptoError::GeneralError("Failed to get bytes".to_string()))?;
        res.append(&mut parse_jwks(&bytes, provider)?)
    }
    Ok(res)
}

/// Parse the JWK bytes received from the oauth provider keys endpoint into a map from kid to
/// JWK.
pub fn parse_jwks(
    json_bytes: &[u8],
    provider: OIDCProvider,
) -> Result<ParsedJWKs, FastCryptoError> {
    let json_str = String::from_utf8_lossy(json_bytes);
    let parsed_list: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&json_str);
    if let Ok(parsed_list) = parsed_list {
        if let Some(keys) = parsed_list["keys"].as_array() {
            let mut ret = Vec::new();
            for k in keys {
                let parsed: JWKReader = serde_json::from_value(k.clone())
                    .map_err(|_| FastCryptoError::GeneralError("Parse error".to_string()))?;

                ret.push((
                    (parsed.kid.clone(), provider.get_config().0.to_owned()),
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

impl OIDCProvider {
    /// Returns a tuple of iss string and the JWK url string for the given provider.
    pub fn get_config(&self) -> (&str, &str) {
        match self {
            OIDCProvider::Google => (
                "https://accounts.google.com",
                "https://www.googleapis.com/oauth2/v2/certs",
            ),
            OIDCProvider::Twitch => (
                "https://id.twitch.tv/oauth2",
                "https://id.twitch.tv/oauth2/keys",
            ),
            OIDCProvider::Facebook => (
                "https://www.facebook.com",
                "https://www.facebook.com/.well-known/oauth/openid/jwks/",
            ),
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
pub struct JWTDetails {
    kid: String,
    header: String,
    iss: String,
    aud: String,
}

impl JWTDetails {
    /// Read a list of Claims and header string and parse them into fields
    /// header, iss, iss_index, aud, aud_index.
    pub fn new(header_base64: &str, claims: &[Claim]) -> Result<Self, FastCryptoError> {
        let header = JWTHeader::new(header_base64)?;
        let claim = claims
            .get(0)
            .ok_or_else(|| FastCryptoError::GeneralError("Invalid claim".to_string()))?;
        if claim.name != ISS {
            return Err(FastCryptoError::GeneralError(
                "iss not found in claims".to_string(),
            ));
        }
        let ext_iss = decode_base64_url(&claim.value_base64, &claim.index_mod_4)?;

        let claim_2 = claims
            .get(1)
            .ok_or_else(|| FastCryptoError::GeneralError("Invalid claim".to_string()))?;
        if claim_2.name != AUD {
            return Err(FastCryptoError::GeneralError(
                "aud not found in claims".to_string(),
            ));
        }
        let ext_aud = decode_base64_url(&claim_2.value_base64, &claim_2.index_mod_4)?;

        Ok(JWTDetails {
            kid: header.kid,
            header: header_base64.to_string(),
            iss: verify_extended_claim(&ext_iss, ISS)?,
            aud: verify_extended_claim(&ext_aud, AUD)?,
        })
    }
}

/// All inputs required for the zk login proof verification and other auxiliary inputs.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginInputs {
    proof_points: ZkLoginProof,
    address_seed: String,
    claims: Vec<Claim>,
    header_base64: String,
    #[serde(skip)]
    parsed_masked_content: JWTDetails,
    #[serde(skip)]
    all_inputs_hash: Vec<Bn254Fr>,
}

impl ZkLoginInputs {
    /// Validate and parse masked content bytes into the struct and other json strings into the struct.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let inputs: ZkLoginInputs =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(inputs)
    }

    /// Initialize JWTDetails
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
        self.parsed_masked_content = JWTDetails::new(&self.header_base64, &self.claims)?;
        Ok(self.to_owned())
    }

    /// Get the parsed kid string.
    pub fn get_kid(&self) -> &str {
        &self.parsed_masked_content.kid
    }

    /// Get the parsed iss string.
    pub fn get_iss(&self) -> &str {
        &self.parsed_masked_content.iss
    }

    /// Get the parsed aud string.
    pub fn get_aud(&self) -> &str {
        &self.parsed_masked_content.aud
    }

    /// Get zk login proof.
    pub fn get_proof(&self) -> &ZkLoginProof {
        &self.proof_points
    }

    /// Get public inputs in arkworks format.
    pub fn get_public_inputs(&self) -> &[Bn254Fr] {
        &self.all_inputs_hash
    }

    /// Get address seed string.
    pub fn get_address_seed(&self) -> &str {
        &self.address_seed
    }

    /// Get address seed string.
    pub fn get_address_params(&self) -> AddressParams {
        AddressParams::new(self.get_iss().to_owned(), self.get_aud().to_owned())
    }

    /// Calculate the poseidon hash from selected fields from inputs, along with the ephemeral pubkey.
    pub fn calculate_all_inputs_hash(
        &self,
        eph_pk_bytes: &[u8],
        modulus: &[u8],
        max_epoch: u64,
    ) -> Result<Vec<Bn254Fr>, FastCryptoError> {
        if self.header_base64.len() > MAX_HEADER_LEN as usize {
            return Err(FastCryptoError::GeneralError("Header too long".to_string()));
        }

        let mut poseidon = PoseidonWrapper::new();
        let addr_seed = to_field(&self.address_seed)?;
        let (first, second) = split_to_two_frs(eph_pk_bytes)?;

        let max_epoch = to_field(&max_epoch.to_string())?;
        let mut padded_claims = self.claims.clone();
        for _ in self.claims.len()..NUM_EXTRACTABLE_STRINGS as usize {
            padded_claims.push(Claim {
                name: "dummy".to_string(),
                value_base64: "e".to_string(),
                index_mod_4: 0,
            });
        }
        let mut claim_f = Vec::new();
        for i in 0..NUM_EXTRACTABLE_STRINGS {
            let val = &padded_claims[i as usize].value_base64;
            if val.len() > MAX_EXTRACTABLE_STR_LEN_B64 as usize {
                return Err(FastCryptoError::GeneralError(
                    "Invalid claim length".to_string(),
                ));
            }
            claim_f.push(hash_ascii_str_to_field(
                &padded_claims[i as usize].value_base64,
                MAX_EXTRACTABLE_STR_LEN_B64,
            )?);
        }
        let mut poseidon_claim = PoseidonWrapper::new();
        let extracted_claims_hash = poseidon_claim.hash(claim_f)?;

        let mut poseidon_index = PoseidonWrapper::new();
        let extracted_index_hash = poseidon_index.hash(
            padded_claims
                .iter()
                .map(|c| to_field(&c.index_mod_4.to_string()).unwrap())
                .collect::<Vec<_>>(),
        )?;
        let header_f = hash_ascii_str_to_field(&self.parsed_masked_content.header, MAX_HEADER_LEN)?;
        let modulus_f = hash_to_field(&[BigUint::from_bytes_be(modulus)], 2048, PACK_WIDTH)?;
        Ok(vec![poseidon.hash(vec![
            first,
            second,
            addr_seed,
            max_epoch,
            extracted_claims_hash,
            extracted_index_hash,
            header_f,
            modulus_f,
        ])?])
    }
}
/// The zk login proof.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

impl ZkLoginProof {
    /// Parse the proof from a json string.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let proof: ZkLoginProof =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidProof)?;
        Ok(proof)
    }

    /// Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    pub fn as_arkworks(&self) -> Proof<Bn254> {
        let a = g1_affine_from_str_projective(self.pi_a.clone());
        let b = g2_affine_from_str_projective(self.pi_b.clone());
        let c = g1_affine_from_str_projective(self.pi_c.clone());
        Proof { a, b, c }
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
    let base64_url_character_set =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    input
        .chars()
        .flat_map(|c| {
            let index = base64_url_character_set.find(c).unwrap() as u8;
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
fn to_field(val: &str) -> Result<Bn254Fr, FastCryptoError> {
    Bn254Fr::from_str(val).map_err(|_| FastCryptoError::InvalidInput)
}

/// Pads a stream of bytes and maps it to a field element
fn hash_ascii_str_to_field(str: &str, max_size: u16) -> Result<Bn254Fr, FastCryptoError> {
    let str_padded = str_to_padded_char_codes(str, max_size)?;
    hash_to_field(&str_padded, 8, PACK_WIDTH)
}

fn str_to_padded_char_codes(str: &str, max_len: u16) -> Result<Vec<BigUint>, FastCryptoError> {
    let arr: Vec<BigUint> = str
        .chars()
        .map(|c| BigUint::from_slice(&([c as u32])))
        .collect();
    pad_with_zeroes(arr, max_len)
}

fn pad_with_zeroes(in_arr: Vec<BigUint>, out_count: u16) -> Result<Vec<BigUint>, FastCryptoError> {
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
    pack_width: u16,
) -> Result<Bn254Fr, FastCryptoError> {
    let packed = convert_base(input, in_width, pack_width)?;
    to_poseidon_hash(packed)
}

/// Helper function to pack field elements from big ints.
fn convert_base(
    in_arr: &[BigUint],
    in_width: u16,
    out_width: u16,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    let bits = big_int_array_to_bits(in_arr, in_width as usize);
    let packed: Vec<Bn254Fr> = bits
        .chunks(out_width as usize)
        .map(|chunk| Bn254Fr::from(BigUint::from_radix_be(chunk, 2).unwrap()))
        .collect();
    match packed.len() != in_arr.len() * in_width as usize / out_width as usize + 1 {
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

/// Parameters for generating an address.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddressParams {
    /// The issuer string.
    pub iss: String,
    /// The audience string.
    pub aud: String,
}

impl AddressParams {
    /// Create address params from iss and aud.
    pub fn new(iss: String, aud: String) -> Self {
        Self { iss, aud }
    }
}
