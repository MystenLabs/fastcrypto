// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoResult;
use serde_json::Value;
use std::fmt;

use super::poseidon::PoseidonWrapper;
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::Proof;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::{
    error::FastCryptoError,
    rsa::{Base64UrlUnpadded, Encoding},
};
use num_bigint::{BigInt, BigUint, Sign};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

type ParsedJWKs = Vec<((String, String), OAuthProviderContent)>;
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
// #[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderContent {
    /// Key type parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
    pub kty: String,
    /// RSA public exponent, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub e: String,
    /// RSA modulus, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub n: String,
    /// Algorithm parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    pub alg: String,
    /// kid
    kid: String,
}

/// Reader struct to parse all fields.
// #[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthProviderContentReader {
    e: String,
    n: String,
    #[serde(rename = "use")]
    my_use: String,
    kid: String,
    kty: String,
    alg: String,
}

impl OAuthProviderContent {
    /// Get the kid string.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Parse OAuthProviderContent from the reader struct.
    pub fn from_reader(reader: OAuthProviderContentReader) -> FastCryptoResult<Self> {
        if reader.alg != "RS256" || reader.my_use != "sig" || reader.kty != "RSA" {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self {
            kty: reader.kty,
            kid: reader.kid,
            e: trim(reader.e),
            n: trim(reader.n),
            alg: reader.alg,
        })
    }

    /// Parse OAuthProviderContent from the reader struct.
    pub fn validate(&self) -> FastCryptoResult<()> {
        if self.alg != "RS256" || self.kty != "RSA" || self.e != "AQAB" {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(())
    }
}

/// Trim trailing '=' so that it is considered a valid base64 url encoding string by base64ct library.
fn trim(str: String) -> String {
    str.trim_end_matches(|c: char| c == '=').to_owned()
}

/// Parse the JWK bytes received from the oauth provider keys endpoint into a map from kid to
/// OAuthProviderContent.
pub fn parse_jwks(
    json_bytes: &[u8],
    provider: OAuthProvider,
) -> Result<ParsedJWKs, FastCryptoError> {
    let json_str = String::from_utf8_lossy(json_bytes);
    let parsed_list: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&json_str);
    if let Ok(parsed_list) = parsed_list {
        if let Some(keys) = parsed_list["keys"].as_array() {
            let mut ret = Vec::new();
            for k in keys {
                let parsed: OAuthProviderContentReader = serde_json::from_value(k.clone())
                    .map_err(|_| FastCryptoError::GeneralError("Parse error".to_string()))?;

                ret.push((
                    (parsed.kid.clone(), provider.get_config().0.to_owned()),
                    OAuthProviderContent::from_reader(parsed)?,
                ));
            }
            return Ok(ret);
        }
    }
    Err(FastCryptoError::GeneralError("JWK not found".to_string()))
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
}

impl ParsedMaskedContent {
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

        Ok(ParsedMaskedContent {
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
    parsed_masked_content: ParsedMaskedContent,
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

    /// Initialize ParsedMaskedContent
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
        self.parsed_masked_content = ParsedMaskedContent::new(&self.header_base64, &self.claims)?;
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
        eph_pubkey_bytes: &[u8],
        modulus: &[u8],
        max_epoch: u64,
    ) -> Result<Vec<Bn254Fr>, FastCryptoError> {
        if self.header_base64.len() > MAX_HEADER_LEN as usize {
            return Err(FastCryptoError::GeneralError("Header too long".to_string()));
        }

        let mut poseidon = PoseidonWrapper::new();
        let addr_seed = to_field(&self.address_seed)?;

        let (first_half, second_half) = eph_pubkey_bytes.split_at(eph_pubkey_bytes.len() / 2);
        let first_bigint = BigInt::from_bytes_be(Sign::Plus, first_half);
        let second_bigint = BigInt::from_bytes_be(Sign::Plus, second_half);

        let eph_public_key_0 = to_field(&first_bigint.to_string())?;
        let eph_public_key_1 = to_field(&second_bigint.to_string())?;
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
            claim_f.push(map_bytes_to_field(
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
        let header_f = map_bytes_to_field(&self.parsed_masked_content.header, MAX_HEADER_LEN)?;
        let modulus_f = map_to_field(&[BigUint::from_bytes_be(modulus)], 2048)?;
        Ok(vec![poseidon.hash(vec![
            eph_public_key_0,
            eph_public_key_1,
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
    if inputs.len() <= 16 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        poseidon1.hash(inputs)
    } else if inputs.len() <= 32 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        let hash1 = poseidon1.hash(inputs[0..16].to_vec())?;

        let mut poseidon2 = PoseidonWrapper::new();
        let hash2 = poseidon2.hash(inputs[16..].to_vec())?;

        let mut poseidon3 = PoseidonWrapper::new();
        poseidon3.hash([hash1, hash2].to_vec())
    } else {
        Err(FastCryptoError::GeneralError(format!(
            "Yet to implement: Unable to hash a vector of length {}",
            inputs.len()
        )))
    }
}

/// Convert a bigint string to a field element.
fn to_field(val: &str) -> Result<Bn254Fr, FastCryptoError> {
    Bn254Fr::from_str(val).map_err(|_| FastCryptoError::InvalidInput)
}

/// Pads a stream of bytes and maps it to a field element
fn map_bytes_to_field(str: &str, max_size: u16) -> Result<Bn254Fr, FastCryptoError> {
    if str.len() > max_size as usize {
        return Err(FastCryptoError::InvalidInput);
    }
    let in_arr: Vec<BigUint> = str
        .chars()
        .map(|c| BigUint::from_slice(&([c as u32])))
        .collect();

    let str_padded = pad_with_zeros(in_arr, max_size)?;
    map_to_field(&str_padded, 8)
}

fn pad_with_zeros(in_arr: Vec<BigUint>, out_count: u16) -> Result<Vec<BigUint>, FastCryptoError> {
    if in_arr.len() > out_count as usize {
        return Err(FastCryptoError::GeneralError("in_arr too long".to_string()));
    }
    let mut padded = in_arr.clone();
    padded.extend(vec![
        BigUint::from_str("0").unwrap();
        out_count as usize - in_arr.len() as usize
    ]);
    Ok(padded)
}

/// Parse the input to a big int array and calculate the poseidon hash after packing.
fn map_to_field(input: &[BigUint], in_width: u16) -> Result<Bn254Fr, FastCryptoError> {
    let num_elements = (input.len() * in_width as usize) / PACK_WIDTH as usize + 1;
    let packed = pack2(input, in_width, PACK_WIDTH, num_elements)?;
    to_poseidon_hash(packed)
}

/// Helper function to pack into exactly outCount chunks of outWidth bits each.
fn pack2(
    in_arr: &[BigUint],
    in_width: u16,
    out_width: u16,
    out_count: usize,
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

/// Convert a big int string to a big endian bytearray.
pub fn big_int_str_to_bytes(value: &str) -> Vec<u8> {
    BigInt::from_str(value)
        .expect("Invalid big int string")
        .to_bytes_be()
        .1
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
