// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;

use super::{poseidon::PoseidonWrapper, api::verify_groth16, verifier::process_vk_special};
use fastcrypto::{
    error::FastCryptoError,
    rsa::{Base64UrlUnpadded, Encoding},
};
use num_bigint::{BigInt, Sign};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use once_cell::sync::OnceCell;

use crate::{bn254::verifier::PreparedVerifyingKey, circom::read_vkey};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

static INSTANCE_GOOGLE: OnceCell<PreparedVerifyingKey> = OnceCell::new();
static INSTANCE_TWITCH: OnceCell<PreparedVerifyingKey> = OnceCell::new();

/// Verify proof using fixed verifying key for the given provider.
pub fn verify_groth16_with_provider(
    provider: OIDCProvider,
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    let pvk = match provider {
        OIDCProvider::Google => google_pvk(),
        OIDCProvider::Twitch => twitch_pvk(),
    };
    verify_groth16(pvk, proof_public_inputs_as_bytes, proof_points_as_bytes)
}

/// Get static Google prepared verifying key. Initialized once and cached.
fn google_pvk() -> &'static PreparedVerifyingKey {
    INSTANCE_GOOGLE
        .get_or_init(|| serialize_verifying_key_from_file("./src/bn254/unit_tests/google.vkey"))
}

/// Get static Google prepared verifying key. Initialized once and cached.
fn twitch_pvk() -> &'static PreparedVerifyingKey {
    INSTANCE_TWITCH
        .get_or_init(|| serialize_verifying_key_from_file("./src/bn254/unit_tests/twitch.vkey"))
}

/// Read in a json file of the verifying key and serialize it to bytes
fn serialize_verifying_key_from_file(vkey_path: &str) -> PreparedVerifyingKey {
    let vk = read_vkey(vkey_path);
    process_vk_special(&vk)
}

/// A parsed result of all aux inputs where the masked content is parsed with
/// all necessary fields.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct AuxInputs {
    masked_content: ParsedMaskedContent,
    jwt_signature: Vec<u8>,
    jwt_sha2_hash: Vec<String>, // Represented in 2 BigInt strings.
    payload_start_index: usize,
    payload_len: usize,
    eph_public_key: Vec<String>, // Represented in 2 BigInt strings.
    max_epoch: u64,
    num_sha2_blocks: usize,
    sub_id_com: String,
}

/// A helper struct that helps to read the aux input from JSON format from file.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct AuxInputsReader {
    masked_content: Vec<u8>,
    jwt_sha2_hash: Vec<String>,
    payload_start_index: usize,
    payload_len: usize,
    eph_public_key: Vec<String>,
    max_epoch: u64,
    num_sha2_blocks: usize,
    sub_id_com: String,
    jwt_signature: String,
}

impl AuxInputs {
    /// Parse and validate all aux inputs from a file.
    pub fn from_fp(path: &str) -> Result<Self, FastCryptoError> {
        let file = File::open(path)
            .map_err(|_| FastCryptoError::GeneralError("Invalid file path".to_string()))?;
        let reader = std::io::BufReader::new(file);
        let inputs: AuxInputsReader =
            serde_json::from_reader(reader).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Self {
            jwt_signature: Base64UrlUnpadded::decode_vec(&inputs.jwt_signature)
                .map_err(|_| FastCryptoError::InvalidInput)?,
            masked_content: ParsedMaskedContent::new(
                &inputs.masked_content,
                inputs.payload_start_index,
                inputs.payload_len,
                inputs.num_sha2_blocks,
            )?,
            jwt_sha2_hash: inputs.jwt_sha2_hash,
            payload_start_index: inputs.payload_start_index,
            payload_len: inputs.payload_len,
            eph_public_key: inputs.eph_public_key,
            max_epoch: inputs.max_epoch,
            num_sha2_blocks: inputs.num_sha2_blocks,
            sub_id_com: inputs.sub_id_com,
        })
    }

    /// Get the jwt hash in byte array format.
    pub fn get_jwt_hash(&self) -> Vec<u8> {
        self.jwt_sha2_hash
            .iter()
            .flat_map(|x| big_int_str_to_hash(x))
            .collect()
    }

    /// Get the ephemeral pubkey in byte array format.
    pub fn get_eph_pub_key(&self) -> Vec<u8> {
        self.eph_public_key
            .iter()
            .flat_map(|x| big_int_str_to_hash(x))
            .collect()
    }
    /// Calculate the poseidon hash from 10 selected fields in the aux inputs.
    pub fn calculate_all_inputs_hash_from_aux_inputs(&self) -> String {
        // Safe to unwrap here all fields are converted to string from valid BigInt.
        let mut poseidon = PoseidonWrapper::new(11);
        let jwt_sha2_hash_0 = Bn254Fr::from_str(&self.jwt_sha2_hash[0]).unwrap();
        let jwt_sha2_hash_1 = Bn254Fr::from_str(&self.jwt_sha2_hash[1]).unwrap();
        let masked_content_hash = Bn254Fr::from_str(&self.masked_content.hash).unwrap();
        let payload_start_index = Bn254Fr::from_str(&self.payload_start_index.to_string()).unwrap();
        let payload_len = Bn254Fr::from_str(&self.payload_len.to_string()).unwrap();
        let eph_public_key_0 = Bn254Fr::from_str(&self.eph_public_key[0]).unwrap();
        let eph_public_key_1 = Bn254Fr::from_str(&self.eph_public_key[1]).unwrap();
        let max_epoch = Bn254Fr::from_str(&self.max_epoch.to_string()).unwrap();
        let nonce = Bn254Fr::from_str(&self.masked_content.nonce).unwrap();
        let num_sha2_blocks = Bn254Fr::from_str(&self.num_sha2_blocks.to_string()).unwrap();
        let sub_id_com = Bn254Fr::from_str(&self.sub_id_com.to_string()).unwrap();

        poseidon
            .hash(&[
                jwt_sha2_hash_0,
                jwt_sha2_hash_1,
                masked_content_hash,
                payload_start_index,
                payload_len,
                eph_public_key_0,
                eph_public_key_1,
                max_epoch,
                nonce,
                num_sha2_blocks,
                sub_id_com,
            ])
            .to_string()
    }
}

/// A structed of all parsed and validated values from the masked content bytes.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct ParsedMaskedContent {
    header: JWTHeader,
    iss: String,
    wallet_id: String,
    nonce: String,
    hash: String,
}

/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct JWTHeader {
    alg: String,
    kid: String,
    typ: String,
}

impl ParsedMaskedContent {
    /// Parse the masked content bytes into a [struct ParsedMaskedContent].
    /// Aux inputs (payload_start_index, payload_len, num_sha2_blocks) are
    /// are used for validation and parsing.
    pub fn new(
        masked_content: &[u8],
        payload_start_index: usize,
        payload_len: usize,
        num_sha2_blocks: usize,
    ) -> Result<Self, FastCryptoError> {
        // Verify the bytes after 64 * num_sha2_blocks should be all 0s.
        if !masked_content[64 * num_sha2_blocks..]
            .iter()
            .all(|&x| x == 0)
        {
            return Err(FastCryptoError::GeneralError(
                "Incorrect payload padding".to_string(),
            ));
        }

        let masked_content_tmp = &masked_content[..64 * num_sha2_blocks];

        // Verify the byte at payload start index is indeed b'.'.
        if masked_content_tmp.get(payload_start_index - 1) != Some(&b'.') {
            return Err(FastCryptoError::GeneralError(
                "Incorrect payload index for separator".to_string(),
            ));
        }

        let header = parse_and_validate_header(
            masked_content_tmp
                .get(0..payload_start_index - 1)
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
        if jwt_length != 8 * (payload_start_index + payload_len) {
            return Err(FastCryptoError::GeneralError(
                "Incorrect jwt length".to_string(),
            ));
        }

        // Parse sha2 pad into a bit array.
        let sha_2_pad = bytearray_to_bits(&masked_content_tmp[payload_start_index + payload_len..]);

        // Verify that the first bit of the bit array of sha2 pad is 1.
        if !sha_2_pad[0] {
            return Err(FastCryptoError::GeneralError(
                "Incorrect sha2 padding".to_string(),
            ));
        }

        // Verify the count of 0s in the sha2 pad bit array satifies the condition
        // with the jwt length.
        validate_zeros_count(&sha_2_pad, jwt_length)?;
        println!("!!validate_zeros_count");

        // Splits the masked payload into 3 parts (that reveals iss, aud, nonce respectively)
        // separated by a delimiter of "=" of any length. With padding etc
        let parts = find_parts_and_indices(
            &masked_content_tmp[payload_start_index..payload_start_index + payload_len],
        )?;

        Ok(Self {
            header,
            iss: parts[0].to_string(),
            wallet_id: parts[1].to_string(),
            nonce: parts[2].to_string(),
            hash: calculate_merklized_hash(masked_content),
        })
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
        find_value(&chunks[2], "\"nonce\":\"", "\",")?,
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
pub fn big_int_str_to_hash(value: &str) -> Vec<u8> {
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
pub fn calculate_merklized_hash(bytes: &[u8]) -> String {
    let mut bitarray = bytearray_to_bits(bytes);
    pad_bitarray(&mut bitarray, 253);
    let bigints = convert_to_bigints(&bitarray, 253);

    let mut poseidon1 = PoseidonWrapper::new(15);
    let hash1 = poseidon1.hash(&bigints[0..15]);

    let mut poseidon2 = PoseidonWrapper::new(bigints.len() - 15);
    let hash2 = poseidon2.hash(&bigints[15..]);

    let mut poseidon3 = PoseidonWrapper::new(2);
    let hash_final = poseidon3.hash(&[hash1, hash2]);

    hash_final.to_string()
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

fn convert_to_bigints(bitarray: &[bool], segment_size: usize) -> Vec<Bn254Fr> {
    let chunks = bitarray.chunks(segment_size);
    chunks
        .map(|chunk| {
            let mut bytes = vec![0; (segment_size + 7) / 8];
            for (i, &bit) in chunk.iter().enumerate() {
                bytes[i / 8] |= (bit as u8) << (7 - i % 8);
            }
            let f = bitarray_to_string(chunk);
            let st = BigInt::from_radix_be(Sign::Plus, &f, 2)
                .unwrap()
                .to_string();
            Bn254Fr::from_str(&st).unwrap()
        })
        .collect()
}

pub enum OIDCProvider {
    Google,
    Twitch,
}
