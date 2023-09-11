// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::poseidon::PoseidonWrapper;
use crate::bn254::zk_login::{OIDCProvider, ZkLoginInputsReader};
use crate::bn254::zk_login_api::Bn254Fr;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::rsa::Base64UrlUnpadded;
use fastcrypto::rsa::Encoding;
use num_bigint::BigUint;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::str::FromStr;

use super::zk_login::{hash_ascii_str_to_field, to_field};

const ZK_LOGIN_AUTHENTICATOR_FLAG: u8 = 0x05;
const SALT_SERVER_URL: &str = "http://salt.api-devnet.mystenlabs.com/get_salt";
const PROVER_SERVER_URL: &str = "http://185.209.177.123:7000/zkp";
const MAX_KEY_CLAIM_NAME_LENGTH: u8 = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH: u8 = 115;
const MAX_AUD_VALUE_LENGTH: u8 = 145;

/// Calculate the Sui address based on address seed and address params.
pub fn get_zk_login_address(address_seed: &str, iss: &str) -> Result<[u8; 32], FastCryptoError> {
    let mut hasher = Blake2b256::default();
    hasher.update([ZK_LOGIN_AUTHENTICATOR_FLAG]);
    let bytes = iss.as_bytes();
    hasher.update([bytes.len() as u8]);
    hasher.update(bytes);
    hasher.update(big_int_str_to_bytes(address_seed)?);
    Ok(hasher.finalize().digest)
}

/// Calculate the Sui address based on address seed and address params.
pub fn gen_address_seed(
    salt: &str,
    name: &str,  // i.e. "sub"
    value: &str, // i.e. the sub value
    aud: &str,   // i.e. the client ID
) -> Result<String, FastCryptoError> {
    let poseidon = PoseidonWrapper::new();
    Ok(poseidon
        .hash(vec![
            hash_ascii_str_to_field(name, MAX_KEY_CLAIM_NAME_LENGTH)?,
            hash_ascii_str_to_field(value, MAX_KEY_CLAIM_VALUE_LENGTH)?,
            hash_ascii_str_to_field(aud, MAX_AUD_VALUE_LENGTH)?,
            poseidon.hash(vec![to_field(salt)?])?,
        ])?
        .to_string())
}

/// Return the OIDC URL for the given parameters. Crucially the nonce is computed.
pub fn get_oidc_url(
    provider: OIDCProvider,
    eph_pk_bytes: &[u8],
    max_epoch: u64,
    client_id: &str,
    redirect_url: &str,
    jwt_randomness: &str,
) -> Result<String, FastCryptoError> {
    let nonce = get_nonce(eph_pk_bytes, max_epoch, jwt_randomness)?;
    Ok(match provider {
            OIDCProvider::Google => format!("https://accounts.google.com/o/oauth2/v2/auth?client_id={}&response_type=id_token&redirect_uri={}&scope=openid&nonce={}", client_id, redirect_url, nonce),
            OIDCProvider::Twitch => format!("https://id.twitch.tv/oauth2/authorize?client_id={}&force_verify=true&lang=en&login_type=login&redirect_uri={}&response_type=id_token&scope=openid&nonce={}", client_id, redirect_url, nonce),
            OIDCProvider::Facebook => format!("https://www.facebook.com/v17.0/dialog/oauth?client_id={}&redirect_uri={}&scope=openid&nonce={}&response_type=id_token", client_id, redirect_url, nonce) })
}

/// Calculate the nonce for the given parameters. Nonce is defined as the Base64Url encoded of the poseidon hash of 4 inputs:
/// first half of eph_pk_bytes in BigInt, second half of eph_pk_bytes in BigInt, max_epoch and jwt_randomness.
pub fn get_nonce(
    eph_pk_bytes: &[u8],
    max_epoch: u64,
    jwt_randomness: &str,
) -> Result<String, FastCryptoError> {
    let poseidon = PoseidonWrapper::new();
    let (first, second) = split_to_two_frs(eph_pk_bytes)?;

    let max_epoch = Bn254Fr::from_str(&max_epoch.to_string())
        .expect("max_epoch.to_string is always non empty string without trailing zeros");
    let jwt_randomness =
        Bn254Fr::from_str(jwt_randomness).map_err(|_| FastCryptoError::InvalidInput)?;

    let hash = poseidon
        .hash(vec![first, second, max_epoch, jwt_randomness])
        .expect("inputs is not too long");
    let data = BigUint::from(hash).to_bytes_be();
    let truncated = &data[data.len() - 20..];
    let mut buf = vec![0; Base64UrlUnpadded::encoded_len(truncated)];
    Ok(Base64UrlUnpadded::encode(truncated, &mut buf)
        .unwrap()
        .to_string())
}

/// A response struct for the salt server.
#[derive(Deserialize, Debug)]
pub struct GetSaltResponse {
    /// The salt in BigInt string.
    salt: String,
}

/// Call the salt server for the given jwt_token and return the salt.
pub async fn get_salt(jwt_token: &str) -> Result<String, FastCryptoError> {
    let client = Client::new();
    let body = json!({ "token": jwt_token });
    let response = client
        .post(SALT_SERVER_URL)
        .json(&body)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let full_bytes = response
        .bytes()
        .await
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let res: GetSaltResponse =
        serde_json::from_slice(&full_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    Ok(res.salt)
}

/// Call the prover backend to get the zkLogin inputs based on jwt_token, max_epoch, jwt_randomness, eph_pubkey and salt.
pub async fn get_proof(
    jwt_token: &str,
    max_epoch: u64,
    jwt_randomness: &str,
    eph_pubkey: &str,
    salt: &str,
) -> Result<ZkLoginInputsReader, FastCryptoError> {
    let body = json!({
    "jwt": jwt_token,
    "extendedEphemeralPublicKey": eph_pubkey,
    "maxEpoch": max_epoch,
    "jwtRandomness": jwt_randomness,
    "salt": salt,
    "keyClaimName": "sub",
    });
    let client = Client::new();
    let response = client
        .post(PROVER_SERVER_URL.to_string())
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let full_bytes = response
        .bytes()
        .await
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let get_proof_response: ZkLoginInputsReader =
        serde_json::from_slice(&full_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    Ok(get_proof_response)
}

/// Given a 33-byte public key bytes (flag || pk_bytes), returns the two Bn254Fr split at the 128 bit index.
pub fn split_to_two_frs(eph_pk_bytes: &[u8]) -> Result<(Bn254Fr, Bn254Fr), FastCryptoError> {
    // Split the bytes deterministically such that the first element contains the first 128
    // bits of the hash, and the second element contains the latter ones.
    let (first_half, second_half) = eph_pk_bytes.split_at(eph_pk_bytes.len() - 16);
    let first_bigint = BigUint::from_bytes_be(first_half);
    // TODO: this is not safe if the buffer is large. Can we use a fixed size array for eph_pk_bytes?
    let second_bigint = BigUint::from_bytes_be(second_half);

    let eph_public_key_0 = Bn254Fr::from(first_bigint);
    let eph_public_key_1 = Bn254Fr::from(second_bigint);
    Ok((eph_public_key_0, eph_public_key_1))
}

/// Convert a big int string to a big endian bytearray.
pub fn big_int_str_to_bytes(value: &str) -> Result<Vec<u8>, FastCryptoError> {
    Ok(BigUint::from_str(value)
        .map_err(|_| FastCryptoError::InvalidInput)?
        .to_bytes_be())
}
