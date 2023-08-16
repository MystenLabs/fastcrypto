// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::poseidon::PoseidonWrapper;
use crate::bn254::zk_login::AddressParams;
use crate::bn254::zk_login::OIDCProvider;
use crate::bn254::zk_login_api::Bn254Fr;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::rsa::Base64UrlUnpadded;
use fastcrypto::rsa::Encoding;
use num_bigint::BigUint;
use std::str::FromStr;

const ZK_LOGIN_AUTHENTICATOR_FLAG: u8 = 0x05;

/// Calculate the Sui address based on address seed and address params.
pub fn get_enoki_address(address_seed: &str, param: AddressParams) -> [u8; 32] {
    let mut hasher = Blake2b256::default();
    hasher.update([ZK_LOGIN_AUTHENTICATOR_FLAG]);
    // unwrap is safe here
    hasher.update(bcs::to_bytes(&AddressParams::new(param.iss, param.aud)).unwrap());
    hasher.update(big_int_str_to_bytes(address_seed));
    hasher.finalize().digest
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
    let mut poseidon = PoseidonWrapper::new();
    let (first, second) = split_to_two_frs(eph_pk_bytes)?;

    let max_epoch = Bn254Fr::from_str(&max_epoch.to_string()).unwrap();
    let jwt_randomness = Bn254Fr::from_str(jwt_randomness).unwrap();

    let hash = poseidon
        .hash(vec![first, second, max_epoch, jwt_randomness])
        .unwrap();
    let data = big_int_str_to_bytes(&hash.to_string());
    let truncated = &data[data.len() - 20..];
    let mut buf = vec![0; Base64UrlUnpadded::encoded_len(truncated)];
    Ok(Base64UrlUnpadded::encode(truncated, &mut buf)
        .unwrap()
        .to_string())
}

/// Given a 33-byte public key bytes (flag || pk_bytes), returns the two Bn254Fr split at the 128 bit index.
pub fn split_to_two_frs(eph_pk_bytes: &[u8]) -> Result<(Bn254Fr, Bn254Fr), FastCryptoError> {
    // Split the bytes deterministically such that the first element contains the first 128
    // bits of the hash, and the second element contains the latter ones.
    let (first_half, second_half) = eph_pk_bytes.split_at(eph_pk_bytes.len() - 16);
    let first_bigint = BigUint::from_bytes_be(first_half);
    let second_bigint = BigUint::from_bytes_be(second_half);

    let eph_public_key_0 = Bn254Fr::from(first_bigint);
    let eph_public_key_1 = Bn254Fr::from(second_bigint);
    Ok((eph_public_key_0, eph_public_key_1))
}

/// Convert a big int string to a big endian bytearray.
pub fn big_int_str_to_bytes(value: &str) -> Vec<u8> {
    BigUint::from_str(value)
        .expect("Invalid big int string")
        .to_bytes_be()
}
