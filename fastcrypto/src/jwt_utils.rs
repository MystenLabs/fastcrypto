// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError;
use base64ct::Base64UrlUnpadded;
use base64ct::Encoding;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Claims that be in the payload body.
#[derive(Deserialize, Serialize, Debug)]
struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl Claims {
    pub fn from_encoded(encoded: &str) -> Result<Self, FastCryptoError> {
        let decoded =
            Base64UrlUnpadded::decode_vec(encoded).map_err(|_| FastCryptoError::InvalidInput)?;
        let claims: Claims =
            serde_json::from_slice(&decoded).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(claims)
    }
}

// Parse and validate a JWT token, returns sub and aud.
pub fn parse_and_validate_jwt(token: &str) -> Result<(String, String), FastCryptoError> {
    // Check if the token contains 3 parts.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(FastCryptoError::InvalidInput);
    }
    // Check header is well formed and valid.
    let _ = JWTHeader::new(parts[0])?;

    // Check if payload is well formed.
    let payload = Claims::from_encoded(parts[1])?;
    Ok((payload.sub, payload.aud))
}

/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Default, Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct JWTHeader {
    alg: String,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
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
        if header.alg != "RS256" {
            return Err(FastCryptoError::GeneralError("Invalid header".to_string()));
        }
        Ok(header)
    }
}
