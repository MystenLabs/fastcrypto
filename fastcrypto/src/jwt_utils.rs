// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError;
use base64ct::Base64UrlUnpadded;
use base64ct::Encoding;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct Header {
    pub typ: String,
    pub alg: String,
    pub kid: String,
}

impl Header {
    pub fn from_encoded(encoded: &str) -> Result<Self, FastCryptoError> {
        let decoded =
            Base64UrlUnpadded::decode_vec(encoded).map_err(|_| FastCryptoError::InvalidInput)?;
        let header: Header =
            serde_json::from_slice(&decoded).map_err(|_| FastCryptoError::InvalidInput)?;
        if header.alg != "RS256" || header.typ != "JWT" {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(header)
    }
}

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
    let _ = Header::from_encoded(parts[0])?;

    // Check if payload is well formed.
    let payload = Claims::from_encoded(parts[1])?;
    Ok((payload.sub, payload.aud))
}
