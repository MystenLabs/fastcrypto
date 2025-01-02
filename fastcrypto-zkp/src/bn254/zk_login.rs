// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::{error::FastCryptoResult, jwt_utils::JWTHeader};
use reqwest::Client;
use serde_json::Value;

use super::utils::split_to_two_frs;
use crate::bn254::poseidon::poseidon_merkle_tree;
use crate::bn254::FieldElement;
use crate::zk_login_utils::{
    g1_affine_from_str_projective, g2_affine_from_str_projective, Bn254FrElement, CircomG1,
    CircomG2,
};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_ff::Zero;
use ark_groth16::Proof;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;
use itertools::Itertools;
use num_bigint::BigUint;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering::{Equal, Greater, Less};
use std::error::Error;
use std::fmt::Display;
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
        // if a Microsoft iss is found, remove the tenant id from it
        if match_micrsoft_iss_substring(&iss) {
            return Self {
                iss: "https://login.microsoftonline.com/v2.0".to_string(),
                kid,
            };
        }
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
    /// This is a test issuer maintained by Mysten that will return a JWT non-interactively.
    /// See https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
    Microsoft,
    /// Example: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_LPSLCkC3A/.well-known/jwks.json
    AwsTenant((String, String)),
    /// https://accounts.karrier.one/.well-known/openid-configuration
    KarrierOne,
    /// https://accounts.credenza3.com/openid-configuration
    Credenza3,
    /// This is a test issuer that will return a JWT non-interactively.
    TestIssuer,
    /// https://oauth2.playtron.one/.well-known/jwks.json
    Playtron,
    /// https://auth.3dos.io/.well-known/openid-configuration
    Threedos,
    /// https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/b2c_1a_prod_signupsignin_onesuizklogin/v2.0/.well-known/openid-configuration
    Onefc,
    /// https://accounts.fantv.world/.well-known/openid-configuration
    FanTV,
    /// https://api.arden.cc/auth/jwks
    Arden,
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
            "TestIssuer" => Ok(Self::TestIssuer),
            "Microsoft" => Ok(Self::Microsoft),
            "KarrierOne" => Ok(Self::KarrierOne),
            "Credenza3" => Ok(Self::Credenza3),
            "Playtron" => Ok(Self::Playtron),
            "Threedos" => Ok(Self::Threedos),
            "Onefc" => Ok(Self::Onefc),
            "FanTV" => Ok(Self::FanTV),
            "Arden" => Ok(Self::Arden),
            _ => {
                let re = Regex::new(
                    r"AwsTenant-region:(?P<region>[^.]+)-tenant_id:(?P<tenant_id>[^/]+)",
                )
                .unwrap();
                if let Some(captures) = re.captures(s) {
                    let region = captures.name("region").unwrap().as_str();
                    let tenant_id = captures.name("tenant_id").unwrap().as_str();
                    Ok(Self::AwsTenant((region.to_owned(), tenant_id.to_owned())))
                } else {
                    Err(FastCryptoError::InvalidInput)
                }
            }
        }
    }
}

impl Display for OIDCProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Google => write!(f, "Google"),
            Self::Twitch => write!(f, "Twitch"),
            Self::Facebook => write!(f, "Facebook"),
            Self::Kakao => write!(f, "Kakao"),
            Self::Apple => write!(f, "Apple"),
            Self::Slack => write!(f, "Slack"),
            Self::TestIssuer => write!(f, "TestIssuer"),
            Self::Microsoft => write!(f, "Microsoft"),
            Self::KarrierOne => write!(f, "KarrierOne"),
            Self::Credenza3 => write!(f, "Credenza3"),
            Self::Playtron => write!(f, "Playtron"),
            Self::Threedos => write!(f, "Threedos"),
            Self::Onefc => write!(f, "Onefc"),
            Self::FanTV => write!(f, "FanTV"),
            Self::Arden => write!(f, "Arden"),
            Self::AwsTenant((region, tenant_id)) => {
                write!(f, "AwsTenant-region:{}-tenant_id:{}", region, tenant_id)
            }
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
            OIDCProvider::Microsoft => ProviderConfig::new(
                "https://login.microsoftonline.com/v2.0",
                "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            ),
            OIDCProvider::AwsTenant((region, tenant_id)) => ProviderConfig::new(
                &format!("https://cognito-idp.{}.amazonaws.com/{}", region, tenant_id),
                &format!(
                    "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
                    region, tenant_id
                ),
            ),
            OIDCProvider::KarrierOne => ProviderConfig::new(
                "https://accounts.karrier.one/",
                "https://accounts.karrier.one/.well-known/jwks",
            ),
            OIDCProvider::Credenza3 => ProviderConfig::new(
                "https://accounts.credenza3.com",
                "https://accounts.credenza3.com/jwks",
            ),
            OIDCProvider::TestIssuer => ProviderConfig::new(
                "https://oauth.sui.io",
                "https://jwt-tester.mystenlabs.com/.well-known/jwks.json",
            ),
            OIDCProvider::Playtron => ProviderConfig::new(
                "https://oauth2.playtron.one",
                "https://oauth2.playtron.one/.well-known/jwks.json",
            ),
            OIDCProvider::Threedos => ProviderConfig::new(
                "https://auth.3dos.io",
                "https://auth.3dos.io/.well-known/jwks.json",
            ),
            OIDCProvider::Onefc => ProviderConfig::new(
                "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/v2.0/",
                "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/b2c_1a_prod_signupsignin_onesuizklogin/discovery/v2.0/keys",
            ),
            OIDCProvider::FanTV => ProviderConfig::new(
                "https://accounts.fantv.world",
                "https://fantv-apis.fantiger.com/v1/web3/jwks.json",
            ),
            OIDCProvider::Arden => ProviderConfig::new(
                "https://oidc.arden.cc",
                "https://api.arden.cc/auth/jwks",
            ),
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
            "https://oauth.sui.io" => Ok(Self::TestIssuer),
            "https://accounts.karrier.one/" => Ok(Self::KarrierOne),
            "https://accounts.credenza3.com" => Ok(Self::Credenza3),
            "https://oauth2.playtron.one" => Ok(Self::Playtron),
            "https://auth.3dos.io" => Ok(Self::Threedos),
            "https://login.onepassport.onefc.com/de3ee5c1-5644-4113-922d-e8336569a462/v2.0/" => {
                Ok(Self::Onefc)
            }
            "https://accounts.fantv.world" => Ok(Self::FanTV),
            "https://oidc.arden.cc" => Ok(Self::Arden),
            iss if match_micrsoft_iss_substring(iss) => Ok(Self::Microsoft),
            _ => match parse_aws_iss_substring(iss) {
                Ok((region, tenant_id)) => {
                    Ok(Self::AwsTenant((region.to_string(), tenant_id.to_string())))
                }
                Err(_) => Err(FastCryptoError::InvalidInput),
            },
        }
    }
}

/// Check if the iss string is formatted as Microsoft's pattern.
fn match_micrsoft_iss_substring(iss: &str) -> bool {
    iss.starts_with("https://login.microsoftonline.com/") && iss.ends_with("/v2.0")
}

/// Parse the region and tenant_id from the iss string for AWS.
fn parse_aws_iss_substring(url: &str) -> Result<(&str, &str), FastCryptoError> {
    let re =
        Regex::new(r"https://cognito-idp\.(?P<region>[^.]+)\.amazonaws\.com/(?P<tenant_id>[^/]+)")
            .unwrap();

    if let Some(captures) = re.captures(url) {
        // Extract the region and tenant_id from the captures
        let region = captures.name("region").unwrap().as_str();
        let tenant_id = captures.name("tenant_id").unwrap().as_str();

        Ok((region, tenant_id))
    } else {
        Err(FastCryptoError::InvalidInput)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
}

impl JWK {
    /// Parse JWK from the reader struct.
    pub fn from_reader(reader: JWKReader) -> FastCryptoResult<Self> {
        let trimmed_e = trim(reader.e);
        // Microsoft does not contain alg field in JWK, so here we only check if it equals to RS256 only if alg field is present.
        if (reader.alg.is_some() && reader.alg != Some("RS256".to_string()))
            || reader.kty != "RSA"
            || trimmed_e != "AQAB"
        {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self {
            kty: reader.kty,
            e: trimmed_e,
            n: trim(reader.n),
            alg: "RS256".to_string(),
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
                "Failed to get JWK {:?} {:?} {:?}",
                e.source(),
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

/// A struct of parsed JWT details, consists of kid, header, iss.
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
    address_seed: Bn254FrElement,
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
            address_seed: Bn254FrElement::from_str(address_seed)
                .map_err(|_| FastCryptoError::InvalidInput)?,
            jwt_details: reader.jwt_details,
        }
        .init()
    }

    /// Initialize JWTDetails by parsing header_base64 and iss_base64_details.
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
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
    pub fn get_address_seed(&self) -> &Bn254FrElement {
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

        let addr_seed = (&self.address_seed).into();
        let (first, second) = split_to_two_frs(eph_pk_bytes)?;

        let max_epoch_f = (&Bn254FrElement::from_str(&max_epoch.to_string())?).into();
        let index_mod_4_f =
            (&Bn254FrElement::from_str(&self.iss_base64_details.index_mod_4.to_string())?).into();

        let iss_base64_f =
            hash_ascii_str_to_field(&self.iss_base64_details.value, MAX_ISS_LEN_B64)?;
        let header_f = hash_ascii_str_to_field(&self.header_base64, MAX_HEADER_LEN)?;
        let modulus_f = hash_to_field(&[BigUint::from_bytes_be(modulus)], 2048, PACK_WIDTH)?;
        poseidon_zk_login(&[
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
    let mut bits = base64_to_bitarray(s)?;
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

    Ok(std::str::from_utf8(&bitarray_to_bytearray(&bits)?)
        .map_err(|_| FastCryptoError::GeneralError("Invalid UTF8 string".to_string()))?
        .to_owned())
}

/// Map a base64 string to a bit array by taking each char's index and convert it to binary form with one bit per u8
/// element in the output. Returns [FastCryptoError::InvalidInput] if one of the characters is not in the base64 charset.
fn base64_to_bitarray(input: &str) -> FastCryptoResult<Vec<u8>> {
    input
        .chars()
        .map(|c| {
            BASE64_URL_CHARSET
                .find(c)
                .map(|index| index as u8)
                .map(|index| (0..6).rev().map(move |i| index >> i & 1))
                .ok_or(FastCryptoError::InvalidInput)
        })
        .flatten_ok()
        .collect()
}

/// Convert a bitarray (each bit is represented by a u8) to a byte array by taking each 8 bits as a
/// byte in big-endian format.
fn bitarray_to_bytearray(bits: &[u8]) -> FastCryptoResult<Vec<u8>> {
    if bits.len() % 8 != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    Ok(bits
        .chunks(8)
        .map(|chunk| {
            let mut byte = 0u8;
            for (i, bit) in chunk.iter().rev().enumerate() {
                byte |= bit << i;
            }
            byte
        })
        .collect())
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
    poseidon_zk_login(&packed)
}

/// Helper function to pack field elements from big ints.
fn convert_base(
    in_arr: &[BigUint],
    in_width: u16,
    out_width: u8,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    if out_width == 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    let bits = big_int_array_to_bits(in_arr, in_width as usize)?;
    let mut packed: Vec<Bn254Fr> = bits
        .rchunks(out_width as usize)
        .map(|chunk| Bn254Fr::from(BigUint::from_radix_be(chunk, 2).unwrap()))
        .collect();
    packed.reverse();
    match packed.len() != (in_arr.len() * in_width as usize).div_ceil(out_width as usize) {
        true => Err(FastCryptoError::InvalidInput),
        false => Ok(packed),
    }
}

/// Convert a big int array to a bit array with 0 paddings.
fn big_int_array_to_bits(integers: &[BigUint], intended_size: usize) -> FastCryptoResult<Vec<u8>> {
    integers
        .iter()
        .map(|integer| {
            let bits = integer.to_radix_be(2);
            match bits.len().cmp(&intended_size) {
                Less => {
                    let extra_bits = intended_size - bits.len();
                    let mut padded = vec![0; extra_bits];
                    padded.extend(bits);
                    Ok(padded)
                }
                Equal => Ok(bits),
                Greater => Err(FastCryptoError::InvalidInput),
            }
        })
        .flatten_ok()
        .collect()
}

/// Calculate the poseidon hash of the field element inputs. If there are no inputs, return an error.
/// If input length is <= 16, calculate H(inputs), if it is <= 32, calculate H(H(inputs[0..16]),
/// H(inputs[16..])), otherwise return an error.
///
/// This functions must be equivalent with the one found in the zk_login circuit.
pub(crate) fn poseidon_zk_login(inputs: &[Bn254Fr]) -> FastCryptoResult<Bn254Fr> {
    if inputs.is_empty() || inputs.len() > 32 {
        return Err(FastCryptoError::InputLengthWrong(inputs.len()));
    }
    poseidon_merkle_tree(&inputs.iter().map(|x| FieldElement(*x)).collect_vec()).map(|x| x.0)
}

#[test]
fn test_poseidon_zk_login_input_sizes() {
    assert!(poseidon_zk_login(&[]).is_err());
    assert!(poseidon_zk_login(&[Bn254Fr::from_str("123").unwrap(); 1]).is_ok());
    assert!(poseidon_zk_login(&[Bn254Fr::from_str("123").unwrap(); 32]).is_ok());
    assert!(poseidon_zk_login(&[Bn254Fr::from_str("123").unwrap(); 33]).is_err());
}
