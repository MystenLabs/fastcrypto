// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of a verifier following RSASSA-PKCS1-v1_5 using SHA-256 (see https://datatracker.ietf.org/doc/rfc3447/).

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::hash::{HashFunction, Sha256};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::Signature as ExternalSignature;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey as ExternalPublicKey;
use rsa::{Pkcs1v15Sign, PublicKey};

#[derive(Clone)]
pub struct RSAPublicKey(pub ExternalPublicKey);

#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature(pub ExternalSignature);

impl RSAPublicKey {
    /// Parse an `RSAPublicKey` from a ASN.1 DER (Distinguished Encoding Rules) encoding.
    pub fn from_der(der: &[u8]) -> FastCryptoResult<Self> {
        // First try to parse the public key using PKCS#8 format and if this fails, try PKCS#1 format
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::from_public_key_der(der)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    /// Parse an `RSAPublicKey` from a PEM (Privacy-Enhanced Mail) encoding. Both PKCS#1 and PKCS#8
    /// formats are supported.
    pub fn from_pem(pem: &str) -> FastCryptoResult<Self> {
        // First try to parse the public key using PKCS#8 format and if this fails, try PKCS#1 format
        let pem = pem.trim();
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::from_public_key_pem(pem)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    /// Verify a signed message. The verification uses SHA-256 for hashing.
    pub fn verify(&self, msg: &[u8], signature: &RSASignature) -> FastCryptoResult<()> {
        self.verify_prehash(&Sha256::digest(msg).digest, signature)
    }

    /// Verify a signed message. The message, `hashed`, must be the output of a cryptographic hash function.
    pub fn verify_prehash(&self, hashed: &[u8], signature: &RSASignature) -> FastCryptoResult<()> {
        self.0
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha256>(),
                hashed,
                signature.0.as_ref(),
            )
            .map_err(|_| FastCryptoError::InvalidSignature)
    }
}

impl RSASignature {
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        Ok(Self(
            ExternalSignature::try_from(bytes).map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::hash::{HashFunction, Sha256};
    use crate::rsa::{RSAPublicKey, RSASignature};
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn jwt_test() {
        // Test vector generated with https://dinochiesa.github.io/jwt/ and signed with RS256.
        let pk_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5NXGDXfb1FDuWgAxQPVH\no+DPUkFl8rCjfj0nvQ++iubfMsMpP3UYu229GwYepOtKOpa4JA6uYGVibXql5ldh\nVZKG4LrGO8TL3S5C2qqac1CQbhwyG+DuyKBj1Fe5C7L/TWKmTep3eKEpolhXuaxN\nHR6R5TsxTb90RFToVRX/20rl8tHz/szWyPzmnLIOqae7UCVPFxenb3O7xa8SvSrV\nrPs2Eej3eEgOYORshP3HC6OQ8GV7ouJuM6VXPdRhb8BEWG/sTKmkr9qvrtoh2PpB\nlnEezat+7tbddPdI6LB4z4CIQzYkTu7OFZY5RV064c3skMmkEht3/Qrb7+MQsEWY\nlwIDAQAB\n-----END PUBLIC KEY-----";
        let pk = RSAPublicKey::from_pem(pk_pem).unwrap();

        let digest = Sha256::digest(b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjE0ZWJjMDRlNmFjM2QzZTk2MDMxZDJjY2QzODZmY2E5NWRkZjMyZGQifQ.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImlkcmlzIiwiYXVkIjoiZXZhbmRlciIsImlhdCI6MTY3OTk5MzM5NywiZXhwIjoxNjc5OTkzOTk3LCJhbHBoYSI6NjgyfQ").digest;

        let signature = "ae2yui9qVdRCEQWq76WoAuXWqb5sE-iZgYu1VP0z7mDY6jMBu-SddKz9Uh-yDzBo9erjJdd4PhadsIUY_mml1hmAbvcGo-IMayw6M-SOKDfMI73sw0U-twzH3DHW9pB2PNUNV3T67mFVL60eOmw7KwotpdQewQwJ_34xEOm5g2UjkFDsFzDydnFmxMMm8PCEjg8DGRhKAfzdtUV00B4KzESSKhwu8oRzEU7D6mbvco7I1TIl3IOKT9JK8y_775_W9Flk6lMildTOe08upqnJeT3dgnKgYKbFyN9IgW_pr7Htu-prtVPXqlfhWxFtqmAZxnKaOXo14oeWWvX05E-wLw";
        let signature_bytes = Base64UrlUnpadded::decode_vec(signature).unwrap();
        let signature = RSASignature::from_bytes(&signature_bytes).unwrap();

        assert!(pk.verify_prehash(&digest, &signature).is_ok());
    }
}
