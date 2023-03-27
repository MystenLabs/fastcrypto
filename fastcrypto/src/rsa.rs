// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of RSASSA-PKCS1-v1_5.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::hash::HashFunction;
use crate::hash::Sha256;
use rsa::pkcs1::{DecodeRsaPublicKey};
use rsa::pkcs1v15::{Signature as ExternalSignature};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::RsaPublicKey as ExternalPublicKey;
use rsa::{Pkcs1v15Sign, PublicKey};
use wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha256;
use wycheproof::rsa_pkcs1_verify::TestSet;
use wycheproof::TestResult;

#[derive(Clone)]
pub struct RSAPublicKey(pub ExternalPublicKey);

#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature(pub ExternalSignature);

impl RSAPublicKey {
    pub fn from_der(der: &[u8]) -> FastCryptoResult<Self> {
        // First try to parse the public key using PKCS#8 format and if this fails, try PKCS#1 format
        Ok(RSAPublicKey(ExternalPublicKey::from(
            rsa::RsaPublicKey::from_public_key_der(der)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )))
    }

    pub fn from_pem(pem: &str) -> FastCryptoResult<Self> {
        // First try to parse the public key using PKCS#8 format and if this fails, try PKCS#1 format
        let pem = pem.trim();
        Ok(RSAPublicKey(ExternalPublicKey::from(
            rsa::RsaPublicKey::from_public_key_pem(pem)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, FastCryptoError> {
        self.0
            .to_public_key_der()
            .map_err(|_| {
                FastCryptoError::GeneralError("Unable to export invalid public key".to_string())
            })
            .map(|x| x.as_ref().to_vec())
    }

    pub fn to_pem(&self) -> Result<String, FastCryptoError> {
        self.0.to_public_key_pem(Default::default()).map_err(|_| {
            FastCryptoError::GeneralError("Unable to export invalid public key".to_string())
        })
    }

    pub fn verify_prehash(&self, msg: &[u8], signature: &RSASignature) -> FastCryptoResult<()> {
        self.0
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha256>(),
                msg,
                &signature.0.as_ref(),
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

#[test]
fn wycheproof_test() {
    let test_set = TestSet::load(Rsa2048Sha256).unwrap();
    for test_group in test_set.test_groups {
        let pk = RSAPublicKey::from_der(&test_group.der).unwrap();
        for test in test_group.tests {
            let mut res = TestResult::Invalid;
            let sig = RSASignature::from_bytes(&test.sig).unwrap();
            if pk
                .verify_prehash(&Sha256::digest(&test.msg).digest, &sig)
                .is_ok()
            {
                res = TestResult::Valid;
            }

            if map_result(test.result) != res {
                // TODO: Fails at 'short signature'
                panic!("{}", test.comment);
            }
        }
    }
}

fn map_result(t: TestResult) -> TestResult {
    match t {
        TestResult::Valid => TestResult::Valid,
        _ => TestResult::Invalid, // Treat Acceptable as Invalid
    }
}
