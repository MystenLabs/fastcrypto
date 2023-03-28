// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of RSASSA-PKCS1-v1_5.

use crate::error::{FastCryptoError, FastCryptoResult};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::Signature as ExternalSignature;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::RsaPublicKey as ExternalPublicKey;
use rsa::{Pkcs1v15Sign, PublicKey};

#[derive(Clone)]
pub struct RSAPublicKey(pub ExternalPublicKey);

#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature(pub ExternalSignature);

impl RSAPublicKey {
    pub fn from_der(der: &[u8]) -> FastCryptoResult<Self> {
        // First try to parse the public key using PKCS#8 format and if this fails, try PKCS#1 format
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::from_public_key_der(der)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    pub fn from_pem(pem: &str) -> FastCryptoResult<Self> {
        // First try to parse the public key using PKCS#8 format and if this fails, try PKCS#1 format
        let pem = pem.trim();
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::from_public_key_pem(pem)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
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
    //use wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha256;
    //use wycheproof::rsa_pkcs1_verify::TestSet;
    //use wycheproof::TestResult;

    #[test]
    fn jwt_test() {
        // Test vector generated with https://dinochiesa.github.io/jwt/
        let pk_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5NXGDXfb1FDuWgAxQPVH\no+DPUkFl8rCjfj0nvQ++iubfMsMpP3UYu229GwYepOtKOpa4JA6uYGVibXql5ldh\nVZKG4LrGO8TL3S5C2qqac1CQbhwyG+DuyKBj1Fe5C7L/TWKmTep3eKEpolhXuaxN\nHR6R5TsxTb90RFToVRX/20rl8tHz/szWyPzmnLIOqae7UCVPFxenb3O7xa8SvSrV\nrPs2Eej3eEgOYORshP3HC6OQ8GV7ouJuM6VXPdRhb8BEWG/sTKmkr9qvrtoh2PpB\nlnEezat+7tbddPdI6LB4z4CIQzYkTu7OFZY5RV064c3skMmkEht3/Qrb7+MQsEWY\nlwIDAQAB\n-----END PUBLIC KEY-----";
        let pk = RSAPublicKey::from_pem(pk_pem).unwrap();

        let header_and_payload = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjE0ZWJjMDRlNmFjM2QzZTk2MDMxZDJjY2QzODZmY2E5NWRkZjMyZGQifQ.eyJpc3MiOiJodHRwczovL3d3dy5mYWNlYm9vay5jb20iLCJhdWQiOiIxMjQxNTU5MzY2NzU1MjE0Iiwic3ViIjoiNzA4NTYyNjExMDA5NTI1IiwiaWF0IjoxNjc5OTMyMDE0LCJleHAiOjE2Nzk5MzU2MTQsImp0aSI6IlRLdnouZGJlYzdjYTMxOTQyYTVkMmU1NmJkMGRiZmI4MjRiMTcxODVlMGYzMGIyMGYyNTczZGU1ZDQ4ZmM5ZjU4M2U0MyIsIm5vbmNlIjoidGVzdCIsImdpdmVuX25hbWUiOiJKb3kiLCJmYW1pbHlfbmFtZSI6IldhbmciLCJuYW1lIjoiSm95IFdhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wbGF0Zm9ybS1sb29rYXNpZGUuZmJzYnguY29tL3BsYXRmb3JtL3Byb2ZpbGVwaWMvP2FzaWQ9NzA4NTYyNjExMDA5NTI1JmhlaWdodD0xMDAmd2lkdGg9MTAwJmV4dD0xNjgyNTI0MDE1Jmhhc2g9QWVTMENxblhPMmNhT3g4WDhRZyJ9";
        let msg = Sha256::digest(header_and_payload).digest;

        let signature = "Z65bdJv-sFO9mNe4i1Tv0fa74rEtSIh3ZzJ29JtojgpA_d40JfE_NVJliYvoZdfqPX85a8NAG-ujKWWzrtv8l3K33r-T0WuUvosai99Y7TrMZt3WtT9pLwoO4s8KPSr9jXjTD94YFhizdKtyHFvaJRVjyUWFTvsQgZP9kyiSPh-7R_CStVan2u0scZRosZeOlZT4dI5xXnt3AFH-vFfaWiZEEunKljIkqvdrtt3x-HLFnjSvKGFi1Ct4LBObdjbNGJULYjQ0-N7yuQevaiYEpSFW1NBfa3p52vMj9XMADhg4wrV7Nuvk7CqERLeL-M8L_KmUGnRXOmMUL-6KTC8Rtw";
        let signature_bytes = Base64UrlUnpadded::decode_vec(signature).unwrap();
        let signature = RSASignature::from_bytes(&signature_bytes).unwrap();

        assert!(pk
            .verify_prehash(msg.as_slice(), &signature)
            .is_ok());
    }

    // TODO: This currently fails at a test case with a short signature. Need to investigate why.
    // #[test]
    // fn wycheproof_test() {
    //     let test_set = TestSet::load(Rsa2048Sha256).unwrap();
    //     for test_group in test_set.test_groups {
    //         let pk = RSAPublicKey::from_der(&test_group.der).unwrap();
    //         for test in test_group.tests {
    //             let mut res = TestResult::Invalid;
    //             let sig = RSASignature::from_bytes(&test.sig).unwrap();
    //             if pk
    //                 .verify_prehash(&Sha256::digest(&test.msg).digest, &sig)
    //                 .is_ok()
    //             {
    //                 res = TestResult::Valid;
    //             }
    //
    //             if map_result(test.result) != res {
    //                 panic!("{}", test.comment);
    //             }
    //         }
    //     }
    // }
    //
    // fn map_result(t: TestResult) -> TestResult {
    //     match t {
    //         TestResult::Valid => TestResult::Valid,
    //         _ => TestResult::Invalid, // Treat Acceptable as Invalid
    //     }
    // }
}
