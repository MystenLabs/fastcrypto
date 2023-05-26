// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of a verifier following RSASSA-PKCS1-v1_5 using SHA-256 (see https://datatracker.ietf.org/doc/rfc3447/).

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::hash::{HashFunction, Sha256};
pub use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::Signature as ExternalSignature;
use rsa::{BigUint, RsaPublicKey as ExternalPublicKey};
use rsa::{Pkcs1v15Sign, PublicKey};

#[derive(Clone)]
pub struct RSAPublicKey(pub ExternalPublicKey);

#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature(pub ExternalSignature);

impl RSAPublicKey {
    /// Parse an `RSAPublicKey` from an ASN.1 DER (Distinguished Encoding Rules) PKCS #1 encoding.
    pub fn from_der(der: &[u8]) -> FastCryptoResult<Self> {
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    /// Parse an `RSAPublicKey` from its components, eg. the modulus (n) and the exponent (e) from a binary big-endian representation.
    pub fn from_raw_components(modulus: &[u8], exponent: &[u8]) -> FastCryptoResult<Self> {
        // The Base64 encodings in a JSON Web Key is big-endian encoded (see RFC 7517 and 7518), so we expect the same here.
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::new(
                BigUint::from_bytes_be(modulus),
                BigUint::from_bytes_be(exponent),
            )
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
    /// Parse signature from binary representation according to https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        Ok(Self(
            ExternalSignature::try_from(bytes).map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::hash::{HashFunction, Sha256};
    use crate::rsa::{Base64UrlUnpadded, Encoding};
    use crate::rsa::{RSAPublicKey, RSASignature};

    #[test]
    fn jwt_test() {
        // Test vector from with RFC 7515 section A.2.1.
        let n_base64 = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
        let n_bytes = Base64UrlUnpadded::decode_vec(n_base64).unwrap();

        let e_base64 = "AQAB";
        let e_bytes = Base64UrlUnpadded::decode_vec(e_base64).unwrap();

        let pk = RSAPublicKey::from_raw_components(&n_bytes, &e_bytes).unwrap();

        let msg = b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let digest = Sha256::digest(msg).digest;

        let signature_base64 = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        let signature_bytes = Base64UrlUnpadded::decode_vec(signature_base64).unwrap();
        let signature = RSASignature::from_bytes(&signature_bytes).unwrap();

        // Valid signature
        assert!(pk.verify_prehash(&digest, &signature).is_ok());
        assert!(pk.verify(msg, &signature).is_ok());

        // Invalid digest
        let mut other_digest = digest;
        other_digest[0] += 1;
        assert!(pk.verify_prehash(&other_digest, &signature).is_err());

        // Invalid message
        let mut other_msg = *msg;
        other_msg[0] += 1;
        assert!(pk.verify(&other_msg, &signature).is_err());

        // Invalid signature
        let mut other_signature_bytes = signature_bytes;
        other_signature_bytes[7] += 1;
        let other_signature = RSASignature::from_bytes(&other_signature_bytes).unwrap();
        assert!(pk.verify_prehash(&other_digest, &signature).is_err());
        assert!(pk.verify(msg, &other_signature).is_err());
    }
}
