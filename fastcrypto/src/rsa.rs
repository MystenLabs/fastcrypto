// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of a verifier following RSASSA-PKCS1-v1_5 using SHA-256 (see https://datatracker.ietf.org/doc/rfc3447/).

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::hash::{HashFunction, Sha256};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::Signature as ExternalSignature;
use rsa::RsaPublicKey as ExternalPublicKey;
use rsa::{Pkcs1v15Sign, PublicKey};

#[derive(Clone)]
pub struct RSAPublicKey(pub ExternalPublicKey);

#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature(pub ExternalSignature);

impl RSAPublicKey {
    /// Parse an `RSAPublicKey` from a ASN.1 DER (Distinguished Encoding Rules) encoding according to PKCS #1.
    pub fn from_der(der: &[u8]) -> FastCryptoResult<Self> {
        Ok(RSAPublicKey(
            rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| FastCryptoError::InvalidInput)?,
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
    use crate::rsa::{RSAPublicKey, RSASignature};
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn jwt_test() {
        // Test vector generated with https://dinochiesa.github.io/jwt/ and signed with RS256.
        let pk_der = &hex::decode("3082010a0282010100e4d5c60d77dbd450ee5a003140f547a3e0cf524165f2b0a37e3d27bd0fbe8ae6df32c3293f7518bb6dbd1b061ea4eb4a3a96b8240eae6065626d7aa5e65761559286e0bac63bc4cbdd2e42daaa9a7350906e1c321be0eec8a063d457b90bb2ff4d62a64dea7778a129a25857b9ac4d1d1e91e53b314dbf744454e85515ffdb4ae5f2d1f3feccd6c8fce69cb20ea9a7bb50254f1717a76f73bbc5af12bd2ad5acfb3611e8f778480e60e46c84fdc70ba390f0657ba2e26e33a5573dd4616fc044586fec4ca9a4afdaafaeda21d8fa4196711ecdab7eeed6dd74f748e8b078cf80884336244eeece159639455d3ae1cdec90c9a4121b77fd0adbefe310b04598970203010001").unwrap();
        let pk = RSAPublicKey::from_der(pk_der).unwrap();

        let msg = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjE0ZWJjMDRlNmFjM2QzZTk2MDMxZDJjY2QzODZmY2E5NWRkZjMyZGQifQ.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImlkcmlzIiwiYXVkIjoiZXZhbmRlciIsImlhdCI6MTY3OTk5MzM5NywiZXhwIjoxNjc5OTkzOTk3LCJhbHBoYSI6NjgyfQ";
        let digest = Sha256::digest(msg).digest;

        let signature = "ae2yui9qVdRCEQWq76WoAuXWqb5sE-iZgYu1VP0z7mDY6jMBu-SddKz9Uh-yDzBo9erjJdd4PhadsIUY_mml1hmAbvcGo-IMayw6M-SOKDfMI73sw0U-twzH3DHW9pB2PNUNV3T67mFVL60eOmw7KwotpdQewQwJ_34xEOm5g2UjkFDsFzDydnFmxMMm8PCEjg8DGRhKAfzdtUV00B4KzESSKhwu8oRzEU7D6mbvco7I1TIl3IOKT9JK8y_775_W9Flk6lMildTOe08upqnJeT3dgnKgYKbFyN9IgW_pr7Htu-prtVPXqlfhWxFtqmAZxnKaOXo14oeWWvX05E-wLw";
        let signature_bytes = Base64UrlUnpadded::decode_vec(signature).unwrap();
        let signature = RSASignature::from_bytes(&signature_bytes).unwrap();

        assert!(pk.verify_prehash(&digest, &signature).is_ok());
        assert!(pk.verify(msg, &signature).is_ok());

        let mut other_digest = digest;
        other_digest[0] += 1;
        assert!(pk.verify_prehash(&other_digest, &signature).is_err());

        let mut other_msg = *msg;
        other_msg[0] += 1;
        assert!(pk.verify(&other_msg, &signature).is_err());

        let mut other_signature_bytes = signature_bytes;
        other_signature_bytes[7] += 1;
        let other_signature = RSASignature::from_bytes(&other_signature_bytes).unwrap();
        assert!(pk.verify_prehash(&other_digest, &signature).is_err());
        assert!(pk.verify(msg, &other_signature).is_err());
    }
}
