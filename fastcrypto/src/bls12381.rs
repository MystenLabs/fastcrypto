// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use std::{
    borrow::Borrow,
    fmt::{self, Debug, Display},
    mem::MaybeUninit,
    str::FromStr,
};

use crate::encoding::Encoding;
use ::blst::{blst_scalar, blst_scalar_from_uint64, BLST_ERROR};
use digest::Mac;

use once_cell::sync::OnceCell;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use zeroize::Zeroize;

use fastcrypto_derive::{SilentDebug, SilentDisplay};

use crate::{
    encoding::Base64,
    error::FastCryptoError,
    pubkey_bytes::PublicKeyBytes,
    serde_helpers::{keypair_decode_base64, BlsSignature},
};
use eyre::eyre;
use serde::{
    de::{self},
    Deserialize, Serialize,
};
use serde::de::DeserializeOwned;
use serde_with::serde_as;

use signature::{Signature, Signer, SignerMut, Verifier};

use crate::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
    VerifyingKey,
};

pub const BLS_PRIVATE_KEY_LENGTH: usize = 32;
pub const BLS_G1_ELEMENT_LENGTH: usize = 48;
pub const BLS_G2_ELEMENT_LENGTH: usize = 96;
pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

///
/// Define Structs
///

trait BLS12381Parameters {
    type PublicKeyType;
    const PK_LENGTH: usize;
    type PrivateKeyType;
    type SignatureType;
    const SIG_LENGTH: usize;
    const DST: &'static[u8];
    type AggregateSignatureType;
}

struct BLS12381MinSigParameters {}
impl BLS12381Parameters for BLS12381MinSigParameters {
    type PublicKeyType = blst::min_sig::PublicKey;
    const PK_LENGTH: usize = BLS_G2_ELEMENT_LENGTH;
    type PrivateKeyType = blst::min_sig::SecretKey;
    type SignatureType = blst::min_sig::Signature;
    const SIG_LENGTH: usize = BLS_G1_ELEMENT_LENGTH;
    const DST: &'static[u8] = DST_G1;
    type AggregateSignatureType = blst::min_sig::AggregateSignature;
}

struct BLS12381MinPkParameters {}
impl BLS12381Parameters for BLS12381MinPkParameters {
    type PublicKeyType = blst::min_pk::PublicKey;
    const PK_LENGTH: usize = BLS_G1_ELEMENT_LENGTH;
    type PrivateKeyType = blst::min_pk::SecretKey;
    type SignatureType = blst::min_pk::Signature;
    const SIG_LENGTH: usize = BLS_G2_ELEMENT_LENGTH;
    const DST: &'static[u8] = DST_G2;
    type AggregateSignatureType = blst::min_pk::AggregateSignature;
}

#[readonly::make]
#[derive(Default, Clone)]
pub struct BLS12381PublicKey<Params: BLS12381Parameters> {
    pub pubkey: Params::PublicKeyType,
    pub bytes: OnceCell<Vec<u8>>,
}

pub type BLS12381MinSigPublicKey = BLS12381PublicKey<BLS12381MinSigParameters>;
pub type BLS12381MinPkPublicKey = BLS12381PublicKey<BLS12381MinPkParameters>;

pub type BLS12381PublicKeyBytes<Params: BLS12381Parameters> = PublicKeyBytes<BLS12381PublicKey<Params>, BLS_G2_ELEMENT_LENGTH>;
pub type BLS12381MinSigPublicKeyBytes = BLS12381PublicKeyBytes<BLS12381MinSigParameters>;
pub type BLS12381MinPkPublicKeyBytes = BLS12381PublicKeyBytes<BLS12381MinPkParameters>;

#[readonly::make]
#[derive(SilentDebug, SilentDisplay, Default)]
pub struct BLS12381PrivateKey<Params: BLS12381Parameters> {
    pub privkey: Params::PrivateKeyType,
    pub bytes: OnceCell<[u8; BLS_PRIVATE_KEY_LENGTH]>,
}

pub type BLS12381MinSigPrivateKey = BLS12381PrivateKey<BLS12381MinSigParameters>;
pub type BLS12381MinPkPrivateKey = BLS12381PrivateKey<BLS12381MinPkParameters>;

// There is a strong requirement for this specific impl. in Fab benchmarks.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")] // necessary so as not to deserialize under a != type.
pub struct BLS12381KeyPair<Params: BLS12381Parameters> {
    name: BLS12381PublicKey<Params>,
    secret: BLS12381PrivateKey<Params>,
}
pub type BLS12381MinSigKeyPair = BLS12381KeyPair<BLS12381MinSigParameters>;
pub type BLS12381MinPkKeyPair = BLS12381KeyPair<BLS12381MinPkParameters>;

#[readonly::make]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLS12381Signature<Params: BLS12381Parameters> {
    #[serde_as(as = "BlsSignature")]
    pub sig: Params::SignatureType,
    #[serde(skip)]
    pub bytes: OnceCell<Vec<u8>>,
}

pub type BLS12381MinSigSignature = BLS12381Signature<BLS12381MinSigParameters>;
pub type BLS12381MinPkSignature = BLS12381Signature<BLS12381MinPkParameters>;

#[readonly::make]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLS12381AggregateSignature<Params: BLS12381Parameters> {
    #[serde_as(as = "Option<BlsSignature>")]
    pub sig: Option<Params::SignatureType>,
    #[serde(skip)]
    pub bytes: OnceCell<Vec<u8>>,
}

pub type BLS12381MinSigAggregateSignature = BLS12381AggregateSignature<BLS12381MinSigParameters>;
pub type BLS12381MinPkAggregateSignature = BLS12381AggregateSignature<BLS12381MinPkParameters>;

///
/// Implement SigningKey
///

impl<Params: BLS12381Parameters> AsRef<[u8]> for BLS12381PublicKey<Params> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.pubkey.to_bytes()))
            .expect("OnceCell invariant violated")
    }
}

impl<Params: BLS12381Parameters> ToFromBytes for BLS12381PublicKey<Params> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let pubkey =
            Params::PublicKeyType::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(BLS12381PublicKey {
            pubkey,
            bytes: OnceCell::new(),
        })
    }
}

impl<Params: BLS12381Parameters> std::hash::Hash for BLS12381PublicKey<Params> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<Params: BLS12381Parameters> PartialEq for BLS12381PublicKey<Params> {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl<Params: BLS12381Parameters> Eq for BLS12381PublicKey<Params> {}

impl<Params: BLS12381Parameters> PartialOrd for BLS12381PublicKey<Params> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}
impl<Params: BLS12381Parameters> Ord for BLS12381PublicKey<Params> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl<Params: BLS12381Parameters> Display for BLS12381PublicKey<Params> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl<Params: BLS12381Parameters> Debug for BLS12381PublicKey<Params> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks.
impl<Params: BLS12381Parameters> Serialize for BLS12381PublicKey<Params> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks.
impl<'de> Deserialize<'de> for BLS12381MinSigPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl<Params: BLS12381Parameters> Verifier<BLS12381Signature<Params>> for BLS12381PublicKey<Params>
    where BLS12381Signature<Params>: Debug,
          <Params as BLS12381Parameters>::SignatureType: Debug {
    fn verify(&self, msg: &[u8], signature: &BLS12381Signature<Params>) -> Result<(), signature::Error> {
        let err = signature
            .sig
            .verify(true, msg, Params::DST, &[], &self.pubkey, true);
        if err == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

impl<'a, Params: BLS12381Parameters> From<&'a BLS12381PrivateKey<Params>> for BLS12381PublicKey<Params> {
    fn from(secret: &'a BLS12381MinSigPrivateKey) -> Self {
        let inner = &secret.privkey;
        let pubkey = inner.sk_to_pk();
        BLS12381PublicKey {
            pubkey,
            bytes: OnceCell::new(),
        }
    }
}

impl<Params: BLS12381Parameters> VerifyingKey for BLS12381PublicKey<Params>
    where <Params as BLS12381Parameters>::SignatureType: Debug,
          <Params as BLS12381Parameters>::PublicKeyType: Debug,
          BLS12381PublicKey<Params>: DeserializeOwned + Clone + Sync + Send + Default + Debug {
    type Sig = BLS12381Signature<Params>;

    const LENGTH: usize = Params::PK_LENGTH;

    fn verify_batch_empty_fail(
        msg: &[u8],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report> {
        // TODO: fix this, the identical message opens up a rogue key attack
        let msgs_refs = (0..sigs.len()).map(|_| msg).collect::<Vec<_>>();
        Self::verify_batch_empty_fail_different_msg(&msgs_refs, pks, sigs)
    }

    fn verify_batch_empty_fail_different_msg<'a, M>(
        msgs: &[M],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report>
    where
        M: Borrow<[u8]> + 'a,
    {
        if sigs.is_empty() {
            return Err(eyre!(
                "Critical Error! This behaviour can signal something dangerous, and \
            that someone may be trying to bypass signature verification through providing empty \
            batches."
            ));
        }
        if sigs.len() != pks.len() || msgs.len() != pks.len() {
            return Err(eyre!(
                "Mismatch between number of messages, signatures and public keys provided"
            ));
        }
        let mut rands: Vec<blst_scalar> = Vec::with_capacity(sigs.len());
        let mut rng = OsRng;

        for _ in 0..sigs.len() {
            let mut vals = [0u64; 4];
            vals[0] = rng.next_u64();
            while vals[0] == 0 {
                // Reject zero as it is used for multiplication.
                vals[0] = rng.next_u64();
            }
            let mut rand_i = MaybeUninit::<blst_scalar>::uninit();
            unsafe {
                blst_scalar_from_uint64(rand_i.as_mut_ptr(), vals.as_ptr());
                rands.push(rand_i.assume_init());
            }
        }

        let result = BLS12381Parameters::SignatureType::verify_multiple_aggregate_signatures(
            &msgs.iter().map(|m| m.borrow()).collect::<Vec<_>>(),
            BLS12381Parameters::DST,
            &pks.iter().map(|pk| &pk.pubkey).collect::<Vec<_>>(),
            false,
            &sigs.iter().map(|sig| &sig.sig).collect::<Vec<_>>(),
            true,
            &rands,
            64,
        );
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(eyre!("Verification failed!"))
        }
    }
}

///
/// Implement Authenticator
///

impl<Params: BLS12381Parameters> AsRef<[u8]> for BLS12381Signature<Params> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.sig.to_bytes()))
            .expect("OnceCell invariant violated")
    }
}

impl<Params: BLS12381Parameters> std::hash::Hash for BLS12381Signature<Params> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<Params: BLS12381Parameters> PartialEq for BLS12381Signature<Params> {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for BLS12381MinSigSignature {}

impl<Params: BLS12381Parameters> Signature for BLS12381Signature<Params>
    where <Params as BLS12381Parameters>::SignatureType: Debug{
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let sig = Params::SignatureType::from_bytes(bytes).map_err(|_e| signature::Error::new())?;
        Ok(Params::SignatureType {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl<Params: BLS12381Parameters> Default for BLS12381Signature<Params> {
    fn default() -> Self {
        // TODO: improve this!
        let ikm: [u8; 32] = [
            0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a, 0x91, 0x0c, 0x8b, 0x72,
            0x85, 0x91, 0x46, 0x4c, 0xca, 0x56, 0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60,
            0xa6, 0x3c, 0x48, 0x99,
        ];

        let sk = Params::PrivateKeyType::key_gen(&ikm, &[]).unwrap();

        let msg = b"hello foo";
        let sig = sk.sign(msg, BLS12381Parameters::DST, &[]);
        Params::SignatureType {
            sig,
            bytes: OnceCell::new(),
        }
    }
}

impl<Params: BLS12381Parameters> Display for BLS12381Signature<Params> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl<Params: BLS12381Parameters + 'static> Authenticator for BLS12381Signature<Params>
    where BLS12381Signature<Params>: Clone + Sync + Send + Debug,
 <Params as BLS12381Parameters>::SignatureType: Debug{
    type PubKey = BLS12381PublicKey<Params>;
    type PrivKey = BLS12381PrivateKey<Params>;
    const LENGTH: usize = BLS12381Parameters::SIG_LENGTH;
}

///
/// Implement SigningKey
///

impl<Params: BLS12381Parameters> AsRef<[u8]> for BLS12381PrivateKey<Params> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.privkey.to_bytes()))
            .expect("OnceCell invariant violated")
    }
}

impl<Params: BLS12381Parameters> ToFromBytes for BLS12381PrivateKey<Params> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let privkey =
            Params::PrivateKeyType::from_bytes(bytes).map_err(|_e| FastCryptoError::InvalidInput)?;
        Ok(BLS12381MinSigPrivateKey {
            privkey,
            bytes: OnceCell::new(),
        })
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<Params: BLS12381Parameters> Serialize for BLS12381PrivateKey<Params> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de, Params:BLS12381Parameters> Deserialize<'de> for BLS12381PrivateKey<Params> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl<Params: BLS12381Parameters + 'static> SigningKey for BLS12381PrivateKey<Params>
    where <Params as BLS12381Parameters>::PrivateKeyType: Sync + Send {
    type PubKey = BLS12381PublicKey<Params>;
    type Sig = BLS12381Signature<Params>;
    const LENGTH: usize = BLS_PRIVATE_KEY_LENGTH;
}

impl<Params: BLS12381Parameters> Signer<BLS12381Signature<Params>> for BLS12381PrivateKey<Params>
    where <Params as BLS12381Parameters>::SignatureType: Debug {
    fn try_sign(&self, msg: &[u8]) -> Result<Params::SignatureType, signature::Error> {
        let sig = self.privkey.sign(msg, Params::DST, &[]);

        Ok(Params::SignatureType {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

///
/// Implement KeyPair
///

impl<Params: BLS12381Parameters> From<BLS12381MinSigPrivateKey> for BLS12381KeyPair<Params> {
    fn from(secret: BLS12381PrivateKey<Params>) -> Self {
        let name = BLS12381PublicKey::<Params>::from(&secret);
        BLS12381KeyPair::<Params> { name, secret }
    }
}

impl<Params: BLS12381Parameters> EncodeDecodeBase64 for BLS12381KeyPair<Params> {
    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.secret.as_ref());
        bytes.extend_from_slice(self.name.as_ref());
        Base64::encode(&bytes[..])
    }

    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        keypair_decode_base64(value)
    }
}

impl<Params: BLS12381Parameters> KeyPair for BLS12381KeyPair<Params>
    where BLS12381KeyPair<Params>: From<BLS12381PrivateKey<Params>>,
          <Params as BLS12381Parameters>::SignatureType: Debug {
    type PubKey = BLS12381PublicKey<Params>;
    type PrivKey = BLS12381PrivateKey<Params>;
    type Sig = BLS12381Signature<Params>;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        BLS12381MinSigPrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        BLS12381KeyPair {
            name: self.name.clone(),
            secret: BLS12381PrivateKey::<Params>::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        let privkey = Params::PrivateKeyType::key_gen(&ikm, &[]).expect("ikm length should be higher");
        let pubkey = privkey.sk_to_pk();
        BLS12381KeyPair::<Params> {
            name: BLS12381PublicKey::<Params> {
                pubkey,
                bytes: OnceCell::new(),
            },
            secret: BLS12381PrivateKey::<Params> {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl<Params: BLS12381Parameters> Signer<BLS12381Signature<Params>> for BLS12381KeyPair<Params>
    where <Params as BLS12381Parameters>::SignatureType: Debug,
BLS12381KeyPair<Params>: Debug {
    fn try_sign(&self, msg: &[u8]) -> Result<BLS12381Signature<Params>, signature::Error> {
        let blst_priv: &Params::PrivateKeyType = &self.secret.privkey;
        let sig = blst_priv.sign(msg, Params::DST, &[]);

        Ok(BLS12381MinSigSignature {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl<Params: BLS12381Parameters> FromStr for BLS12381KeyPair<Params> {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

///
/// Implement AggregateAuthenticator
///

// Don't try to use this externally
impl<Params: BLS12381Parameters> AsRef<[u8]> for BLS12381AggregateSignature<Params> {
    fn as_ref(&self) -> &[u8] {
        match self.sig {
            Some(sig) => self
                .bytes
                .get_or_try_init::<_, eyre::Report>(|| Ok(sig.to_bytes()))
                .expect("OnceCell invariant violated"),
            None => &[],
        }
    }
}

impl<Params: BLS12381Parameters> Display for BLS12381AggregateSignature<Params> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// see [#34](https://github.com/MystenLabs/narwhal/issues/34)
impl<Params: BLS12381Parameters> Default for BLS12381AggregateSignature<Params> {
    fn default() -> Self {
        BLS12381MinSigAggregateSignature {
            sig: None,
            bytes: OnceCell::new(),
        }
    }
}

impl<Params: BLS12381Parameters> AggregateAuthenticator for BLS12381AggregateSignature<Params>
    where <Params as BLS12381Parameters>::SignatureType: Clone + Send + Sync + Debug,
{
    type Sig = BLS12381Signature<Params>;
    type PubKey = BLS12381PublicKey<Params>;
    type PrivKey = BLS12381PrivateKey<Params>;

    /// Parse a key from its byte representation
    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, FastCryptoError> {
        Params::AggregateSignatureType::aggregate(
            &signatures
                .into_iter()
                .map(|x| &x.borrow().sig)
                .collect::<Vec<_>>(),
            true,
        )
        .map(|sig| BLS12381AggregateSignature::<Params> {
            sig: Some(sig.to_signature()),
            bytes: OnceCell::new(),
        })
        .map_err(|_| FastCryptoError::GeneralError)
    }

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError> {
        match self.sig {
            Some(ref mut sig) => {
                let mut aggr_sig = Params::AggregateSignatureType::from_signature(sig);
                aggr_sig
                    .add_signature(&signature.sig, true)
                    .map_err(|_| FastCryptoError::GeneralError)?;
                self.sig = Some(aggr_sig.to_signature());
                Ok(())
            }
            None => {
                self.sig = Some(signature.sig);
                Ok(())
            }
        }
    }

    fn add_aggregate(&mut self, signature: Self) -> Result<(), FastCryptoError> {
        match self.sig {
            Some(ref mut sig) => match signature.sig {
                Some(to_add) => {
                    let result = Params::AggregateSignatureType::aggregate(&[sig, &to_add], true)
                        .map_err(|_| FastCryptoError::GeneralError)?
                        .to_signature();
                    self.sig = Some(result);
                    Ok(())
                }
                None => Ok(()),
            },
            None => {
                self.sig = signature.sig;
                Ok(())
            }
        }
    }

    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        message: &[u8],
    ) -> Result<(), FastCryptoError> {
        let result = self
            .sig
            .ok_or(FastCryptoError::GeneralError)?
            .fast_aggregate_verify(
                true,
                message,
                BLS12381Parameters::DST,
                &pks.iter().map(|x| &x.pubkey).collect::<Vec<_>>()[..],
            );
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoError::GeneralError);
        }
        Ok(())
    }

    fn verify_different_msg(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        let result = self
            .sig
            .ok_or(FastCryptoError::GeneralError)?
            .aggregate_verify(
                true,
                messages,
                Params::DST,
                &pks.iter().map(|x| &x.pubkey).collect::<Vec<_>>()[..],
                true,
            );
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoError::GeneralError);
        }
        Ok(())
    }

    fn batch_verify<'a>(
        signatures: &[&Self],
        pks: Vec<impl Iterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        if signatures.len() != pks.len() || signatures.len() != messages.len() {
            return Err(FastCryptoError::InputLengthWrong(signatures.len()));
        }
        let mut pk_iter = pks.into_iter();
        for i in 0..signatures.len() {
            let sig = signatures[i].sig;
            let result = sig
                .ok_or(FastCryptoError::GeneralError)?
                .fast_aggregate_verify(
                    true,
                    messages[i],
                    Params::DST,
                    &pk_iter
                        .next()
                        .unwrap()
                        .map(|x| &x.pubkey)
                        .collect::<Vec<_>>()[..],
                );
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err(FastCryptoError::GeneralError);
            }
        }
        Ok(())
    }
}

///
/// Implement VerifyingKeyBytes
///

impl<Params: BLS12381Parameters> TryFrom<BLS12381PublicKeyBytes<Params>> for BLS12381PublicKey<Params> {
    type Error = signature::Error;

    fn try_from(bytes: BLS12381PublicKeyBytes<Params>) -> Result<BLS12381PublicKey<Params>, Self::Error> {
        BLS12381PublicKey::from_bytes(bytes.as_ref()).map_err(|_| Self::Error::new())
    }
}

impl<Params: BLS12381Parameters> From<&BLS12381PublicKey<Params>> for BLS12381PublicKeyBytes<Params> {
    fn from(pk: &BLS12381PublicKey<Params>) -> BLS12381PublicKeyBytes<Params> {
        BLS12381PublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

impl<Params: BLS12381Parameters>  zeroize::Zeroize for BLS12381PrivateKey<Params> {
    fn zeroize(&mut self) {
        self.bytes.take().zeroize();
        self.privkey.zeroize();
    }
}

impl<Params: BLS12381Parameters> zeroize::ZeroizeOnDrop for BLS12381PrivateKey<Params> {}

impl<Params: BLS12381Parameters> Drop for BLS12381PrivateKey<Params> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<Params: BLS12381Parameters> zeroize::Zeroize for BLS12381KeyPair<Params> {
    fn zeroize(&mut self) {
        self.secret.zeroize()
    }
}

impl<Params: BLS12381Parameters> zeroize::ZeroizeOnDrop for BLS12381KeyPair<Params> {}

impl<Params: BLS12381Parameters> Drop for BLS12381KeyPair<Params> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<Params: BLS12381Parameters> ToFromBytes for BLS12381AggregateSignature<Params>
    where <Params as BLS12381Parameters>::SignatureType: Debug{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let sig = Params::SignatureType::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(BLS12381AggregateSignature::<Params> {
            sig: Some(sig),
            bytes: OnceCell::new(),
        })
    }
}
