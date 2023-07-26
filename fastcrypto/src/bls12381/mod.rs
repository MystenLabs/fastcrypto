// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [BLS signature scheme over the BLS 12-381 curve](https://en.wikipedia.org/wiki/BLS_digital_signature).
//!
//! ```rust
//! # use fastcrypto::bls12381::min_sig::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! use rand::thread_rng;
//! let kp = BLS12381KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```

use crate::serde_helpers::BytesRepresentation;
use crate::traits::{
    AggregateAuthenticator, AllowedRng, Authenticator, EncodeDecodeBase64, InsecureDefault,
    KeyPair, Signer, SigningKey, ToFromBytes, VerifyingKey,
};
use crate::{
    encoding::Base64, encoding::Encoding, error::FastCryptoError,
    serialize_deserialize_with_to_from_bytes,
};
use crate::{generate_bytes_representation, impl_base64_display_fmt};
use blst::{blst_scalar, blst_scalar_from_le_bytes, blst_scalar_from_uint64, BLST_ERROR};
#[cfg(any(test, feature = "experimental"))]
use eyre::eyre;
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::OnceCell;
use std::{
    borrow::Borrow,
    fmt::{self, Debug},
    mem::MaybeUninit,
    str::FromStr,
};

/// BLS signatures use two groups G1, G2, where elements of the first can be encoded using 48 bytes
/// and of the second using 96 bytes. BLS supports two modes:
/// - Minimal-signature-size (or min-sig) - signatures are in G1 and public keys are in G2.
/// - Minimal-pubkey-size (or min-pk) - signature are in G2 and public keys are in G1.
///
/// Below we define BLS related objects for each of the modes, see instantiations
/// [fastcrypto::bls12381::min_sig] and [fastcrypto::bls12381::min_pk].
macro_rules! define_bls12381 {
(
    $pk_length:expr,
    $sig_length:expr,
    $dst_string:expr
) => {

/// BLS 12-381 public key.
///
/// For optimizing performance, throughout this module we assume that before being used, public keys
/// are:
/// * Validated by calling [BLS12381PublicKey::validate]), and,
/// * Proof-of-Possession (PoP) is performed on them as a protection against rough key attacks.
#[readonly::make]
#[derive(Clone)]
pub struct BLS12381PublicKey {
    pub pubkey: blst::PublicKey,
    pub bytes: OnceCell<[u8; $pk_length]>,
}

/// BLS 12-381 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct BLS12381PrivateKey {
    pub privkey: blst::SecretKey,
    pub bytes: OnceCell<zeroize::Zeroizing<[u8; BLS_PRIVATE_KEY_LENGTH]>>,
}

/// BLS 12-381 key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct BLS12381KeyPair {
    public: BLS12381PublicKey,
    private: BLS12381PrivateKey,
}

/// BLS 12-381 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct BLS12381Signature {
    pub sig: blst::Signature,
    pub bytes: OnceCell<[u8; $sig_length]>,
}

/// Aggregation of multiple BLS 12-381 signatures.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct BLS12381AggregateSignature {
    pub sig: blst::Signature,
    pub bytes: OnceCell<[u8; $sig_length]>,
}

//
// Boilerplate code for [BLS12381PublicKey].
//

impl std::hash::Hash for BLS12381PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for BLS12381PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for BLS12381PublicKey {}

impl PartialOrd for BLS12381PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for BLS12381PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl_base64_display_fmt!(BLS12381PublicKey);

impl Debug for BLS12381PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl AsRef<[u8]> for BLS12381PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| self.pubkey.to_bytes())
    }
}

impl ToFromBytes for BLS12381PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        // key_validate() does NOT validate the public key. Please use validate() where needed.
        let pubkey =
            blst::PublicKey::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(BLS12381PublicKey {
            pubkey,
            bytes: OnceCell::new(),
        })
    }
}

//
// Custom code for [BLS12381PublicKey].
//

// Needed since the current NW implementation requires default public keys.
// Note that deserialization of this object will fail if we validate it is a valid public key.
impl InsecureDefault for BLS12381PublicKey {
    fn insecure_default() -> Self {
        BLS12381PublicKey {
            pubkey: blst::PublicKey::default(),
            bytes: OnceCell::new(),
        }
    }
}

serialize_deserialize_with_to_from_bytes!(BLS12381PublicKey, $pk_length);
generate_bytes_representation!(BLS12381PublicKey, {$pk_length}, BLS12381PublicKeyAsBytes);

impl<'a> From<&'a BLS12381PrivateKey> for BLS12381PublicKey {
    fn from(secret: &'a BLS12381PrivateKey) -> Self {
        let inner = &secret.privkey;
        let pubkey = inner.sk_to_pk();
        BLS12381PublicKey {
            pubkey,
            bytes: OnceCell::new(),
        }
    }
}

// TODO: Once NW does not need to ser/deser public keys in many places we should call validate
// during deserialization and get rid of this function.
impl BLS12381PublicKey {
    pub fn validate(&self) -> Result<(), FastCryptoError> {
        self.pubkey.validate().map_err(|_e| FastCryptoError::InvalidInput)
    }
}

impl VerifyingKey for BLS12381PublicKey {
    type PrivKey = BLS12381PrivateKey;
    type Sig = BLS12381Signature;
    const LENGTH: usize = $pk_length;

    fn verify(&self, msg: &[u8], signature: &BLS12381Signature) -> Result<(), FastCryptoError> {
        // verify() only validates the signature. Please use pk that was validated.
        let err = signature
            .sig
            .verify(true, msg, $dst_string, &[], &self.pubkey, false);
        if err == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidSignature)
        }
    }

    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail(
        msg: &[u8],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report> {
        if sigs.is_empty() {
            return Err(eyre!(
                "Critical Error! This behaviour can signal something dangerous, and \
            that someone may be trying to bypass signature verification through providing empty \
            batches."
            ));
        }
        if sigs.len() != pks.len() {
            return Err(eyre!(
                "Mismatch between number of signatures and public keys provided"
            ));
        }
        let aggregated_sig = BLS12381AggregateSignature::aggregate(sigs)
            .map_err(|_| eyre!("Signature aggregation before verifying failed!"))?;
        aggregated_sig
            .verify(pks, msg)
            .map_err(|_| eyre!("Batch verification failed!"))
    }

    #[cfg(any(test, feature = "experimental"))]
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

        let rands = get_random_scalars(sigs.len());

        let result = blst::Signature::verify_multiple_aggregate_signatures(
            &msgs.iter().map(|m| m.borrow()).collect::<Vec<_>>(),
            $dst_string,
            &pks.iter().map(|pk| &pk.pubkey).collect::<Vec<_>>(),
            false,
            &sigs.iter().map(|sig| &sig.sig).collect::<Vec<_>>(),
            true,
            &rands,
            BLS_BATCH_RANDOM_SCALAR_LENGTH,
        );
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(eyre!("Batch verification failed!"))
        }
    }
}

fn get_random_scalar<Rng: AllowedRng>(rng: &mut Rng) -> blst_scalar {
    static_assertions::const_assert!(
        64 <= BLS_BATCH_RANDOM_SCALAR_LENGTH && BLS_BATCH_RANDOM_SCALAR_LENGTH <= 128
    );

    let mut vals = [0u64; 4];
    loop {
        vals[0] = rng.next_u64();
        vals[1] = rng.next_u64();

        // Reject zero as it is used for multiplication.
        let vals1_lsb = vals[1] & (((1u128 << (BLS_BATCH_RANDOM_SCALAR_LENGTH - 64)) - 1) as u64);
        if vals[0] | vals1_lsb != 0 {
            break;
        }
    }
    let mut rand_i = MaybeUninit::<blst_scalar>::uninit();
    unsafe {
        blst_scalar_from_uint64(rand_i.as_mut_ptr(), vals.as_ptr());
        return rand_i.assume_init();
    }
}

fn get_one() -> blst_scalar {
    let mut one = blst_scalar::default();
    let mut vals = [0u8; 32];
    vals[0] = 1;
    unsafe {
        blst_scalar_from_le_bytes(&mut one, vals.as_ptr(), 32);
    }
    one
}

// Always generates 128bit numbers though not all the bits must be used.
fn get_random_scalars(n: usize) -> Vec<blst_scalar> {
    if n == 0 {
        return Vec::new();
    }
    let mut rands: Vec<blst_scalar> = Vec::with_capacity(n);
    // The first coefficient can safely be set to 1 (see https://github.com/MystenLabs/fastcrypto/issues/120)
    rands.push(get_one());
    let mut rng = rand::thread_rng();
    (1..n).into_iter().for_each(|_| rands.push(get_random_scalar(&mut rng)));
    rands
}

//
// Boilerplate code for [BLS12381PrivateKey].
//

impl PartialEq for BLS12381PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for BLS12381PrivateKey {}

// All fields impl zeroize::ZeroizeOnDrop directly or indirectly (OnceCell's drop will call
// ZeroizeOnDrop).
impl zeroize::ZeroizeOnDrop for BLS12381PrivateKey {}

impl AsRef<[u8]> for BLS12381PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| zeroize::Zeroizing::new(self.privkey.to_bytes())).as_ref()
    }
}

impl ToFromBytes for BLS12381PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        // from_bytes() validates that the key is in the right group.
        let privkey =
            blst::SecretKey::from_bytes(bytes).map_err(|_e| FastCryptoError::InvalidInput)?;
        Ok(BLS12381PrivateKey {
            privkey,
            bytes: OnceCell::new(),
        })
    }
}

//
// Custom code for [BLS12381PrivateKey].
//

serialize_deserialize_with_to_from_bytes!(BLS12381PrivateKey, BLS_PRIVATE_KEY_LENGTH);

impl SigningKey for BLS12381PrivateKey {
    type PubKey = BLS12381PublicKey;
    type Sig = BLS12381Signature;
    const LENGTH: usize = BLS_PRIVATE_KEY_LENGTH;
}

impl Signer<BLS12381Signature> for BLS12381PrivateKey {
    fn sign(&self, msg: &[u8]) -> BLS12381Signature {
        BLS12381Signature {
            sig: self.privkey.sign(msg, $dst_string, &[]),
            bytes: OnceCell::new(),
        }
    }
}

//
// Boilerplate code for [BLS12381Signature].
//

impl PartialEq for BLS12381Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for BLS12381Signature {}

impl std::hash::Hash for BLS12381Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl AsRef<[u8]> for BLS12381Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| self.sig.to_bytes())
    }
}

impl ToFromBytes for BLS12381Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        // from_bytes() does NOT check if the signature is in the right group. We check that when
        // verifying the signature.
        let sig = blst::Signature::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(BLS12381Signature {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl_base64_display_fmt!(BLS12381Signature);

//
// Custom code for [BLS12381Signature].
//

serialize_deserialize_with_to_from_bytes!(BLS12381Signature, $sig_length);

impl Default for BLS12381Signature {
    fn default() -> Self {
        // Setting the first byte to 0xc0 (1100), the first bit represents its in compressed form,
        // the second bit represents its infinity point. See more: https://github.com/supranational/blst#serialization-format
        let mut infinity: [u8; $sig_length] = [0; $sig_length];
        infinity[0] = 0xc0;

        BLS12381Signature {
            sig: blst::Signature::from_bytes(&infinity).expect("Should decode infinity signature"),
            bytes: OnceCell::new(),
        }
    }
}

impl Authenticator for BLS12381Signature {
    type PubKey = BLS12381PublicKey;
    type PrivKey = BLS12381PrivateKey;
    const LENGTH: usize = $sig_length;
}

//
// Boilerplate code for [BLS12381KeyPair].
//

impl From<BLS12381PrivateKey> for BLS12381KeyPair {
    fn from(private: BLS12381PrivateKey) -> Self {
        let public = BLS12381PublicKey::from(&private);
        BLS12381KeyPair { public, private }
    }
}

/// The bytes form of the keypair only contain the private key bytes
impl AsRef<[u8]> for BLS12381KeyPair {
    fn as_ref(&self) -> &[u8] {
        self.private.as_ref()
    }
}

impl ToFromBytes for BLS12381KeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        BLS12381PrivateKey::from_bytes(bytes).map(|private| private.into())
    }
}

//
// Custom code for [BLS12381KeyPair].
//

serialize_deserialize_with_to_from_bytes!(BLS12381KeyPair, BLS_KEYPAIR_LENGTH);

impl KeyPair for BLS12381KeyPair {
    type PubKey = BLS12381PublicKey;
    type PrivKey = BLS12381PrivateKey;
    type Sig = BLS12381Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        BLS12381PrivateKey::from_bytes(self.private.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        BLS12381KeyPair {
            public: self.public.clone(),
            private: BLS12381PrivateKey::from_bytes(self.private.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        // TODO: Consider moving to key gen version 5.
        let privkey = blst::SecretKey::key_gen(&ikm, &[]).expect("ikm length should be higher");
        let pubkey = privkey.sk_to_pk();
        BLS12381KeyPair {
            public: BLS12381PublicKey {
                pubkey,
                bytes: OnceCell::new(),
            },
            private: BLS12381PrivateKey {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl Signer<BLS12381Signature> for BLS12381KeyPair {
    fn sign(&self, msg: &[u8]) -> BLS12381Signature {
        self.private.sign(msg)
    }
}

impl FromStr for BLS12381KeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

//
// Boilerplate code for [BLS12381AggregateSignature].
//

impl_base64_display_fmt!(BLS12381AggregateSignature);

impl PartialEq for BLS12381AggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for BLS12381AggregateSignature {}

impl Default for BLS12381AggregateSignature {
    fn default() -> Self {
        BLS12381Signature::default().into()
    }
}

impl AsRef<[u8]> for BLS12381AggregateSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| self.sig.to_bytes())
    }
}

impl From <BLS12381Signature> for BLS12381AggregateSignature {
    fn from(sig: BLS12381Signature) -> Self {
        BLS12381AggregateSignature {
            sig: sig.sig,
            bytes: OnceCell::new(),
        }
    }
}

//
// Custom code for [BLS12381AggregateSignature].
//

serialize_deserialize_with_to_from_bytes!(BLS12381AggregateSignature, $sig_length);
generate_bytes_representation!(BLS12381AggregateSignature, {$sig_length}, BLS12381AggregateSignatureAsBytes);

impl ToFromBytes for BLS12381AggregateSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        // from_bytes does NOT validate the signature. We do that in verify.
        let sig = blst::Signature::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(BLS12381AggregateSignature {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl AggregateAuthenticator for BLS12381AggregateSignature {
    type Sig = BLS12381Signature;
    type PubKey = BLS12381PublicKey;
    type PrivKey = BLS12381PrivateKey;

    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, FastCryptoError> {
        // aggregate() below does not validate signatures.
        blst::AggregateSignature::aggregate(
            &signatures
                .into_iter()
                .map(|x| &x.borrow().sig)
                .collect::<Vec<_>>(),
            false,
        )
        .map(|sig| BLS12381AggregateSignature {
            sig: sig.to_signature(),
            bytes: OnceCell::new(),
        })
        .map_err(|_| FastCryptoError::InvalidInput)
    }

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError> {
        let mut aggr_sig = blst::AggregateSignature::from_signature(&self.sig);
        // add_signature() does not validate the new signature.
        aggr_sig.add_signature(&signature.sig, false).map_err(|_| FastCryptoError::InvalidInput)?;
        self.sig = aggr_sig.to_signature();
        self.bytes.take();
        Ok(())
    }

    fn add_aggregate(&mut self, signature: Self) -> Result<(), FastCryptoError> {
        // aggregate() does not validate the new signature.
        let result = blst::AggregateSignature::aggregate(&[&self.sig, &signature.sig], false)
            .map_err(|_| FastCryptoError::InvalidInput)?.to_signature();
        self.sig = result;
        self.bytes.take();
        Ok(())
    }

    // This function assumes that that all public keys were verified using a proof of possession.
    // See comment above [BLS12381PublicKey].
    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        message: &[u8],
    ) -> Result<(), FastCryptoError> {
        // Validate signatures but not public keys which the user must validate before calling this.
        let result = self
            .sig
            .fast_aggregate_verify(
                true,
                message,
                $dst_string,
                &pks.iter().map(|x| &x.pubkey).collect::<Vec<_>>()[..],
            );
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoError::InvalidSignature);
        }
        Ok(())
    }

    // This function assumes that that all public keys were verified using a proof of possession.
    // See comment above [BLS12381PublicKey].
    fn verify_different_msg(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        // Validate signatures but not public keys which the user must validate before calling this.
        let result = self
            .sig
            .aggregate_verify(
                true,
                messages,
                $dst_string,
                &pks.iter().map(|x| &x.pubkey).collect::<Vec<_>>()[..],
                false,
            );
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(FastCryptoError::InvalidSignature);
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

        if signatures.is_empty() {
            // verify_multiple_aggregate_signatures fails on empty input, but we accept here.
            return Ok(())
        }

        let mut agg_pks: Vec<blst::PublicKey> = Vec::with_capacity(signatures.len());
        for keys in pks {
             let keys_as_vec = keys.map(|x| x.pubkey.borrow()).collect::<Vec<_>>();
             agg_pks.push(blst::AggregatePublicKey::aggregate(&keys_as_vec, false).unwrap().to_public_key()
             );
         }

        // Validate signatures but not public keys which the user must validate before calling this.
        let result = blst::Signature::verify_multiple_aggregate_signatures(
            &messages,
            $dst_string,
            &agg_pks.iter().map(|m| m.borrow()).collect::<Vec<_>>(),
            false,
            &signatures.iter().map(|agg_sig| &agg_sig.sig).collect::<Vec<_>>(),
            true,
            &get_random_scalars(signatures.len()),
            BLS_BATCH_RANDOM_SCALAR_LENGTH,
        );
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(FastCryptoError::GeneralOpaqueError)
        }
    }
}

};

} // macro_rules! define_bls12381.

/// The length of a private key in bytes.
pub const BLS_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of public keys when using the [min_pk] module and the length of signatures when using the [min_sig] module.
pub const BLS_G1_LENGTH: usize = 48;

/// The length of public keys when using the [min_sig] module and the length of signatures when using the [min_pk] module.
pub const BLS_G2_LENGTH: usize = 96;

/// The key pair bytes length used by helper is the same as the private key length. This is because only private key is serialized.
pub const BLS_KEYPAIR_LENGTH: usize = BLS_PRIVATE_KEY_LENGTH;

/// The statistical probability (in bits) that a batch of signatures which includes invalid
/// signatures will pass batch_verify.
const BLS_BATCH_RANDOM_SCALAR_LENGTH: usize = 96;

/// Module minimizing the size of signatures.
pub mod min_sig;

/// Module minimizing the size of public keys.
pub mod min_pk;

#[cfg(feature = "experimental")]
pub mod mskr;
