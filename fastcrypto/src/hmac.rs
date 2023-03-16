// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [HMAC](https://www.rfc-editor.org/rfc/rfc2104) and [HKDF](https://tools.ietf.org/html/rfc5869).

use crate::error::FastCryptoError;
#[cfg(any(test, feature = "experimental"))]
use crate::hash::ReverseWrapper;
#[cfg(any(test, feature = "experimental"))]
use crate::traits::{KeyPair, SigningKey};
use crate::{hash::Digest, traits::ToFromBytes};
use digest::OutputSizeUser;
#[cfg(any(test, feature = "experimental"))]
use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    typenum::{IsLess, Le, NonZero},
    HashMarker,
};

use crate::private_seed::PrivateSeed;
use hkdf::hmac::{Hmac, Mac};

/// Creation of a keypair using the [RFC 5869](https://tools.ietf.org/html/rfc5869) HKDF specification.
/// This requires choosing an HMAC function of the correct length (conservatively, the size of a private key for this curve).
/// Despite the unsightly generics (which aim to ensure this works for a wide range of hash functions), this is straightforward to use.
///
/// Example:
/// ```rust
/// use fastcrypto::hash::Sha3_256;
/// use fastcrypto::ed25519::Ed25519KeyPair;
/// use fastcrypto::hmac::hkdf_generate_from_ikm;
/// # fn main() {
///     let ikm = b"some_ikm";
///     let info = b"my_app";
///     let salt = b"some_salt";
///     let my_keypair = hkdf_generate_from_ikm::<Sha3_256, Ed25519KeyPair>(ikm, salt, info);
///
///     let my_keypair_default_info = hkdf_generate_from_ikm::<Sha3_256, Ed25519KeyPair>(ikm, salt, &[]);
/// # }
/// ```
///
/// Note: This HKDF function may not match the native library's deterministic key generation functions.
/// For example, observe that in the blst library:
/// ```rust
/// use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
/// use fastcrypto::hash::Sha3_256;
/// use fastcrypto::traits::{KeyPair, SigningKey, ToFromBytes};
/// use fastcrypto::hmac::hkdf_generate_from_ikm;
///
/// # fn main() {
///     let ikm = b"02345678001234567890123456789012";
///     let info = b"my_app";
///     let salt = b"some_salt";

///     let my_keypair = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(ikm, salt, info).unwrap();
///     let native_sk = blst::min_sig::SecretKey::key_gen_v4_5(ikm, salt, info).unwrap();

///     assert_ne!(native_sk.to_bytes(), my_keypair.private().as_bytes());
/// # }
/// ```
#[cfg(any(test, feature = "experimental"))]
pub fn hkdf_generate_from_ikm<H, K>(
    ikm: &[u8],  // IKM (32 bytes).
    salt: &[u8], // Salt (can be empty).
    info: &[u8], // Info (can be empty).
) -> Result<K, FastCryptoError>
where
    // This is a tad tedious, because of HKDF's use of a sealed trait. But mostly harmless since the traits exposed (H and K) are both defined in fastcrypto.
    H: ReverseWrapper,
    <<H as ReverseWrapper>::Variant as CoreProxy>::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <<<H as ReverseWrapper>::Variant as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<<H as ReverseWrapper>::Variant as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>:
        NonZero,
    K: KeyPair,
{
    // When HMAC is applied, salt is padded with zeros if shorter than the H's block size
    // (both for Some(&[]) and None as the value of salt).
    let hk = hkdf::Hkdf::<H::Variant, Hmac<H::Variant>>::new(Some(salt), ikm);

    let mut okm = vec![0u8; K::PrivKey::LENGTH];
    hk.expand(info, &mut okm)
        .map_err(|_| FastCryptoError::GeneralOpaqueError)?;

    let secret_key = K::PrivKey::from_bytes(&okm[..]).unwrap();

    let keypair = K::from(secret_key);
    Ok(keypair)
}

////////////////////////////////////////////////////////////////////////
/// HMAC-SHA3-256 based functions

const HMAC_KEY_RECOMMENDED_LENGTH: usize = 32;
const HKDF_KEY_RECOMMENDED_LENGTH: usize = 32;

/// Type for key in [hmac_sha3_256].
pub type HmacKey = PrivateSeed<HMAC_KEY_RECOMMENDED_LENGTH, false>;

/// [Keyed-Hash Message Authentication Code](https://www.rfc-editor.org/rfc/rfc2104) (HMAC) using SHA3-256.
pub fn hmac_sha3_256(key: &HmacKey, message: &[u8]) -> Digest<32> {
    let mut hash = Hmac::<sha3::Sha3_256>::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    hash.update(message);
    let output = hash.finalize();
    Digest {
        digest: output.into_bytes().into(),
    }
}

/// Type for input keying material in [hkdf_sha3_256].
pub type HkdfIkm = PrivateSeed<HKDF_KEY_RECOMMENDED_LENGTH, false>;

/// [HMAC-based Extract-and-Expand Key Derivation Function](https://tools.ietf.org/html/rfc5869) (HKDF) using SHA3-256.
pub fn hkdf_sha3_256(
    ikm: &HkdfIkm,
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>, FastCryptoError> {
    if output_length > sha3::Sha3_256::output_size() * 255 {
        return Err(FastCryptoError::InputTooLong(
            sha3::Sha3_256::output_size() * 255,
        ));
    }
    let hk = hkdf::Hkdf::<sha3::Sha3_256, Hmac<sha3::Sha3_256>>::new(Some(salt), ikm.as_bytes());
    let mut output: Vec<u8> = vec![0; output_length];
    hk.expand(info, output.as_mut_slice())
        .map_err(|_| FastCryptoError::GeneralOpaqueError)?;
    Ok(output)
}
