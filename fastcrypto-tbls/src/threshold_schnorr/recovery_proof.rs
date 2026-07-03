// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::ecies_v1::{Ciphertext, RecoveryPackage, SharedComponents};
use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::Extensions::{Encryption, Recovery};
use crate::threshold_schnorr::EG;
use fastcrypto::error::FastCryptoError::InvalidProof;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};

/// Cryptographic proof attached to a complaint: an ECIES recovery package that opens the
/// dealer's shared ciphertext with the accuser's private key and produces shares that fail a
/// supplied verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryProof(RecoveryPackage<EG>);

impl RecoveryProof {
    /// Verify the proof for the given `accuser_id`: decrypt `ciphertext` via the recovery
    /// package and confirm the resulting shares fail `verifier`. The caller supplies
    /// `accuser_id` from their protocol context — it is *not* carried inside the proof.
    ///
    /// Assumes `shared` has already been verified by the caller (i.e. it comes from a
    /// ciphertext the caller has verified).
    pub fn check<S: BCSSerialized>(
        &self,
        accuser_id: PartyId,
        enc_pk: &ecies_v1::PublicKey<EG>,
        ciphertext: &Ciphertext,
        shared: &SharedComponents<EG>,
        random_oracle: &RandomOracle,
        verifier: impl Fn(&S) -> FastCryptoResult<()>,
    ) -> FastCryptoResult<()> {
        // Check that the recovery package is valid, and if not, return an error since the complaint is invalid.
        shared
            .decrypt_with_recovery_package(
                ciphertext,
                &self.0,
                &random_oracle.extend(&Recovery(accuser_id).to_string()),
                &random_oracle.extend(&Encryption.to_string()),
                enc_pk,
                accuser_id as usize,
            )
            .and_then(|buffer| check_recovered_shares(&buffer, verifier))
    }

    pub fn create(
        accuser_id: PartyId,
        ciphertext: &ecies_v1::SharedComponents<EG>,
        enc_sk: &ecies_v1::PrivateKey<EG>,
        random_oracle: &RandomOracle,
        rng: &mut impl AllowedRng,
    ) -> Self {
        Self(ciphertext.create_recovery_package(
            enc_sk,
            &random_oracle.extend(&Recovery(accuser_id).to_string()),
            rng,
        ))
    }
}

/// Given the `buffer` decrypted from an accuser's recovery package, decide whether their complaint
/// holds: it is valid ([`Ok`]) when the bytes fail to deserialize or the recovered shares fail
/// `verifier`, and invalid ([`InvalidProof`]) when the shares verify correctly.
pub(crate) fn check_recovered_shares<S: BCSSerialized>(
    bytes: &[u8],
    verifier: impl Fn(&S) -> FastCryptoResult<()>,
) -> FastCryptoResult<()> {
    match S::from_bytes(bytes) {
        Ok(shares) if verifier(&shares).is_ok() => Err(InvalidProof),
        _ => Ok(()),
    }
}
