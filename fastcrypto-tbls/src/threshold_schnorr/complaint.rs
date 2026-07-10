// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// TODO: This module is only used by the legacy `batch_avss` and can be removed once that is gone.

use crate::ecies_v1;
use crate::ecies_v1::RecoveryPackage;
use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::recovery_proof::check_recovered_shares;
use crate::threshold_schnorr::Extensions::{Encryption, Recovery};
use crate::threshold_schnorr::EG;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};

/// A complaint by an accuser that it could not decrypt or verify its shares.
/// Given enough responses to the complaint, the accuser can recover its shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Complaint {
    pub(crate) accuser_id: PartyId,
    pub(crate) proof: RecoveryPackage<EG>,
}

impl Complaint {
    /// Try to decrypt the shares for the accuser.
    pub fn check<S: BCSSerialized>(
        &self,
        enc_pk: &ecies_v1::PublicKey<EG>,
        ciphertext: &ecies_v1::MultiRecipientEncryption<EG>,
        random_oracle: &RandomOracle,
        verifier: impl Fn(&S) -> FastCryptoResult<()>,
    ) -> FastCryptoResult<()> {
        // Check that the recovery package is valid, and if not, return an error since the complaint is invalid.
        ciphertext
            .decrypt_with_recovery_package(
                &self.proof,
                &random_oracle.extend(&Recovery(self.accuser_id).to_string()),
                &random_oracle.extend(&Encryption.to_string()),
                enc_pk,
                self.accuser_id as usize,
            )
            .and_then(|buffer| check_recovered_shares(&buffer, verifier))
    }

    pub fn create(
        accuser_id: PartyId,
        ciphertext: &ecies_v1::MultiRecipientEncryption<EG>,
        enc_sk: &ecies_v1::PrivateKey<EG>,
        random_oracle: &RandomOracle,
        rng: &mut impl AllowedRng,
    ) -> Self {
        Self {
            accuser_id,
            proof: ciphertext.create_recovery_package(
                enc_sk,
                &random_oracle.extend(&Recovery(accuser_id).to_string()),
                rng,
            ),
        }
    }
}

/// A response to a complaint, containing the responder's shares. Constructed only via
/// `Receiver::handle_complaint`, which gates on `Complaint::check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintResponse<S> {
    pub(crate) responder_id: PartyId,
    pub(crate) shares: S,
}
