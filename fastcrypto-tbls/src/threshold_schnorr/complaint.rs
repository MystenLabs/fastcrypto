// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::ecies_v1::RecoveryPackage;
use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::Extensions::{Encryption, Recovery};
use crate::threshold_schnorr::EG;
use fastcrypto::error::FastCryptoError::InvalidProof;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};
use tracing::debug;

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
        let buffer = ciphertext.decrypt_with_recovery_package(
            &self.proof,
            &random_oracle.extend(&Recovery(self.accuser_id).to_string()),
            &random_oracle.extend(&Encryption.to_string()),
            enc_pk,
            self.accuser_id as usize,
        )?;

        let shares = match S::from_bytes(&buffer) {
            Ok(s) => s,
            Err(_) => {
                debug!(
                    "Complaint by party {} is valid: C complaint failed to deserialize shares",
                    self.accuser_id
                );
                return Ok(());
            }
        };

        match verifier(&shares) {
            Ok(_) => {
                debug!(
                    "Complaint by party {} is invalid: Shares verify correctly",
                    self.accuser_id
                );
                Err(InvalidProof)
            }
            Err(_) => {
                debug!(
                    "Complaint by party {} is valid: Shares do not verify correctly",
                    self.accuser_id
                );
                Ok(())
            }
        }
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

/// A response to a complaint, containing the responders shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintResponse<S> {
    pub(crate) responder_id: PartyId,
    pub(crate) shares: S,
}

impl<S> ComplaintResponse<S> {
    pub(crate) fn create(responder_id: PartyId, shares: S) -> Self {
        ComplaintResponse {
            responder_id,
            shares,
        }
    }
}
