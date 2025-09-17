use crate::ecies_v1;
use crate::ecies_v1::RecoveryPackage;
use crate::nodes::PartyId;
use crate::threshold_schnorr::bcs::BCSSerialized;
use crate::threshold_schnorr::ro_extension::Extension::{Encryption, Recovery};
use crate::threshold_schnorr::ro_extension::RandomOracleWrapper;
use crate::threshold_schnorr::EG;
use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use serde::Deserialize;
use tracing::debug;

/// A complaint by an accuser that it could not decrypt or verify its shares.
/// Given enough responses to the complaint, the accuser can recover its shares.
#[derive(Clone, Debug)]
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
        random_oracle: &RandomOracleWrapper,
        verifier: impl Fn(&S) -> FastCryptoResult<()>,
    ) -> FastCryptoResult<()> {
        // Check that the recovery package is valid, and if not, return an error since the complaint is invalid.
        let buffer = ciphertext.decrypt_with_recovery_package(
            &self.proof,
            &random_oracle.extend(Recovery(self.accuser_id)),
            &random_oracle.extend(Encryption),
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
        random_oracle: &RandomOracleWrapper,
        rng: &mut impl AllowedRng,
    ) -> Self {
        Self {
            accuser_id,
            proof: ciphertext.create_recovery_package(
                enc_sk,
                &random_oracle.extend(Recovery(accuser_id)),
                rng,
            ),
        }
    }
}

/// A response to a complaint, containing a recovery package for the accuser.
#[derive(Debug, Clone)]
pub struct ComplaintResponse {
    pub(crate) responder_id: PartyId,
    pub(crate) recovery_package: RecoveryPackage<EG>,
}

impl ComplaintResponse {
    pub(crate) fn create(
        responder_id: PartyId,
        ciphertext: &ecies_v1::MultiRecipientEncryption<EG>,
        enc_secret_key: &ecies_v1::PrivateKey<EG>,
        ro: &RandomOracleWrapper,
        rng: &mut impl AllowedRng,
    ) -> Self {
        ComplaintResponse {
            responder_id,
            recovery_package: ciphertext.create_recovery_package(
                enc_secret_key,
                &ro.extend(Recovery(responder_id)),
                rng,
            ),
        }
    }

    pub(crate) fn decrypt_with_response<T: for<'a> Deserialize<'a>>(
        &self,
        ro: &RandomOracleWrapper,
        enc_pk: &ecies_v1::PublicKey<EG>,
        ciphertext: &ecies_v1::MultiRecipientEncryption<EG>,
    ) -> FastCryptoResult<T> {
        let bytes = ciphertext.decrypt_with_recovery_package(
            &self.recovery_package,
            &ro.extend(Recovery(self.responder_id)),
            &ro.extend(Encryption),
            enc_pk,
            self.responder_id as usize,
        )?;
        bcs::from_bytes(&bytes).map_err(|_| InvalidInput)
    }
}
