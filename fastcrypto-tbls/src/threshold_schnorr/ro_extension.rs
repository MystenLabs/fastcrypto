use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::ro_extension::Extension::{Challenge, Encryption, Recovery};

pub enum Extension {
    Recovery(PartyId),
    Encryption,
    Challenge,
}

/// Helper trait to extend a random oracle with context-specific strings.
pub trait RandomOracleExtensions {
    fn base(&self) -> &RandomOracle;

    /// Extend the base random oracle with a context-specific string.
    fn extension(&self, extension: Extension) -> RandomOracle {
        let extension_string = match extension {
            Recovery(accuser) => &format!("recovery of {accuser}"),
            Encryption => "encryption",
            Challenge => "challenge",
        };
        self.base().extend(extension_string)
    }
}
