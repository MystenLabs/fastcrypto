use crate::nodes::PartyId;
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::ro_extension::Extension::{Challenge, Encryption, Recovery};

pub enum Extension {
    Recovery(PartyId),
    Encryption,
    Challenge,
}

/// A wrapper around [RandomOracle] to provide domain separation for different uses.
pub struct RandomOracleWrapper {
    random_oracle: RandomOracle,
}

impl RandomOracleWrapper {
    pub fn extend(self: &RandomOracleWrapper, extension: Extension) -> RandomOracle {
        let extension_string = match extension {
            Recovery(accuser) => &format!("recovery of {accuser}"),
            Encryption => "encryption",
            Challenge => "challenge",
        };
        self.random_oracle.extend(extension_string)
    }
}

impl From<RandomOracle> for RandomOracleWrapper {
    fn from(random_oracle: RandomOracle) -> Self {
        RandomOracleWrapper { random_oracle }
    }
}
