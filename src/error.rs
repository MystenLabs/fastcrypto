// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

// A function should validate its arguments and return an indicative errors where needed.
// However, once the function is executing the cryptographic protocol/algorithm (directly/
// indirectly) then it should not return explicit errors as it might leak private information.
// In those cases the function should return the opaque, general error FastCryptoError::GeneralError.
// When in doubt, prefer FastCryptoError::GeneralError.

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FastCryptoError {
    #[error("Invalid value was given to the function")]
    InvalidInput,

    #[error("Expected input of length at least {0}")]
    InputTooShort(usize),

    #[error("Expected input of length at most {0}")]
    InputTooLong(usize),

    #[error("General cryptographic error")]
    GeneralError,
}
