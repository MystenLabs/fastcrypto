// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Collection of errors to be used in fastcrypto.
//!
//! A function should validate its arguments and return an indicative errors where needed.
//! However, once the function is executing the cryptographic protocol/algorithm (directly/
//! indirectly) then it should not return explicit errors as it might leak private information.
//! In those cases the function should return the opaque, general error [FastCryptoError::GeneralError].
//! When in doubt, prefer [FastCryptoError::GeneralError].

use thiserror::Error;

/// Collection of errors to be used in fastcrypto.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum FastCryptoError {
    /// Invalid value was given to the function
    #[error("Invalid value was given to the function")]
    InvalidInput,

    /// Input is to short.
    #[error("Expected input of length at least {0}")]
    InputTooShort(usize),

    /// Input is to long.
    #[error("Expected input of length at most {0}")]
    InputTooLong(usize),

    /// Input length is wrong.
    #[error("Expected input of length exactly {0}")]
    InputLengthWrong(usize),

    /// Invalid signature was given to the function
    #[error("Invalid signature was given to the function")]
    InvalidSignature,

    /// General opaque cryptographic error.
    #[error("General cryptographic error")]
    GeneralError,
}
