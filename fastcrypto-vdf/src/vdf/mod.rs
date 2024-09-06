// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a implementation of a verifiable delay function (VDF), using Wesolowski's
//! construction with ideal class groups.

use fastcrypto::error::FastCryptoResult;

pub mod pietrzak;
pub mod wesolowski;

/// This represents a Verifiable Delay Function (VDF) construction.
pub trait VDF {
    /// The type of the input to the VDF.
    type InputType;

    /// The type of the output from the VDF.
    type OutputType;

    /// The type of the proof of correctness for this VDF.
    type ProofType;

    /// Evaluate this VDF and return the output and a proof of correctness.
    fn evaluate(
        &self,
        input: &Self::InputType,
    ) -> FastCryptoResult<(Self::OutputType, Self::ProofType)>;

    /// Verify the output and proof from a VDF.
    fn verify(
        &self,
        input: &Self::InputType,
        output: &Self::OutputType,
        proof: &Self::ProofType,
    ) -> FastCryptoResult<()>;
}
