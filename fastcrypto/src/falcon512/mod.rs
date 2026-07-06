// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Falcon-512 (NIST PQC Round-3; FIPS 206 / FN-DSA is not final yet).
//! Verification only so far; see [`verify`] for the ported reference
//! verifier and its strict/permissive entry points.

// Only the KAT tests reach the verifier for now, so dead-code analysis of
// the non-test build is silenced. The clippy style lints are silenced to
// keep the ported code close to its source.
#[allow(
    dead_code,
    clippy::module_inception,
    clippy::needless_range_loop,
    clippy::manual_range_contains
)]
pub(crate) mod verify;
