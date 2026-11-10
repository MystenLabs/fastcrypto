// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runs the Creusot proof of `check_quorum` on the production source file.

// `check_quorum` is `pub(crate)` and has no callers here.
#[allow(dead_code)]
#[path = "../../../fastcrypto-threshold/src/quorum.rs"]
pub mod quorum;
