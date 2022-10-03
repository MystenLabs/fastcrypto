// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// This module contains an implementation of a negligible-cost (apart from some ocassional pk copying) trivial
/// cryptographic signature scheme.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
pub mod hash;
pub mod signature;