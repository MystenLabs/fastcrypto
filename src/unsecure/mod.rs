// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// This module contains an unsecure non-cryptographic hash function. The purpose of this library is to allow 
/// seamless benchmarking of systems without taking into account the cost of cryptographic primitives - and hence
/// providing a theoretical maximal throughput that a system could achieve if the cost of crypto is optimized
/// away.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
pub mod hash;
