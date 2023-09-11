// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "gmp"))]
pub mod num_bigint;

#[cfg(feature = "gmp")]
pub mod gmp;
