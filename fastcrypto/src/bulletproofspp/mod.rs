// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bulletproofs++ (BP++) reciprocal range proofs over Ristretto255.
pub mod range_proof;

mod circuit;
mod crs;
mod norm_linear;
mod transcript;
mod util;

pub use norm_linear::NormLength;
pub use range_proof::{Range, RangeProof};

/// A proof's norm length is a type parameter, named with typenum's
/// unsigned type-level integers: `RangeProof<typenum::U32>`. Re-exported so
/// callers need not depend on typenum themselves.
pub use typenum;
