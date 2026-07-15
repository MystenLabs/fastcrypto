// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// The verifier in this module is a Rust port of the verify path of the
// Falcon reference implementation, as packaged in PQClean
// (crypto_sign/falcon-512/clean: vrfy.c, codec.c, common.c), with the
// twiddle tables carried over verbatim. The reference code is:
//
//   Copyright (c) 2017-2019  Falcon Project
//
//   Permission is hereby granted, free of charge, to any person obtaining
//   a copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall be
//   included in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//   author: Thomas Pornin <thomas.pornin@nccgroup.com>

//! Self-contained Falcon-512 signature **verification**.
//!
//! A Rust port of the reference verify path (see the license notice above
//! for provenance): Montgomery-NTT ring arithmetic with precomputed twiddle
//! tables and no naive modular reductions on the hot path, the compressed wire codec,
//! and SHAKE-256 hash-to-point via the `sha3` crate this workspace already
//! pins. Its correctness is gated by the 100 NIST Round-3 KAT vectors
//! replayed in this crate's tests, "tests/vectors/falcon512-KAT.rsp"
//!
//! Verification is run by the validators, so this module
//! implements verify only. Key generation and signing need Falcon's
//! floating-point Gaussian sampler and are out of scope here.
//! Hypothesis: we need to own the verifier as the FIPS-206 might change its specs
//!     and we might need to hyper personalize the verifers per interface!
//!
//! ## Two entry points: [`verify`] vs [`verify_strict`]
//!
//! - [`verify`] — permissive / interop: accepts both header families (`0x29`
//!   compressed, `0x39` padded), i.e. any real signer's output.
//! - [`verify_strict`] — canonical / authenticator: exactly one accepted
//!   byte-string per signature (666 bytes, header `0x39`, zero tail). The
//!   only entry point a transaction authenticator should use, otherwise a
//!   re-encoded signature changes the tx digest (malleability).
//!
//! References:
//! - Falcon specification: <https://falcon-sign.info/falcon.pdf>
//! - FIPS 202 (SHAKE): <https://csrc.nist.gov/pubs/fips/202/final>

// Crate-visible so `falcon512::sign` can encode keygen output with the same
// codec the verifier parses.
pub(crate) mod codec;
mod ntt;
mod verify;

// The permissive `verify` is only referenced by the KAT tests (see the
// module docs), so the re-export is unused in non-test builds.
#[allow(unused_imports)]
pub use self::verify::{
    derive_public_key, validate_public_key, validate_secret_key, verify, verify_strict,
};

// === Falcon-512 parameters (fixed by the NIST submission) ===

/// Ring degree n = 2^9.
pub const N: usize = 512;

/// The Falcon ring modulus.
pub const Q: u32 = 12289; // it has enough roots of unities

/// Public-key length: 1 header byte + 512 coefficients at 14 bits each.
pub const PUBKEY_LEN: usize = 897;

/// Smallest acceptable signature: header(1) + nonce(40) + 1 body byte.
pub const SIG_MIN_LEN: usize = 42;

/// Largest acceptable signature. The 666-byte cap forbids the 809-byte
/// constant-time format by construction; its decoder does not exist here.
pub const SIG_MAX_LEN: usize = 666;

/// The fixed "padded" signature size (header + nonce + zero-padded body).
pub const SIG_PADDED_LEN: usize = 666;

/// PQClean secret-key length: header byte `0x59`, then f and g at 6 bits per
/// coefficient and F at 8 bits per coefficient (1 + 384 + 384 + 512).
pub const SECKEY_LEN: usize = 1281;

/// Squared L2-norm bound for a valid Falcon-512 signature (spec parameter).
pub const L2_BOUND: u32 = 34034726;
