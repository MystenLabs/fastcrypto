// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Raw FFI bindings to mldsa-native's ML-DSA-65 `_internal` API (see `../PROVENANCE.md`).
//!
//! This module is intentionally a thin translation of the C API. It performs no
//! validation or policy decisions: callers are responsible for providing
//! correctly formatted byte buffers, constructing any FIPS 204 message prefixes,
//! and supplying randomness where required.
//!
//! The library is built with `MLD_CONFIG_NO_RANDOMIZED_API` (see `build.rs`), so
//! the vendored C never obtains entropy itself. Every operation that requires
//! randomness instead takes it as an explicit pointer argument.
//!
//! # Safety
//!
//! For every function in this module:
//! - Every pointer must refer to a live buffer of the documented size.
//! - No two buffer arguments may overlap. This matches mldsa-native's verified
//!   CBMC contracts.
//! - Buffers are treated as byte arrays only; there are no alignment
//!   requirements.
//!
//! The function declarations here are mirrored in `abi_check.c`. If a future
//! update of mldsa-native changes one of the C function signatures, the build
//! fails instead of silently introducing an FFI ABI mismatch.


#![allow(non_camel_case_types)]
#![allow(dead_code)]

/// FIPS 204 parameters size
/// Generic consts:
pub const MLDSA_SEEDBYTES: usize = 32;
pub const MLDSA_RNDBYTES: usize = 32;
/// MLDSA65 specific ones:
pub const MLDSA65_PUBLICKEYBYTES: usize = 1952;
pub const MLDSA65_SECRETKEYBYTES: usize = 4032;
pub const MLDSA65_BYTES: usize = 3309;

extern "C" {
    /// Implements FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal).
    ///
    /// `pk` and `sk` must point to `MLDSA65_PUBLICKEYBYTES`/`MLDSA65_SECRETKEYBYTES` bytes;
    /// `seed` to `MLDSA_SEEDBYTES` bytes. Returns 0 on success.
    #[link_name = "PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal"]
    pub fn mldsa65_keypair_internal(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;

    /// Implements FIPS 204 Algorithm 7 (ML-DSA.Sign_internal, `externalmu = 0`).
    ///
    /// `sig` must point to `MLDSA65_BYTES` bytes (fixed length; no output-length parameter).
    /// `pre` is the caller-constructed FIPS 204 message-prefix (`0x00 || ctxlen || ctx` for pure
    /// ML-DSA) and is not validated here — the C enforces `ctxlen <= 255` only on the verify
    /// path, so the signing caller owns that check. `rnd` is `MLDSA_RNDBYTES` of fresh
    /// randomness for hedged signing. `sk` must point to `MLDSA65_SECRETKEYBYTES` bytes and is
    /// assumed valid (mldsa-native does not validate secret keys on the signing path). Returns 0
    /// on success; on any nonzero return the C has zeroized `sig`.
    #[link_name = "PQCP_MLDSA_NATIVE_MLDSA65_signature_internal"]
    pub fn mldsa65_signature_internal(
        sig: *mut u8,
        m: *const u8,
        mlen: usize,
        pre: *const u8,
        prelen: usize,
        rnd: *const u8,
        sk: *const u8,
        externalmu: i32,
    ) -> i32;

    /// Implements FIPS 204 Algorithm 3 (ML-DSA.Verify).
    ///
    /// `sig` must point to `MLDSA65_BYTES` bytes, `pk` to `MLDSA65_PUBLICKEYBYTES` bytes; `ctx`
    /// may be NULL when `ctxlen` is 0 (upstream documents this). Verification needs no
    /// randomness. Returns 0 iff the signature verifies; nonzero also covers rejected encodings
    /// and `ctxlen > 255`, so callers must treat it as opaque failure, never classify it.
    #[link_name = "PQCP_MLDSA_NATIVE_MLDSA65_verify"]
    pub fn mldsa65_verify(
        sig: *const u8,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    // FIPS 204's pure-ML-DSA message prefix: domain separator 0x00, then the (empty) context's
    // length, then the (empty) context itself. See Algorithm 2/3 in FIPS 204.
    const EMPTY_CONTEXT_PREFIX: [u8; 2] = [0x00, 0x00];

    #[test]
    fn keypair_sign_verify_smoke_test() {
        let seed = [7u8; MLDSA_SEEDBYTES];
        let mut pk = [0u8; MLDSA65_PUBLICKEYBYTES];
        let mut sk = [0u8; MLDSA65_SECRETKEYBYTES];
        let rc =
            unsafe { mldsa65_keypair_internal(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
        assert_eq!(rc, 0);
        assert_ne!(
            pk, [0u8; MLDSA65_PUBLICKEYBYTES],
            "keygen left pk untouched"
        );

        let msg = b"fastcrypto-pq sys smoke test";
        let rnd = [9u8; MLDSA_RNDBYTES];
        let mut sig = [0u8; MLDSA65_BYTES];
        let rc = unsafe {
            mldsa65_signature_internal(
                sig.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                EMPTY_CONTEXT_PREFIX.as_ptr(),
                EMPTY_CONTEXT_PREFIX.len(),
                rnd.as_ptr(),
                sk.as_ptr(),
                0,
            )
        };
        assert_eq!(rc, 0);
        assert_ne!(sig, [0u8; MLDSA65_BYTES], "signing left sig untouched");

        let rc = unsafe {
            mldsa65_verify(
                sig.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                pk.as_ptr(),
            )
        };
        assert_eq!(rc, 0, "valid signature failed to verify");

        let rc = unsafe {
            mldsa65_verify(
                sig.as_ptr(),
                b"wrong message".as_ptr(),
                13,
                std::ptr::null(),
                0,
                pk.as_ptr(),
            )
        };
        assert_ne!(rc, 0, "signature verified against the wrong message");
    }

    #[test]
    fn same_seed_same_keypair() {
        let seed = [42u8; MLDSA_SEEDBYTES];
        let mut pk1 = [0u8; MLDSA65_PUBLICKEYBYTES];
        let mut sk1 = [0u8; MLDSA65_SECRETKEYBYTES];
        let mut pk2 = [0u8; MLDSA65_PUBLICKEYBYTES];
        let mut sk2 = [0u8; MLDSA65_SECRETKEYBYTES];
        unsafe {
            assert_eq!(
                mldsa65_keypair_internal(pk1.as_mut_ptr(), sk1.as_mut_ptr(), seed.as_ptr()),
                0
            );
            assert_eq!(
                mldsa65_keypair_internal(pk2.as_mut_ptr(), sk2.as_mut_ptr(), seed.as_ptr()),
                0
            );
        }
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }
}
