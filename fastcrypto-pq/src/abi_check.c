/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Compile-time ABI checks for the mldsa-native functions declared in `sys.rs`.
 *
 * Rust's `extern "C"` declarations assume the C function signatures are correct.
 * If a future update of mldsa-native changes a function's prototype but keeps the
 * same symbol name, everything still compiles and links, but every call through
 * FFI has undefined behavior.
 *
 * This file prevents that. It re-declares each bound function with the exact
 * prototype that `sys.rs` expects. In C, conflicting declarations of the same
 * function are a compile-time error, so any ABI drift is caught during the build.
 *
 * Keep this file and `sys.rs` in sync. If a re-pin causes these declarations to
 * stop compiling, update both files together after confirming the ABI change is
 * intentional.
 *
 * These constants define the serialized ML-DSA object sizes exposed through the
 * Rust API and must not change without deliberate review. This is critical for Sui.
 */

#include <stddef.h>
#include <stdint.h>

#include "mldsa_native.h"

typedef char mld_assert_seed_len[(MLDSA_SEEDBYTES == 32) ? 1 : -1];
typedef char mld_assert_rnd_len[(MLDSA_RNDBYTES == 32) ? 1 : -1];
typedef char mld_assert_pk_len[(MLDSA65_PUBLICKEYBYTES == 1952) ? 1 : -1];
typedef char mld_assert_sk_len[(MLDSA65_SECRETKEYBYTES == 4032) ? 1 : -1];
typedef char mld_assert_sig_len[(MLDSA65_BYTES == 3309) ? 1 : -1];

int PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(
    uint8_t pk[1952],
    uint8_t sk[4032],
    const uint8_t seed[32]);

int PQCP_MLDSA_NATIVE_MLDSA65_signature_internal(
    uint8_t sig[3309],
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pre,
    size_t prelen,
    const uint8_t rnd[32],
    const uint8_t sk[4032],
    int externalmu);

int PQCP_MLDSA_NATIVE_MLDSA65_verify(
    const uint8_t sig[3309],
    const uint8_t *m,
    size_t mlen,
    const uint8_t *ctx,
    size_t ctxlen,
    const uint8_t pk[1952]);
