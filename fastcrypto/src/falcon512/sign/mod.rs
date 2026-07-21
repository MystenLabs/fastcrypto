// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Falcon-512 signing and key generation through PQClean `falcon-padded-512`
//! via [`pqcrypto-falcon`](https://crates.io/crates/pqcrypto-falcon), built
//! without SIMD features (portable C only). Verification stays with the
//! in-crate port in [`super::verify`]; nothing here routes to PQClean's.
//!
//! # Seeded key generation
//!
//! [`keygen_from_seed`] fixes the map seed -> key pair: the 48-byte seed is
//! absorbed into SHAKE256 and the stream drives the reference keygen —
//! exactly the construction PQClean applies to its own OS-drawn seed and
//! the one Algorand's `GenerateKey` uses in their Falcon fork. The "clean"
//! backend emulates floating point in integers (`fpr` is a `uint64_t`), so
//! the result is bit-identical across platforms, and the KAT cross-check in
//! `falcon512_sign_tests` pins the map to the 100 NIST Round-3 vectors.
//! **This module is the canonical map**; mnemonic-derived accounts must
//! treat its output as the source of truth.
//!
//! On TypeScript interop: `@noble/post-quantum`'s `falcon512padded.keygen`
//! (0.6.1) matches this map on most seeds — all 100 KATs and our pinned
//! vectors — but NOT all: differential testing found a seed (~1 in 10^3)
//! where noble emits a different, equally valid key pair, because its
//! bigint NTRU-solve applies implementation-specific accept/reject bounds
//! (noble's own docs call falcon keys "implementation-specific").
//! Signatures cross-verify in both directions regardless; key *derivation*
//! done in TS must therefore be validated against this module per account,
//! never trusted blindly.
//!
//! FIPS 206 (per NIST's 2025 status updates) is expected to *forbid* seeds
//! as a portable key format, precisely because FN-DSA keygen KAT-exactness
//! will not be required across implementations. The map frozen here is
//! therefore implementation-defined forever: it is pinned to the vendored
//! PQClean sources (`pqcrypto-falcon = "=0.4.1"`, upstream archived). Note
//! that Pornin's `fn-dsa` crate — the migration target for sign/verify once
//! FIPS 206 is final — generates keys with the ntrugen algorithm, a
//! *different* seed -> key map; it can take over signing but never account
//! derivation.
//!
//! Signatures remain randomized (OS salt) and need no reproducibility.
//!
//! # Example
//! ```rust
//! use fastcrypto::falcon512::sign::{keygen_from_seed, sign};
//! use fastcrypto::falcon512::Falcon512PublicKey;
//! use fastcrypto::traits::{ToFromBytes, VerifyingKey};
//! let (sk, pk) = keygen_from_seed(&[7u8; 48]);
//! assert_eq!(keygen_from_seed(&[7u8; 48]), (sk, pk)); // same seed, same keys
//! let sig = sign(&sk, &pk, b"Hello, world!").unwrap();
//! let pk = Falcon512PublicKey::from_bytes(&pk).unwrap();
//! let sig = <fastcrypto::falcon512::Falcon512Signature as ToFromBytes>::from_bytes(&sig).unwrap();
//! assert!(pk.verify(b"Hello, world!", &sig).is_ok());
//! ```

use crate::error::FastCryptoError;
use pqcrypto_falcon::falconpadded512;
use pqcrypto_traits::sign::{DetachedSignature as _, SecretKey as _};
use rand::RngCore as _;
use std::os::raw::c_uint;
use zeroize::Zeroize as _;

use super::verify;
use super::verify::{codec, N, PUBKEY_LEN, SECKEY_LEN, SIG_PADDED_LEN};

/// Keygen consumes a 48-byte seed — the reference implementation's explicit
/// SHAKE256 seed size (falcon.h), which is also what PQClean's own keypair
/// draws internally and what `@noble/post-quantum`'s `keygen` takes, so one
/// seed value reproduces the same key pair across all three.
//
// 48 — not 32 like the other fastcrypto schemes — is deliberate: any other
// length changes the SHAKE input and loses byte-compatibility with the
// reference construction (and noble's API, which requires exactly 48;
// they declined to relax it in noble-post-quantum#44). The mnemonic side
// produces the 48 bytes via `Falcon512KeyPair::generate_from_ikm`
// (HKDF-SHA3-256 expand). See the module docs for the limits of noble
// keygen equivalence.
pub const KEYGEN_SEED_LEN: usize = 48;

/// `FALCON_KEYGEN_TEMP_9` from PQClean's inner.h: keygen scratch for
/// logn = 9, which the C code requires to be 64-bit aligned.
const KEYGEN_TMP_LEN: usize = 14336;

/// PQClean's incremental SHAKE256 state (`shake256incctx` in fips202.h): 25
/// Keccak lanes plus one word of buffer position, caller-allocated. The C
/// `shake256_inc_ctx_release` is a no-op for this backend, so plain drop
/// (after zeroizing — the state absorbed the seed) is correct.
#[repr(C)]
struct Shake256IncCtx {
    ctx: [u64; 26],
}

// Internal symbols of the statically linked PQClean archives. pqcrypto-falcon
// exposes no seeded keypair — it mirrors the NIST API, whose keypair()
// hardwires an OS `randombytes` call — but the deterministic core it wraps is
// exported from the objects it links, so we bind that directly. Soundness
// rests on the exact `=0.4.1` pin in Cargo.toml (these signatures and the
// struct layout are that source tree's) and on the KAT cross-check test,
// which fails loudly if any of it drifts.
//
// Two ABI hazards the pin freezes: pqcrypto-falcon ships (but never compiles)
// a second, heap-based `shake256incctx` in its pqclean/common/fips202.h — its
// build's -I order selects pqcrypto-internals' array-based variant, which is
// what the linked objects were compiled against; and `shake256_inc_*` are
// unprefixed C symbols, so a downstream binary linking another vendored
// PQClean-style library could introduce an incompatible definition that the
// linker resolves silently. Both would surface as KAT failures (or crashes),
// not wrong keys.
extern "C" {
    #[link_name = "shake256_inc_init"]
    fn pqclean_shake256_init(state: *mut Shake256IncCtx);
    #[link_name = "shake256_inc_absorb"]
    fn pqclean_shake256_absorb(state: *mut Shake256IncCtx, input: *const u8, inlen: usize);
    #[link_name = "shake256_inc_finalize"]
    fn pqclean_shake256_finalize(state: *mut Shake256IncCtx);
    /// keygen.c: samples (f, g), solves the NTRU equation for F and writes
    /// h = g/f, drawing all randomness from the SHAKE256 stream. Loops
    /// internally until the key is valid, so it cannot fail; `big_g` and `h`
    /// may be null when the caller does not want them.
    #[link_name = "PQCLEAN_FALCONPADDED512_CLEAN_keygen"]
    fn pqclean_falcon512_keygen(
        rng: *mut Shake256IncCtx,
        f: *mut i8,
        g: *mut i8,
        big_f: *mut i8,
        big_g: *mut i8,
        h: *mut u16,
        logn: c_uint,
        tmp: *mut u8,
    );
}

/// Deterministically derive a PQClean-format key pair from a seed, returned
/// as (secret key, public key) bytes. Same seed, same key pair, on every
/// platform and across implementations of the reference keygen — this is the
/// frozen account-derivation map (see the module docs for why it can never
/// change once accounts depend on it), and the byte-for-byte mirror of
/// PQClean's `crypto_sign_keypair` with the OS draw replaced by the caller's
/// seed. The NIST KAT cross-check replays exactly this function, and
/// `@noble/post-quantum`'s `falcon512padded.keygen` returns the same key
/// pair for the same seed.
//
// TODO: decide whether the production wallet path should domain-separate the
// seed (SHAKE256(tag || seed)) instead of raw injection. Raw injection is
// what the reference/Algorand/noble construction does — switching would buy
// cross-protocol seed hygiene at the cost of that cross-implementation
// equality, so the hygiene likely belongs one layer up, in how the wallet
// derives the 48 bytes from the mnemonic.
pub fn keygen_from_seed(seed: &[u8; KEYGEN_SEED_LEN]) -> ([u8; SECKEY_LEN], [u8; PUBKEY_LEN]) {
    let mut rng = Shake256IncCtx { ctx: [0; 26] };
    let mut f = [0i8; N];
    let mut g = [0i8; N];
    let mut big_f = [0i8; N];
    let mut h = [0u16; N];
    // u64-backed for the 64-bit alignment keygen demands of its scratch.
    let mut tmp = vec![0u64; KEYGEN_TMP_LEN / 8];
    unsafe {
        pqclean_shake256_init(&mut rng);
        pqclean_shake256_absorb(&mut rng, seed.as_ptr(), seed.len());
        pqclean_shake256_finalize(&mut rng);
        // G is skipped (the signer recomputes it from f, g, F); h is taken
        // from keygen rather than re-inverting g/f here, and the two paths
        // are checked against each other in tests.
        pqclean_falcon512_keygen(
            &mut rng,
            f.as_mut_ptr(),
            g.as_mut_ptr(),
            big_f.as_mut_ptr(),
            std::ptr::null_mut(),
            h.as_mut_ptr(),
            9,
            tmp.as_mut_ptr() as *mut u8,
        );
    }

    // PQClean secret-key layout: header 0x59, then f and g trimmed to 6 bits
    // each, F at 8. keygen resamples until |f|, |g| < 2^5 and NTRU-solve
    // bounds |F| < 2^7, so encoding cannot fail on its output.
    let mut sk = [0u8; SECKEY_LEN];
    sk[0] = 0x50 + 9;
    let ok = codec::trim_i8_encode(&f, 6, &mut sk[1..385])
        && codec::trim_i8_encode(&g, 6, &mut sk[385..769])
        && codec::trim_i8_encode(&big_f, 8, &mut sk[769..1281]);
    assert!(ok, "falcon keygen emitted out-of-range coefficients");
    let pk = codec::encode_pubkey(&h);

    // Everything except h/pk is secret material on the stack and heap.
    f.zeroize();
    g.zeroize();
    big_f.zeroize();
    tmp.zeroize();
    rng.ctx.zeroize();
    (sk, pk)
}

/// Generate a key pair from fresh OS-backed randomness, returned as (secret
/// key, public key) bytes. Draws a seed from `thread_rng` and defers to
/// [`keygen_from_seed`], so the random and seeded paths are one code path.
pub fn keygen() -> ([u8; SECKEY_LEN], [u8; PUBKEY_LEN]) {
    let mut seed = [0u8; KEYGEN_SEED_LEN];
    rand::thread_rng().fill_bytes(&mut seed);
    let out = keygen_from_seed(&seed);
    seed.zeroize();
    out
}

/// Sign `msg` with a PQClean-format secret key. `pk` is the matching public
/// key, passed in to avoid re-deriving it per call; every signature is checked with
/// [`verify::verify_strict`] before it is returned, so signer drift surfaces
/// as `GeneralError` here instead of a signature the verifier rejects.
pub fn sign(
    sk: &[u8; SECKEY_LEN],
    pk: &[u8; PUBKEY_LEN],
    msg: &[u8],
) -> Result<[u8; SIG_PADDED_LEN], FastCryptoError> {
    let sk =
        falconpadded512::SecretKey::from_bytes(sk).map_err(|_| FastCryptoError::InvalidInput)?;
    let sig: [u8; SIG_PADDED_LEN] = falconpadded512::detached_sign(msg, &sk)
        .as_bytes()
        .try_into()
        .map_err(|_| {
            FastCryptoError::GeneralError("falcon signature is not the 666-byte padded form".into())
        })?;
    // TODO: We can remove this condition in production.
    if sig[0] != 0x39 || !verify::verify_strict(pk, msg, &sig) {
        return Err(FastCryptoError::GeneralError(
            "falcon signature failed the strict verify gate".into(),
        ));
    }
    Ok(sig)
}
