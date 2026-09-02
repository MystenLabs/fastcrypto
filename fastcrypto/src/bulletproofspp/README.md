# Bulletproofs++ Range Proofs

Implementation of [Bulletproofs++](https://eprint.iacr.org/2022/510) (BP++), a zero-knowledge range proof, over Ristretto255. 
Given Pedersen commitments `V_1, ..., V_M`, a proof demonstrates knowledge of openings `V_i = v_i*G + s_i*H_0` with values `0 <= v_i < 2^b` for `i = 1, ..., M`, bit size `b` in `{8, 16, 32, 64}` and any batch size `M >= 1`, in a single short transcript.

Each value `v_i` is decomposed into `b/4` base-16 digits, digit-set membership is proven via the reciprocal argument with one multiplicity vector shared across the batch, per-value challenge weights bind each value individually, and everything reduces to a single weighted norm-linear argument. 
Proofs are non-interactive (Fiat–Shamir over a Merlin transcript) and honest-verifier zero-knowledge (perfect outside a challenge set of density `O(1)/q`). 
Knowledge soundness holds under the discrete-logarithm assumption in the random-oracle model, in exact form: the extractor outputs the openings `(v_i, s_i)` for arbitrary group elements `V_i`, with no assumption on how the inputs were formed.

## Module layout

| File | Contents |
| --- | --- |
| `range_proof.rs` | Public API (`Range`, `RangeProof::{prove,verify}(_batch)`), serialization |
| `circuit.rs` | Range circuit: constraint blocks, blinding, error-row cancellation |
| `norm_linear.rs` | Weighted norm-linear argument (prover with lazy generator folding, single-MSM verifier) |
| `crs.rs` | Generators: hash-to-curve derivation, per-size process-wide cache, precomputed MSM tables |
| `transcript.rs` | Merlin transcript wrapper |
| `util.rs` | Scalar-vector helpers, batch inversion |

Values are committed with `fastcrypto::pedersen`; the CRS maps BP++'s value
base to `pedersen::H` and the blinding base to `pedersen::G`, so existing
`PedersenCommitment`/`Blinding` values open directly under this proof system.

## Proof sizes

Proofs have a size of `64*log2(nm) + 160` bytes, where `nm = max(M*b/4, 16)` rounded up
to a power of two. 
The table below compares BulletProofs (BP) and BulletProofs++ proof sizes for different (aggregate) range proof configurations.

| Config | BP (bytes) | BP++ (bytes) | smaller |
| --- | ---: | ---: | ---: |
| 16-bit x1 | 544 | 416 | 24% |
| 32-bit x1 | 608 | 416 | 32% |
| 64-bit x1 | 672 | 416 | 38% |
| 16-bit x4 | 672 | 416 | 38% |
| 16-bit x8 | 736 | 480 | 35% |
| 32-bit x8 | 800 | 544 | 32% |
| 64-bit x16 | 928 | 672 | 28% |
| 64-bit x32 | 992 | 736 | 26% |

## Benchmarks

The two tables below compare BP and BP++ prover and verifier performance for different (aggregate) range proof configurations.
All benchmarks were done on an Apple M2 Max MacBook Pro with 96 GB RAM.
The BP baseline is `fastcrypto::bulletproofs` (the dalek `bulletproofs` crate v5 with cached generators).
To reproduce both tables run `cargo bench -p fastcrypto --features experimental --bench bulletproofspp`.

**Proving (ms):**

| Config | BP | BP++ | speedup |
| --- | ---: | ---: | ---: |
| 16-bit x1 | 2.10 | 1.24 | 1.7x |
| 32-bit x1 | 3.86 | 1.26 | 3.1x |
| 64-bit x1 | 7.28 | 1.29 | 5.6x |
| 16-bit x4 | 7.89 | 1.39 | 5.7x |
| 16-bit x8 | 15.40 | 2.08 | 7.4x |
| 32-bit x8 | 28.42 | 3.97 | 7.2x |
| 64-bit x16 | 106.5 | 13.61 | 7.8x |
| 64-bit x32 | 205.1 | 27.11 | 7.6x |

**Verification (ms):**

| Config | BP | BP++ | speedup |
| --- | ---: | ---: | ---: |
| 16-bit x1 | 0.36 | 0.31 | 1.1x |
| 32-bit x1 | 0.57 | 0.31 | 1.8x |
| 64-bit x1 | 1.00 | 0.32 | 3.2x |
| 16-bit x4 | 1.06 | 0.35 | 3.0x |
| 16-bit x8 | 1.74 | 0.49 | 3.6x |
| 32-bit x8 | 2.85 | 0.68 | 4.2x |
| 64-bit x16 | 8.53 | 1.92 | 4.4x |
| 64-bit x32 | 15.94 | 3.55 | 4.5x |

## Implementation notes

- Verification is one multi-scalar multiplication. Generator folding is never
  performed by the verifier; each base generator's coefficient is computed
  from the bits of its index, and the combined commitment is folded into the
  same MSM instead of being materialized.
- The prover folds generators lazily (tensor-weight bookkeeping, deferred
  batch folds), so each round's messages are one MSM each over the base
  generators.
- MSMs over the fixed generator set use precomputed tables
  (`fastcrypto::groups::PrecomputableMultiScalarMul`); the precomputation
  itself falls back to a plain MSM above the measured Straus/Pippenger
  crossover.
- Derived CRSs (hash-to-curve generators plus tables) are cached per size for
  the lifetime of the process.
- Not constant-time: variable-time MSMs are used throughout, as in the dalek
  Bulletproofs implementation. Do not use where prover timing side channels
  matter.
- The hash-to-curve DSTs and transcript labels are not yet frozen; the
  serialized regression vector must be regenerated when they are.
