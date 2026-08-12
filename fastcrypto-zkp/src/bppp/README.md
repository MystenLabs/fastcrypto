# Bulletproofs++ Range Proofs

Implementation of [Bulletproofs++](https://eprint.iacr.org/2022/510), a zero-knowledge range proof, over Ristretto255. 
Given Pedersen commitments `V_1, ..., V_M`, a proof demonstrates knowledge of openings `V_i = v_i*G + s_i*H_0` with values `0 <= v_i < 2^b` for `i = 1, ..., M`, bit size `b` in `{8, 16, 32, 64}` and any batch size `M >= 1`, in a single short transcript.

Each value `v_i` is decomposed into `b/4` base-16 digits, digit-set membership is proven via the reciprocal argument with one multiplicity vector shared across the batch, per-value challenge weights bind each value individually, and everything reduces to a single weighted norm-linear argument. Proofs are non-interactive (Fiat–Shamir over a Merlin transcript) and honest-verifier zero-knowledge (perfect outside a challenge set of density `O(1)/q`). Knowledge soundness holds under the discrete-logarithm assumption in the random-oracle model, in exact form: the extractor outputs the openings `(v_i, s_i)` for arbitrary group elements `V_i`, with no assumption on how the inputs were formed.

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

`|proof| = 64*log2(nm) + 160` bytes, where `nm = max(M*b/4, 16)` rounded up
to a power of two. Baseline: aggregated range proofs of the dalek
`bulletproofs` crate v5 (Ristretto255), which requires aggregation sizes to
be powers of two.

| Config | BP++ (bytes) | BP (bytes) | smaller |
| --- | ---: | ---: | ---: |
| 16-bit x1 | 416 | 544 | 24% |
| 32-bit x1 | 416 | 608 | 32% |
| 64-bit x1 | 416 | 672 | 38% |
| 16-bit x4 | 416 | 672 | 38% |
| 16-bit x8 | 480 | 736 | 35% |
| 32-bit x8 | 544 | 800 | 32% |
| 64-bit x16 | 672 | 928 | 28% |
| 64-bit x32 | 736 | 992 | 26% |

## Benchmarks

Apple M2 Max, criterion medians; reproduce the BP++ side with
`cargo bench -p fastcrypto-zkp --bench bppp`. BP baseline measured on the
same machine with the dalek `bulletproofs` crate v5.

**Proving (ms):**

| Config | BP | BP++ | speedup |
| --- | ---: | ---: | ---: |
| 16-bit x1 | 2.03 | 1.24 | 1.6x |
| 32-bit x1 | 3.69 | 1.25 | 2.9x |
| 64-bit x1 | 6.86 | 1.29 | 5.3x |
| 16-bit x4 | 7.59 | 1.38 | 5.5x |
| 16-bit x8 | 15.24 | 2.10 | 7.3x |
| 32-bit x8 | 27.71 | 3.98 | 7.0x |
| 64-bit x16 | 101.7 | 13.74 | 7.4x |
| 64-bit x32 | 199.5 | 27.36 | 7.3x |

**Verification (ms):**

| Config | BP | BP++ | speedup |
| --- | ---: | ---: | ---: |
| 16-bit x1 | 0.37 | 0.32 | 1.2x |
| 32-bit x1 | 0.56 | 0.32 | 1.8x |
| 64-bit x1 | 0.98 | 0.32 | 3.1x |
| 16-bit x4 | 1.03 | 0.35 | 3.0x |
| 16-bit x8 | 1.66 | 0.49 | 3.4x |
| 32-bit x8 | 2.68 | 0.70 | 3.8x |
| 64-bit x16 | 8.13 | 1.98 | 4.1x |
| 64-bit x32 | 15.06 | 3.67 | 4.1x |

## Implementation notes

- Verification is one multi-scalar multiplication. Generator folding is never
  performed by the verifier; each base generator's coefficient is computed
  from the bits of its index, and the combined commitment is folded into the
  same MSM instead of being materialized.
- The prover folds generators lazily (tensor-weight bookkeeping, deferred
  batch folds), so each round's messages are one MSM each over the base
  generators.
- MSMs over the fixed generator set use precomputed tables
  (`fastcrypto::groups::PrecomputedMultiScalarMul`), with a fallback to a
  plain MSM above the measured Straus/Pippenger crossover.
- Derived CRSs (hash-to-curve generators plus tables) are cached per size for
  the lifetime of the process.
- Not constant-time: variable-time MSMs are used throughout, as in the dalek
  Bulletproofs implementation. Do not use where prover timing side channels
  matter.
- The hash-to-curve DSTs and transcript labels are not yet frozen; the
  serialized regression vector must be regenerated when they are.
