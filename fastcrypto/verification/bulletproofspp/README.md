<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::bulletproofspp`

Proofs about the batched Bulletproofs++ range proof (`fastcrypto/src/bulletproofspp`), the
protocol of [ePrint 2026/2648](https://eprint.iacr.org/2026/2648) §5. There are two layers:

* `Model/` is a Lean model of the Rust code, one file per module and function by function, over
  any field `F` and any `F`-module `E`. The theorems below are about this model.
* `Generated/` is a Lean translation of the Rust code made by
  [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The other Lean files at the top
  level prove that the translated functions of `util.rs`, `laurent.rs`, `constraints.rs` and
  `norm_linear.rs` compute the model's, with scalars mapped to `F` and points to `E`. The other
  modules are not linked to their translation yet (see [below](#what-is-not-proved)).

The Rust code carries no annotations. It is written in a style Aeneas can translate: index loops
instead of iterator chains and closures.

## Theorems

`Generators::new` is an input, a function of `nm`. Most results assume that for the batch's `nm`
it returns `H_LEN` and `nm` generators, with `g = pedersen::H` and `h_vec[0] = pedersen::G`:
*generators of the right shape*.

1. **`RangeProof.completeness`: honest proofs are accepted.** For values in `range` and blindings
   of the same length, `prove_batch` returns a proof that `verify_batch` accepts for the Pedersen
   commitments to the values, for every choice of the prover's random draws. This needs
   generators of the right shape, and a transcript hash that never outputs `-j` for `j < 16`, so
   that no inversion fails.

2. **`RangeProof.verify_extract`: special soundness.** Take a tree of accepting runs of
   `verify_batch` on fixed commitments, `range` and `dst`, each with its own transcript hash, with
   distinct challenges at every fork. Then every commitment is `PedersenCommitment::new` of a value
   in `range`, or the generators satisfy a nontrivial linear relation. This needs generators of the
   right shape with `2^rounds` dividing `nm`, `α ∉ {0, -1, ..., -15}`, `ρ, δ, τ ≠ 0`, and
   `2, 1, ..., N_d ≠ 0` in `F`. The tree has, from the root, `N_d + 16` branches at `α`, `nm + 1`
   with distinct `ρ²` at `ρ`, 2 at `β`, `M(nm + 8) + 1` at `λ`, 13 at `τ` and 4 per round at `γ`.

3. **`RangeProof.zero_knowledge`: honest-verifier zero-knowledge.** The transcripts of
   `prove_batch` are within statistical distance `22 / |F|` of those of a simulator that sees only
   the commitments, `range`, `dst` and the generators (VCVio's `ChallengeVerifyProtocol.HVZK`).
   This needs a finite field with a uniform sampler, at least one value, and generators of the
   right shape that are multiples `h_j g` of `g` with `h_0 ≠ 0`, as in a prime-order group.

4. **`RangeProof.verify_batch_local`: each challenge depends only on its log.** Two transcript
   hashes that agree on the verifier's log at each challenge (`α`, `ρ`, `λ`, `β`, `δ`, `τ` and
   each round's `γ`) give the same result. Each log starts with the statement (`dst`, `n_bits`,
   `m`, every `V_i`) and contains every prover message before the challenge.

5. **`RangeProof.challenge_decodes`: the logs are unambiguous.** If two challenge logs, of any
   statements and proofs, absorb the same labels and bytes, they are the same log of the same
   statement, for any injective encoding of points. This needs `n_bits` and `m` to fit a `u64`.

6. **`RangeProof.challengeLogs_nodup`: no challenge is drawn twice.** Within a run, no two
   challenges are drawn at the same log.

The lemmas about the translation say, for each function, that it returns what the model returns,
including the same errors and, for `norm_linear`, the same transcript:

* `util.rs`: `inner_product`, `weighted_inner_product`, `weighted_norm`, `to_scalars`,
  `power_vector`, `vec_add`, `vec_scalar_mul`, `hadamard`, `pad_to`, `batch_invert`, `to_digits`
  for `d ≤ 16` and `multiplicities` for digits below 16.
* `laurent.rs`: `new`, `monomial`, `degree`, `coeff`, `scale`, `+`, `-`, `from_terms`, `eval`,
  `inner_product` and `weighted_inner_product`, for polynomials whose powers lie within `2^29`
  (`2^28` for the inner products), and the `Coefficient` impl of `Vec<RistrettoScalar>` on
  vectors of one length.
* `constraints.rs`: `Constraints::new`, for parameters with `d > 0`, `n_d = m d` and `nm ≥ 15`
  (`ParamsOK`), and `p_n`.
* `norm_linear.rs`: `prove` and `verify` (`prove_spec`, `verify_spec`), for generators with at
  least one point in `h_vec` and lengths for which no `usize` arithmetic overflows, and with them
  `LazyBases`, `Weights` and `Generators::commit`.

## Files

| File | Contents |
|---|---|
| `Correctness.lean`, `Soundness.lean`, `ZeroKnowledge.lean`, `Proofs/Hygiene.lean` | The theorems above. |
| `Model/` | The model of the Rust code, one file per module, with the same names. |
| `Proofs/` | Lemmas about each module of the model, and completeness and special soundness of `norm_linear` and `circuit`. |
| `Spec/` | The protocol of the paper, used inside the proofs. |
| `Scalar.lean` | `ScalarModel`: what is assumed about `RistrettoScalar`. |
| `Points.lean` | `PointModel`, `GensOK` and `TranscriptModel`: what is assumed about `RistrettoPoint`, the MSM tables of `Generators` and the Merlin transcript. |
| `Util.lean`, `Laurent.lean`, `Constraints.lean` | The translations of `util.rs`, `laurent.rs` and `constraints.rs` compute the model. |
| `NormLinear.lean`, `LazyBases.lean`, `Prove.lean`, `Verify.lean` | The translation of `norm_linear.rs` computes the model: its helpers, `LazyBases::msm`, `prove` and `verify`. |
| `Theorems.lean` | Imports everything. |
| `Generated/` | The translation of `util.rs`, `laurent.rs`, `constraints.rs`, `norm_linear.rs` and `Generators::msm`, made by `extract.sh`. `groups`, `pedersen`, `serde_helpers`, `merlin` and `transcript.rs` (except `Label`) are opaque. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Defines `u64::ilog2`, `i32::unsigned_abs` and `slice::from_ref`, which Aeneas leaves as axioms. Called by `extract.sh`. |

To check the proofs, install Lean with `elan` and run, here:

```bash
lake exe cache get
lake build
```

The first build also compiles the Aeneas and VCVio libraries. To regenerate `Generated/` after
changing the Rust code, get `charon` and `aeneas` from the Aeneas release named in `extract.sh`
and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

* **The model.** The theorems are about `Model/`, so they trust that it matches the Rust code,
  except where `Util.lean` proves it does. In the model:
  * scalars are a field and points a module over it, `Vec` is `List`, `FastCryptoResult` is
    `Except`, and `&mut BpppTranscript` is a state monad;
  * the Merlin transcript is a log of labelled entries and an arbitrary function from logs to
    challenges, `Transcript::new` absorbs its label under `"dom-sep"`, and a `u64` is 8
    little-endian bytes;
  * the prover's random draws are an input, indexed by slot; for zero-knowledge they are uniform,
    and `protocol` (`ZeroKnowledge.lean`), which casts `range_proof` as a VCVio protocol, is part
    of the model.
* **Translation.** The lemmas about the translation are about the Lean code in `Generated/`, so
  they trust that Charon and Aeneas translate the Rust code faithfully, and the definitions of
  `u64::ilog2`, `i32::unsigned_abs` and `slice::from_ref` that `fix_aeneas_output.py` adds. `debug_assert!`s are
  translated as checks that fail, so the lemmas assume equal lengths where the Rust code asserts
  them. Aeneas clones tuples by copying, so cloning `(i32, C)` in `Laurent::from_terms` is
  assumed to return its argument.
* **Scalars** (`ScalarModel`). `RistrettoScalar` maps to the field `F` by some `φ`, under which
  `zero`, `generator`, `+` (also by reference), `-x`, `*`, `+=`, `*=` and `From<u64>` are `F`'s,
  `clone` returns its argument, and `inverse` fails exactly on zero.
* **Points** (`PointModel`). `RistrettoPoint` maps to the module `E` by some `ψ`, under which
  `zero` is `0`, `==` is equality and `multi_scalar_mul` is the sum of the products, failing
  with `InvalidInput` exactly on different lengths.
* **MSM tables** (`GensOK`). The mixed MSM over the precomputed tables of `Generators` is the
  model's over `[g, h_vec.., g_vec..]`.
* **Transcript** (`TranscriptModel`). `transcript.rs` maps to the model's transcript by some `τ`,
  under which `domain_sep`, `append_point`, `append_scalars` and `challenge_scalar` act as the
  model's, with each `Label` as its byte string.
* **Merlin and Ristretto.** Merlin frames `(label, message)` pairs unambiguously, and Ristretto
  points have a canonical encoding.
* **Generators.** `Generators::new` returns generators with no known linear relation. They are
  not absorbed into the transcript, because `range` and `m` determine them.

## What is not proved

* The translations of `circuit.rs` and `range_proof.rs` are not yet shown to compute the model,
  so the theorems are not yet about the Rust code. `transcript.rs` and the rest of `crs.rs` are
  assumed rather than translated.
* `Generators::new` (hash-to-curve), the MSM precomputation tables, serialization and test-only
  code are not modelled.
* From special soundness to knowledge soundness of the non-interactive proof (tree extraction and
  the Fiat–Shamir transform in the random-oracle model), and zero-knowledge of the non-interactive
  proof in the random-oracle model, are standard steps, cited rather than proved.
* Fiat–Shamir hygiene of the prover's transcript is not needed: by completeness it derives the
  same challenges as the verifier on honest runs.
