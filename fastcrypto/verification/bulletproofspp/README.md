<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::bulletproofspp`

Proofs about the batched Bulletproofs++ range proof (`fastcrypto/src/bulletproofspp`), the
protocol of [ePrint 2026/2648](https://eprint.iacr.org/2026/2648) §5. There are two layers:

* `Model/` is a Lean model of the Rust code, one file per module and function by function, over
  any field `F` and any `F`-module `E`. The theorems below are about this model.
* `Generated/` is a Lean translation of the Rust code made by
  [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). `Util.lean` proves that the
  translated functions of `util.rs` compute the model's, with scalars mapped to `F`. The other
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

The `util.rs` lemmas in `Util.lean` say, for each function, that the translation returns what the
model returns: `inner_product`, `weighted_inner_product`, `weighted_norm`, `to_scalars`,
`power_vector`, `vec_add`, `vec_scalar_mul`, `hadamard`, `pad_to`, `batch_invert` (including its
error when an input is zero), `to_digits` for `d ≤ 16` and `multiplicities` for digits below 16.

## Files

| File | Contents |
|---|---|
| `Correctness.lean`, `Soundness.lean`, `ZeroKnowledge.lean`, `Proofs/Hygiene.lean` | The theorems above. |
| `Model/` | The model of the Rust code, one file per module, with the same names. |
| `Proofs/` | Lemmas about each module of the model, and completeness and special soundness of `norm_linear` and `circuit`. |
| `Spec/` | The protocol of the paper, used inside the proofs. |
| `Scalar.lean` | `ScalarModel`: what is assumed about `RistrettoScalar`. |
| `Util.lean` | The translation of `util.rs` computes `Model/Util.lean`. |
| `Theorems.lean` | Imports everything. |
| `Generated/` | The translation of `util.rs`, made by `extract.sh`. `groups`, `pedersen`, `serde_helpers` and `merlin` are opaque. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Defines `u64::ilog2`, which Aeneas leaves as an axiom. Called by `extract.sh`. |

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
* **Translation.** `Util.lean` is about the Lean code in `Generated/`, so it trusts that Charon and
  Aeneas translate `util.rs` faithfully, and the definition of `u64::ilog2` that
  `fix_aeneas_output.py` adds. `debug_assert!`s are translated as checks that fail, so the lemmas
  assume equal lengths where `util.rs` asserts them.
* **Scalars** (`ScalarModel`). `RistrettoScalar` maps to the field `F` by some `φ`, under which
  `zero`, `generator`, `+`, `*`, `+=`, `*=` and `From<u64>` are `F`'s, `clone` returns its
  argument, and `inverse` fails exactly on zero.
* **Merlin and Ristretto.** Merlin frames `(label, message)` pairs unambiguously, and Ristretto
  points have a canonical encoding.
* **Generators.** `Generators::new` returns generators with no known linear relation. They are
  not absorbed into the transcript, because `range` and `m` determine them.

## What is not proved

* The translations of `laurent.rs`, `constraints.rs`, `transcript.rs`, `crs.rs`, `norm_linear.rs`,
  `circuit.rs` and `range_proof.rs` are not yet shown to compute the model.
* `Generators::new` (hash-to-curve), the MSM precomputation tables, serialization and test-only
  code are not modelled.
* From special soundness to knowledge soundness of the non-interactive proof (tree extraction and
  the Fiat–Shamir transform in the random-oracle model), and zero-knowledge of the non-interactive
  proof in the random-oracle model, are standard steps, cited rather than proved.
* Fiat–Shamir hygiene of the prover's transcript is not needed: by completeness it derives the
  same challenges as the verifier on honest runs.
