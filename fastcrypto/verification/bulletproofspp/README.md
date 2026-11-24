<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::bulletproofspp`

Proofs about the batched Bulletproofs++ range proof (`fastcrypto/src/bulletproofspp`), the
protocol of [ePrint 2026/2648](https://eprint.iacr.org/2026/2648) §5. There are two layers:

* `Model/` is a Lean model of the Rust code, one file per module and function by function, over
  any field `F` and any `F`-module `E`. The protocol theorems are about this model.
* `Generated/` is a Lean translation of the Rust code made by
  [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The other Lean files at the top
  level prove that the translated functions compute the model's, with scalars mapped to `F` and
  points to `E`, up to `RangeProof::prove_batch` and `RangeProof::verify_batch`. This links the
  protocol theorems to the Rust code.

The Rust code carries no annotations. It is written in a style Aeneas can translate: index loops
instead of iterator chains and closures.

## Theorems about the Rust code

These are in `Theorems.lean`, about the translation of `range_proof.rs`. They assume the models
of scalars, points, the transcript and the generators listed [below](#what-is-assumed)
(`Models`), and batches of at most `(usize::MAX - 256) / 256` values.

1. **`RangeProof.completeness_rust`: honest proofs are accepted.** For values in `range` and
   blindings of the same length, `RangeProof::prove_batch` returns a proof, for every state of
   the random number generator, and `RangeProof::verify_batch` accepts it for the Pedersen
   commitments to the values. This needs a transcript hash that never outputs `-j` for `j < 16`.

2. **`RangeProof.verify_batch_refines`: the verifier is the model's.** `RangeProof::verify_batch`
   accepts exactly when the model's `verify_batch` accepts. So special soundness, the locality of
   the challenges and the unambiguity of the logs below hold for the Rust verifier.

3. **`RangeProof.prove_batch_refines`: the prover is the model's.** `RangeProof::prove_batch`
   returns the model's proof for some choice of the prover's random draws, or fails when the
   model's does.

## Theorems about the model

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
including the same errors (or, from `circuit.rs` on, an error exactly when the model errs) and
the same transcript:

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
* `circuit.rs`: `CircuitParams::new`, `prove` for some draws of the random number generator
  (`circuit_prove_spec`, through `Witness::new`, `commit_c_s` and `prove_witness` with the honest
  reciprocals), and `verify` (`circuit_verify_spec`).
* `range_proof.rs`: `setup`, `prove_batch` and `verify_batch`.

## Files

| File | Contents |
|---|---|
| `Correctness.lean`, `Soundness.lean`, `ZeroKnowledge.lean`, `Proofs/Hygiene.lean` | The theorems above. |
| `Model/` | The model of the Rust code, one file per module, with the same names. |
| `Proofs/` | Lemmas about each module of the model, and completeness and special soundness of `norm_linear` and `circuit`. |
| `Spec/` | The protocol of the paper, used inside the proofs. |
| `Scalar.lean` | `ScalarModel`: what is assumed about `RistrettoScalar`. |
| `Points.lean` | `PointModel`, `GensOK`, `TranscriptModel` and `PedersenModel`: what is assumed about `RistrettoPoint`, the MSM tables of `Generators`, the Merlin transcript and `PedersenCommitment::new`. |
| `Util.lean`, `Laurent.lean`, `Constraints.lean` | The translations of `util.rs`, `laurent.rs` and `constraints.rs` compute the model. |
| `NormLinear.lean`, `LazyBases.lean`, `Prove.lean`, `Verify.lean` | The translation of `norm_linear.rs` computes the model: its helpers, `LazyBases::msm`, `prove` and `verify`. |
| `Circuit.lean`, `CircuitWitness.lean`, `CircuitOpening.lean`, `CircuitProve.lean`, `CircuitVerify.lean` | The translation of `circuit.rs` computes the model: its helpers, `Witness::new`, the opening of `C(T)`, `prove` and `verify`. `Circuit.lean` also has `RandOK`, what is assumed about `RistrettoScalar::rand`. |
| `RangeProof.lean` | The translation of `range_proof.rs` computes the model, with `TranscriptInit` and `GensNewModel`, what is assumed about creating transcripts and `Generators::new`. |
| `Theorems.lean` | The theorems about the Rust code. |
| `Generated/` | The translation of the Rust code from `RangeProof::prove_batch` and `RangeProof::verify_batch` down, made by `extract.sh`. `groups`, `pedersen` (except `Range`), `serde_helpers`, `merlin`, `transcript.rs` (except `Label`), `crs::compatible_with_pedersen_commitments` and `crs::cached_generators` are opaque. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Defines `u64::ilog2`, `i32::unsigned_abs`, `slice::from_ref`, `usize::next_power_of_two`, `Range::bits` and `Range::is_in_range`, which Aeneas leaves as axioms. Called by `extract.sh`. |

To check the proofs, install Lean with `elan` and run, here:

```bash
lake exe cache get
lake build
```

The first build also compiles the Aeneas and VCVio libraries. To regenerate `Generated/` after
changing the Rust code, get `charon` and `aeneas` from the Aeneas release named in `extract.sh`
and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

* **The model.** The theorems about the model are about `Model/`. The theorems about the Rust
  code use it only through the lemmas about the translation. In the model:
  * scalars are a field and points a module over it, `Vec` is `List`, `FastCryptoResult` is
    `Except`, and `&mut BpppTranscript` is a state monad;
  * the Merlin transcript is a log of labelled entries and an arbitrary function from logs to
    challenges, `Transcript::new` absorbs its label under `"dom-sep"`, and a `u64` is 8
    little-endian bytes;
  * the prover's random draws are an input, indexed by slot; for zero-knowledge they are uniform,
    and `protocol` (`ZeroKnowledge.lean`), which casts `range_proof` as a VCVio protocol, is part
    of the model.
* **Translation.** The lemmas about the translation are about the Lean code in `Generated/`, so
  they trust that Charon and Aeneas translate the Rust code faithfully, and the definitions that
  `fix_aeneas_output.py` adds. `debug_assert!`s are
  translated as checks that fail, so the lemmas assume equal lengths where the Rust code asserts
  them. Aeneas clones tuples by copying, so cloning `(i32, C)` in `Laurent::from_terms` is
  assumed to return its argument.
* **Scalars** (`ScalarModel`). `RistrettoScalar` maps to the field `F` by some `φ`, under which
  `zero`, `generator`, `+` (also by reference), `-x`, `*`, `+=`, `*=` and `From<u64>` are `F`'s,
  `clone` returns its argument, and `inverse` fails exactly on zero. `rand` does not fail
  (`RandOK`).
* **Points** (`PointModel`). `RistrettoPoint` maps to the module `E` by some `ψ`, under which
  `zero` is `0`, `==` is equality and `multi_scalar_mul` is the sum of the products, failing
  with `InvalidInput` exactly on different lengths.
* **MSM tables** (`GensOK`). The mixed MSM over the precomputed tables of `Generators` is the
  model's over `[g, h_vec.., g_vec..]`.
* **Pedersen commitments** (`PedersenModel`). `PedersenCommitment::new` commits to `v` with
  blinding `b` as `v H + b G` for the images `G`, `H` of `pedersen::G`, `pedersen::H`.
* **Transcript** (`TranscriptModel`, `TranscriptInit`). `transcript.rs` maps to the model's
  transcript by some `τ`, under which `new`, `domain_sep`, `append_message`, `append_u64`,
  `append_point`, `append_commits`, `append_scalars` and `challenge_scalar` act as the model's,
  with each `Label` as its byte string, and with some `oracle` as the hash.
* **`Generators::new`** (`GensNewModel`). It does not panic, succeeds for powers of two at least
  16, and returns `H_LEN` and `nm` generators with `g = pedersen::H` and
  `h_vec[0] = pedersen::G`, whose MSM tables satisfy `GensOK`. The model's `generators` is
  `Generators::new` under `ψ` (`genM`).
* **Merlin and Ristretto.** Merlin frames `(label, message)` pairs unambiguously, and Ristretto
  points have a canonical encoding.
* **Generators.** `Generators::new` returns generators with no known linear relation. They are
  not absorbed into the transcript, because `range` and `m` determine them.

## What is not proved

* `transcript.rs`, `Generators::new` and `PedersenCommitment::new` are assumed rather than
  translated.
* Zero-knowledge is proved for the model, with uniform draws. The Rust prover computes the model's
  proof for the draws it makes, but nothing links its random number generator to uniform draws.
* `circuit::prove_witness` is proved for the honest reciprocals and witness, the only ones the
  Rust prover uses.
* `Generators::new` (hash-to-curve), the MSM precomputation tables, serialization and test-only
  code are not modelled.
* From special soundness to knowledge soundness of the non-interactive proof (tree extraction and
  the Fiat–Shamir transform in the random-oracle model), and zero-knowledge of the non-interactive
  proof in the random-oracle model, are standard steps, cited rather than proved.
* Fiat–Shamir hygiene of the prover's transcript is not needed: by completeness it derives the
  same challenges as the verifier on honest runs.
