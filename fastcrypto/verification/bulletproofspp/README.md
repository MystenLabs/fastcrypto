<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::bulletproofspp`

Proofs about the batched Bulletproofs++ range proof (`fastcrypto/src/bulletproofspp`), the
protocol of [ePrint 2026/2648](https://eprint.iacr.org/2026/2648) §5, in two layers:

* `Model/` is a Lean model of the Rust code, one file per module and function by function, over
  any field `F` and any `F`-module `E`. The protocol theorems are about this model.
* `Generated/` is a Lean translation of the Rust code made by
  [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The lemmas in `Proofs/` show that
  the translated functions compute the model's, up to `RangeProof::prove_batch` and
  `RangeProof::verify_batch`, which links the protocol theorems to the Rust code.

The Rust code carries no annotations. The theorems are in `Theorems.lean`, their assumptions in
`Assumptions.lean` and the model in `Model/`, whose Lean docs are the precise statements.

## Theorems

In `Theorems.lean`.

### About the Rust code

Under the models of `Assumptions.lean` (`Models`), for batches of at most
`(usize::MAX - 256) / 256` values:

1. **`RangeProof.completeness_rust`.** For values in range, `prove_batch` returns a proof for
   every state of the random number generator, and `verify_batch` accepts it.
2. **`RangeProof.verify_batch_refines`.** `verify_batch` accepts exactly when the model's
   verifier does, so theorems 7, 9 and 10 hold for the Rust verifier.
3. **`RangeProof.prove_batch_refines`.** `prove_batch` returns the model's proof for the draws of
   its random number generator.
4. **`RangeProof.prove_batch_distribution`.** With an ideal random number generator,
   `prove_batch` has the distribution of the model's prover with uniform masks and blindings.
5. **`RangeProof.zero_knowledge_rust`.** If the transcript hash returns an honest verifier's
   challenges, `prove_batch` has the distribution that theorem 8 simulates.

### About the model

6. **`RangeProof.completeness`.** Honest proofs are accepted.
7. **`RangeProof.verify_extract`: special soundness.** From a tree of accepting runs, every
   commitment opens to a value in range, or the generators satisfy a linear relation.
8. **`RangeProof.zero_knowledge`: honest-verifier zero-knowledge**, within statistical distance
   `21 / |F|`.
9. **`RangeProof.verify_batch_local`.** Each challenge depends only on its log, which starts with
   the statement and has every prover message before it.
10. **`RangeProof.challenge_decodes`.** The challenge logs decode unambiguously.
11. **`RangeProof.challengeLogs_nodup`.** No challenge is drawn twice in a run.

Most of them need generators of the right shape (`H_LEN` and `nm` points, with `g` and `h_vec[0]`
the Pedersen bases); see each theorem's doc for its hypotheses.

## What is assumed

In `Assumptions.lean` and `Model/`, besides the translation; each theorem takes the ones it
needs:

* **Translation.** Charon and Aeneas translate the Rust code faithfully, and the definitions that
  `fix_aeneas_output.py` adds are right. Aeneas clones `(i32, C)` in `Laurent::from_terms` by
  copying.
* **The model.** Scalars are a field and points a module over it, the Merlin transcript is a log
  with an arbitrary function from logs to challenges, and the prover's random draws are an input.
* **Opaque code**, mapped to the model:
  * `ScalarModel`: `RistrettoScalar`'s operations are `F`'s, and `rand` does not fail (`RandOK`);
  * `PointModel`: `RistrettoPoint`'s are `E`'s, including `multi_scalar_mul`;
  * `GensOK` and `GensNewModel`: `Generators::new` and its MSM tables;
  * `PedersenModel`: `PedersenCommitment::new` is `v H + b G`;
  * `TranscriptModel` and `TranscriptInit`: `transcript.rs` acts as the model's transcript.
* **`IdealRng`**, for 4 and 5: the draws of `RistrettoScalar::rand` are uniform and independent.
* **Merlin and Ristretto**: Merlin frames `(label, message)` pairs unambiguously, and Ristretto
  points have a canonical encoding. `Generators::new` returns generators with no known linear
  relation.

## What is not proved

* `transcript.rs`, `Generators::new` (hash-to-curve), `PedersenCommitment::new`, the MSM tables
  and serialization are assumed rather than translated.
* Theorems 4 and 5 are about the prover's output under the models; they fix the distribution of
  the Rust proofs when `ψ` is injective, as for Ristretto.
* Knowledge soundness and zero-knowledge of the non-interactive proof in the random-oracle model
  follow from theorems 7 and 8 by standard steps, which are cited rather than proved.

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | The theorems, and their axiom reports. |
| `Assumptions.lean` | The assumptions about the opaque code (`Models`) and `IdealRng`. |
| `Model/` | The model of the Rust code, one file per module, with the same names. |
| `Proofs/Model/`, `Proofs/Spec/` | Lemmas about the model, and the protocol of the paper (with its challenge `δ`, which the Rust code omits and the proofs set to 1). |
| `Proofs/` | The translation computes the model: `Util.lean`, `Laurent.lean`, `Constraints.lean`, `NormLinear.lean` (with `LazyBases.lean`, `Prove.lean`, `Verify.lean`), `Circuit*.lean` and `RangeProof.lean`; and lemmas for the theorems (`Correctness.lean`, `Soundness.lean`, `ZeroKnowledge.lean`, `RustTheorems.lean`). The maps from the translation to the model that the theorems use (`toRP`, `toRange`, `rngD`, `genM`, `toRes`, `rustProve`) are defined there. |
| `Generated/` | The translation from `RangeProof::prove_batch` and `RangeProof::verify_batch` down. `groups`, `pedersen` (except `Range`), `serde_helpers`, `merlin`, `transcript.rs` (except `Label`) and two `crs` functions are opaque. |
| `extract.sh` | Regenerates `Generated/`: get `charon` and `aeneas` from the Aeneas release it names and run `CHARON=... AENEAS=... ./extract.sh`. |
| `fix_aeneas_output.py` | Defines standard-library functions that Aeneas leaves as axioms. Called by `extract.sh`. |

The workflow `Bulletproofs++ Lean Proof` (with `lean-proof.yml`) runs `extract.sh`, fails if
`Generated/` is out of date, builds the proofs, and fails if a proof uses `sorry` or an axiom
report is absent.
