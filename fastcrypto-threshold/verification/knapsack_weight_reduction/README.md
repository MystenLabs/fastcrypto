<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto_threshold::knapsack_weight_reduction`

Proofs about the weight reduction in `fastcrypto-threshold/src/knapsack_weight_reduction.rs`,
against a Lean translation of the Rust code made by
[Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code carries no annotations.
It is written in a style Aeneas can translate: `for` loops instead of iterator chains, and small
functions instead of closures.

A reviewer reads the files at the top of this folder in full: the theorems in `Theorems.lean`, the
assumptions they take in `Assumptions.lean`, and the script that makes the translation,
`extract.sh`. The Lean docs there are the precise statements. The files in `Proofs/` are lemmas,
which Lean checks, and `Generated/` is the translation, which CI checks is up to date.

## Theorems

In `Theorems.lean`. For a set `S` of parties, `w(S)` and `w'(S)` are the sums of the original and
reduced weights.

1. **`verify_reduction_sound`.** `verify_reduction` never panics, and if it accepts
   `(w', t', f')`, then for every `S`: `w(S) < t ⇒ w'(S) < t'`,
   `w(S) ≥ t + f + delta ⇒ w'(S) ≥ t' + f'`, `w(S) ≤ f ⇒ w'(S) ≤ f'` and
   `w(S) ≥ t + delta ⇒ w'(S) ≥ t'`.
2. **`reduce_weights_passes_verify`.** `reduce_weights` never panics, and `verify_reduction`
   accepts every reduction it returns, which therefore has the properties of 1.

## What is assumed

In `Assumptions.lean`, besides the translation:

* **Translation.** Charon and Aeneas translate `knapsack_weight_reduction.rs` faithfully.
* **`ToStringReturns`**: `to_string` returns on every `&str`. It is only used for error messages.
* **`SortByPermutes`**, for 2: `sort_by` with a total order (`TotalOrderOn`) returns a permutation,
  as Rust documents. That `greedy_reject`'s comparator is one is proved.
* **`usize`** has 32 or 64 bits. The theorems hold for both.

## What is not proved

* Completeness of `verify_reduction`: it may reject a reduction that has the four properties.
* Optimality of `reduce_weights`: how small the reduced total is.

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | The theorems, and their axiom reports. |
| `Assumptions.lean` | The assumptions. |
| `Proofs/` | The lemmas: weights of subsets and the four properties (`Subsets.lean`), the knapsack table (`Knapsack.lean`), `verify_reduction` (`Verify.lean`), and `reduce_weights` (`Reduce.lean`). |
| `Generated/` | The translation of `verify_reduction`, `reduce_weights` and the functions they call. |
| `extract.sh` | Regenerates `Generated/`: get `charon` and `aeneas` from the Aeneas release it names and run `CHARON=... AENEAS=... ./extract.sh`. |

The workflow `Weight Reduction Lean Proof` (with `lean-proof.yml`) runs `extract.sh`, fails if
`Generated/` is out of date, builds the proofs, and fails if a proof uses `sorry` or an axiom
report is absent.
