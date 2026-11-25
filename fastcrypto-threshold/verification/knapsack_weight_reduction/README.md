<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto_threshold::knapsack_weight_reduction`

Proofs about the weight reduction in `fastcrypto-threshold/src/knapsack_weight_reduction.rs`,
against a Lean translation of the Rust code made by
[Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code carries no annotations.
It is written in a style Aeneas can translate: `for` loops instead of iterator chains, and small
functions instead of closures.

`reduce_weights(weights, t, f, delta, total_weight_lower_bound)` reduces the weights `w` and
thresholds `(t, f)` to `(w', t', f')`, and `verify_reduction(weights, t, f, delta, reduction)`
checks such a reduction. For a set `S` of parties, `w(S)` and `w'(S)` are the sums of the original
and reduced weights of the parties in `S`.

The theorems and their assumptions are in `Spec.lean`, the one file a reviewer reads in full.
Everything else is a lemma, which Lean checks.

## Theorems

1. **`verify_reduction_sound`: `verify_reduction` does not panic, and an accepted reduction
   preserves the thresholds.** On every input, it returns `Ok(())` or an error, without
   overflowing or indexing out of bounds; in particular, the `panic!` in `max_reduced_weight` is
   unreachable. If it returns `Ok(())`, then for every set `S` of parties:
   * (P) `w(S) < t` implies `w'(S) < t'`,
   * (L1) `w(S) ≥ t + f + delta` implies `w'(S) ≥ t' + f'`,
   * (L2) `w(S) ≤ f` implies `w'(S) ≤ f'`,
   * (L3) `w(S) ≥ t + delta` implies `w'(S) ≥ t'`.

2. **`reduce_weights_passes_verify`: `reduce_weights` does not panic, and computes reductions
   that pass the check.** On every input, it returns a reduction or an error, without
   overflowing or indexing out of bounds. If it returns `Ok(reduction)`, then `verify_reduction`
   with the same `weights`, `t`, `f` and `delta` returns `Ok(())` on it. So by 1, every
   reduction it returns has the four properties.

Both need `ToStringReturns`, and 2 also needs `SortByPermutes`, both listed
[below](#what-is-assumed).

## Files

| File | Contents |
|---|---|
| `Spec.lean` | The theorems above, their assumptions (`ToStringReturns`, `SortByPermutes`), and their axiom reports. |
| `Subsets.lean` | The weight of a subset (`wsum`) and of all parties (`total`), the four guarantees (`ReductionPropertiesHold`), the relaxation step of the knapsack table (`relax`), and that the checks in `verify_reduction` imply the guarantees (`properties_of_checks`). |
| `Knapsack.lean` | What `sum_u16`, `max_reduced_weight` and `knapsack_min_original` return (`sum_u16_spec`, `max_reduced_weight_spec`, `knapsack_min_original_spec`). |
| `Verify.lean` | What `verify_reduction` returns (`verify_reduction_spec`), and when it accepts (`verify_reduction_accepts`). |
| `Reduce.lean` | What `check_candidate`, `sweep` and `reduce_weights` return (`check_candidate_spec`, `sweep_spec`, `reduce_weights_spec`), that the original weights pass `verify_reduction` (`identity_passes`), and that the comparator in `greedy_reject` is a total order (`greedy_comparator_total`). |
| `Generated/` | The translation of `verify_reduction`, `reduce_weights` and the functions they call, made by `extract.sh`. |
| `extract.sh` | Regenerates `Generated/`. |

To regenerate `Generated/` after changing `knapsack_weight_reduction.rs`, get `charon` and
`aeneas` from the Aeneas release named in `extract.sh` and run `CHARON=... AENEAS=... ./extract.sh`.

The workflow `Weight Reduction Lean Proof` checks this on each change to `fastcrypto-threshold`:
it runs `extract.sh`, fails if `Generated/` is not what `extract.sh` makes from the current Rust
code, builds the proofs, and fails if a proof uses `sorry` or an axiom report is absent.

## What is assumed

* **Translation.** The proofs are about the Lean code in `Generated/`, so they trust that Charon
  and Aeneas translate `knapsack_weight_reduction.rs` faithfully.
* **Error messages** (`ToStringReturns`). `to_string` returns on every `&str`. It and
  `<str as Display>::fmt` stay axioms, with nothing else assumed: they are only called to build
  the message of a `GeneralError`.
* **Sorting** (`SortByPermutes`). `sort_by` stays an axiom. The proofs assume what Rust documents
  about it: if the comparator returns on the elements of the slice and is a total order on them,
  `sort_by` returns a permutation of the slice. Nothing is assumed about the order, which only
  affects whether `greedy_reject` skips a candidate early. That the comparator in `greedy_reject`
  returns and is a total order on the parties it sorts is proved (`greedy_comparator_total`).
* **`usize`** has 32 or 64 bits. The theorems hold for both.

## What is not proved

* Completeness of `verify_reduction`: it may reject a reduction that has the four properties.
* Optimality of `reduce_weights`: the proofs say nothing about how small the reduced total is.
