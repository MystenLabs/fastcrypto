<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto_threshold::knapsack_weight_reduction`

Proofs about the weight-reduction checker `verify_reduction` in
`fastcrypto-threshold/src/knapsack_weight_reduction.rs`, against a Lean translation of the Rust
code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code carries no
annotations. It is written in a style Aeneas can translate: index loops instead of iterator
chains and closures.

`verify_reduction(weights, t, f, delta, reduction)` checks a reduction of the weights `w` and
thresholds `(t, f)` to `reduction = (w', t', f')`. `Nodes::knapsack_reduce` calls it on the output
of `reduce_weights`, so the guarantees below hold for every reduction it returns. For a set `S` of
parties, `w(S)` and `w'(S)` are the sums of the original and reduced weights of the parties in
`S`.

The theorems are in `Theorems.lean`. Everything else is a lemma.

## Theorems

1. **`verify_reduction_sound`: an accepted reduction preserves the thresholds.** If
   `verify_reduction` returns `Ok(())`, then for every set `S` of parties:
   * (P) `w(S) < t` implies `w'(S) < t'`,
   * (L1) `w(S) ≥ t + f + delta` implies `w'(S) ≥ t' + f'`,
   * (L2) `w(S) ≤ f` implies `w'(S) ≤ f'`,
   * (L3) `w(S) ≥ t + delta` implies `w'(S) ≥ t'`.

2. **`verify_reduction_no_panic`: `verify_reduction` does not panic.** On every input, it
   returns `Ok(())` or an error, without overflowing or indexing out of bounds. In particular,
   the `panic!` in `max_reduced_weight` is unreachable.

Both need `ToStringReturns`, listed [below](#what-is-assumed).

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | The theorems above. |
| `Spec.lean` | The weight of a subset (`wsum`) and of all parties (`total`), the four guarantees (`ReductionPropertiesHold`), the relaxation step of the knapsack table (`relax`), and that the checks in `verify_reduction` imply the guarantees (`properties_of_checks`). |
| `Knapsack.lean` | What `sum_u16`, `max_reduced_weight` and `knapsack_min_original` return (`sum_u16_spec`, `max_reduced_weight_spec`, `knapsack_min_original_spec`). |
| `Verify.lean` | What `verify_reduction` returns (`verify_reduction_spec`), and the assumption `ToStringReturns`. |
| `Generated/` | The translation of `verify_reduction` and the functions it calls, made by `extract.sh`. |
| `extract.sh` | Regenerates `Generated/`. |

To regenerate `Generated/` after changing `knapsack_weight_reduction.rs`, get `charon` and
`aeneas` from the Aeneas release named in `extract.sh` and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

* **Translation.** The proofs are about the Lean code in `Generated/`, so they trust that Charon
  and Aeneas translate `knapsack_weight_reduction.rs` faithfully.
* **Error messages** (`ToStringReturns`). `to_string` returns on every `&str`. It and
  `<str as Display>::fmt` stay axioms, with nothing else assumed: they are only called to build
  the message of a `GeneralError`.
* **`usize`** has 32 or 64 bits. The theorems hold for both.

## What is not proved

* Completeness: `verify_reduction` may reject a reduction that has the four properties. This
  only affects whether `reduce_weights` finds a reduction, not the guarantees above.
* Anything about `reduce_weights`, other than what follows from `Nodes::knapsack_reduce` checking
  its output with `verify_reduction`.
