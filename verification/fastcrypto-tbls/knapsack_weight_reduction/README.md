# Formal verification of weight reduction (Creusot)

This crate runs a machine-checked proof, using [Creusot](https://github.com/creusot-rs/creusot),
that the weight reduction checker `verify_reduction` in `fastcrypto-tbls` is sound.

## What is proved

If `verify_reduction(weights, t, f, delta, reduction)` returns `Ok(())`, then for **every** subset
`S` of the parties, where `w` are the original and `w'` the reduced weights:

| Property | Statement |
|---|---|
| (P) privacy | `w(S) < t  =>  w'(S) < t'` |
| (L1) liveness | `w(S) >= t + f + delta  =>  w'(S) >= t' + f'` |
| (L2) Byzantine bound | `w(S) <= f  =>  w'(S) <= f'` |
| (L3) liveness | `w(S) >= t + delta  =>  w'(S) >= t'` |

Tests can only sample subsets (there are `2^n`), while the proof covers all of them. Because the
checker is sound, the guarantee holds for every reduction that passes it, however it was produced.

The proof also shows that `verify_reduction` and its helpers (`sum_u16`, `knapsack_min_original`,
`max_reduced_weight`) never panic, index out of bounds or overflow, for any input.

Completeness is **not** proved: `verify_reduction` may reject a valid reduction. That only affects
whether the reducer finds a good reduction, not security.

## How the proof is tied to the production code

The production code in
[`fastcrypto-tbls/src/knapsack_weight_reduction.rs`](../../../fastcrypto-tbls/src/knapsack_weight_reduction.rs)
stays plain Rust: the verified functions sit between `// BEGIN CREUSOT-VERIFIED` and
`// END CREUSOT-VERIFIED` markers, with no annotations.

Everything for the proof lives in this directory:

- [`verified_knapsack_weight_reduction.rs`](verified_knapsack_weight_reduction.rs): a copy of
  that region with the Creusot contracts, loop invariants and proof steps added, plus the logic
  definitions and lemmas the proof uses.
- [`transform_code_test.rs`](transform_code_test.rs): the test `creusot_copy_matches_production`.
  It removes comments and annotations from the copy and checks that the result is the same code
  as the production region. It is compiled into the fastcrypto-tbls tests, so it runs in normal
  CI without Creusot. Only these annotations may be added, each as its own statement or
  attribute: `#[requires]`, `#[ensures]`, `#[invariant]`, `#[variant]`, `proof_assert!` and
  `let x = snapshot!`. `#[trusted]` is rejected.
- `lib.rs`, `Cargo.toml`, `why3find.json`: the crate that `cargo creusot` builds. It is outside
  the workspace.

When you change the production region:

1. Make the same change in `verified_knapsack_weight_reduction.rs`; the test fails until you do.
2. Run `cargo creusot` here and fix the annotations if the proof no longer goes through.

## Trusted base

- Creusot, Why3 and the SMT solvers (Alt-Ergo, Z3, CVC5, CVC4).
- The `creusot-std` specifications of the few standard library items used: slice and `Vec`
  indexing, `vec!`, `usize::min` and `str::to_owned`.
- The model of a subset as a sequence of booleans and the definition of `wsum` in `verified_knapsack_weight_reduction.rs`,
  which a reviewer should check matches the intended meaning of `w(S)`.
- The copy check in `creusot_copy_matches_production`. It doesn't cover the stand-ins at the top
  of `verified_knapsack_weight_reduction.rs` (`MAX_PARTIES`, `ReducedWeights`). Their exact values don't matter to the
  soundness proof: the theorem holds for any value of `MAX_PARTIES` up to 65,537.

## Checking that the proof is meaningful

A proof can pass because its statement is too weak. As a sanity check, each of these mutations of
the copy in `verified_knapsack_weight_reduction.rs` makes the proof fail:

- removing the (P) check from `verify_reduction`;
- keeping the larger instead of the smaller candidate in `knapsack_min_original`.

## Running the proofs

Install Creusot 0.14.0 by following its
[installation guide](https://guide.creusot.rs/installation.html) (it needs `rustup` and `opam`),
then from this directory:

```sh
cargo creusot
```

This compiles the crate with Creusot's pinned nightly toolchain and runs the provers. It takes
about 30 seconds and should end with `Proved (8 files)`. Creusot writes its output and proof
caches to `verif/` (gitignored).
