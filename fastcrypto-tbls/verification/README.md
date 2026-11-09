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

The verified functions live in
[`src/knapsack_weight_reduction/verified.rs`](../src/knapsack_weight_reduction/verified.rs).
Their contracts, loop invariants and proof steps are written next to the code, behind
`cfg(creusot)`, so normal builds compile plain Rust and `fastcrypto-tbls` gains no dependency.
This crate includes that file as is (`#[path = ...]`), so the proof is about the code that ships:
there is no copy to keep in sync.

`verify_reduction` in `knapsack_weight_reduction.rs` is a one-line wrapper that unpacks
`ReducedWeights` and calls the verified function.

Changes to `verified.rs` must keep the proofs passing.

## Trusted base

- Creusot, Why3 and the SMT solvers (Alt-Ergo, Z3, CVC5, CVC4).
- The `creusot-std` specifications of the few standard library items used: slice and `Vec`
  indexing, `vec!`, `usize::min` and `str::to_owned`.
- The model of a subset as a sequence of booleans and the definition of `wsum` in `verified.rs`,
  which a reviewer should check matches the intended meaning of `w(S)`.

## Checking that the proof is meaningful

A proof can pass because its statement is too weak. As a sanity check, each of these mutations of
`verified.rs` makes the proof fail:

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
about 30 seconds and should end with `Proved (8 files)`. The proof certificates under `verif/`
(`proof.json`) let `cargo creusot --replay` re-check them without searching again.
