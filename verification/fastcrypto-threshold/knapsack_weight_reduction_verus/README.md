# Formal verification of weight reduction (Verus)

This crate runs a machine-checked proof, using [Verus](https://github.com/verus-lang/verus), that
the weight reduction checker `verify_reduction` in `fastcrypto-threshold` is sound.

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
`max_reduced_weight`) never panic, index out of bounds or overflow, for any input, and that every
loop terminates. The `panic!` in `max_reduced_weight` is proved unreachable.

Completeness is **not** proved: `verify_reduction` may reject a valid reduction. That only affects
whether the reducer finds a good reduction, not security.

## How the proof is tied to the production code

The production code in
[`fastcrypto-threshold/src/knapsack_weight_reduction.rs`](../../../fastcrypto-threshold/src/knapsack_weight_reduction.rs)
stays plain Rust: the verified functions sit between `// BEGIN VERUS-VERIFIED` and
`// END VERUS-VERIFIED` markers, with no annotations.

Everything for the proof lives in this directory:

- [`verified_knapsack_weight_reduction.rs`](verified_knapsack_weight_reduction.rs): a copy of
  that region with the Verus contracts, loop invariants and proof steps added, plus, in a
  `verus!` block above it, the spec definitions and lemmas the proof uses. The annotations use
  Verus's attribute syntax, so the copy is still plain Rust apart from them.
- [`transform_code_test.rs`](transform_code_test.rs): the test `verus_copy_matches_production`.
  It removes comments and annotations from the copy and checks that the result is the same code
  as the production region. It is compiled into the fastcrypto-threshold tests, so it runs in
  normal CI without Verus. Only these annotations may be added: `#[verus_spec(...)]` attributes
  and `proof! { ... }` / `proof_decl! { ... }` statements. The test also checks:
  - every function in the region has a `#[verus_spec]`. Verus silently skips a function outside
    `verus!` that has none, so a dropped attribute would otherwise leave it unverified;
  - the main theorem on `verify_reduction` has an `ensures` and no `requires`;
  - the copy contains none of `assume(`, `admit(`, `assume_specification`, `external_body`,
    `#[verifier::external]`, `#[verus_verify(external...)]` or `#[verifier::truncate]`.
- `lib.rs`, `Cargo.toml`, `Cargo.lock`: the crate that `cargo verus` builds. It is outside the
  workspace.

When you change the production region:

1. Make the same change in `verified_knapsack_weight_reduction.rs`; the test fails until you do.
2. Run `cargo verus verify` here and fix the annotations if the proof no longer goes through.

## Trusted base

- Verus and the Z3 SMT solver it ships with.
- The `vstd` specifications of the few standard library items used: slice and `Vec` indexing
  (`Index` and `IndexMut`), `vec![x; n]`, `usize::min`, `<str as ToString>::to_string`,
  `core::panicking::panic_fmt` (whose precondition makes the `panic!` a proof obligation), and
  `<Vec<T> as Deref>::deref` (the `&Vec<T>` to `&[T]` coercion).
- The `#[verifier::external_type_specification]` for `FastCryptoError`, which only lets the
  verified code construct its variants.
- The model of a subset as a sequence of booleans and the definitions of `wsum` and
  `reduction_properties_hold` in `verified_knapsack_weight_reduction.rs`, which a reviewer should
  check match the intended meaning of `w(S)` and of (P), (L1), (L2) and (L3).
- The copy check in `verus_copy_matches_production`. It doesn't cover the stand-ins at the top of
  `verified_knapsack_weight_reduction.rs` (`MAX_PARTIES`, `ReducedWeights`). Their exact values
  don't matter to the soundness proof: the theorem holds for any value of `MAX_PARTIES` up to
  65,537.

## Checking that the proof is meaningful

A proof can pass because its statement is too weak. As a sanity check, each of these mutations of
the copy in `verified_knapsack_weight_reduction.rs` makes the proof fail:

- removing the (P) check from `verify_reduction`;
- removing the (L3) check;
- comparing the (P) bound against `t'` instead of `t' - 1`, which would accept `w'(S) == t'`;
- comparing the (L2) bound against `f' + 1` instead of `f'`;
- keeping the larger instead of the smaller candidate in `knapsack_min_original`;
- iterating the knapsack update upward, which lets a party be counted twice;
- adding `assert(false)` before `Ok(())`, which shows the proof context is not contradictory;
- dropping the facts about entry 0 from `max_reduced_weight`, which makes its `panic!` reachable.

## Running the proofs

Install the Verus release `0.2026.11.02.8bf68ee` from
[GitHub](https://github.com/verus-lang/verus/releases/tag/release%2F0.2026.11.02.8bf68ee) by
following its [installation guide](https://github.com/verus-lang/verus/blob/main/INSTALL.md),
put its directory on your `PATH`, and install the Rust toolchain it is built against:

```sh
rustup install 1.99.1
```

The `vstd` version in `Cargo.toml` must match the Verus release; update both together. Then from
this directory:

```sh
cargo verus verify
```

The first run compiles fastcrypto with Verus's toolchain, which takes about 40 seconds. The proofs
themselves take about 2 seconds and should end with `verification results:: 14 verified, 0 errors`.
