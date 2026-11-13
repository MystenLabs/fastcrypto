# Formal verification of weight reduction (Aeneas and Lean)

This directory holds a machine-checked proof, using [Aeneas](https://github.com/AeneasVerif/aeneas)
and [Lean](https://lean-lang.org), that the weight reduction checker `verify_reduction` in
`fastcrypto-threshold` is sound.

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

The theorem is `verify_reduction_spec` in
[`KnapsackWeightReduction/Proofs.lean`](KnapsackWeightReduction/Proofs.lean). Its `⦃ r => ... ⦄`
form also says that, for every input, `verify_reduction` returns: it terminates and never panics,
overflows or indexes out of bounds. The `panic!` in `max_reduced_weight` is therefore unreachable.
`verify_reduction_sound_finset` restates the theorem with subsets as Mathlib `Finset`s and `w(S)`
as a `Finset` sum, so the statement doesn't depend on the definitions in `Spec.lean`.

Both theorems depend only on Lean's standard axioms (`propext`, `Classical.choice`, `Quot.sound`),
which `#print axioms` confirms: there is no `sorry` and no added axiom.

Completeness is **not** proved: `verify_reduction` may reject a valid reduction. That only affects
whether the reducer finds a good reduction, not security.

## How the proof is tied to the production code

There is no annotated copy. The proof is about a Lean translation of the production code itself:

- [Charon](https://github.com/AeneasVerif/charon) compiles `fastcrypto-threshold` and extracts
  `verify_reduction` and everything it calls, after borrow checking, and Aeneas translates that
  to pure Lean: [`KnapsackWeightReduction/Types.lean`](KnapsackWeightReduction/Types.lean) and
  [`KnapsackWeightReduction/Funs.lean`](KnapsackWeightReduction/Funs.lean). These two files are
  generated: don't edit them. Arithmetic overflow, out-of-bounds indexing and `panic!` become
  failures in Lean, so a proof that a function returns `ok` shows that it can't panic.
- [`KnapsackWeightReduction/FunsExternal.lean`](KnapsackWeightReduction/FunsExternal.lean) is
  written by hand. It models the two standard library functions the translation calls but the
  Aeneas library doesn't cover, `ToString::to_string` and `Display for str`, which only build the
  messages of the `GeneralError`s.
- [`KnapsackWeightReduction/Spec.lean`](KnapsackWeightReduction/Spec.lean) defines subsets, their
  weights and the four properties, and proves the lemmas that don't involve the code.
- [`KnapsackWeightReduction/Proofs.lean`](KnapsackWeightReduction/Proofs.lean) proves a
  specification for each function and loop in `Funs.lean`, and the main theorem.
- [`translation_freshness_test.rs`](translation_freshness_test.rs): the test
  `aeneas_translation_is_fresh`. It hashes the code the translation was generated from (the
  region between the `AENEAS-VERIFIED` markers in
  [`fastcrypto-threshold/src/knapsack_weight_reduction.rs`](../../../fastcrypto-threshold/src/knapsack_weight_reduction.rs),
  plus `MAX_PARTIES` and `ReducedWeights`, ignoring comments and whitespace) and compares it with
  [`translated_code.sha256`](translated_code.sha256). It is compiled into the
  fastcrypto-threshold tests, so it runs in normal CI without Charon, Aeneas or Lean.
- [`extract.sh`](extract.sh) regenerates the translation and records the new hash.

When you change the production region:

1. Run `extract.sh` (see below); the test fails until you do.
2. Run `lake build` here and fix the proofs if they no longer go through.

## Trusted base

- Lean's kernel, which checks every proof step.
- Charon and Aeneas. Their translation of the Rust code to Lean is not itself verified, so a bug
  in it could make the Lean code differ from what `rustc` compiles. This is the main trusted
  component.
- The Aeneas library's Lean models of the standard library items the code uses: slice and `Vec`
  indexing, `vec![x; n]`, `usize::min`, `Vec::deref`, and integer arithmetic and casts. The step
  specifications Aeneas proves about them are checked by Lean like everything else.
- The two models in `FunsExternal.lean`: `to_string` succeeds. The string contents aren't modelled,
  and nothing depends on them.
- The definitions in `Spec.lean` (`wsum`, `total`, `ReductionPropertiesHold`), which a reviewer
  should check match the intended meaning of `w(S)` and of the four properties.
  `verify_reduction_sound_finset` shows the statement with Mathlib's `Finset.sum` instead.
- The freshness check. It covers the code the translation is generated from in this crate, but not
  the definition of `FastCryptoError` in fastcrypto, which the theorem doesn't depend on.

Unlike a proof that assumes a 64-bit target, the translation leaves the width of `usize` open
(32 or 64 bits), so the theorem holds on both.

## Checking that the proof is meaningful

A proof can pass because its statement is too weak. As a sanity check, each of these mutations of
the production code makes `lake build` fail once the translation is regenerated:

- comparing the (P) bound against `t'` instead of `t' - 1`, which would accept `w'(S) == t'`;
- computing the (L2) bound with `delta` instead of `f`;
- computing the (L3) bound with `f` instead of `delta`;
- keeping the larger instead of the smaller candidate in `knapsack_min_original`;
- starting entry 0 of the table at 1, which makes the `panic!` in `max_reduced_weight` reachable.

Each one fails at the step of the proof that depends on what was changed. They are chosen to keep
the shape of the generated code, so that they test the proof rather than the proof script.

## Running the proofs

Install Lean with [elan](https://github.com/leanprover/elan). From this directory:

```sh
lake exe cache get   # download the prebuilt Mathlib (once)
lake build
```

`lake-manifest.json` pins Aeneas's Lean library to the commit below, and with it Lean
`v4.36.0-rc2` and Mathlib. With Mathlib cached, the build takes about 50 seconds and should end with
`Build completed successfully`.

## Regenerating the translation

This needs Charon and Aeneas, built from source at these commits:

| Tool | Commit |
|---|---|
| Aeneas | `0d21a9ec7bbbb110110cacc14464a47fd71c8705` |
| Charon | `454586e9b770231e66d2062993e632dfc06463e2` (Aeneas's `charon-pin`) |

Build them by following the
[Aeneas installation instructions](https://github.com/AeneasVerif/aeneas#installation--build),
which need `rustup` and `opam` (OCaml 5.3.0). On macOS, Aeneas's `Makefile` needs GNU make; running
`dune build` in `src` builds the same `aeneas` binary. Then:

```sh
CHARON=/path/to/charon/bin/charon AENEAS=/path/to/aeneas/bin/aeneas ./extract.sh
lake build
```

`extract.sh` takes about a minute, most of it Charon compiling the crate.
