# Formal verification of the DKG's `merge` (Aeneas and Lean)

This directory holds a machine-checked proof, using [Aeneas](https://github.com/AeneasVerif/aeneas)
and [Lean](https://lean-lang.org), about `Party::merge` in
`fastcrypto-threshold/src/dkg_v1.rs`, which is generic over the groups `G` and `EG`, and the two
functions it calls: `UsedProcessedMessages::from` and `Nodes::node_id_to_node`.

## What is proved

Assume every message passed to `merge` has a valid sender, that is, a node id of the party's
`nodes`. This is the assumption in `merge`'s doc comment: the messages come from
`process_message`, whose sanity check rejects invalid senders. Let `used` be the input keeping
only the first message of each sender, in order, `w` the total weight of the senders of `used`,
and `t' = old_t.unwrap_or(t)`. Then `merge` doesn't panic, and:

- if `w < t'`, it returns `Err(NotEnoughInputs)`;
- otherwise, if every message in `used` has a complaint, it returns `Err(GeneralError(_))`;
- otherwise, it returns `Ok((conf, used))`, where `conf.sender` is the party's id and
  `conf.complaints` are the complaints of the messages in `used`, in order.

So the theorem says exactly what `merge` returns for every input that satisfies the assumption,
apart from the text of the `GeneralError`. "Doesn't panic" covers the
`.expect("checked in process_message")`, the `u32` sum of the weights, and every index; every loop
terminates.

The theorem is `merge_spec` in [`DkgMerge/Proofs.lean`](DkgMerge/Proofs.lean). `used` is
`firstBySender` in [`DkgMerge/Spec.lean`](DkgMerge/Spec.lean), which also proves that its senders
are distinct (`firstBySender_nodup`), that they are the senders of the input
(`mem_senders_firstBySender`), and that it is a sublist of the input (`firstBySender_sublist`).

The theorem depends only on Lean's standard axioms (`propext`, `Classical.choice`, `Quot.sound`):
there is no `sorry` and no added axiom. [`DkgMerge.lean`](DkgMerge.lean) checks this with
`#print axioms`, so `lake build` fails if that changes.

Without the assumption, `merge` can panic: `ProcessedMessage` has public fields and derives
`Deserialize`, so a caller that passes a message with an invalid sender, instead of one returned by
`process_message`, makes the `.expect` fail.

Not covered: the other DKG steps (`process_message`, `process_confirmations`, `aggregate`), which do
cryptography.

## Why the proof uses stand-in types

Aeneas can't translate fastcrypto's `GroupElement` trait. Its associated type `ScalarType: Scalar`
and `Scalar: GroupElement<ScalarType = Self>` refer to each other. Charon can't turn the associated
type into a type parameter because of that cycle, so it leaves the constraint
`ScalarType = Self` on `Scalar`, and Aeneas doesn't support such constraints (it stops with an
internal error). Verus rejects the same cycle. Every generic type and function in
fastcrypto-threshold is bounded by `GroupElement`.

The verified functions never use the bound: they only read party ids, weights and complaints. So
[`standins/`](standins) is a small crate with stand-ins for the DKG types without the bounds, and
the proof holds for every `G` and `EG`, which covers the production code. The stand-ins in
[`standins/src/lib.rs`](standins/src/lib.rs) keep the fields the verified functions use
(`Node::weight`, `Nodes::nodes`, `Message::sender`, `ProcessedMessage::{message, complaint}`,
`Confirmation::{sender, complaints}`, `UsedProcessedMessages`, `Party::{id, nodes, t, old_t}`), and
replace the others with fields of type `G` or `EG`.

Aeneas also can't translate what the `tracing` macros expand to (static callsites, closures and
`dyn` traits), so the stand-in crate defines `debug!`, `info!` and `error!` as no-ops.

Code that does use the group operations, like `aggregate`, can't be verified this way. It would
need the trait hierarchy in fastcrypto to change so that it has no cycle, or Aeneas to support
the constraint.

## How the proof is tied to the production code

There is no annotated copy. The verified functions sit between
`// BEGIN AENEAS-VERIFIED: <name>` and `// END AENEAS-VERIFIED: <name>` markers in
[`dkg_v1.rs`](../../../fastcrypto-threshold/src/dkg_v1.rs) (`used_processed_messages_from`,
`merge`) and [`nodes.rs`](../../../fastcrypto-threshold/src/nodes.rs) (`node_id_to_node`), and
[`standins/build.rs`](standins/build.rs) copies these regions into the stand-in crate at build
time, inside impl blocks for the stand-in types. So the code Charon translates is the production
code, as text.

- [Charon](https://github.com/AeneasVerif/charon) compiles the stand-in crate and extracts `merge`
  and everything it calls, after borrow checking, and Aeneas translates that to pure Lean:
  [`DkgMerge/Types.lean`](DkgMerge/Types.lean) and [`DkgMerge/Funs.lean`](DkgMerge/Funs.lean).
  These two files are generated: don't edit them. Arithmetic overflow, out-of-bounds indexing and
  failed `expect`s become failures in Lean, so a proof that a function returns `ok` shows that it
  can't panic.
- [`DkgMerge/FunsExternal.lean`](DkgMerge/FunsExternal.lean) is written by hand. It models the four
  standard library functions the translation calls but the Aeneas library doesn't cover:
  `Option::clone`, as the standard library defines it, and `to_string`, `Display for str` and
  `Debug for FastCryptoError`, which only build error messages.
- [`DkgMerge/Spec.lean`](DkgMerge/Spec.lean) defines `firstBySender`, `weightOf` and `complaints`,
  and proves the lemmas that don't involve the code.
- [`DkgMerge/Proofs.lean`](DkgMerge/Proofs.lean) proves a specification for each function and loop
  in `Funs.lean`, and the main theorem.
- [`translation_freshness_test.rs`](translation_freshness_test.rs): the test
  `dkg_merge_lean_translation_is_fresh`. It hashes the code the translation was generated from (the
  three regions and the stand-in crate, ignoring comments and whitespace) and compares it with
  [`translated_code.sha256`](translated_code.sha256). It is compiled into the fastcrypto-threshold
  tests, so it runs in normal CI without Charon, Aeneas or Lean.
- [`extract.sh`](extract.sh) regenerates the translation and records the new hash.

When you change a production region or the stand-ins:

1. Run `extract.sh` (see below); the test fails until you do.
2. Run `lake build` here and fix the proofs if they no longer go through.

## Code changes in the verified functions

Behavior is the same for every input:

- `UsedProcessedMessages::from` keeps the first message of each sender with a loop that records the
  senders seen so far in a `Vec`, instead of itertools' `unique_by`, which Aeneas doesn't model.
  This takes time proportional to the number of messages times the number of distinct senders,
  which is at most the number of nodes.
- `merge` sums the weights in a loop instead of with `.map(..).sum()`, and checks whether every
  message has a complaint in the loop that collects the complaints, instead of with `.all(..)`.
- `merge` builds the logged list of parties inside the `debug!` call, so the list is now only built
  when debug logging is enabled.
- The loops iterate over `&filtered_messages.0[..]`, a slice, because the Aeneas library models
  iterating over a slice but not over a `&Vec`.

`node_id_to_node` is unchanged.

## Trusted base

- Lean's kernel, which checks every proof step.
- Charon and Aeneas. Their translation of the Rust code to Lean is not itself verified, so a bug in
  it could make the Lean code differ from what `rustc` compiles. This is the main trusted component.
- The Aeneas library's Lean models of the standard library items the code uses: slice iterators,
  `<[T]>::contains`, `<[T]>::get`, `Vec::push`, `Vec::clone`, indexing with `..`,
  `Option::unwrap_or` and `ok_or`, `Result::expect`, and integer arithmetic and casts.
- The models in `FunsExternal.lean`. The string contents aren't modelled, and nothing depends on
  them.
- The stand-in types, which a reviewer should check keep the fields above with the production
  types. The theorem's hypotheses `hG` and `hEG` say that cloning a value of type `G` or `EG`
  returns the same value. They stand for the derived `Clone`s of the production fields that the
  stand-ins replace (`PublicPoly`, `RecoveryPackage` and so on), which copy their value.
- The no-op logging. The arguments of the logging calls (lengths, ids and the joined list of ids)
  are not verified.
- The definitions in `Spec.lean` (`firstBySender`, `weightOf`, `complaints`), which a reviewer
  should check match the intended meaning. The lemmas about `firstBySender` help with that.
- The freshness check. It covers the regions and the stand-in crate, but not the definition of
  `FastCryptoError` in fastcrypto, which the theorem only uses for its variant names.

## Checking that the proof is meaningful

A proof can pass because its statement is too weak. As a sanity check, each of these mutations
makes `lake build` fail once the translation is regenerated:

- dropping the weight check (comparing against `required_t / 2`);
- recording the wrong sender as seen in `UsedProcessedMessages::from`, which keeps duplicates;
- including each complaint twice;
- dropping the check that some message has no complaint;
- looking up the wrong node in `node_id_to_node`;
- changing the theorem to claim that the threshold is `t` instead of `old_t.unwrap_or(t)`.

Each one fails at the step of the proof that depends on what was changed. They are chosen to keep
the shape of the generated code, so that they test the proof rather than the proof script.

## Running the proofs

Install Lean with [elan](https://github.com/leanprover/elan). From this directory:

```sh
lake exe cache get   # download the prebuilt Mathlib (once)
lake build
```

`lake-manifest.json` pins Aeneas's Lean library to the commit below, and with it Lean
`v4.36.0-rc2` and Mathlib. With Mathlib cached, the build takes under a minute and should end
with `Build completed successfully`.

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

`extract.sh` compiles the stand-in crate, which depends on fastcrypto, so the first run takes a few
minutes; later runs take about a minute.
