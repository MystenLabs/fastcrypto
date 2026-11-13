# Formal verification of the DKG's `merge` (Verus)

This crate runs a machine-checked proof, using [Verus](https://github.com/verus-lang/verus), about
`Party::merge` in `fastcrypto-threshold/src/dkg_v1.rs`, which is generic over the groups `G` and
`EG`, and the two functions it calls: `UsedProcessedMessages::from` and `Nodes::node_id_to_node`.

## What is proved

Assume every message passed to `merge` has a valid sender, that is, a node id of the party's
`nodes`. This is the assumption in `merge`'s doc comment: the messages come from
`process_message`, whose sanity check rejects invalid senders. Then:

- `merge` never panics: the `.expect("checked in process_message")` can't fire, the `u32` sum of
  weights can't overflow, and no index is out of bounds. Every loop terminates.
- If it returns `Ok((conf, used))`:
  - `used` is `processed_messages` keeping only the first message of each sender, in order
    (`first_by_sender`). Its senders are distinct and are exactly the senders of
    `processed_messages` (`lemma_first_by_sender`);
  - the total weight of the senders of `used` is at least `old_t.unwrap_or(t)`;
  - `conf.sender` is the party's id, and `conf.complaints` are exactly the complaints of the
    messages in `used`, in order;
  - at least one message in `used` has no complaint.

Without the assumption, Verus reports that the `.expect` in `merge` can fail. `ProcessedMessage`
has public fields and derives `Deserialize`, so a caller that passes a message with an invalid
sender, instead of one returned by `process_message`, makes `merge` panic.

Not covered: what the error cases mean beyond not panicking, and the other DKG steps
(`process_message`, `process_confirmations`, `aggregate`), which do cryptography.

## Why the proof uses stand-in types

Verus can't use fastcrypto's `GroupElement` trait. Its associated type `ScalarType: Scalar` and
`Scalar: GroupElement<ScalarType = Self>` refer to each other, and Verus rejects such cycles
between trait declarations ("found a cyclic self-reference in a definition"). This is a soundness
check with no opt-out. Every generic type and function in fastcrypto-threshold is bounded by
`GroupElement`.

The verified functions never use the bound: they only read party ids, weights and complaints. So
the copy in [`verified_dkg_merge.rs`](verified_dkg_merge.rs) defines stand-ins for the DKG types
without the bounds, and the proof holds for every `G` and `EG`, which covers the production code.
The stand-ins keep the fields the verified functions use (`Node::weight`, `Nodes::nodes`,
`Message::sender`, `ProcessedMessage::{message, complaint}`, `Confirmation::{sender, complaints}`,
`UsedProcessedMessages`, `Party::{id, nodes, t, old_t}`) and replace the others with `Opaque`.

Code that does use the group operations, like `aggregate`, can't be verified this way. It would
need the trait hierarchy in fastcrypto to change so that it has no cycle, or a stand-in for the
group itself.

## How the proof is tied to the production code

The production code stays plain Rust. The verified functions sit between
`// BEGIN VERUS-VERIFIED: <name>` and `// END VERUS-VERIFIED: <name>` markers, in
[`dkg_v1.rs`](../../../fastcrypto-threshold/src/dkg_v1.rs) (`used_processed_messages_from`,
`merge`) and [`nodes.rs`](../../../fastcrypto-threshold/src/nodes.rs) (`node_id_to_node`).

Everything for the proof lives in this directory:

- [`verified_dkg_merge.rs`](verified_dkg_merge.rs): the stand-in types, the spec definitions and
  lemmas in a `verus!` block, and a copy of the three regions with `#[verus_spec(...)]` contracts,
  loop invariants and closure specs, and `proof! { ... }` steps.
- [`transform_code_test.rs`](transform_code_test.rs): the test `verus_copy_matches_production`,
  compiled into the fastcrypto-threshold tests, so it runs in normal CI without Verus. For each
  region, it removes comments and annotations from the copy and checks that the result is the same
  code as the production region, ignoring formatting. It also checks that:
  - every function in a region has a `#[verus_spec]` (Verus silently skips one without);
  - `merge`'s only precondition is the documented assumption (`MERGE_REQUIRES` in the test), so it
    can't be widened without changing the test;
  - `external_body` appears only on `Opaque`, `Complaint` and the two `Clone` stand-ins;
  - the copy contains none of `assume(`, `admit(`, `assume_specification`,
    `#[verifier::external]`, `#[verus_verify(external...)]` or `#[verifier::truncate]`.
- `lib.rs`, `Cargo.toml`, `Cargo.lock`: the crate that `cargo verus` builds. It is outside the
  workspace.

When you change a production region:

1. Make the same change in `verified_dkg_merge.rs`; the test fails until you do.
2. Run `cargo verus verify` here and fix the annotations if the proof no longer goes through.

## Code changes in the verified functions

Behavior is the same for every input:

- `UsedProcessedMessages::from` keeps the first message of each sender with a `HashSet` loop
  instead of itertools' `unique_by`, which has no Verus spec.
- `merge` sums the weights in a loop instead of with `.map(..).sum()` (vstd has no spec for
  `sum`), and builds the logged list of parties inside the `debug!` call (vstd has no spec for
  `join`). The list is now only built when debug logging is enabled.

The `for` loop over the messages, the `.all(...)` with its closure, `unwrap_or` and
`node_id_to_node` are unchanged.

## Trusted base

- Verus and the Z3 SMT solver it ships with.
- The `vstd` specifications of the standard library items used: `HashSet::new` and `insert` (with
  the axiom that `u16` keys behave), `Vec` and slice indexing, `get`, `push` and `new`,
  `Option::unwrap_or`, `ok_or` and `is_some`, `Iterator::all` on a slice iterator, `for` loops
  over `&Vec`, and `str::to_string`.
- The stand-in types, which a reviewer should check keep the fields above with the production
  types, and the two `external_body` `Clone`s, which say that the derived `Clone` copies the value.
- The logging macros, which are no-ops in the copy, so their arguments (lengths, ids and the joined
  list of ids) are not verified.
- The spec definitions `first_by_sender`, `weight_of_senders`, `complaints`, `sender_seq` and
  `sender_set` in `verified_dkg_merge.rs`, which a reviewer should check match the intended
  meaning.

## Checking that the proof is meaningful

Each of these mutations of the copy in `verified_dkg_merge.rs` makes the proof fail:

- dropping the total-weight check;
- keeping the last message of a sender instead of the first;
- dropping the complaints from the confirmation;
- dropping the check that some message has no complaint;
- looking up the wrong node in `node_id_to_node`;
- dropping the precondition, which makes Verus report that the `.expect` can fail;
- adding `assert(false)` before `Ok(..)`, which shows the proof context is not contradictory.

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

The first run compiles fastcrypto with Verus's toolchain, which takes about a minute. The proofs
themselves take a few seconds and should end with `verification results:: 12 verified, 0 errors`.
