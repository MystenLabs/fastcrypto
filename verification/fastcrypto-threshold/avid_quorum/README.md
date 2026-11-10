# Formal verification of the AVID quorum check (Creusot)

This crate runs a machine-checked proof, using [Creusot](https://github.com/creusot-rs/creusot),
of `check_quorum` in `fastcrypto-threshold`. `Avid::decode_or_complain` calls it first and returns
its error, and otherwise always returns `Ok`.

## What is proved

For all `senders`, `weights` and `required`, with at most 65,536 parties:

| Property | Statement |
|---|---|
| Soundness | If `check_quorum` returns `Ok`, then `senders` is nonempty, every sender is a party, the senders are distinct, and their total weight is at least `required`. |
| Completeness | If those conditions hold and there are no more senders than parties, `check_quorum` returns `Ok`. |

The proof also shows that `check_quorum` never panics, indexes out of bounds or overflows.

Not proved: that `decode_or_complain` calls `check_quorum` with the weights of its nodes. That link
is the three lines at the top of its body, and is left to review.

## How the proof is tied to the production code

The production code stays plain Rust: `check_quorum` sits between `// BEGIN CREUSOT-VERIFIED` and
`// END CREUSOT-VERIFIED` markers in
[`fastcrypto-threshold/src/threshold_schnorr/avid.rs`](../../../fastcrypto-threshold/src/threshold_schnorr/avid.rs),
with no annotations.

- [`verified_avid_quorum.rs`](verified_avid_quorum.rs) is a copy of that region with the contract
  and loop invariants added, plus the logic definitions they use.
- [`transform_code_test.rs`](transform_code_test.rs) has the test `creusot_copy_matches_production`.
  It removes comments and annotations from the copy and checks that the result is the same code as
  the production region. It is compiled into the fastcrypto-threshold tests, so it runs in normal CI
  without Creusot. `#[trusted]` is rejected.

When you change the production region, make the same change in the copy and run `cargo creusot`
here.

## Trusted base

- Creusot, Why3 and the SMT solvers (Alt-Ergo, Z3, CVC5, CVC4).
- The `creusot-std` specifications of the standard library items used: slice and `Vec` indexing and
  `vec!`, `len` and `is_empty`.
- The definitions of `sender_weight` and `is_quorum` in `verified_avid_quorum.rs`.

## Checking that the proof is meaningful

A proof can pass because its statement is too weak. As a sanity check, each of these mutations of
`check_quorum` in the copy makes the proof fail:

- removing the duplicate check, the party range check, or the empty check;
- removing the weight check, or changing it to `total + 1 < required` or `total <= required`.

## Running the proofs

Install Creusot 0.14.0 by following its
[installation guide](https://guide.creusot.rs/installation.html) (it needs `rustup` and `opam`),
then from this directory:

```sh
cargo creusot
```

This compiles the crate with Creusot's pinned nightly toolchain and runs the provers, and should
end with `Proved (2 files)`. Creusot writes its output and proof caches to `verif/` (gitignored).
