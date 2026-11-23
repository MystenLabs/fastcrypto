# Style

How the protocol-level files are written. The goal is that a reviewer, human or LLM, can read off
exactly what is assumed and what is proved, without reading proofs.

## Scope

The protocol files assume their lemmas about the code (`Contracts` and the like) and state no proof
of them. Whether the code satisfies them is proved, where it is, by a `Link*.lean` file from the
lemmas about the code in the module's folder, and listed in each folder's `README.md`. Keeping
this out of the black-box files means that a change to the code changes the link, not the
protocol theorems.

## What belongs here

The protocol layer is meant to cover the parts of fastcrypto that need it, so every declaration has to earn its maintenance
cost. Add something only if it gives an assurance that tests and human review cannot give easily:

- **Theorems about all executions or all inputs.** Liveness and agreement of a protocol over every
  order of events and every behaviour of the corrupt parties, or properties of a distribution such
  as Shamir privacy. Tests only see the cases they run.
- **Composition.** Properties that follow from several building blocks together (e.g. DKG from
  AVSS and Shamir), where a reviewer would have to keep many functions and assumptions in mind at
  once.
- **Explicit assumptions.** Writing down exactly what a theorem needs from the code, the caller and
  the network. This is often the main insight: it shows what a caller like Hashi must do.

Leave out what does not add such an assurance:

- Restatements of a single contract, or theorems a reviewer can check at a glance, unless another
  theorem builds on them.
- Anything the link to the code already gives, e.g. example instances showing that the
  assumptions are consistent (the Rust code satisfying its lemmas already shows that).
- Notes on how a lemma is proved for the code or how a caller meets its obligations. They belong
  with the link or the caller and change with the code; here they would go stale.
- Duplicate statements of the same fact. Define it once and refer to it.

## Structure

1. One file per building block, in this order: `Api` (the Rust functions as black boxes),
   `Contracts` (what we expect from them), the execution and caller model, then theorems.
2. Every assumption is a field of a named structure: a contract (`Contracts`, `DkgContracts`), a
   caller obligation or network assumption (`Run`, `Certificate`, ...), or the parameters
   (`Setup.Valid`). A condition used in several theorems gets a named definition
   (e.g. `Setup.Tolerates`).
3. Theorems are proved from their hypotheses only: no `axiom`, `sorry` or assumptions in
   `variable` declarations.

## Naming

4. `Api` fields are the Rust function names in camelCase. Each doc starts with the full Rust path
   of the item it stands for, in backticks, followed by any notes, e.g.
   `` `fastcrypto_threshold::polynomial::Poly::eval`. ``. This lets tools find the code that a contract
   is about.
5. Contract and assumption fields are named after what they state (`recover_sound`,
   `process_invalid_iff`, `gets_message`), not numbered.

## Docs

6. Documentation lives on the Lean declaration it describes, never in a separate file. The
   exception is each folder's `README.md`, which indexes its files, theorems and lemmas with a
   one-line summary each and how each lemma holds for the code; the Lean docs stay authoritative.
7. A contract's doc is its statement as a short formula over the Rust calls, e.g.
   `` `recover_i(m, vs) = Ok(o)` ⇒ `verify_i(m, o.my_shares)` ``. Notation such as `f_i` is defined
   once, in the doc of the enclosing structure.
8. An assumption's doc says what it states and, for non-contracts, whether it is a caller obligation
   or a network assumption. It does not say which theorems use it, why it holds, or how it is
   checked.
9. An idealization (no panics, determinism, shared configuration, abstracted randomness) is stated
   once, on the declaration it applies to (usually `Api`).
10. A theorem's doc states the conclusion in Rust terms. It does not restate hypotheses that are
    named structures or definitions; the reviewer reads those where they are defined. Only
    hypotheses written out in the signature (e.g. "`dealers` is nonempty") are mentioned.

## Contracts

11. Contracts only relate the black-box functions to each other; no algebra. A new concept becomes
    a new black box (as `DkgApi` did), not a Lean definition of its implementation.
12. A contract states no more than the proofs need. Weaker contracts are easier to check and
    survive refactors of the Rust code.

## Proofs

13. Proofs are short and split into lemmas, one per step. Prefer `obtain`, `rw` and `exact` to
    large `simp` calls, so that proofs survive Mathlib upgrades and are easy to repair.
