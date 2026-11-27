<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::merkle`

Proofs about fastcrypto's Merkle tree (`fastcrypto/src/merkle.rs`), against a Lean translation of
the Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code
carries no annotations. It is written in a style Aeneas can translate: `for` loops instead of
iterator chains and closures.

A reviewer reads the files at the top of this folder in full: the theorems in `Theorems.lean`, the
assumptions they take and the definitions they are stated with in `Assumptions.lean`, and the two
scripts that make the translation, `extract.sh` and `fix_aeneas_output.py`. The Lean docs there
are the precise statements. The files in `Proofs/` are lemmas, which Lean checks, and
`Generated/` is the translation, which CI checks is up to date.

## Theorems

In `Theorems.lean`. `H` is the hash function, and a *zero output* is an `x` with
`H(x) = [0; 32]`, the bytes of `Node::Empty`.

1. **`get_proof_complete`.** For a tree built from `n` leaf hashes (`4n ≤ usize::MAX`),
   `get_proof` gives every leaf a proof with `⌈log₂ n⌉` siblings that `verify` and
   `verify_for_trusted_tree` accept against `root()`.
2. **`verify_binding`.** `verify` never panics, and two accepted proofs for the same root, index
   and `n` are for the same leaf, or `H` has a collision. Nothing is assumed about the root.
3. **`verify_for_trusted_tree_sound`.** `verify_for_trusted_tree` never panics, and against the
   root of a tree built by `MerkleTree` it accepts a proof of any length for index `i` only for
   the `i`th leaf, or `H` has a collision or a zero output. The root must be trusted, which is why
   `verify` checks the proof length.
4. **`verify_for_trusted_tree_with_unserialized_leaf_sound`.** As 3, for leaves serialized with
   BCS.
5. **`non_inclusion_sound`.** Against the root of a tree over sorted leaves, an accepted
   non-inclusion proof shows that the target is not a leaf, or `H` has a collision or a zero
   output.
6. **`non_inclusion_complete`.** For a target that is not a leaf,
   `compute_non_inclusion_proof` returns a proof that the verifier accepts.
7. **`non_inclusion_no_panic`.** The non-inclusion verifier never panics.

## What is assumed

In `Assumptions.lean`, besides the translation; each theorem takes the ones it needs:

* **Translation.** Charon and Aeneas translate `merkle.rs` faithfully, and the two changes of
  `fix_aeneas_output.py` (two `AsRef` impls defined, serde's traits emptied) are sound.
* **`HashModel`**: `HashFunction` hashes the concatenation of its inputs with some `H`. Collision
  resistance is not assumed: the theorems conclude a collision or a zero output instead.
* **Leaf type**, for non-inclusion: `OrdModel` (`<=` returns, `>=` is its flip), `<=` is a
  partial order, `EqModel`, `CloneIsId`.
* **BCS**: `bcs::to_bytes` returns (`BcsReturns`) and is injective (`BcsInjective`).
* **`PartitionPointSpec`**, for 6: `partition_point` behaves as Rust documents.
* **Caller**: the leaves are sorted, and `hs` are their leaf hashes.
* **`usize`** has 32 or 64 bits. The theorems hold for both.

## What is not proved

* `build_from_serialized` and `build_from_unserialized` are not translated (loops over a generic
  `IntoIterator`), so the theorems are stated for `build_from_leaf_hashes`.

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | The theorems, and their axiom reports. |
| `Assumptions.lean` | The assumptions, and the definitions the theorems are stated with (`ZeroHash`, `IsTreeRoot`, `SerializedLeafHashes`, `LeRel`). |
| `Proofs/` | The lemmas: the hash (`Hash.lean`), a list model of the tree (`Model.lean`), what paths can open to (`Opening.lean`), and what `build_from_leaf_hashes`, `get_proof`, `verify` and the non-inclusion functions return (`Build.lean`, `GetProof.lean`, `Verify.lean`, `NonInclusion.lean`, `NonInclusionComplete.lean`). |
| `Generated/` | The translation of `merkle.rs`. `hash` (except `Digest`), `bcs` and serde are opaque. |
| `extract.sh` | Regenerates `Generated/`: get `charon` and `aeneas` from the Aeneas release it names and run `CHARON=... AENEAS=... ./extract.sh`. |
| `fix_aeneas_output.py` | Patches the Aeneas output. Called by `extract.sh`. |

The workflow `Merkle Lean Proof` (with `lean-proof.yml`) runs `extract.sh`, fails if `Generated/`
is out of date, builds the proofs, and fails if a proof uses `sorry` or an axiom report is absent.
