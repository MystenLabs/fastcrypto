<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::merkle`

Proofs about fastcrypto's Merkle tree (`fastcrypto/src/merkle.rs`), against a Lean translation of
the Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code
carries no annotations. It is written in a style Aeneas can translate: index loops instead of
iterator chains and closures.

The theorems are in `Theorems.lean`. Everything else is a lemma.

## Theorems

`H` is the function the hash computes (see [assumptions](#what-is-assumed)), and a *collision* is
a pair of byte strings `x ≠ y` with `H(x) = H(y)`.

### `MerkleProof::verify(root, leaf, i, n)`, for a root that is not trusted

1. **`verify_binding`: the root is a commitment to the leaves.** If `verify` accepts two proofs
   for the same `root`, index `i` and number of leaves `n`, they are for the same leaf, or `H` has
   a collision. This holds for any `root` and any proofs, also ones not made by `MerkleTree`. The
   proof finds the colliding inputs.

2. **`verify_complete`: honest proofs are accepted.** Build a tree from `n` leaf hashes with
   `build_from_leaf_hashes`, where `4n ≤ usize::MAX`. Then building it and taking its `root()` do
   not panic, and for every leaf, `get_proof` returns a proof that `verify` accepts against that
   root.

### `MerkleProof::verify_for_trusted_tree(root, leaf, i)`, which does not check the proof length

3. **`verify_for_trusted_tree_binding`.** As 1, but only for two proofs of the same length.
   Without equal lengths it is false: a proof for index `1` of length 1, `[s]`, and one of length
   2, `[s', t]`, give the same root if `s = inner_hash(s', leaf_hash(leaf'))` and
   `t = leaf_hash(leaf)`. This is why `verify` checks the length.

4. **`verify_for_trusted_tree_complete`.** As 2, and the proofs have `⌈log₂ n⌉` siblings.

### Facts the theorems rest on

* `expected_proof_length(n)`, computed with `leading_zeros`, is `⌈log₂ n⌉`: the number of siblings
  `get_proof` returns.
* `verify` accepts exactly when `i < n`, the proof has `⌈log₂ n⌉` siblings (fewer than
  `usize::BITS`), `i < 2^len`, and hashing the leaf up the path gives `root`. So for
  `n > 2^(usize::BITS - 1)` it rejects every proof, which is why completeness needs a bound on
  `n`.

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | The theorems above. |
| `Hash.lean` | `HashModel`, and what `leaf_hash` and `inner_hash` return under it. |
| `Model.lean` | A model of the tree as lists (`levels`, `rootOf`, `pathOf`, `fold`, `depth`): hashing a leaf up its path gives the root (`fold_pathOf`), and paths of the same length from different leaves to the same root give a collision (`fold_binding`). |
| `Build.lean` | `build_from_leaf_hashes` returns the concatenated `levels` of the leaf hashes, and `root` returns `rootOf` (`build_spec`, `root_spec`). |
| `GetProof.lean` | `get_proof(i)` returns `pathOf(i)` (`get_proof_spec`). |
| `Verify.lean` | What `hash_along_path`, `expected_proof_length`, `compute_root`, `verify` and `verify_for_trusted_tree` return (`verify_spec`, `verify_for_trusted_tree_spec`, `expected_proof_length_spec`, ...). |
| `Result.lean` | From a Hoare triple about a generated function to what it returns. |
| `Generated/` | The translation of `merkle.rs`, made by `extract.sh`. The `hash` module is opaque except for `Digest`. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Defines two standard-library functions that Aeneas leaves as axioms. Called by `extract.sh`. |

To regenerate `Generated/` after changing `merkle.rs`, get `charon` and `aeneas` from the Aeneas
release named in `extract.sh` and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

* The translation: Charon, Aeneas and `fix_aeneas_output.py`. The script replaces the axioms that
  Aeneas emits for two `AsRef` impls of the standard library with their definitions:
  `<[T] as AsRef<[T]>>::as_ref` returns its argument, and `<&T as AsRef<U>>::as_ref` calls `T`'s
  `as_ref`.
* `HashModel inst H`, defined in `Hash.lean`, about the `HashFunction` impl, which Lean sees as a
  structure of opaque functions: there is a map `absorbed` from hasher states to byte strings such
  that `T::default()` has absorbed nothing, `update(data)` appends `data.as_ref()`, and
  `finalize()` returns `H` of the bytes absorbed. None of the three panics.
* Nothing else is assumed about `H`. In particular, collision resistance is not assumed: the
  binding theorems conclude that a collision exists.
* `alloc::fmt::format` and `core::hint::must_use` stay axioms. They are only called in the error
  branch of `get_proof`, and nothing is assumed about them.
* `usize` has 32 or 64 bits, as in Aeneas' library. The theorems hold for both.

## What is not proved

* `build_from_serialized` and `build_from_unserialized` are not translated: Aeneas cannot
  translate their loops over a generic `IntoIterator`. Both push `leaf_hash` of each leaf and call
  `build_from_leaf_hashes`, which is why the completeness theorems are stated for leaves whose
  `leaf_hash` is the `i`th leaf hash.
* `is_right_most` is translated but nothing is proved about it, and `MerkleNonInclusionProof` and
  `compute_non_inclusion_proof` are not translated.
