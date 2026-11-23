<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::merkle`

Proofs about fastcrypto's Merkle tree (`fastcrypto/src/merkle.rs`), against a Lean translation of
the Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code
carries no annotations. It is written in a style Aeneas can translate: index loops instead of
iterator chains and closures.

The theorems are in `Theorems.lean`. Everything else is a lemma.

## Theorems

They hold for every hash function `T: HashFunction<32>` whose impl satisfies `HashModel inst H`
for some function `H` from byte strings to 32-byte arrays (see [assumptions](#what-is-assumed)).
A collision of `H` is a pair of byte strings `x ≠ y` with `H(x) = H(y)`.

| Theorem | Statement |
|---|---|
| `verify_binding` | For any `n`, any `root` and any index `i`: if `p.verify(&root, leaf, i, n)` and `p'.verify(&root, leaf', i, n)` both return `Ok(())`, then `leaf = leaf'` or `H` has a collision. |
| `verify_complete` | For leaf hashes `hs` with `4 · hs.len() ≤ usize::MAX`, `MerkleTree::build_from_leaf_hashes(hs)` returns a tree `t` and `t.root()` returns a node `root`, both without panicking. For every `i < hs.len()` and every `leaf` with `leaf_hash(leaf) = hs[i]`, `t.get_proof(i)` returns `Ok(p)` and `p.verify(&root, leaf, i, hs.len())` returns `Ok(())`. |
| `verify_for_trusted_tree_binding` | If `p.verify_for_trusted_tree(&root, leaf, i)` and `p'.verify_for_trusted_tree(&root, leaf', i)` both return `Ok(())` and `p.len() = p'.len()`, then `leaf = leaf'` or `H` has a collision. |
| `verify_for_trusted_tree_complete` | As `verify_complete`, with `verify_for_trusted_tree`, and `p.len() = depth(hs.len())`. |

`verify_binding` says the root is a commitment to the leaves: it assumes nothing about where
`root`, `p` and `p'` come from, so it holds against a prover that never runs `MerkleTree`. Its
proof is a reduction: it finds the colliding inputs.

`verify_for_trusted_tree_binding` needs the equal lengths. Without them it is false: a proof for
index `1` of length 1, `[s]`, and one of length 2, `[s', t]`, give the same root if
`s = inner_hash(s', leaf_hash(leaf'))` and `t = leaf_hash(leaf)`. This is why `verify` checks the
length.

`depth(n)` is `0` for `n ≤ 1`, and `depth(⌈n/2⌉) + 1` otherwise, which is `⌈log₂ n⌉`. The lemma
`verify_spec` shows that `verify` accepts exactly when `i < n`, `p.len() = depth(n)`,
`p.len() < usize::BITS`, `i < 2^p.len()`, and the leaf hashed up the path is `root`. So for
`n > 2^(usize::BITS - 1)`, where `depth(n) = usize::BITS`, `verify` rejects every proof.
`verify_complete` needs `4n ≤ usize::MAX` for this reason, and for the tree's nodes to fit in a
`Vec`.

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
