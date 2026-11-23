<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::merkle`

Proofs about fastcrypto's Merkle tree (`fastcrypto/src/merkle.rs`), against a Lean translation of
the Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code
carries no annotations. It is written in a style Aeneas can translate: index loops instead of
iterator chains and closures.

The theorems are in `Theorems.lean`. Everything else is a lemma.

## Theorems

`H` is the function the hash computes (see [assumptions](#what-is-assumed)). A *collision* is a
pair of byte strings `x ≠ y` with `H(x) = H(y)`, and a *zero output* is a byte string `x` with
`H(x) = [0; 32]`, the bytes of `Node::Empty`. The theorems about trusted trees have zero outputs
as an extra case because the code treats a node of 32 zero bytes as empty, e.g.
`MerkleNonInclusionProof::verify_for_trusted_tree` accepts any proof against a root of zero
bytes.

### `MerkleProof::verify(root, leaf, i, n)`, for a root that is not trusted

1. **`verify_binding`: the root is a commitment to the leaves.** If `verify` accepts two proofs
   for the same `root`, index `i` and number of leaves `n`, they are for the same leaf, or `H` has
   a collision. This holds for any `root` and any proofs, also ones not made by `MerkleTree`. The
   proof finds the colliding inputs.

2. **`verify_complete`: honest proofs are accepted.** Build a tree from `n` leaf hashes with
   `build_from_leaf_hashes`, where `4n ≤ usize::MAX`. Then building it and taking its `root()` do
   not panic, and for every leaf, `get_proof` returns a proof that `verify` accepts against that
   root.

3. **`verify_no_panic`: `verify` does not panic.** For every proof, root, leaf, index and `n`, it
   returns `Ok(())` or an error.

### `MerkleProof::verify_for_trusted_tree(root, leaf, i)`, which does not check the proof length

4. **`verify_for_trusted_tree_sound`: proofs open only the real leaf of a trusted tree.** Let
   `root` be the root of a tree built with `build_from_leaf_hashes` from leaf hashes `hs`, with
   `4n ≤ usize::MAX`. If `verify_for_trusted_tree` accepts a proof of any length for index `i` and
   `leaf`, then `i < n` and `leaf_hash(leaf) = hs[i]`, or `H` has a collision or a zero output.

   The root must be trusted: against a root that was not built by `MerkleTree`, a proof for index
   `1` of length 1, `[s]`, and one of length 2, `[s', t]`, give the same root for different leaves
   if `s = inner_hash(s', leaf_hash(leaf'))` and `t = leaf_hash(leaf)`. This is why `verify`
   checks the length.

5. **`verify_for_trusted_tree_complete`.** As 2, and the proofs have `⌈log₂ n⌉` siblings.

6. **`verify_for_trusted_tree_no_panic`.** As 3.

### `MerkleNonInclusionProof::verify_for_trusted_tree(root, target)`

7. **`non_inclusion_sound`: a non-inclusion proof shows that the target is not a leaf.** Let `ls`
   be sorted by `L`'s `<=`, and `root` the root of the tree that `build_from_unserialized(ls)`
   builds: `build_from_leaf_hashes` of the leaf hashes of `bcs::to_bytes(ls[j])`, with
   `4n ≤ usize::MAX`. If `verify_for_trusted_tree(root, target)` accepts a non-inclusion proof,
   then `target` is not in `ls`, or `H` has a collision or a zero output. This needs two
   assumptions on `L`, listed [below](#what-is-assumed).

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | The theorems above. |
| `Hash.lean` | `HashModel`, and what `leaf_hash` and `inner_hash` return under it. |
| `Model.lean` | A model of the tree as lists (`levels`, `rootOf`, `pathOf`, `fold`, `depth`): hashing a leaf up its path gives the root (`fold_pathOf`), and paths of the same length from different leaves to the same root give a collision (`fold_binding`). |
| `Opening.lean` | What a path of any length can open to in a tree built by `MerkleTree` (`trusted_opening`), and that the honest path of any leaf but the last has a left child whose sibling is a hash (`right_most`). |
| `Build.lean` | `build_from_leaf_hashes` returns the concatenated `levels` of the leaf hashes, and `root` returns `rootOf` (`build_spec`, `root_spec`). |
| `GetProof.lean` | `get_proof(i)` returns `pathOf(i)` (`get_proof_spec`). |
| `Verify.lean` | What `hash_along_path`, `expected_proof_length`, `compute_root`, `verify` and `verify_for_trusted_tree` return (`verify_spec`, `verify_for_trusted_tree_spec`, `expected_proof_length_spec`, ...). |
| `NonInclusion.lean` | What `is_right_most`, `verify_for_trusted_tree_with_unserialized_leaf` and `MerkleNonInclusionProof::verify_for_trusted_tree` check (`is_right_most_spec`, `ni_accepts`), the assumptions `OrdModel` and `BcsInjective`, and soundness against the model root (`ni_sound`). |
| `Result.lean` | From a Hoare triple about a generated function to what it returns, and the `ok_inv` tactic. |
| `Generated/` | The translation of `merkle.rs`, made by `extract.sh`. The `hash` module is opaque except for `Digest`, and so are `bcs` and serde. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Defines two standard-library functions that Aeneas leaves as axioms, and empties serde's trait structures. Called by `extract.sh`. |

To regenerate `Generated/` after changing `merkle.rs`, get `charon` and `aeneas` from the Aeneas
release named in `extract.sh` and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

* The translation: Charon, Aeneas and `fix_aeneas_output.py`. The script replaces the axioms that
  Aeneas emits for two `AsRef` impls of the standard library with their definitions:
  `<[T] as AsRef<[T]>>::as_ref` returns its argument, and `<&T as AsRef<U>>::as_ref` calls `T`'s
  `as_ref`. It also empties serde's trait structures, which are mutually recursive and which Lean
  rejects. The generated code only passes a `Serialize` impl on to `bcs::to_bytes`.
* `HashModel inst H`, defined in `Hash.lean`, about the `HashFunction` impl, which Lean sees as a
  structure of opaque functions: there is a map `absorbed` from hasher states to byte strings such
  that `T::default()` has absorbed nothing, `update(data)` appends `data.as_ref()`, and
  `finalize()` returns `H` of the bytes absorbed. None of the three panics.
* Nothing else is assumed about `H`. In particular, collision resistance is not assumed: the
  binding and soundness theorems conclude that a collision or a zero output exists.
* For `non_inclusion_sound`, two hypotheses about the leaf type `L`, defined in `NonInclusion.lean`:
  * `OrdModel`: `L`'s `PartialOrd` impl has `a >= b` equal to `b <= a`, and `a <= a`. Rust
    requires both of any `Ord` impl.
  * `BcsInjective`: `bcs::to_bytes` does not serialize two different values to the same bytes.
    `bcs::to_bytes` itself stays an axiom.
* `alloc::fmt::format` and `core::hint::must_use` stay axioms. They are only called in the error
  branch of `get_proof`, and nothing is assumed about them.
* `usize` has 32 or 64 bits, as in Aeneas' library. The theorems hold for both.

## What is not proved

* `build_from_serialized` and `build_from_unserialized` are not translated: Aeneas cannot
  translate their loops over a generic `IntoIterator`. Both push `leaf_hash` of each leaf and call
  `build_from_leaf_hashes`, which is why the completeness theorems are stated for leaves whose
  `leaf_hash` is the `i`th leaf hash.
* Completeness of non-inclusion proofs: that `compute_non_inclusion_proof` returns a proof that
  `verify_for_trusted_tree` accepts. It is not translated: it calls `<[T]>::partition_point`, which
  Aeneas' library does not model.
* That `MerkleNonInclusionProof::verify_for_trusted_tree` does not panic. It calls
  `bcs::to_bytes` and `L`'s `<=` and `>=`, which are opaque.
