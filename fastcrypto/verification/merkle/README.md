<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto::merkle`

Proofs about fastcrypto's Merkle tree (`fastcrypto/src/merkle.rs`), against a Lean translation of
the Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code
carries no annotations. It is written in a style Aeneas can translate: index loops instead of
iterator chains and closures.

The theorems are in `Theorems.lean`. Everything else is a lemma.

## Theorems

`H` is the hash function. A *zero output* is an input `x` with `H(x) = [0; 32]`, which the code
treats as `Node::Empty`.

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

7. **`verify_for_trusted_tree_with_unserialized_leaf_sound`.** As 4, for leaves serialized with
   BCS: if `root` is the root of the tree that `build_from_unserialized(ls)` builds and
   `verify_for_trusted_tree_with_unserialized_leaf` accepts a proof for index `i` and `l`, then
   `i < n` and `l = ls[i]`, or `H` has a collision or a zero output. This needs `BcsInjective`,
   listed [below](#what-is-assumed).

### `MerkleNonInclusionProof::verify_for_trusted_tree(root, target)`

8. **`non_inclusion_sound`: a non-inclusion proof shows that the target is not a leaf.** Let `ls`
   be sorted by `L`'s `<=`, and `root` the root of the tree that `build_from_unserialized(ls)`
   builds: `build_from_leaf_hashes` of the leaf hashes of `bcs::to_bytes(ls[j])`, with
   `4n ≤ usize::MAX`. If `verify_for_trusted_tree(root, target)` accepts a non-inclusion proof,
   then `target` is not in `ls`, or `H` has a collision or a zero output. This needs
   `OrdModel` and `BcsInjective`, listed [below](#what-is-assumed).

9. **`non_inclusion_complete`: honest non-inclusion proofs are accepted.** For `ls`, the tree and
   `4n ≤ usize::MAX` as in 8, and a `target` that is not in `ls`: building the tree and taking its
   `root()` do not panic, and `compute_non_inclusion_proof(ls, target)` returns a proof that
   `verify_for_trusted_tree(root, target)` accepts. This needs `OrdModel`, `LinearOrd`, `EqModel`,
   `CloneIsId` and `PartitionPointSpec`, listed [below](#what-is-assumed).

10. **`non_inclusion_no_panic`: the verifier does not panic.** For every proof, root and target,
   `verify_for_trusted_tree` returns `Ok(())` or an error. This needs `BcsReturns`, `OrdModel` and
   `LinearOrd`, listed [below](#what-is-assumed).

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
| `NonInclusion.lean` | What `is_right_most`, `verify_for_trusted_tree_with_unserialized_leaf` and `MerkleNonInclusionProof::verify_for_trusted_tree` check (`is_right_most_spec`, `ni_accepts`), the assumptions `OrdModel`, `BcsInjective` and `BcsReturns`, soundness against the model root (`ni_sound`), and that the verifier returns (`ni_returns`). |
| `NonInclusionComplete.lean` | What `compute_non_inclusion_proof` returns (`compute_spec`), that `verify_for_trusted_tree` accepts it (`ni_complete`), and the assumptions `PartitionPointSpec`, `LinearOrd`, `EqModel` and `CloneIsId`. |
| `Result.lean` | From a Hoare triple about a generated function to what it returns, and the `ok_inv` tactic. |
| `Generated/` | The translation of `merkle.rs`, made by `extract.sh`. The `hash` module is opaque except for `Digest`, and so are `bcs` and serde. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Defines two standard-library functions that Aeneas leaves as axioms, and empties serde's trait structures. Called by `extract.sh`. |

To regenerate `Generated/` after changing `merkle.rs`, get `charon` and `aeneas` from the Aeneas
release named in `extract.sh` and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

Each named assumption is a `def` or `structure` in the Lean files, and each theorem takes the ones
it needs as hypotheses.

* **Translation.** The proofs are about the Lean code in `Generated/`, so they trust that Charon
  and Aeneas translate `merkle.rs` faithfully. They also trust the two changes
  `fix_aeneas_output.py` makes to that code:
  * Aeneas emits an axiom, a function with no body, for standard-library functions its Lean
    library does not model. The script gives two of them their obvious bodies:
    `<[T] as AsRef<[T]>>::as_ref` returns its argument, and `<&T as AsRef<U>>::as_ref` calls `T`'s
    `as_ref`.
  * serde's traits refer to each other, which Lean does not accept for structures. The script
    replaces them with empty structures. This loses nothing: the generated code never calls a serde
    method, it only passes a `Serialize` impl on to `bcs::to_bytes`, which is opaque.
* **Hash function** (`HashModel`). `HashFunction` hashes the concatenation of its `update` inputs
  with some function `H`, and does not panic. Nothing else, in particular not collision resistance:
  the theorems conclude that `H` has a collision or a zero output.
* **Leaf type `L`**, for non-inclusion. `>=` is the flipped `<=`, and `<=` returns and is
  reflexive, transitive and antisymmetric (`OrdModel`, `LinearOrd`). Rust requires all of these of
  an `Ord` impl. `==` is false for different values (`EqModel`), and `clone` returns its argument
  (`CloneIsId`).
* **BCS**, for leaves serialized with BCS. `bcs::to_bytes` returns on every value (`BcsReturns`) and is
  injective (`BcsInjective`).
* **`partition_point`**, for `non_inclusion_complete`. It returns the partition index of a
  partitioned slice, as Rust documents (`PartitionPointSpec`).
* **Caller.** The leaves are sorted by `<=` (`SortedLe`), and `hs` are their leaf hashes.
* **Error branches.** `format`, `must_use`, `<str as Display>::fmt` and `to_string` stay axioms,
  with nothing assumed. They are only called when `get_proof` or `compute_non_inclusion_proof`
  returns an error.
* **`usize`** has 32 or 64 bits. The theorems hold for both.

## What is not proved

* `build_from_serialized` and `build_from_unserialized` are not translated: Aeneas cannot
  translate their loops over a generic `IntoIterator`. Both push `leaf_hash` of each leaf and call
  `build_from_leaf_hashes`, which is why the completeness theorems are stated for leaves whose
  `leaf_hash` is the `i`th leaf hash.
