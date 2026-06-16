// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A [NestedMerkleTree] commits to a sequence of rows of leaves. Each row is committed by its own
//! Merkle tree (its `row_root`). A top tree then commits to those row roots. A
//! [NestedMerkleProof] for a leaf carries both an inclusion proof against its row root and an
//! inclusion proof binding that row root to the top root.

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidMessage, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::Blake2b256;
use fastcrypto::merkle::{MerkleProof, MerkleTree, Node};
use serde::{Deserialize, Serialize};

/// A two-level Merkle commitment to a sequence of rows of leaves.
pub struct NestedMerkleTree {
    row_trees: Vec<MerkleTree<Blake2b256>>,
    top_tree: MerkleTree<Blake2b256>,
}

/// Inclusion proof for a leaf in a [NestedMerkleTree]: row proof up to the (implied) row root,
/// then top proof binding that row root to the dispersal's top root. The intermediate row root
/// is derived from `row_proof` + leaf during verification — not stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NestedMerkleProof {
    pub row_proof: MerkleProof,
    pub top_proof: MerkleProof,
}

#[allow(dead_code)]
impl NestedMerkleTree {
    /// Build a tree committing to `rows`. `rows[i][j]` is the `j`-th leaf in row `i`.
    pub fn new<S: Serialize>(rows: impl IntoIterator<Item = Vec<S>>) -> FastCryptoResult<Self> {
        let row_trees: Vec<MerkleTree<Blake2b256>> = rows
            .into_iter()
            .map(|row| MerkleTree::<Blake2b256>::build_from_unserialized(row.iter()))
            .collect::<FastCryptoResult<_>>()?;
        let row_roots: Vec<Node> = row_trees.iter().map(|t| t.root()).collect();
        let top_tree = MerkleTree::<Blake2b256>::build_from_unserialized(row_roots.iter())?;
        Ok(Self {
            row_trees,
            top_tree,
        })
    }

    /// The top tree's root — the overall commitment.
    pub fn top_root(&self) -> Node {
        self.top_tree.root()
    }

    /// Root of the row tree for row `row_idx`, or `None` if out of bounds.
    pub fn row_root(&self, row_idx: usize) -> Option<Node> {
        self.row_trees.get(row_idx).map(|t| t.root())
    }

    /// Inclusion proof for the leaf at position `leaf_idx` in row `row_idx`.
    pub fn get_proof(
        &self,
        row_idx: usize,
        leaf_idx: usize,
    ) -> FastCryptoResult<NestedMerkleProof> {
        let row_tree = self.row_trees.get(row_idx).ok_or(InvalidInput)?;
        Ok(NestedMerkleProof {
            row_proof: row_tree.get_proof(leaf_idx)?,
            top_proof: self.top_tree.get_proof(row_idx)?,
        })
    }

    /// Compute the root of a row's Merkle subtree, byte-identical to what [Self::new] would build
    /// for the same row.
    pub fn compute_row_root<S: Serialize>(row: &[S]) -> FastCryptoResult<Node> {
        Ok(MerkleTree::<Blake2b256>::build_from_unserialized(row.iter())?.root())
    }
}

impl NestedMerkleProof {
    /// Verify this proof against `top_root` for `leaf` at position (`row_idx`, `leaf_idx`).
    pub fn verify<S: Serialize>(
        &self,
        top_root: &Node,
        leaf: &S,
        row_idx: usize,
        leaf_idx: usize,
    ) -> FastCryptoResult<()> {
        (self.derive_top_root(leaf, row_idx, leaf_idx)? == *top_root)
            .then_some(())
            .ok_or(InvalidProof)
    }

    /// Derive the implied row root from this proof's row portion and `leaf` at `leaf_idx`.
    /// Returns [InvalidMessage] if the path is malformed.
    pub fn derive_row_root<S: Serialize>(
        &self,
        leaf: &S,
        leaf_idx: usize,
    ) -> FastCryptoResult<Node> {
        self.row_proof
            .compute_root(&bcs::to_bytes(leaf).map_err(|_| InvalidInput)?, leaf_idx)
            .ok_or(InvalidMessage)
    }

    /// Derive the implied top root from this proof and `leaf` at (`row_idx`, `leaf_idx`): walk
    /// the row proof from the leaf to an implied row root, then walk the top proof from that row
    /// root to an implied top root. Returns [InvalidMessage] if either path is malformed.
    pub fn derive_top_root<S: Serialize>(
        &self,
        leaf: &S,
        row_idx: usize,
        leaf_idx: usize,
    ) -> FastCryptoResult<Node> {
        let row_root = self.derive_row_root(leaf, leaf_idx)?;
        self.top_proof
            .compute_root(
                &bcs::to_bytes(&row_root).map_err(|_| InvalidInput)?,
                row_idx,
            )
            .ok_or(InvalidMessage)
    }
}
