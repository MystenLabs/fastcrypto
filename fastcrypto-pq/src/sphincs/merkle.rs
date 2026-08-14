// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared Merkle-tree helpers used by both XMSS (Tree ADRS) and FORS (FORS_TREE ADRS).
//!
//! Three operations show up identically in both constructions:
//!   - Compute a node at `(height z, index i)` by recursing to leaves.
//!   - Build the authentication path from a leaf up to the root.
//!   - Fold a leaf up to a root along an authentication path.
//!
//! Each caller supplies the leaf producer and an ADRS builder for interior nodes;
//! everything else — parity-based sibling order, index shifting, hashing — is shared.

use crate::sphincs::hash::tweakable_hash;
use crate::sphincs::Adrs;

/// Recursively compute the node at height `z`, index `i`.
///   - `leaf(i)` produces the leaf value at global index `i` (called only at `z == 0`).
///   - `mk_interior_adrs(height, index)` builds the ADRS used to hash an interior
///     node at the given (parent) height and index.
pub fn merkle_node(
    leaf: &impl Fn(u32) -> Vec<u8>,
    mk_interior_adrs: &impl Fn(u16, u32) -> Adrs,
    i: u32,
    z: u16,
    pk_seed: &[u8],
) -> Vec<u8> {
    if z == 0 {
        leaf(i)
    } else {
        let lnode = merkle_node(leaf, mk_interior_adrs, 2 * i, z - 1, pk_seed);
        let rnode = merkle_node(leaf, mk_interior_adrs, 2 * i + 1, z - 1, pk_seed);
        tweakable_hash(pk_seed, mk_interior_adrs(z, i), &[lnode, rnode].concat())
    }
}

/// Build a length-`h` authentication path for leaf `leaf_idx` in a Merkle tree.
/// `node_at(height, local_sibling_idx)` supplies the sibling node at each step.
pub fn build_auth_path<F>(h: u16, leaf_idx: u32, node_at: F) -> Vec<Vec<u8>>
where
    F: Fn(u16, u32) -> Vec<u8>,
{
    let mut auth = Vec::with_capacity(h as usize);
    let mut idx = leaf_idx;
    for height in 0..h {
        let sibling = idx ^ 1;
        auth.push(node_at(height, sibling));
        idx /= 2;
    }
    auth
}

/// Fold `leaf` up to the root by consuming each sibling in `auth`. At each step,
/// the parity of `idx` decides sibling order; `mk_interior_adrs` builds the ADRS
/// for the parent node at the new height/index.
pub fn compute_root_from_path(
    leaf: Vec<u8>,
    mut idx: u32,
    auth: &[Vec<u8>],
    pk_seed: &[u8],
    mk_interior_adrs: impl Fn(u16, u32) -> Adrs,
) -> Vec<u8> {
    let mut cur = leaf;
    for (h, sibling) in auth.iter().enumerate() {
        let combined = if idx.is_multiple_of(2) {
            [cur.as_slice(), sibling.as_slice()].concat()
        } else {
            [sibling.as_slice(), cur.as_slice()].concat()
        };
        idx /= 2;
        cur = tweakable_hash(pk_seed, mk_interior_adrs((h + 1) as u16, idx), &combined);
    }
    cur
}
