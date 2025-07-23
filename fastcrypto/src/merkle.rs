// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A simple Merkle tree implementation.

extern crate alloc;

use alloc::{format, vec::Vec};
use bcs::to_bytes;
use core::{fmt::Debug, marker::PhantomData};

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::hash::{Blake2b256, Digest, HashFunction};
use serde::{Deserialize, Serialize};

/// The length of the digests used in the merkle tree.
pub const DIGEST_LEN: usize = 32;

pub const LEAF_PREFIX: [u8; 1] = [0];
pub const INNER_PREFIX: [u8; 1] = [1];
pub const EMPTY_NODE: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

/// A node in the Merkle tree.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Node {
    /// A node with an empty subtree.
    Empty,
    /// A node with children, hash value of length 32 bytes.
    Digest([u8; DIGEST_LEN]),
}

impl Node {
    /// Get the byte representation of [`self`].
    pub fn bytes(&self) -> [u8; DIGEST_LEN] {
        match self {
            Node::Empty => EMPTY_NODE,
            Node::Digest(val) => *val,
        }
    }
}

impl From<Digest<DIGEST_LEN>> for Node {
    fn from(value: Digest<DIGEST_LEN>) -> Self {
        Self::Digest(value.digest)
    }
}

impl From<[u8; DIGEST_LEN]> for Node {
    fn from(value: [u8; DIGEST_LEN]) -> Self {
        Self::Digest(value)
    }
}

impl AsRef<[u8]> for Node {
    fn as_ref(&self) -> &[u8] {
        match self {
            Node::Empty => EMPTY_NODE.as_ref(),
            Node::Digest(val) => val.as_ref(),
        }
    }
}

/// A proof that some data is at index `leaf_index` in a [`MerkleTree`].
#[derive(Serialize, Deserialize)]
pub struct MerkleProof<T = Blake2b256> {
    _hash_type: PhantomData<T>,
    /// The sibling hash values on the path from the leaf to the root.
    path: Vec<Node>,
}

// Cannot be derived as many hash functions don't implement `Clone` and the derive is not smart
// enough to see that it is not necessary.
impl<T> Clone for MerkleProof<T> {
    fn clone(&self) -> Self {
        Self {
            _hash_type: PhantomData,
            path: self.path.clone(),
        }
    }
}

// Cannot be derived as many hash functions don't implement `Debug` and the derive is not smart
// enough to see that it is not necessary.
impl<T> core::fmt::Debug for MerkleProof<T> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_struct(&format!("MerkleProof<{}>", core::any::type_name::<T>()))
            .field("path", &self.path)
            .finish()
    }
}

impl<T> PartialEq for MerkleProof<T> {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq(&other.path)
    }
}

impl Eq for MerkleProof {}

impl<T> MerkleProof<T>
where
    T: HashFunction<DIGEST_LEN>,
{
    /// Construct Merkle proof from list of hashes and leaf index.
    pub fn new(path: &[Node]) -> Self {
        Self {
            _hash_type: PhantomData,
            path: path.into(),
        }
    }

    /// Verifies the proof given a Merkle root and the leaf data.
    pub fn verify_proof(
        &self,
        root: &Node,
        leaf: &[u8],
        leaf_index: usize,
    ) -> FastCryptoResult<()> {
        if self.compute_root(leaf, leaf_index).as_ref() != Some(root) {
            return Err(FastCryptoError::InvalidProof);
        }
        Ok(())
    }

    pub fn verify_proof_with_unserialized_leaf<L: Serialize>(
        &self,
        root: &Node,
        leaf: &L,
        leaf_index: usize,
    ) -> FastCryptoResult<()> {
        let bytes = to_bytes(leaf).map_err(|_| FastCryptoError::InvalidInput)?;
        self.verify_proof(root, &bytes, leaf_index)
    }

    /// Recomputes the Merkle root from the proof and the provided leaf data.
    ///
    /// Returns `None` if the provided index is too large.
    pub fn compute_root(&self, leaf: &[u8], leaf_index: usize) -> Option<Node> {
        if leaf_index >> self.path.len() != 0 {
            return None;
        }
        let mut current_hash = leaf_hash::<T>(leaf);
        let mut level_index = leaf_index;
        for sibling in self.path.iter() {
            // The sibling hash of the current node
            if level_index % 2 == 0 {
                // The current node is a left child
                current_hash = inner_hash::<T>(&current_hash, sibling);
            } else {
                // The current node is a right child
                current_hash = inner_hash::<T>(sibling, &current_hash);
            };
            // Update to the level index one level up in the tree
            level_index /= 2;
        }
        Some(current_hash)
    }

    // Check if the proof is for the rightmost leaf in the tree
    pub fn is_right_most(&self, leaf_index: usize) -> bool {
        let mut level_index = leaf_index;
        for sibling in self.path.iter() {
            // The sibling hash of the current node
            if level_index % 2 == 0 {
                // The current node is a left child
                if sibling.as_ref() != EMPTY_NODE.as_ref() {
                    return false;
                }
            }
            // Update to the level index one level up in the tree
            level_index /= 2;
        }
        true
    }
}

/// A proof that some data is not in a Merkle tree.
/// Note that the requirement for `Serialize` trait on leaves can be relaxed later if needed.
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "L: Serialize",
    deserialize = "L: serde::de::DeserializeOwned"
))]
pub struct MerkleNonInclusionProof<L, T = Blake2b256>
where
    L: Ord + Serialize,
{
    _hash_type: PhantomData<T>,
    pub index: usize,
    pub left_leaf: Option<(L, MerkleProof<T>)>,
    pub right_leaf: Option<(L, MerkleProof<T>)>,
}

impl<L, T> MerkleNonInclusionProof<L, T>
where
    T: HashFunction<DIGEST_LEN>,
    L: Ord + Serialize,
{
    pub fn new(
        left_leaf: Option<(L, MerkleProof<T>)>,
        right_leaf: Option<(L, MerkleProof<T>)>,
        index: usize,
    ) -> Self {
        Self {
            _hash_type: PhantomData,
            left_leaf,
            right_leaf,
            index,
        }
    }
}

impl<L, T> core::fmt::Debug for MerkleNonInclusionProof<L, T>
where
    L: Debug + Ord + Serialize,
    T: HashFunction<DIGEST_LEN>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(&format!(
            "MerkleNonInclusionProof<L={}, T={}>",
            std::any::type_name::<L>(),
            std::any::type_name::<T>()
        ))
        .field("left_leaf", &self.left_leaf)
        .field("right_leaf", &self.right_leaf)
        .field("index", &self.index)
        .finish()
    }
}

/// Non inclusion proof verification implemented using the Serialize trait.
impl<L, T> MerkleNonInclusionProof<L, T>
where
    T: HashFunction<DIGEST_LEN>,
    L: Ord + Serialize,
{
    fn is_valid_neighbor(
        &self,
        neighbor: &L,
        proof: &MerkleProof<T>,
        neighbor_index: usize,
        root: &Node,
    ) -> FastCryptoResult<()> {
        proof.verify_proof_with_unserialized_leaf(root, neighbor, neighbor_index)
    }

    // Prove non-inclusion of target_leaf in a Merkle tree assuming that the tree is sorted.
    // Edge case explanations
    // - Empty tree: no leaves, automatically valid
    // - Target leaf smaller than all: no left neighbor, right neighbor must be at position 0
    // - Target leaf larger than all: left neighbor must be rightmost leaf
    pub fn verify_proof(&self, root: &Node, target_leaf: &L) -> FastCryptoResult<()> {
        // Note: For empty trees, we don't need to check anything
        if root.as_ref() == EMPTY_NODE.as_ref() {
            return Ok(());
        }

        let right_leaf_index = self.index;

        if let Some((left_leaf, left_proof)) = &self.left_leaf {
            let left_leaf_index = self.index - 1;
            // Check that the left leaf is a valid neighbor
            self.is_valid_neighbor(left_leaf, left_proof, left_leaf_index, root)?;
            // Check that the left leaf is less than the target leaf
            if left_leaf >= target_leaf {
                return Err(FastCryptoError::InvalidProof);
            }
            // Milestone: If left leaf is present, then left_leaf < target_leaf
        } else if right_leaf_index != 0 || self.right_leaf.is_none() {
            return Err(FastCryptoError::InvalidProof);
            // Milestone: If left leaf is not present, then right leaf must be present with index 0.
        }

        if let Some((right_leaf, right_proof)) = &self.right_leaf {
            // Check that the right leaf is a valid neighbor
            self.is_valid_neighbor(right_leaf, right_proof, right_leaf_index, root)?;
            // Check that the right leaf is greater than the target leaf
            if right_leaf <= target_leaf {
                return Err(FastCryptoError::InvalidProof);
            }

            // Milestone: If right leaf is present, then right_leaf > target_leaf
        } else if let Some((_, left_proof)) = &self.left_leaf {
            let left_leaf_index = self.index - 1;
            if !left_proof.is_right_most(left_leaf_index) {
                return Err(FastCryptoError::InvalidProof);
            }
            // Milestone: If right leaf is not present, then left leaf must be present and be the rightmost leaf
        } else {
            return Err(FastCryptoError::InvalidProof);
        }

        Ok(())
    }
}

/// Merkle tree using a hash function `T` (default: [`Blake2b256`]) from the [`fastcrypto`] crate.
///
/// The data of the leaves is prefixed with `0x00` before hashing and hashes of inner nodes are
/// computed over the concatenation of their children prefixed with `0x01`. Hashes of empty
/// subtrees (i.e. subtrees without data at their leaves) are replaced with all zeros.
#[derive(Serialize, Deserialize)]
pub struct MerkleTree<T = Blake2b256> {
    _hash_type: PhantomData<T>,
    // The nodes of the Merkle tree are stored in a vector level by level starting with
    // the leaf hashes.
    nodes: Vec<Node>,
    n_leaves: usize,
}

impl<T> core::fmt::Debug for MerkleTree<T> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_struct(&format!("MerkleTree<{}>", core::any::type_name::<T>()))
            .field("nodes", &self.nodes)
            .field("n_leaves", &self.n_leaves)
            .finish()
    }
}

impl<T> MerkleTree<T>
where
    T: HashFunction<DIGEST_LEN>,
{
    /// Create the [`MerkleTree`] as a commitment to the provided data.
    pub fn build_from_serialized<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: AsRef<[u8]>,
    {
        Self::build_from_leaf_hashes(iter.into_iter().map(|leaf| leaf_hash::<T>(leaf.as_ref())))
    }

    /// Create the [`MerkleTree`] as a commitment to the provided data.
    /// The data is serialized using BCS and then hashed to produce the leaf hashes.
    /// Note: Sometimes implementing AsRef<[u8]> makes the calling code more complex.
    /// In those cases, prefer this method over build_from_serialized.
    /// On the other hand, we pay the cost of serializing the leaves multiple times.
    pub fn build_from_unserialized<I>(iter: I) -> FastCryptoResult<Self>
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: Serialize,
    {
        let leaf_hashes: FastCryptoResult<Vec<Node>> = iter
            .into_iter()
            .map(|leaf| {
                let bytes = to_bytes(&leaf).map_err(|_| FastCryptoError::InvalidInput)?;
                Ok(leaf_hash::<T>(&bytes))
            })
            .collect();
        Ok(Self::build_from_leaf_hashes(leaf_hashes?))
    }

    /// Create the [`MerkleTree`] as a commitment to the provided data hashes.
    pub fn build_from_leaf_hashes<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator<Item = Node>,
    {
        let iter = iter.into_iter();

        // Create the capacity that we know will be needed, since the vec will be
        // reused by the call to from_leaf_nodes.
        let mut nodes = Vec::with_capacity(n_nodes(iter.len()));
        nodes.extend(iter);

        let n_leaves = nodes.len();
        let mut level_nodes = n_leaves;
        let mut prev_level_index = 0;

        // Fill all other nodes of the Merkle Tree
        while level_nodes > 1 {
            if level_nodes % 2 == 1 {
                // We need an empty sibling for the last node on the previous level
                nodes.push(Node::Empty);
                level_nodes += 1;
            }

            let new_level_index = prev_level_index + level_nodes;

            (prev_level_index..new_level_index)
                .step_by(2)
                .for_each(|index| nodes.push(inner_hash::<T>(&nodes[index], &nodes[index + 1])));

            prev_level_index = new_level_index;
            level_nodes /= 2;
        }

        Self {
            nodes,
            n_leaves,
            _hash_type: PhantomData,
        }
    }

    /// Verify that the root of `self` matches the provided root hash.
    pub fn verify_root(&self, root: &Node) -> bool {
        self.root() == *root
    }

    /// Get a copy of the root hash of `self`.
    pub fn root(&self) -> Node {
        self.nodes.last().map_or(Node::Empty, |val| val.clone())
    }

    /// Get the [`MerkleProof`] for the leaf at `leaf_index` consisting
    /// of all sibling hashes on the path from the leaf to the root.
    pub fn get_proof(&self, leaf_index: usize) -> FastCryptoResult<MerkleProof<T>> {
        if leaf_index >= self.n_leaves {
            return Err(FastCryptoError::GeneralError(format!(
                "Leaf index out of bounds: {}",
                leaf_index
            )));
        }
        let mut path = Vec::with_capacity(
            usize::try_from(self.n_leaves.ilog2()).expect("this is smaller than `n_leaves`") + 1,
        );
        let mut level_index = leaf_index;
        let mut n_level = self.n_leaves;
        let mut level_base_index = 0;
        while n_level > 1 {
            // All levels contain an even number of nodes
            n_level = n_level.next_multiple_of(2);
            let sibling_index = if level_index % 2 == 0 {
                level_base_index + level_index + 1
            } else {
                level_base_index + level_index - 1
            };
            path.push(self.nodes[sibling_index].clone());
            // Index of the parent on the next level
            level_index /= 2;
            level_base_index += n_level;
            n_level /= 2;
        }
        Ok(MerkleProof {
            _hash_type: PhantomData,
            path,
        })
    }

    /// Compute the non-inclusion proof for the target leaf.
    /// Returns an error if the target leaf is already in the tree.
    pub fn compute_non_inclusion_proof<L: Ord + Serialize + Clone>(
        &self,
        leaves: &[L],
        target_leaf: &L,
    ) -> FastCryptoResult<MerkleNonInclusionProof<L, T>> {
        let position = leaves.partition_point(|x| x <= target_leaf);
        if position > 0 && leaves[position - 1] == *target_leaf {
            return Err(FastCryptoError::GeneralError(
                "Target leaf is already in the tree".to_string(),
            ));
        }

        let left_leaf_proof = if position > 0 {
            Some((leaves[position - 1].clone(), self.get_proof(position - 1)?))
        } else {
            None
        };

        let right_leaf_proof = if position < leaves.len() {
            Some((leaves[position].clone(), self.get_proof(position)?))
        } else {
            None
        };

        Ok(MerkleNonInclusionProof::new(
            left_leaf_proof,
            right_leaf_proof,
            position,
        ))
    }
}

/// Computes the hash of the provided input to be used as a leaf hash of a Merkle tree.
pub(crate) fn leaf_hash<T>(input: &[u8]) -> Node
where
    T: HashFunction<DIGEST_LEN>,
{
    let mut hash_fun = T::default();
    hash_fun.update(LEAF_PREFIX);
    hash_fun.update(input);
    hash_fun.finalize().into()
}

fn inner_hash<T>(left: &Node, right: &Node) -> Node
where
    T: HashFunction<DIGEST_LEN>,
{
    let mut hash_fun = T::default();
    hash_fun.update(INNER_PREFIX);
    hash_fun.update(left.bytes());
    hash_fun.update(right.bytes());
    hash_fun.finalize().into()
}

pub(crate) fn n_nodes(n_leaves: usize) -> usize {
    let mut lvl_nodes = n_leaves;
    let mut tot_nodes = 0;
    while lvl_nodes > 1 {
        lvl_nodes += lvl_nodes % 2;
        tot_nodes += lvl_nodes;
        lvl_nodes /= 2;
    }
    tot_nodes + lvl_nodes
}
