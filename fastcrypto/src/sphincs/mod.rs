// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod hash;
pub mod winternitz_ots;

/// FIPS 205 Section 4.2 — ADRS (Address)
///
/// 32-byte structure, 8 big-endian words:
///   Word 0      : layer address
///   Words 1-3   : tree address  (12 bytes; upper 4 zero, lower 8 = u64)
///   Word 4      : type
///   Words 5-7   : type-dependent (zeroed whenever type is changed)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Adrs([u8; 32]);

impl Adrs {
    pub fn new() -> Self {
        Self([0u8; 32])
    }

    // --- word read/write helpers (big-endian) ---

    fn get_word(&self, word: usize) -> u32 {
        let off = word * 4;
        u32::from_be_bytes(self.0[off..off + 4].try_into().unwrap())
    }

    fn set_word(&mut self, word: usize, val: u32) {
        let off = word * 4;
        self.0[off..off + 4].copy_from_slice(&val.to_be_bytes());
    }

    // --- layer (word 0) ---

    pub fn with_layer_address(mut self, layer: impl Into<u32>) -> Self {
        self.set_word(0, layer.into());
        self
    }

    pub fn get_layer_address(&self) -> u32 {
        self.get_word(0)
    }

    // --- tree address (words 1-3, 12 bytes) ---

    pub fn with_tree_address(mut self, tree: [u8; 12]) -> Self {
        self.0[4..16].copy_from_slice(&tree);
        self
    }

    pub fn get_tree_address(&self) -> [u8; 12] {
        self.0[4..16].try_into().unwrap()
    }

    // --- type (word 4) — zeroes words 5-7 on change ---

    pub fn with_type(mut self, adrs_type: AdrsType) -> Self {
        self.set_word(4, adrs_type as u32);
        self.0[20..32].fill(0);
        self
    }

    pub fn get_type(&self) -> AdrsType {
        let x = self.get_word(4);
        match x {
            0 => AdrsType::WotsHash,
            1 => AdrsType::WotsPk,
            2 => AdrsType::Tree,
            3 => AdrsType::ForsTree,
            4 => AdrsType::ForsRoots,
            5 => AdrsType::WotsPrf,
            6 => AdrsType::ForsPrf,
            _ => unreachable!("Invalid AdrsType"),
        }
    }

    // --- type-dependent fields (words 5-7) ---

    // Word 5: key pair address (WOTS_HASH, WOTS_PK, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF)
    pub fn with_key_pair_address(mut self, kp: impl Into<u32>) -> Self {
        self.set_word(5, kp.into());
        self
    }

    pub fn get_key_pair_address(&self) -> u32 {
        self.get_word(5)
    }

    // Word 6: chain address (WOTS_HASH, WOTS_PRF)
    pub fn with_chain_address(mut self, chain: impl Into<u32>) -> Self {
        self.set_word(6, chain.into());
        self
    }

    pub fn get_chain_address(&self) -> u32 {
        self.get_word(6)
    }

    // Word 7: hash address (WOTS_HASH)
    pub fn with_hash_address(mut self, hash: impl Into<u32>) -> Self {
        self.set_word(7, hash.into());
        self
    }

    pub fn get_hash_address(&self) -> u32 {
        self.get_word(7)
    }

    // Word 6: tree height (TREE, FORS_TREE)
    pub fn with_tree_height(mut self, height: impl Into<u32>) -> Self {
        self.set_word(6, height.into());
        self
    }

    pub fn get_tree_height(&self) -> u32 {
        self.get_word(6)
    }

    // Word 7: tree index (TREE, FORS_TREE)
    pub fn with_tree_index(mut self, index: impl Into<u32>) -> Self {
        self.set_word(7, index.into());
        self
    }

    pub fn get_tree_index(&self) -> u32 {
        self.get_word(7)
    }

    /// Compressed address (ADRSc) for SHA2-based parameter sets.
    /// Strips zero-padding to produce 22 bytes. FIPS 205 Section 11.1.
    ///
    ///  Byte 0:        layer (truncated to u8)
    ///  Bytes 1-8:     tree address (lower 8 of the 12-byte field)
    ///  Byte 9:        type (truncated to u8)
    ///  Bytes 10-13:   key pair / padding (word 5)
    ///  Bytes 14-17:   chain / tree height / padding (word 6)
    ///  Bytes 18-21:   hash / tree index / padding (word 7)
    pub fn compress(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.0[3]; // layer: low byte of word 0
        out[1..9].copy_from_slice(&self.0[8..16]); // tree: lower 8 bytes
        out[9] = self.0[19]; // type: low byte of word 4
        out[10..22].copy_from_slice(&self.0[20..32]); // words 5-7
        out
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
