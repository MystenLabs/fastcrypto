// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use digest::Digest;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use std::fmt::Debug;

/// Random Oracle from SHA3-512.
/// - prefix should be globally unique.
/// - evaluate serializes the given input and outputs SHA3-512(prefix_len as big-endian u32 | prefix | input).
/// - Subprotocols may use a prefix that is extended from the prefix of its parent protocol, by
///   deriving a new instance using extend, which simply concatenates the strings with the separator
///   "-". E.g., RandomOracle::new("abc").extend("def") = RandomOracle::new("abc-def").
///
/// The caller must make sure to:
/// - Choose distinct prefix & extension strings, preferably without "-" in them (asserted in debug
///   mode).
/// - Ensure that the length of prefix & extension is small enough to fit in u32.
///   Violating this constraint will cause a panic.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomOracle {
    prefix: String,
}

impl RandomOracle {
    /// Create a fresh random oracle with a given "session id"/prefix.
    pub fn new(initial_prefix: &str) -> Self {
        debug_assert!(!initial_prefix.contains('-'));
        // Since we shouldn't get such long prefixes, it's safe to assert here.
        assert!(initial_prefix.len() < u32::MAX as usize);
        Self {
            prefix: initial_prefix.into(),
        }
    }

    /// Evaluate the random oracle on a given input.
    pub fn evaluate<T: Serialize>(&self, obj: &T) -> [u8; 64] {
        let mut hasher = Sha3_512::default();
        let len: u32 = self
            .prefix
            .len()
            .try_into()
            .expect("prefix length should be less than u32::MAX, checked when set");
        hasher.update(len.to_be_bytes());
        hasher.update(&self.prefix);
        let serialized = bcs::to_bytes(obj).expect("serialize should never fail");
        hasher.update(&serialized);
        hasher.finalize().into()
    }

    /// Derive a new random oracle from the current one and additional string (can be done multiple times).
    pub fn extend(&self, extension: &str) -> Self {
        debug_assert!(!extension.contains('-'));
        // Since we shouldn't get such long prefixes, it's safe to assert here.
        assert!(self.prefix.len() + extension.len() + 1 < u32::MAX as usize);
        Self {
            prefix: self.prefix.clone() + "-" + extension,
        }
    }
}
