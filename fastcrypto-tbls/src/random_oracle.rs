// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use digest::Digest;
use serde::Serialize;
use sha3::Sha3_512;

/// Random Oracle from Sha3.
/// - prefix should be globally unique.
/// - evaluate serializes the given input and outputs SHA3-512(prefix_len as u32 | prefix | input).
/// - Subprotocols may use a prefix that is extended from the prefix of its parent protocol, by
///   deriving a new instance using extend, which simply concatenates the strings with the separator
///   "-". The caller must make sure to choose distinct prefix & extension strings.
///     E.g., RandomOracle::new("abc-").extend("def") = RandomOracle::new("abc-def")

#[derive(Clone, PartialEq, Eq)]
pub struct RandomOracle {
    prefix: String,
}

impl RandomOracle {
    pub fn new(initial_prefix: &str) -> Self {
        // Since we shouldn't get such long prefixes, it's safe to assert here.
        assert!(initial_prefix.len() < u32::MAX as usize);
        Self {
            prefix: initial_prefix.into(),
        }
    }

    pub fn evaluate<T: Serialize>(&self, obj: &T) -> [u8; 64] {
        let mut hasher = Sha3_512::default();
        let len: u32 = self
            .prefix
            .len()
            .try_into()
            .expect("prefix length should be less than u32::MAX, tested when set");
        hasher.update(len.to_be_bytes());
        hasher.update(&self.prefix);
        let serialized = bcs::to_bytes(obj).expect("serialize should never fail");
        hasher.update(&serialized);
        hasher.finalize().into()
    }

    pub fn extend(&self, extension: &str) -> Self {
        // Since we shouldn't get such long prefixes, it's safe to assert here.
        assert!(self.prefix.len() + extension.len() + 1 < u32::MAX as usize);
        Self {
            prefix: self.prefix.clone() + "-" + extension,
        }
    }
}
