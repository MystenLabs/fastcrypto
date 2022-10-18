// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use mysten_util_mem::{malloc_size_of_is_0, MallocSizeOf, MallocSizeOfOps};

// Implement MallocSizeOf for various fastcrypto structs. This is needed in Sui.
malloc_size_of_is_0!(crate::bls12381::BLS12381PublicKey);
malloc_size_of_is_0!(crate::bls12381::BLS12381Signature);
malloc_size_of_is_0!(crate::bls12381::BLS12381AggregateSignature);
malloc_size_of_is_0!(crate::ed25519::Ed25519PublicKey);
malloc_size_of_is_0!(crate::ed25519::Ed25519Signature);
impl MallocSizeOf for crate::ed25519::Ed25519AggregateSignature {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops)
    }
}
