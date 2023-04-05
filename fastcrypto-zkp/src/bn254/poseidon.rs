// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::Fr;
use fastcrypto::hash::Digest;
use light_poseidon::{Poseidon, PoseidonBytesHasher};

/// Wrapper struct for Poseidon hash instance.
pub struct PoseidonWrapper {
    instance: Poseidon<Fr>,
}

impl PoseidonWrapper {
    /// Initialize a Poseidon hash function with the given size.
    pub fn new(size: usize) -> Self {
        Self {
            instance: Poseidon::<Fr>::new_circom(size).unwrap(),
        }
    }

    /// Calculate the hash of the given inputs.
    pub fn hash(&mut self, inputs: &[&[u8]]) -> Digest<32> {
        Digest {
            digest: self.instance.hash_bytes(inputs).unwrap(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::PoseidonWrapper;

    #[test]
    fn poseidon_test() {
        // Test vector from https://docs.rs/light-poseidon/0.0.4/light_poseidon/
        let mut poseidon = PoseidonWrapper::new(2);
        let digest = poseidon.hash(&[&[1u8; 32], &[2u8; 32]]).digest;
        assert_eq!(
            digest,
            [
                13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123,
                132, 254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
            ]
        )
    }
}
