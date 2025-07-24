// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;
extern crate rand;

mod merkle_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::merkle::*;
    use serde::{Deserialize, Serialize};

    // Mimicking ObjectCheckpointState in Sui
    #[derive(Serialize, Deserialize)]
    struct TestLeaf {
        id: [u8; 32],
        data: Option<[u8; 32]>,
        #[serde(skip)]
        bytes: Vec<u8>,
    }

    impl TestLeaf {
        fn new(id: [u8; 32], data: Option<[u8; 32]>) -> Self {
            let serialized = bcs::to_bytes(&(id, data)).unwrap();
            Self {
                id,
                data,
                bytes: serialized,
            }
        }

        fn random() -> Self {
            Self::new(rand::random::<[u8; 32]>(), Some(rand::random::<[u8; 32]>()))
        }
    }

    impl AsRef<[u8]> for TestLeaf {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    fn merkle_tree_build(c: &mut Criterion) {
        static INPUT_SIZES: [usize; 6] = [16, 64, 256, 1024, 4096, 16384];

        let mut group: BenchmarkGroup<_> = c.benchmark_group("MerkleTreeBuild");

        for size in INPUT_SIZES.iter() {
            let input: Vec<TestLeaf> = (0..*size).map(|_| TestLeaf::random()).collect();
            group.bench_function(format!("MerkleTreeBuildAndSerialize-{}", size), |b| {
                b.iter(|| {
                    let mt: MerkleTree = MerkleTree::build_from_unserialized(&input).unwrap();
                    mt.root()
                });
            });
            group.bench_function(format!("MerkleTreeBuild-{}", size), |b| {
                b.iter(|| {
                    let mt: MerkleTree = MerkleTree::build_from_serialized(&input);
                    mt.root()
                });
            });
        }
    }

    criterion_group! {
        name = merkle_benches;
        config = Criterion::default();
        targets = merkle_tree_build,
    }
}

criterion_main!(merkle_benches::merkle_benches,);
