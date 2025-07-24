// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;
extern crate rand;

mod merkle_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::merkle::*;
    use once_cell::sync::OnceCell;
    use serde::{Deserialize, Serialize};

    // Mimicking ObjectCheckpointState in Sui
    #[derive(Serialize, Deserialize)]
    struct TestLeaf {
        id: [u8; 32],
        data: Option<[u8; 32]>,
        #[serde(skip)]
        bytes: OnceCell<Vec<u8>>,
    }

    impl TestLeaf {
        fn random() -> Self {
            Self {
                id: rand::random::<[u8; 32]>(),
                data: Some(rand::random::<[u8; 32]>()),
                bytes: OnceCell::new(),
            }
        }
    }

    impl AsRef<[u8]> for TestLeaf {
        fn as_ref(&self) -> &[u8] {
            self.bytes.get_or_init(|| bcs::to_bytes(&self).unwrap())
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
