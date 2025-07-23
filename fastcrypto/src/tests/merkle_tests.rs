// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::*;
use crate::merkle::*;

const TEST_INPUT: [&[u8]; 9] = [
    b"foo", b"bar", b"fizz", b"baz", b"buzz", b"fizz", b"foobar", b"walrus", b"fizz",
];

#[test]
fn test_n_nodes() {
    assert!(n_nodes(0) == 0);
    assert!(n_nodes(1) == 1);
    assert!(n_nodes(2) == 3);
    assert!(n_nodes(3) == 7);
    assert!(n_nodes(4) == 7);
    assert!(n_nodes(5) == 13);
    assert!(n_nodes(6) == 13);
    assert!(n_nodes(7) == 15);
    assert!(n_nodes(8) == 15);
    assert!(n_nodes(9) == 23);
}

#[test]
fn test_merkle_tree_empty() {
    let mt: MerkleTree = MerkleTree::build_from_serialized::<[&[u8]; 0]>([]);
    assert_eq!(mt.root().bytes(), EMPTY_NODE);
}

#[test]
fn test_merkle_tree_single_element() {
    let test_inp = "Test";
    let mt: MerkleTree = MerkleTree::build_from_serialized(&[test_inp.as_bytes()]);
    let mut hash_fun = Blake2b256::default();
    hash_fun.update(LEAF_PREFIX);
    hash_fun.update(test_inp.as_bytes());
    assert_eq!(mt.root().bytes(), hash_fun.finalize().digest);
}

#[test]
fn test_merkle_tree_empty_element() {
    let mt: MerkleTree = MerkleTree::build_from_serialized(&[&[]]);
    let mut hash_fun = Blake2b256::default();
    hash_fun.update(LEAF_PREFIX);
    hash_fun.update([]);
    assert_eq!(mt.root().bytes(), hash_fun.finalize().digest);
}

#[test]
fn test_get_path_out_of_bounds() {
    let test_inp: Vec<_> = [
        "foo", "bar", "fizz", "baz", "buzz", "fizz", "foobar", "walrus", "fizz",
    ]
    .iter()
    .map(|x| x.as_bytes())
    .collect();
    for i in 0..test_inp.len() {
        let mt: MerkleTree = MerkleTree::build_from_serialized(&test_inp[..i]);
        match mt.get_proof(i.next_power_of_two()) {
            Err(_) => {}
            Ok(_) => panic!("Expected an error"),
        }
    }
}

#[test]
fn test_merkle_path_verify() {
    for i in 0..TEST_INPUT.len() {
        let mt: MerkleTree = MerkleTree::build_from_serialized(&TEST_INPUT[..i]);
        for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
            let proof = mt.get_proof(index).unwrap();
            assert!(proof.verify_proof(&mt.root(), leaf_data, index).is_ok());
        }
    }
}

#[test]
fn test_merkle_path_verify_fails_for_wrong_index() {
    for i in 0..TEST_INPUT.len() {
        let mt: MerkleTree = MerkleTree::build_from_serialized(&TEST_INPUT[..i]);
        for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
            let proof = mt.get_proof(index).unwrap();
            assert!(proof
                .verify_proof(&mt.root(), leaf_data, index + 1)
                .is_err());
        }
    }
}

#[test]
fn test_merkle_proof_is_right_most() {
    for i in 0..TEST_INPUT.len() {
        let mt: MerkleTree = MerkleTree::build_from_serialized(&TEST_INPUT[..i]);
        for j in 0..i {
            let proof = mt.get_proof(j).unwrap();
            println!("proof: {:?}", proof);
            if j == i - 1 {
                assert!(proof.is_right_most(j));
            } else {
                assert!(!proof.is_right_most(j));
            }
        }
    }
}

mod non_inclusion_proof {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let mt: MerkleTree = MerkleTree::build_from_unserialized::<[&[u8]; 0]>([]).unwrap();
        let non_inclusion_proof = mt
            .compute_non_inclusion_proof(&[], &"foo".as_bytes())
            .unwrap();
        assert!(non_inclusion_proof.left_leaf.is_none());
        assert!(non_inclusion_proof.right_leaf.is_none());
        assert_eq!(non_inclusion_proof.index, 0);
        assert!(non_inclusion_proof
            .verify_proof(&mt.root(), &"foo".as_bytes())
            .is_ok());
        assert!(non_inclusion_proof
            .verify_proof(&mt.root(), &"bar".as_bytes())
            .is_ok());
    }

    #[test]
    fn test_single_leaf() {
        let mt: MerkleTree = MerkleTree::build_from_unserialized(&["foo".as_bytes()]).unwrap();

        let non_inclusion_proof = mt
            .compute_non_inclusion_proof(&["foo".as_bytes()], &"bar".as_bytes())
            .unwrap();
        println!("non_inclusion_proof: {:?}", non_inclusion_proof);
        assert!(non_inclusion_proof
            .verify_proof(&mt.root(), &"bar".as_bytes())
            .is_ok());
        assert!(non_inclusion_proof
            .verify_proof(&mt.root(), &"foo".as_bytes())
            .is_err());

        let non_inclusion_proof =
            mt.compute_non_inclusion_proof(&["foo".as_bytes()], &"foo".as_bytes());
        assert!(non_inclusion_proof.is_err());
    }

    #[test]
    fn test_multiple_leaves() {
        const TEST_INPUT: [&str; 9] = [
            "foo", "bar", "fizz", "baz", "buzz", "fizz", "foobar", "walrus", "fizz",
        ];
        let mut sorted_test_input = TEST_INPUT.to_vec();
        sorted_test_input.sort();
        println!("sorted_test_input: {:?}", sorted_test_input);
        let mt: MerkleTree = MerkleTree::build_from_unserialized(&sorted_test_input).unwrap();

        let test_cases = [["fuzz", "yankee", "aloha"].to_vec(), TEST_INPUT.to_vec()].concat();
        println!("test_cases: {:?}", test_cases);
        for item in test_cases {
            println!("item: {:?}", item);
            let non_inclusion_proof = mt.compute_non_inclusion_proof(&sorted_test_input, &item);
            if TEST_INPUT.contains(&item) {
                assert!(non_inclusion_proof.is_err());
            } else {
                assert!(non_inclusion_proof.is_ok());
                let non_inclusion_proof = non_inclusion_proof.unwrap();
                assert!(non_inclusion_proof.verify_proof(&mt.root(), &item).is_ok());
            }
        }
    }
}
