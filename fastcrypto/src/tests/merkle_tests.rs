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
    let mt: MerkleTree = MerkleTree::build::<[&[u8]; 0]>([]);
    assert_eq!(mt.root().bytes(), EMPTY_NODE);
}

#[test]
fn test_merkle_tree_single_element() {
    let test_inp = "Test";
    let mt: MerkleTree = MerkleTree::build(&[test_inp.as_bytes()]);
    let mut hash_fun = Blake2b256::default();
    hash_fun.update(LEAF_PREFIX);
    hash_fun.update(test_inp.as_bytes());
    assert_eq!(mt.root().bytes(), hash_fun.finalize().digest);
}

#[test]
fn test_merkle_tree_empty_element() {
    let mt: MerkleTree = MerkleTree::build(&[&[]]);
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
        let mt: MerkleTree = MerkleTree::build(&test_inp[..i]);
        match mt.get_proof(i.next_power_of_two()) {
            Err(_) => {}
            Ok(_) => panic!("Expected an error"),
        }
    }
}

#[test]
fn test_merkle_path_verify() {
    for i in 0..TEST_INPUT.len() {
        let mt: MerkleTree = MerkleTree::build(&TEST_INPUT[..i]);
        for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
            let proof = mt.get_proof(index).unwrap();
            assert!(proof.verify_proof(&mt.root(), leaf_data, index).is_ok());
        }
    }
}

#[test]
fn test_merkle_path_verify_fails_for_wrong_index() {
    for i in 0..TEST_INPUT.len() {
        let mt: MerkleTree = MerkleTree::build(&TEST_INPUT[..i]);
        for (index, leaf_data) in TEST_INPUT[..i].iter().enumerate() {
            let proof = mt.get_proof(index).unwrap();
            assert!(proof.verify_proof(&mt.root(), leaf_data, index + 1).is_err());
        }
    }
}
