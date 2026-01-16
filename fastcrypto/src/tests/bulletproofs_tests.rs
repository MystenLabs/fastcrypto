// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::bulletproofs::RangeProof;

///
/// Test Range Proofs
///
const TEST_DOMAIN: &[u8; 7] = b"NARWHAL";

#[test]
fn test_range_proof_valid() {
    let upper_bound: usize = 64;
    let blinding = RistrettoScalar::from_byte_array(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ])
    .unwrap();

    let range_proof =
        RangeProof::prove_bit_length(1u64, blinding, upper_bound, TEST_DOMAIN).unwrap();

    assert!(range_proof
        .verify_bit_length(upper_bound, TEST_DOMAIN)
        .is_ok());
}

// #[test]
// fn test_range_proof_invalid() {
//     let upper_bound: usize = 64;
//     let blinding = RistrettoScalar::from_byte_array(&[
//         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
//         0, 1,
//     ]).unwrap();
//
//     let (commitment, range_proof) =
//         RangeProof::prove_bit_length(1u64, blinding, upper_bound, TEST_DOMAIN).unwrap();
//
//     let mut range_proof_bytes = range_proof.as_bytes().to_vec();
//     // Change it a little
//     range_proof_bytes[0] += 1;
//     let invalid_range_proof = RangeProof::from_bytes(&range_proof_bytes[..]).unwrap();
//
//     assert!(invalid_range_proof
//         .verify_bit_length(&commitment, upper_bound, TEST_DOMAIN)
//         .is_err());
// }

#[test]
fn test_handle_prove_invalid_upper_bound() {
    let invalid_upper_bound = 22;
    let blinding = RistrettoScalar::from_byte_array(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ])
    .unwrap();

    assert!(
        RangeProof::prove_bit_length(1u64, blinding, invalid_upper_bound, TEST_DOMAIN).is_err()
    );
}

#[test]
fn test_handle_verify_invalid_upper_bound() {
    let valid_upper_bound = 64;
    let invalid_upper_bound = 22;
    let blinding = RistrettoScalar::from_byte_array(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ])
    .unwrap();

    let range_proof =
        RangeProof::prove_bit_length(1u64, blinding, valid_upper_bound, TEST_DOMAIN).unwrap();

    assert!(range_proof
        .verify_bit_length(invalid_upper_bound, TEST_DOMAIN)
        .is_err());
}

use crate::groups::ristretto255::RistrettoScalar;
use crate::serde_helpers::ToFromByteArray;
use proptest::arbitrary::Arbitrary;

proptest::proptest! {
    #[test]
    fn proptest_0_to_2_pow_64(
        secret in <u64>::arbitrary(),
    ) {
        let upper_bound = 64;
    let blinding = RistrettoScalar::from_byte_array(&[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ]).unwrap();

        let range_proof =
            RangeProof::prove_bit_length(secret, blinding, upper_bound, TEST_DOMAIN).unwrap();

        assert!(range_proof.verify_bit_length(upper_bound, TEST_DOMAIN).is_ok());
    }
}
