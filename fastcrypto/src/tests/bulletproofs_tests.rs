// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::bulletproofs::RangeProof;
use crate::groups::ristretto255::RistrettoScalar;
use rand::thread_rng;
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::pedersen::PedersenCommitment;

const TEST_DOMAIN: &[u8; 7] = b"NARWHAL";

#[test]
fn test_range_proof_valid() {
    let upper_bound: usize = 64;
    let output = RangeProof::prove(1u64, upper_bound, TEST_DOMAIN, &mut thread_rng()).unwrap();
    assert!(output
        .range_proof
        .verify(
            &output.commitment,
            &output.blinding_factor,
            upper_bound,
            TEST_DOMAIN
        )
        .is_ok());
}

#[test]
fn test_handle_prove_invalid_upper_bound() {
    let invalid_upper_bound = 22;
    let output =
        RangeProof::prove(1u64, invalid_upper_bound, TEST_DOMAIN, &mut thread_rng()).unwrap();
    assert!(output
        .range_proof
        .verify(
            &output.commitment,
            &output.blinding_factor,
            invalid_upper_bound,
            TEST_DOMAIN
        )
        .is_err());
}

#[test]
fn test_handle_verify_invalid_upper_bound() {
    let valid_upper_bound = 64;
    let invalid_upper_bound = 22;
    let output =
        RangeProof::prove(1u64, valid_upper_bound, TEST_DOMAIN, &mut thread_rng()).unwrap();
    assert!(output
        .range_proof
        .verify(
            &output.commitment,
            &output.blinding_factor,
            invalid_upper_bound,
            TEST_DOMAIN
        )
        .is_err());
}

#[test]
fn test_additive_commitments() {
    let mut rng = thread_rng();

    let value_1 = RistrettoScalar::from(1u64);
    let (commitment_1, bf_1) = PedersenCommitment::commit(&value_1, &mut rng);

    let value_2 = RistrettoScalar::from(2u64);
    let (commitment_2, bf_2) = PedersenCommitment::commit(&value_2, &mut rng);

    let commitment_3 = commitment_1 + commitment_2;
    let bf_3 = bf_1 + bf_2;
    let expected_value = value_1 + value_2;
    commitment_3.verify(&expected_value, &bf_3).unwrap();
}

//
// #[test]
// fn test_aggregated_range_proof() {
//     let upper_bound: usize = 64;
//     let blindings = [
//         RistrettoScalar::from(7),
//         RistrettoScalar::from(11),
//         RistrettoScalar::from(13),
//         RistrettoScalar::from(17),
//     ];
//     let aggregated_range_proof = AggregateRangeProof::prove_bit_length(
//         &[1u64, 2u64, 3u64, 4u64],
//         upper_bound,
//         &blindings,
//         TEST_DOMAIN,
//     )
//     .unwrap();
//     assert!(aggregated_range_proof
//         .verify_bit_length(upper_bound, TEST_DOMAIN)
//         .is_ok());
// }
//
// #[test]
// fn test_aggregated_range_proof_test_upper_bounds() {
//     let upper_bound: usize = 8;
//     let blindings = [
//         RistrettoScalar::from(7),
//         RistrettoScalar::from(11),
//         RistrettoScalar::from(13),
//         RistrettoScalar::from(17),
//     ];
//     assert!(AggregateRangeProof::prove_bit_length(
//         &[1u64, 2u64, 3u64, 256u64],
//         upper_bound,
//         &blindings,
//         TEST_DOMAIN,
//     )
//     .is_err());
//
//     let upper_bound: usize = 16;
//     assert!(AggregateRangeProof::prove_bit_length(
//         &[1u64, 2u64, 3u64, 256u64],
//         upper_bound,
//         &blindings,
//         TEST_DOMAIN,
//     )
//     .is_ok());
// }
//
// use crate::groups::ristretto255::RistrettoScalar;
// use crate::serde_helpers::ToFromByteArray;
// use proptest::arbitrary::Arbitrary;
// use rand::thread_rng;
//
// proptest::proptest! {
//     #[test]
//     fn proptest_0_to_2_pow_64(
//         secret in <u64>::arbitrary(),
//     ) {
//         let upper_bound = 64;
//     let blinding = RistrettoScalar::from_byte_array(&[
//         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
//         0, 1,
//     ]).unwrap();
//
//         let range_proof =
//             RangeProof::prove_bit_length(secret, blinding, upper_bound, TEST_DOMAIN).unwrap();
//
//         assert!(range_proof.verify_bit_length(upper_bound, TEST_DOMAIN).is_ok());
//     }
// }
