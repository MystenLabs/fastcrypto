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
        .proof
        .verify(
            &output.commitment,
            &output.blinding,
            upper_bound,
            TEST_DOMAIN
        )
        .is_ok());
}

#[test]
fn test_handle_verify_invalid_upper_bound() {
    let valid_upper_bound = 64;
    let invalid_upper_bound = 22;
    let output =
        RangeProof::prove(1u64, valid_upper_bound, TEST_DOMAIN, &mut thread_rng()).unwrap();
    assert!(output
        .proof
        .verify(
            &output.commitment,
            &output.blinding,
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
