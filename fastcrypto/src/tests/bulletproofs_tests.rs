// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::bulletproofs::{Range, RangeProof};
use crate::groups::ristretto255::RistrettoScalar;
use rand::thread_rng;
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::pedersen::PedersenCommitment;

const TEST_DOMAIN: &[u8; 7] = b"NARWHAL";

#[test]
fn test_range_proof_valid() {
    let range = Range::Bits32;
    let output = RangeProof::prove(1u64, &range, TEST_DOMAIN, &mut thread_rng()).unwrap();
    assert!(output
        .proof
        .verify(&output.commitment, &output.blinding, &range, TEST_DOMAIN)
        .is_ok());
}
