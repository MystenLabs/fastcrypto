// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::serde_helpers::ToFromByteArray;
use crate::test_helpers::verify_serialization;
use crate::vrf::ecvrf::{ECVRFKeyPair, ECVRFProof};
use crate::vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;

// TODO: Add regressions tests.

#[test]
fn test_proof() {
    let kp = ECVRFKeyPair::generate(&mut thread_rng());
    let input1 = b"Hello, world!";
    let (output1, proof1) = kp.output(input1);

    let input2 = b"Farewell, world!";
    let (output2, proof2) = kp.output(input2);

    assert!(proof1.verify_output(input1, &kp.pk, &output1).is_ok());
    assert!(proof1.verify_output(input1, &kp.pk, &output2).is_err());

    assert!(proof1.verify(input2, &kp.pk).is_err());
    assert!(proof2.verify_output(input2, &kp.pk, &output2).is_ok());

    assert_ne!(output1, output2);
}

#[test]
fn test_serialize_deserialize() {
    let kp = ECVRFKeyPair::generate(&mut thread_rng());
    let pk = &kp.pk;
    let sk = &kp.sk;
    let input = b"Hello, world!";
    let (output, proof) = kp.output(input);

    verify_serialization(&kp, None);
    verify_serialization(pk, None);
    verify_serialization(sk, None);
    verify_serialization(&proof, None);

    // A proof consists of a point, a challenge (half length of field elements) and a field element.
    let proof_serialized = bincode::serialize(&proof).unwrap();
    assert_eq!(
        RistrettoPoint::BYTE_LENGTH
            + RistrettoScalar::BYTE_LENGTH / 2
            + RistrettoScalar::BYTE_LENGTH,
        proof_serialized.len()
    );
    let proof_reconstructed: ECVRFProof = bincode::deserialize(&proof_serialized).unwrap();
    assert!(proof_reconstructed
        .verify_output(input, &kp.pk, &output)
        .is_ok());
}
