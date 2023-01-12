// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::vrf::ecvrf::{ECVRFKeyPair, ECVRFProof};
use crate::vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;

#[test]
fn test_proof() {
    let kp = ECVRFKeyPair::generate(&mut thread_rng());
    let input1 = b"Hello, world!";
    let (output1, proof1) = kp.output(input1);

    let input2 = b"Farewell, world!";
    let (output2, proof2) = kp.output(input2);

    assert!(proof1.verify_output(input1, &kp.pk, output1).is_ok());
    assert!(proof1.verify_output(input1, &kp.pk, output2).is_err());

    assert!(proof1.verify(input2, &kp.pk).is_err());
    assert!(proof2.verify_output(input2, &kp.pk, output2).is_ok());

    assert_ne!(output1, output2);
}

#[test]
fn test_serialize_deserialize() {
    let kp = ECVRFKeyPair::generate(&mut thread_rng());

    let kp_serialized = bincode::serialize(&kp).unwrap();
    let kp_reconstructed = bincode::deserialize(&kp_serialized).unwrap();
    assert_eq!(&kp, &kp_reconstructed);

    let pk_serialized = bincode::serialize(&kp.pk).unwrap();
    let pk_reconstructed = bincode::deserialize(&pk_serialized).unwrap();
    assert_eq!(&kp.pk, &pk_reconstructed);

    let sk_serialized = bincode::serialize(&kp.sk).unwrap();
    let sk_reconstructed = bincode::deserialize(&sk_serialized).unwrap();
    assert_eq!(&kp.sk, &sk_reconstructed);

    let input = b"Hello, world!";
    let (output, proof) = kp.output(input);
    let proof_serialized = bincode::serialize(&proof).unwrap();

    // A proof consists of a point, a challenge (half length of field elements) and a field element.
    assert_eq!(32 + 16 + 32, proof_serialized.len());

    let proof_reconstructed: ECVRFProof = bincode::deserialize(&proof_serialized).unwrap();
    assert!(proof_reconstructed
        .verify_output(input, &kp.pk, output)
        .is_ok());
}
