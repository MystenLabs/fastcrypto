// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Encoding, Hex};
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::serde_helpers::ToFromByteArray;
use crate::test_helpers::verify_serialization;
use crate::vrf::ecvrf::{ECVRFKeyPair, ECVRFPrivateKey, ECVRFProof, ECVRFPublicKey};
use crate::vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;

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
fn test_ecvrf_prove() {
    let secret_key_bytes =
        Hex::decode("b057530c45b7b0f4b96f9b21b011072b2a513f45dd9537ad796acf571055550f").unwrap();
    let sk = bcs::from_bytes::<ECVRFPrivateKey>(&secret_key_bytes).unwrap();
    let kp = ECVRFKeyPair::from(sk);

    let input = Hex::decode("01020304").unwrap();
    let (output, proof) = kp.output(&input);

    assert_eq!(
        "2640d12c11a372c726348d60ec74ac80320960ba541fb3e66af0a21590c0a75bf5ccf408d5070c5de77f87c733512f575b4a03511d0031dc2e78ab1582fbbef919b52732c8cb1f44b27ad1d1293dec0f",
        Hex::encode(bcs::to_bytes(&proof).unwrap())
    );
    assert_eq!(
        "84588b918a6c9f5b8b74e56a305bb1c2d44e73f68457e991a1dc8defd51672c36b07a2fa95b9f1e701d0152b35d373ab8c48468f0de4bb5abfe84504319fd00c",
        Hex::encode(output)
    );

    assert!(proof.verify_output(&input, &kp.pk, &output).is_ok());
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

#[test]
fn test_ecvrf_verify() {
    let output: [u8; 64] = Hex::decode("4fad431c7402fa1d4a7652e975aeb9a2b746540eca0b1b1e59c8d19c14a7701918a8249136e355455b8bc73851f7fc62c84f2e39f685b281e681043970026ed8").unwrap().try_into().unwrap();

    let alpha_string = b"Hello, world!";

    let public_key_bytes =
        Hex::decode("1ea6f0f467574295a2cd5d21a3fd3a712ade354d520d3bd0fe6088d7b7c2e00e").unwrap();
    let public_key = bcs::from_bytes::<ECVRFPublicKey>(&public_key_bytes).unwrap();

    let proof_bytes = Hex::decode("d8ad2eafb4f2eaf317447726e541359f26dfce248431fe09984fdc73144abb6ceb006c57a29a742eae5a81dd04239870769e310a81046cbbaff8b0bd27a6d6affee167ebba50549b58ffdf9aa192f506").unwrap();
    let proof = bcs::from_bytes::<ECVRFProof>(&proof_bytes).unwrap();

    assert!(proof
        .verify_output(alpha_string, &public_key, &output)
        .is_ok());
}

#[test]
fn test_ecvrf_invalid() {
    let output = b"invalid hash, invalid hash, invalid hash, invalid hash, invalid ";

    let alpha_string = b"Hello, world!";

    let public_key_bytes =
        Hex::decode("1ea6f0f467574295a2cd5d21a3fd3a712ade354d520d3bd0fe6088d7b7c2e00e").unwrap();
    let public_key = bcs::from_bytes::<ECVRFPublicKey>(&public_key_bytes).unwrap();

    let proof_bytes = Hex::decode("d8ad2eafb4f2eaf317447726e541359f26dfce248431fe09984fdc73144abb6ceb006c57a29a742eae5a81dd04239870769e310a81046cbbaff8b0bd27a6d6affee167ebba50549b58ffdf9aa192f506").unwrap();
    let proof = bcs::from_bytes::<ECVRFProof>(&proof_bytes).unwrap();

    assert!(proof
        .verify_output(alpha_string, &public_key, output)
        .is_err());
}
