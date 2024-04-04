use std::ops::Mul;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof as ArkworksProof};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;

use fastcrypto::groups::bls12381::{G1Element, Scalar, SCALAR_LENGTH};
use fastcrypto::serde_helpers::ToFromByteArray;

use crate::dummy_circuits::DummyCircuit;
use crate::groth16::{Proof, VerifyingKey};

#[test]
fn test_verify_with_processed_vk() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut thread_rng();
    let c = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 65536,
    };

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
    let ark_proof: ArkworksProof<Bls12_381> =
        Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap().into();
    let public_input = c.a.unwrap().mul(c.b.unwrap());

    let mut proof_bytes = Vec::new();
    ark_proof.serialize_compressed(&mut proof_bytes).unwrap();
    let proof: Proof<G1Element> = bcs::from_bytes(&proof_bytes).unwrap();

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    let vk = VerifyingKey::from_arkworks_format(&vk_bytes).unwrap();

    let prepared_vk = crate::groth16::PreparedVerifyingKey::from(&vk);
    let public_inputs = vec![scalar_from_arkworks(&public_input)];
    prepared_vk.verify(&public_inputs, &proof).unwrap()
}

fn scalar_from_arkworks(scalar: &Fr) -> Scalar {
    let mut scalar_bytes = [0u8; SCALAR_LENGTH];
    scalar
        .serialize_compressed(scalar_bytes.as_mut_slice())
        .unwrap();
    scalar_bytes.reverse();
    Scalar::from_byte_array(&scalar_bytes).unwrap()
}
