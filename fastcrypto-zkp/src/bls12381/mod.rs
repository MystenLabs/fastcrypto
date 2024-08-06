// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]

//! Groth16 verifier over the BLS12-381 elliptic curve construction.

use fastcrypto::groups::bls12381::G1Element;

use crate::groth16;

/// API that takes in serialized inputs
pub mod api;

#[cfg(test)]
mod test_helpers;

/// A prepared Groth16 verifying key in the BLS12-381 construction.
pub type PreparedVerifyingKey = groth16::PreparedVerifyingKey<G1Element>;

/// A Groth16 verifying key in the BLS12-381 construction.
pub type VerifyingKey = groth16::VerifyingKey<G1Element>;

/// A Groth16 proof in the BLS12-381 construction.
pub type Proof = groth16::Proof<G1Element>;

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use crate::bls12381::PreparedVerifyingKey;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;

    use crate::bls12381::test_helpers::{
        from_arkworks_proof, from_arkworks_scalar, from_arkworks_vk,
    };
    use crate::dummy_circuits::DummyCircuit;

    #[test]
    fn test_verify_with_processed_vk() {
        const PUBLIC_SIZE: usize = 128;
        let rng = &mut thread_rng();
        let c = DummyCircuit::<Fr> {
            a: Some(<Fr>::rand(rng)),
            b: Some(<Fr>::rand(rng)),
            num_variables: PUBLIC_SIZE,
            num_constraints: 256,
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
        let ark_proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
        let public_input = c.a.unwrap().mul(c.b.unwrap());

        let proof = from_arkworks_proof(&ark_proof);
        let vk = from_arkworks_vk(&vk);
        let prepared_vk = PreparedVerifyingKey::from(&vk);
        let public_inputs = vec![from_arkworks_scalar(&public_input)];

        assert!(prepared_vk.verify(&public_inputs, &proof).is_ok());
    }
}
