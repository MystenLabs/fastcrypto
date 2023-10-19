// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::{Bls12_381, Fr};
pub use ark_ff::ToConstraintField;

use ark_crypto_primitives::prf::{PRFGadget, PRF};
use ark_crypto_primitives::{
    prf::blake2s::constraints::Blake2sGadget, prf::blake2s::Blake2s as B2SPRF,
};
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use blake2::{digest::Digest, Blake2s256};

use ark_r1cs_std::prelude::*;
use ark_std::rand::thread_rng;
use fastcrypto_zkp::bls12381::conversions::BlsFr;
use fastcrypto_zkp::bls12381::verifier::PreparedVerifyingKey;
use fastcrypto_zkp::bls12381::{FieldElement, Proof};

#[derive(Clone, Copy, Debug)]
struct Blake2sCircuit {
    input: [u8; 32],
    blake2_seed: [u8; 32],
    pub expected_output: [u8; 32],
}

impl Blake2sCircuit {
    fn new() -> Self {
        // We're going to prove knowledge of the blake2 hash of this secret
        // see https://en.wikipedia.org/wiki/Cluedo
        let statement = b"butler in the yard with a wrench";
        let bytes = statement.to_vec();

        // as a sanity-check, we'll also compute the blake2 hash of the secret
        // with the reference implementation

        // Blake2s takes a seed parameter. We use a default seed.
        let seed: [u8; 32] = [0u8; 32];

        // Compute the hash by traditional means.
        let mut h = Blake2s256::new_with_prefix(seed);
        h.update(&bytes);
        let hash_result = h.finalize();

        // We use the arkworks API for blake2s as well and check it matches
        let input: [u8; 32] = bytes[..].try_into().unwrap();
        let out = B2SPRF::evaluate(&seed, &input).unwrap();

        // the traditional means and the arkworks implementation match
        assert_eq!(hash_result.as_slice(), out.as_slice());

        // at this stage, we can publish the seed and the expected hash output,
        // and we'll prove we know the input
        Self {
            input: statement.to_owned(),
            blake2_seed: seed,
            expected_output: out,
        }
    }
}

impl ConstraintSynthesizer<Fr> for Blake2sCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // initialize the blake2s gadget and allocate the seed
        let seed_var = UInt8::new_input_vec(cs.clone(), &self.blake2_seed).unwrap();

        // declare the witnesses
        let input_var = UInt8::new_witness_vec(cs.clone(), &self.input).unwrap();

        // declare the public intended output
        let desired_out_var = <Blake2sGadget as PRFGadget<_, Fr>>::OutputVar::new_input(cs, || {
            Ok(self.expected_output)
        })
        .unwrap();

        // link the intended output to a blake2s computation on the input, i.e. constrain Blake2s(seed, input) == output
        let output_var = Blake2sGadget::evaluate(&seed_var, &input_var).unwrap();
        output_var.enforce_equal(&desired_out_var).unwrap();

        Ok(())
    }
}

fn main() {
    let mut rng = &mut thread_rng();

    let circuit = Blake2sCircuit::new();
    // Sanity-check
    {
        let cs = ConstraintSystem::<Fr>::new_ref();

        circuit.generate_constraints(cs.clone()).unwrap();
        println!("Num constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }

    let params =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, rng).unwrap();

    // prepare a proof (note: there is nothing trustable about the trivial setup involved here)
    let proof = Proof::from(
        Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &params, &mut rng)
            .unwrap(),
    );

    println!(
        "Generated proof of knowledge of Blake2s preimage of {}",
        hex::encode(circuit.expected_output)
    );

    // prepare the verification key
    let pvk = PreparedVerifyingKey::from(&params.vk.into());

    // provide the public inputs (the hash target) for verification
    let inputs: Vec<FieldElement> = [&circuit.blake2_seed[..], &circuit.expected_output[..]]
        .iter()
        .flat_map::<Vec<BlsFr>, _>(|x| x.to_field_elements().unwrap())
        .map(FieldElement::from)
        .collect();

    // Verify the proof
    assert!(pvk.verify(&inputs, &proof).unwrap());
    println!(
        "Checked proof of knowledge of Blake2s preimage of {}!",
        hex::encode(circuit.expected_output)
    );
}
