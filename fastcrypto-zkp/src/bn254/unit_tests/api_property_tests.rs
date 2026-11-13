// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Property tests of the BN254 Groth16 byte API on corrupted inputs. On Sui these bytes come from
//! transactions, so the API must never panic on them, and a corrupted input must never verify
//! unless it still encodes the original statement.

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

use crate::bn254::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use crate::dummy_circuits::Fibonacci;

const NUM_CONSTRAINTS: usize = 8;

struct Fixture {
    vk_bytes: Vec<u8>,
    inputs: Vec<Fr>,
    proof: Proof<Bn254>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let rng = &mut StdRng::seed_from_u64(0);
        let (a, b) = (Fr::rand(rng), Fr::rand(rng));
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            Fibonacci::<Fr>::new(NUM_CONSTRAINTS, a, b),
            rng,
        )
        .unwrap();
        let proof =
            Groth16::<Bn254>::prove(&pk, Fibonacci::new(NUM_CONSTRAINTS, a, b), rng).unwrap();
        Fixture {
            vk_bytes: serialize(&vk),
            inputs: vec![a, b],
            proof,
        }
    })
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

#[derive(Clone, Debug)]
enum ByteMutation {
    Flip(Index, u8),
    Insert(Index, u8),
    Remove(Index),
    Truncate(Index),
}

fn byte_mutation() -> impl Strategy<Value = ByteMutation> {
    prop_oneof![
        6 => (any::<Index>(), 1..=u8::MAX).prop_map(|(i, m)| ByteMutation::Flip(i, m)),
        1 => (any::<Index>(), any::<u8>()).prop_map(|(i, b)| ByteMutation::Insert(i, b)),
        1 => any::<Index>().prop_map(ByteMutation::Remove),
        1 => any::<Index>().prop_map(ByteMutation::Truncate),
    ]
}

fn apply(bytes: &mut Vec<u8>, mutation: &ByteMutation) {
    let len = bytes.len();
    match mutation {
        ByteMutation::Insert(i, b) => bytes.insert(i.index(len + 1), *b),
        _ if len == 0 => {}
        ByteMutation::Flip(i, mask) => bytes[i.index(len)] ^= mask,
        ByteMutation::Remove(i) => {
            bytes.remove(i.index(len));
        }
        ByteMutation::Truncate(i) => bytes.truncate(i.index(len)),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn corrupted_inputs_do_not_verify_unless_they_encode_the_same_statement(
        mutations in vec((0..6usize, byte_mutation()), 1..4),
    ) {
        let fixture = fixture();
        let mut parts = prepare_pvk_bytes(&fixture.vk_bytes).unwrap();
        parts.push(fixture.inputs.iter().flat_map(serialize).collect());
        parts.push(serialize(&fixture.proof));
        let original = parts.clone();
        for (part, mutation) in &mutations {
            apply(&mut parts[*part], mutation);
        }

        let verdict = verify_groth16_in_bytes(
            &parts[0], &parts[1], &parts[2], &parts[3], &parts[4], &parts[5],
        );
        if verdict == Ok(true) {
            // The verifying key parts are only compared as values, since `prepare_pvk_bytes` is
            // the canonical producer of them.
            prop_assert_eq!(
                verify_groth16_in_bytes(
                    &original[0], &original[1], &original[2], &original[3], &parts[4], &parts[5],
                ),
                Ok(true)
            );
            let inputs: Vec<Fr> = parts[4]
                .chunks(32)
                .map(|c| Fr::deserialize_compressed(c).unwrap())
                .collect();
            prop_assert_eq!(&inputs, &fixture.inputs);
            prop_assert_eq!(
                Proof::<Bn254>::deserialize_compressed(parts[5].as_slice()).unwrap(),
                fixture.proof.clone()
            );
        }
    }

    #[test]
    fn prepare_pvk_bytes_handles_corrupted_keys(
        mutations in vec(byte_mutation(), 1..4),
    ) {
        let mut vk_bytes = fixture().vk_bytes.clone();
        for mutation in &mutations {
            apply(&mut vk_bytes, mutation);
        }
        // Must not panic. When it succeeds, the result must have the four parts of a key.
        if let Ok(parts) = prepare_pvk_bytes(&vk_bytes) {
            prop_assert_eq!(parts.len(), 4);
        }
    }
}
