// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Differential property tests of the BLS12-381 Groth16 verifier against arkworks.
//!
//! The verifier in [crate::groth16] is our own implementation on top of blst. These tests check
//! that it agrees with `ark-groth16` on two levels, for inputs derived from valid proofs:
//! * which serialized verifying keys, public inputs and proofs parse, and
//! * which of them verify.
//!
//! A disagreement on the first is a malleability or canonicity bug. A disagreement on the second
//! means one of the two verifiers is unsound or incomplete.

use std::sync::OnceLock;

use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

use crate::bls12381::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use crate::dummy_circuits::Fibonacci;

const G1_SIZE: usize = 48;
const SCALAR_SIZE: usize = 32;
const NUM_CONSTRAINTS: usize = 8;

/// One circuit with two valid statements (public inputs and proof) for it.
struct Fixture {
    vk: VerifyingKey<Bls12_381>,
    vk_bytes: Vec<u8>,
    statements: Vec<(Vec<Fr>, Proof<Bls12_381>)>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let rng = &mut StdRng::seed_from_u64(0);
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            Fibonacci::<Fr>::new(NUM_CONSTRAINTS, Fr::from(1u64), Fr::from(1u64)),
            rng,
        )
        .unwrap();
        let statements = (0..2)
            .map(|_| {
                let (a, b) = (Fr::rand(rng), Fr::rand(rng));
                let proof =
                    Groth16::<Bls12_381>::prove(&pk, Fibonacci::new(NUM_CONSTRAINTS, a, b), rng)
                        .unwrap();
                (vec![a, b], proof)
            })
            .collect();
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        Fixture {
            vk,
            vk_bytes,
            statements,
        }
    })
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

/// The six byte strings taken by [verify_groth16_in_bytes].
#[derive(Clone, Debug)]
struct VerifierInput {
    vk_gamma_abc: Vec<u8>,
    alpha_beta: Vec<u8>,
    gamma_neg: Vec<u8>,
    delta_neg: Vec<u8>,
    public_inputs: Vec<u8>,
    proof: Vec<u8>,
}

impl VerifierInput {
    fn new(inputs: &[Fr], proof: &Proof<Bls12_381>) -> Self {
        let pvk = prepare_pvk_bytes(&fixture().vk_bytes).unwrap();
        Self {
            vk_gamma_abc: pvk[0].clone(),
            alpha_beta: pvk[1].clone(),
            gamma_neg: pvk[2].clone(),
            delta_neg: pvk[3].clone(),
            public_inputs: inputs.iter().flat_map(serialize).collect(),
            proof: serialize(proof),
        }
    }

    fn parts_mut(&mut self) -> [&mut Vec<u8>; 6] {
        [
            &mut self.vk_gamma_abc,
            &mut self.alpha_beta,
            &mut self.gamma_neg,
            &mut self.delta_neg,
            &mut self.public_inputs,
            &mut self.proof,
        ]
    }

    /// The verdict of our verifier: `None` if the input does not parse, otherwise whether the
    /// proof verifies.
    fn fastcrypto_verdict(&self) -> Option<bool> {
        verify_groth16_in_bytes(
            &self.vk_gamma_abc,
            &self.alpha_beta,
            &self.gamma_neg,
            &self.delta_neg,
            &self.public_inputs,
            &self.proof,
        )
        .ok()
    }

    /// The verdict of arkworks on the same bytes, using arkworks' compressed, validated encoding
    /// for every element.
    fn arkworks_verdict(&self) -> Option<bool> {
        let vk_gamma_abc = parse_concatenated::<G1Affine>(&self.vk_gamma_abc, G1_SIZE)?;
        let alpha_beta = parse_exact::<PairingOutput<Bls12_381>>(&self.alpha_beta)?;
        let gamma_neg = parse_exact::<G2Affine>(&self.gamma_neg)?;
        let delta_neg = parse_exact::<G2Affine>(&self.delta_neg)?;
        let public_inputs = parse_concatenated::<Fr>(&self.public_inputs, SCALAR_SIZE)?;
        let proof = parse_exact::<Proof<Bls12_381>>(&self.proof)?;

        let pvk = PreparedVerifyingKey {
            vk: VerifyingKey {
                gamma_abc_g1: vk_gamma_abc,
                ..fixture().vk.clone()
            },
            alpha_g1_beta_g2: alpha_beta.0,
            gamma_g2_neg_pc: gamma_neg.into(),
            delta_g2_neg_pc: delta_neg.into(),
        };
        Some(
            Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
                .unwrap_or(false),
        )
    }
}

/// Deserialize a `T` that must use all of `bytes` and be its canonical encoding.
///
/// Arkworks alone is not strict enough as a reference: with the infinity flag set it ignores the
/// remaining bytes of a point, so it accepts many encodings of the identity. Requiring that the
/// value re-serializes to `bytes` removes those.
fn parse_exact<T: CanonicalDeserialize + CanonicalSerialize>(bytes: &[u8]) -> Option<T> {
    let mut reader = bytes;
    let value = T::deserialize_compressed(&mut reader).ok()?;
    (reader.is_empty() && serialize(&value) == bytes).then_some(value)
}

/// Deserialize `bytes` as a concatenation of `T`s of `size` bytes each, without a length prefix.
fn parse_concatenated<T: CanonicalDeserialize + CanonicalSerialize>(
    bytes: &[u8],
    size: usize,
) -> Option<Vec<T>> {
    if !bytes.len().is_multiple_of(size) {
        return None;
    }
    bytes.chunks(size).map(parse_exact).collect()
}

/// A byte-level change to one of the serialized inputs.
#[derive(Clone, Debug)]
enum ByteMutation {
    Flip(Index, u8),
    /// Set the top three bits, which hold the compression, infinity and sign flags of the
    /// zcash-style point encodings.
    SetFlags(Index, u8),
    Insert(Index, u8),
    Remove(Index),
    Truncate(Index),
    Clear,
}

fn byte_mutation() -> impl Strategy<Value = ByteMutation> {
    prop_oneof![
        8 => (any::<Index>(), 1..=u8::MAX).prop_map(|(i, m)| ByteMutation::Flip(i, m)),
        3 => (any::<Index>(), 0..8u8).prop_map(|(i, f)| ByteMutation::SetFlags(i, f << 5)),
        1 => (any::<Index>(), any::<u8>()).prop_map(|(i, b)| ByteMutation::Insert(i, b)),
        1 => any::<Index>().prop_map(ByteMutation::Remove),
        1 => any::<Index>().prop_map(ByteMutation::Truncate),
        1 => Just(ByteMutation::Clear),
    ]
}

fn apply(bytes: &mut Vec<u8>, mutation: &ByteMutation) {
    let len = bytes.len();
    match mutation {
        ByteMutation::Insert(i, b) => bytes.insert(i.index(len + 1), *b),
        _ if len == 0 => {}
        ByteMutation::Flip(i, mask) => bytes[i.index(len)] ^= mask,
        ByteMutation::SetFlags(i, flags) => {
            // Point encodings start every 48 bytes, so aim at those first bytes.
            let start = i.index(len.div_ceil(G1_SIZE)) * G1_SIZE;
            bytes[start] = (bytes[start] & 0x1f) | flags;
        }
        ByteMutation::Remove(i) => {
            bytes.remove(i.index(len));
        }
        ByteMutation::Truncate(i) => bytes.truncate(i.index(len)),
        ByteMutation::Clear => bytes.clear(),
    }
}

/// How to build the proof in a semantic test case from the fixture's valid proofs.
#[derive(Clone, Debug)]
enum ProofChoice {
    Valid(Index),
    /// `(r·A, r⁻¹·B, C)` for a valid proof `(A, B, C)`, which is again a valid proof.
    Rerandomized(Index, u64),
    /// `(A, B, C)` taken from possibly different valid proofs.
    Mixed(Index, Index, Index),
    /// A valid proof with some of its points replaced by the identity.
    WithIdentity(Index, bool, bool, bool),
    /// A valid proof with some of its points negated.
    Negated(Index, bool, bool, bool),
}

fn proof_choice() -> impl Strategy<Value = ProofChoice> {
    prop_oneof![
        any::<Index>().prop_map(ProofChoice::Valid),
        (any::<Index>(), any::<u64>()).prop_map(|(i, r)| ProofChoice::Rerandomized(i, r)),
        any::<(Index, Index, Index)>().prop_map(|(a, b, c)| ProofChoice::Mixed(a, b, c)),
        any::<(Index, bool, bool, bool)>()
            .prop_map(|(i, a, b, c)| ProofChoice::WithIdentity(i, a, b, c)),
        any::<(Index, bool, bool, bool)>()
            .prop_map(|(i, a, b, c)| ProofChoice::Negated(i, a, b, c)),
    ]
}

/// Which public inputs to use in a semantic test case.
#[derive(Clone, Debug)]
enum InputsChoice {
    Valid(Index),
    Random(u64, usize),
    /// Valid inputs with `p` added to one of them, which only differs as an integer.
    PlusModulus(Index, Index),
}

fn inputs_choice() -> impl Strategy<Value = InputsChoice> {
    prop_oneof![
        3 => any::<Index>().prop_map(InputsChoice::Valid),
        1 => (any::<u64>(), 0usize..4).prop_map(|(seed, n)| InputsChoice::Random(seed, n)),
        1 => any::<(Index, Index)>().prop_map(|(s, i)| InputsChoice::PlusModulus(s, i)),
    ]
}

fn statement(i: &Index) -> &'static (Vec<Fr>, Proof<Bls12_381>) {
    let statements = &fixture().statements;
    &statements[i.index(statements.len())]
}

fn build_proof(choice: &ProofChoice) -> Proof<Bls12_381> {
    match choice {
        ProofChoice::Valid(i) => statement(i).1.clone(),
        ProofChoice::Rerandomized(i, seed) => {
            let proof = &statement(i).1;
            let r = Fr::rand(&mut StdRng::seed_from_u64(*seed));
            let r = if r.is_zero() { Fr::from(1u64) } else { r };
            Proof {
                a: (proof.a * r).into_affine(),
                b: (proof.b * r.inverse().unwrap()).into_affine(),
                c: proof.c,
            }
        }
        ProofChoice::Mixed(a, b, c) => Proof {
            a: statement(a).1.a,
            b: statement(b).1.b,
            c: statement(c).1.c,
        },
        ProofChoice::WithIdentity(i, a, b, c) => {
            let proof = &statement(i).1;
            Proof {
                a: if *a { G1Affine::zero() } else { proof.a },
                b: if *b { G2Affine::zero() } else { proof.b },
                c: if *c { G1Affine::zero() } else { proof.c },
            }
        }
        ProofChoice::Negated(i, a, b, c) => {
            let proof = &statement(i).1;
            let neg1 = |p: G1Affine, n: bool| {
                if n {
                    (-G1Projective::from(p)).into_affine()
                } else {
                    p
                }
            };
            let neg2 = |p: G2Affine, n: bool| {
                if n {
                    (-G2Projective::from(p)).into_affine()
                } else {
                    p
                }
            };
            Proof {
                a: neg1(proof.a, *a),
                b: neg2(proof.b, *b),
                c: neg1(proof.c, *c),
            }
        }
    }
}

fn build_inputs(choice: &InputsChoice) -> VerifierInputParts {
    match choice {
        InputsChoice::Valid(i) => VerifierInputParts::Scalars(statement(i).0.clone()),
        InputsChoice::Random(seed, n) => {
            let rng = &mut StdRng::seed_from_u64(*seed);
            VerifierInputParts::Scalars((0..*n).map(|_| Fr::rand(rng)).collect())
        }
        InputsChoice::PlusModulus(s, i) => {
            let inputs = &statement(s).0;
            let target = i.index(inputs.len());
            let bytes = inputs
                .iter()
                .enumerate()
                .flat_map(|(j, x)| {
                    if j == target {
                        add_modulus_le(&serialize(x))
                    } else {
                        serialize(x)
                    }
                })
                .collect();
            VerifierInputParts::Bytes(bytes)
        }
    }
}

enum VerifierInputParts {
    Scalars(Vec<Fr>),
    Bytes(Vec<u8>),
}

/// Add the scalar field modulus to a 32-byte little-endian integer, wrapping on overflow.
fn add_modulus_le(bytes: &[u8]) -> Vec<u8> {
    let modulus = Fr::MODULUS.0;
    let mut out = Vec::with_capacity(SCALAR_SIZE);
    let mut carry = 0u128;
    for (limb, chunk) in modulus.iter().zip(bytes.chunks(8)) {
        let sum = u64::from_le_bytes(chunk.try_into().unwrap()) as u128 + *limb as u128 + carry;
        out.extend_from_slice(&(sum as u64).to_le_bytes());
        carry = sum >> 64;
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Both verifiers reach the same verdict on proofs and inputs built from valid ones,
    /// including rerandomized proofs (which are valid), and proofs with mixed, negated or
    /// identity points (which are not).
    #[test]
    fn verifiers_agree_on_structured_proofs(
        proof in proof_choice(),
        inputs in inputs_choice(),
    ) {
        let built = build_proof(&proof);
        let input = match build_inputs(&inputs) {
            VerifierInputParts::Scalars(scalars) => VerifierInput::new(&scalars, &built),
            VerifierInputParts::Bytes(bytes) => VerifierInput {
                public_inputs: bytes,
                ..VerifierInput::new(&[], &built)
            },
        };
        let expected = input.arkworks_verdict();
        prop_assert_eq!(input.fastcrypto_verdict(), expected);
        if let (ProofChoice::Valid(i) | ProofChoice::Rerandomized(i, _), InputsChoice::Valid(j)) =
            (&proof, &inputs)
        {
            prop_assert_eq!(expected, Some(i.index(2) == j.index(2)));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Both verifiers parse the same byte strings and reach the same verdict on them, for
    /// byte-level corruptions of a valid input.
    #[test]
    fn verifiers_agree_on_corrupted_bytes(
        statement_index in any::<Index>(),
        mutations in vec((0..6usize, byte_mutation()), 1..4),
    ) {
        let (inputs, proof) = statement(&statement_index);
        let mut input = VerifierInput::new(inputs, proof);
        for (part, mutation) in &mutations {
            apply(input.parts_mut()[*part], mutation);
        }
        prop_assert_eq!(input.fastcrypto_verdict(), input.arkworks_verdict());
    }

    /// [prepare_pvk_bytes] accepts exactly the verifying keys that arkworks parses (using all the
    /// bytes, and with at least one element in `gamma_abc`), and prepares the same key.
    #[test]
    fn verifying_key_parser_agrees_with_arkworks(
        mutations in vec(byte_mutation(), 0..4),
    ) {
        let mut vk_bytes = fixture().vk_bytes.clone();
        for mutation in &mutations {
            apply(&mut vk_bytes, mutation);
        }
        let expected = parse_exact::<VerifyingKey<Bls12_381>>(&vk_bytes)
            .filter(|vk| !vk.gamma_abc_g1.is_empty())
            .map(|vk| {
                let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
                vec![
                    vk.gamma_abc_g1.iter().flat_map(serialize).collect(),
                    serialize(&PairingOutput::<Bls12_381>(pvk.alpha_g1_beta_g2)),
                    serialize(&(-vk.gamma_g2.into_group()).into_affine()),
                    serialize(&(-vk.delta_g2.into_group()).into_affine()),
                ]
            });
        prop_assert_eq!(prepare_pvk_bytes(&vk_bytes).ok(), expected);
    }
}

#[test]
fn fixture_statements_verify() {
    for (inputs, proof) in &fixture().statements {
        let input = VerifierInput::new(inputs, proof);
        assert_eq!(input.arkworks_verdict(), Some(true));
        assert_eq!(input.fastcrypto_verdict(), Some(true));
    }
    // Sanity check of the GT encoding assumed by `arkworks_verdict`.
    let pvk = prepare_pvk_bytes(&fixture().vk_bytes).unwrap();
    let alpha_beta: Fq12 = parse_exact::<PairingOutput<Bls12_381>>(&pvk[1]).unwrap().0;
    assert_eq!(
        alpha_beta,
        Groth16::<Bls12_381>::process_vk(&fixture().vk)
            .unwrap()
            .alpha_g1_beta_g2
    );
}
