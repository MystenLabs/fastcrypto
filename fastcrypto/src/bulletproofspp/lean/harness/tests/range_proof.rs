// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests that `RangeProof` and its Lean model (`../bindings/BpppHarness.lean`) produce byte-identical
//! proofs from the same randomness, and accept and reject the same proofs.
//!
//! The Merlin transcript is not modelled in Lean. The tests run the Rust verifier, log its
//! transcript, and pass the model the entries and the challenges; the model refuses to continue
//! from a transcript that differs from the entries.

use bppp_lean_harness::open;
use fastcrypto::bulletproofspp::lean_support::{
    crs, proof_elements, witness_draws, ProofElements, TranscriptLog,
};
use fastcrypto::bulletproofspp::range_proof::{Range, RangeProof};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::pedersen::{self, Blinding, PedersenCommitment};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_lean_testing::lean_rs::LeanCapability;
use fastcrypto_lean_testing::{hex, hex_all, same};
use proptest::collection::vec;
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

const RANGES: [Range; 4] = [Range::Bits8, Range::Bits16, Range::Bits32, Range::Bits64];

/// The entries in the form of `BpppHarness.entryString`, and the challenges.
fn transcript_inputs(log: TranscriptLog) -> [Vec<String>; 2] {
    let label = |label: &[u8]| String::from_utf8(label.to_vec()).unwrap();
    let entries = log
        .entries
        .iter()
        .map(|(l, data)| match data {
            Some(data) => format!("a|{}|{}", label(l), ::hex::encode(data)),
            None => format!("c|{}", label(l)),
        })
        .collect();
    [entries, hex_all(&log.challenges)]
}

fn points(commitments: &[PedersenCommitment]) -> Vec<RistrettoPoint> {
    commitments.iter().map(|c| c.0).collect()
}

fn rounds(elements: &ProofElements) -> Vec<RistrettoPoint> {
    elements.rounds.iter().flat_map(|(x, r)| [*x, *r]).collect()
}

fn values_in(range: &Range, values: &[u64]) -> Vec<u64> {
    let shift = 64 - range.bits();
    values.iter().map(|v| v >> shift).collect()
}

/// A statement and a proof of it, possibly tampered with.
#[derive(Clone, Debug)]
struct Instance {
    range: Range,
    dst: Vec<u8>,
    commitments: Vec<PedersenCommitment>,
    proof: Vec<u8>,
}

impl Instance {
    fn rust(&self) -> bool {
        RangeProof::from_bytes(&self.proof)
            .unwrap()
            .verify_batch(&self.commitments, &self.range, &self.dst)
            .is_ok()
    }

    fn lean(&self, lean: &LeanCapability<'static>) -> bool {
        let elements = proof_elements(&self.proof).unwrap();
        let crs = crs(self.range, self.commitments.len()).unwrap();
        let (_, log) = RangeProof::from_bytes(&self.proof)
            .unwrap()
            .verify_batch_logged(&self.commitments, &self.range, &self.dst)
            .unwrap();
        let [entries, challenges] = transcript_inputs(log);
        let input = vec![
            vec![::hex::encode(&self.dst)],
            hex_all(&points(&self.commitments)),
            vec![hex(&crs.g)],
            hex_all(&crs.h_vec),
            hex_all(&crs.g_vec),
            hex_all(&[elements.c_l, elements.c_o, elements.c_r, elements.c_s]),
            hex_all(&rounds(&elements)),
            vec![hex(&elements.l_final)],
            hex_all(&elements.n_final),
            entries,
            challenges,
        ];
        lean.exported::<(u64, Vec<Vec<String>>), Result<bool, String>>("bppp_harness_verify_batch")
            .unwrap()
            .call(self.range.bits() as u64, input)
            .unwrap()
            .unwrap()
    }
}

fn honest() -> impl Strategy<Value = Instance> {
    (
        0..RANGES.len(),
        vec(any::<u64>(), 1..=4),
        any::<u64>(),
        vec(any::<u8>(), 0..8),
    )
        .prop_map(|(range, values, seed, dst)| {
            let range = RANGES[range];
            let values = values_in(&range, &values);
            let mut rng = StdRng::seed_from_u64(seed);
            let (commitments, blindings): (Vec<PedersenCommitment>, Vec<Blinding>) = values
                .iter()
                .map(|&v| PedersenCommitment::commit_u64(v, &mut rng))
                .unzip();
            let proof = RangeProof::prove_batch(&values, &blindings, &range, &dst, &mut rng)
                .unwrap()
                .to_bytes();
            Instance {
                range,
                dst,
                commitments,
                proof,
            }
        })
}

/// The inputs of `RangeProof::prove_batch`, with its random draws given by `seed`.
#[derive(Clone, Debug)]
struct ProverInput {
    range: Range,
    dst: Vec<u8>,
    values: Vec<u64>,
    blindings: Vec<RistrettoScalar>,
    seed: u64,
}

impl ProverInput {
    fn commitments(&self) -> Vec<PedersenCommitment> {
        self.values
            .iter()
            .zip(&self.blindings)
            .map(|(v, s)| PedersenCommitment::new(&RistrettoScalar::from(*v), &Blinding(*s)))
            .collect()
    }

    fn rust(&self) -> Vec<u8> {
        let blindings: Vec<Blinding> = self.blindings.iter().map(|s| Blinding(*s)).collect();
        let mut rng = StdRng::seed_from_u64(self.seed);
        RangeProof::prove_batch(&self.values, &blindings, &self.range, &self.dst, &mut rng)
            .unwrap()
            .to_bytes()
    }

    /// The proof from the model, with the transcript of the Rust proof `expected`.
    fn lean(&self, lean: &LeanCapability<'static>, expected: &[u8]) -> Vec<u8> {
        let crs = crs(self.range, self.values.len()).unwrap();
        let (_, log) = RangeProof::from_bytes(expected)
            .unwrap()
            .verify_batch_logged(&self.commitments(), &self.range, &self.dst)
            .unwrap();
        let [entries, challenges] = transcript_inputs(log);
        let mut rng = StdRng::seed_from_u64(self.seed);
        let draws = witness_draws(self.range, &self.values, &self.blindings, &mut rng).unwrap();
        let input = vec![
            vec![::hex::encode(&self.dst)],
            self.values.iter().map(u64::to_string).collect(),
            hex_all(&self.blindings),
            vec![hex(&crs.g)],
            hex_all(&crs.h_vec),
            hex_all(&crs.g_vec),
            hex_all(&[*pedersen::G, *pedersen::H]),
            hex_all(&draws.r_o),
            hex_all(&draws.r_l),
            hex_all(&draws.r_r),
            hex_all(&draws.n_s),
            vec![hex(&draws.l_s)],
            entries,
            challenges,
        ];
        lean.exported::<(u64, Vec<Vec<String>>), Result<Vec<String>, String>>(
            "bppp_harness_prove_batch",
        )
        .unwrap()
        .call(self.range.bits() as u64, input)
        .unwrap()
        .unwrap()
        .iter()
        .flat_map(|chunk| ::hex::decode(chunk).unwrap())
        .collect()
    }
}

fn prover_input() -> impl Strategy<Value = ProverInput> {
    (
        0..RANGES.len(),
        vec(any::<u64>(), 1..=4),
        any::<u64>(),
        any::<u64>(),
        vec(any::<u8>(), 0..8),
    )
        .prop_map(|(range, values, seed, blinding_seed, dst)| {
            let range = RANGES[range];
            let values = values_in(&range, &values);
            let mut rng = StdRng::seed_from_u64(blinding_seed);
            let blindings = values
                .iter()
                .map(|_| RistrettoScalar::rand(&mut rng))
                .collect();
            ProverInput {
                range,
                dst,
                values,
                blindings,
                seed,
            }
        })
}

#[derive(Clone, Copy, Debug)]
enum Tamper {
    Point(usize),
    Scalar(usize),
    SwapRound(usize),
    Commitment(usize),
    ExtraCommitment,
    Dst,
    Range(usize),
}

impl Instance {
    fn element(&self, i: usize) -> [u8; 32] {
        self.proof[32 * i..32 * (i + 1)].try_into().unwrap()
    }

    fn set_element(&mut self, i: usize, element: [u8; 32]) {
        self.proof[32 * i..32 * (i + 1)].copy_from_slice(&element);
    }

    fn tamper(mut self, tamper: Tamper) -> Self {
        let elements = proof_elements(&self.proof).unwrap();
        let num_rounds = elements.rounds.len();
        let num_points = 4 + 2 * num_rounds;
        let generator = RistrettoPoint::generator();
        match tamper {
            Tamper::Point(i) => {
                let i = i % num_points;
                let point = RistrettoPoint::from_byte_array(&self.element(i)).unwrap();
                self.set_element(i, (point + generator).to_byte_array());
            }
            Tamper::Scalar(i) => {
                let i = num_points + i % (1 + elements.n_final.len());
                let scalar = RistrettoScalar::from_byte_array(&self.element(i)).unwrap();
                let scalar = scalar + RistrettoScalar::from(1u64);
                self.set_element(i, scalar.to_byte_array());
            }
            Tamper::SwapRound(i) => {
                let i = 4 + 2 * (i % num_rounds);
                let (x, r) = (self.element(i), self.element(i + 1));
                self.set_element(i, r);
                self.set_element(i + 1, x);
            }
            Tamper::Commitment(i) => {
                let i = i % self.commitments.len();
                self.commitments[i] = PedersenCommitment(self.commitments[i].0 + generator);
            }
            Tamper::ExtraCommitment => self.commitments.push(PedersenCommitment(generator)),
            Tamper::Dst => self.dst.push(0),
            Tamper::Range(i) => {
                let others: Vec<Range> = RANGES
                    .into_iter()
                    .filter(|r| r.bits() != self.range.bits())
                    .collect();
                self.range = others[i % others.len()];
            }
        }
        self
    }
}

fn tampering() -> impl Strategy<Value = Tamper> {
    prop_oneof![
        any::<usize>().prop_map(Tamper::Point),
        any::<usize>().prop_map(Tamper::Scalar),
        any::<usize>().prop_map(Tamper::SwapRound),
        any::<usize>().prop_map(Tamper::Commitment),
        Just(Tamper::ExtraCommitment),
        Just(Tamper::Dst),
        any::<usize>().prop_map(Tamper::Range),
    ]
}

#[test]
fn proves_identically() {
    let lean = open();
    same(
        prover_input(),
        |input| hex::encode(input.rust()),
        |input| hex::encode(input.lean(&lean, &input.rust())),
    );
}

#[test]
fn accepts_honest_proofs() {
    let lean = open();
    same(
        honest(),
        |instance| {
            assert!(instance.rust());
            true
        },
        |instance| instance.lean(&lean),
    );
}

#[test]
fn rejects_tampered_proofs() {
    let lean = open();
    same(
        (honest(), tampering()).prop_map(|(instance, tamper)| instance.tamper(tamper)),
        |instance| {
            assert!(!instance.rust());
            false
        },
        |instance| instance.lean(&lean),
    );
}

/// The frozen proof of `range_proof::tests::regression_test`.
#[test]
fn accepts_regression_proof() {
    let commitment = |s: &str| {
        let bytes: [u8; 32] = ::hex::decode(s).unwrap().try_into().unwrap();
        PedersenCommitment(RistrettoPoint::from_byte_array(&bytes).unwrap())
    };
    let instance = Instance {
        range: Range::Bits32,
        dst: b"test".to_vec(),
        commitments: [
            "442e20bdd70d96394130625763bb90729481036a4c0643972d0febc382919279",
            "464bbfe7ad1f58a942a57736d2627fe6d514609f0caeeb855eb6cacfe665c773",
            "24161bc7218ec384347e95140a2bdbaf44040cdb3b92ae1dd5083ec55d8ccc4c",
            "f821e18063a4f31afd5cffe02426f8a8dfb3db79d2982297b44e4160ed04a770",
        ]
        .map(commitment)
        .to_vec(),
        proof: ::hex::decode(
            "00d5d5d1529f01cf6420ec103dace15476ca510f5b92ae6762bc25f4bd1249021219fad1752e829b54c9726bdb9253128ba6e82ca16fd8ea2595e26a536b4406621a5bbe5a65f5d917da8906719361ad8dcb5c9618861e1ccaee288bd7db8d5e9e5b0e4cb21110d789b367d90e778ec30faeda08c405e7b40a64c9f55e355105dad137e8eb12facf2017dd0887338d6d1416718a9ab599e36a5fc26844b2ce5f44c9c0a0e79d43c07257498c7d755a0fb1e36d620fb312db78f230c11795af452ec6fd20bdddcd078dd121fd667b1226e14f79027b1502b770e804c776ce2e617c2e34ae010e418b31f72222ae7e76d5107747b507355aaa17b89d113ff8ee16963d2647afb472778c27d1983e8e0741be8e3252ce46faa2973ce1f6e352f670484baa1173bae5e99c5f3f0ff65ee368d191f8519986017a8faf1e08d6310d0f0bdf52df2d0b75fdbbdd56eacce0a932270b24b242ec9efb49a062b1d8dd4a0032d10c7962108d26a9239e1103806279e12396a064585f6b878050a84bbe41058a3416edfe76b21e7ec4945454970e53fe7cfb47d49e87373ae22f5ae499b50238eb4f534c997a1e88772fdc181885e7089147978798c99c43867803f5d554015048dbb1bbaa9976da6a08d9457c049a4521e733a28994bb3060f17119940509",
        )
        .unwrap(),
    };
    assert!(instance.rust());
    assert!(instance.lean(&open()));
}
