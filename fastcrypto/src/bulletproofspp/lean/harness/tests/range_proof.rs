// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests that `RangeProof` and its Lean model (`../model/BpppHarness.lean`) produce byte-identical
//! proofs from the same randomness, and accept and reject the same proofs.
//!
//! The Merlin transcript is not modelled in Lean. The tests replay it here and pass the model both
//! the absorbed entries and the challenges. The replay needs no trust: a wrong one gives challenges
//! under which honest proofs fail, and the model refuses to continue from a log that differs from
//! the replayed entries.

use bppp_lean_harness::open;
use fastcrypto::bulletproofspp::range_proof::{Range, RangeProof};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::pedersen::{self, Blinding, PedersenCommitment};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_lean_testing::lean_rs::LeanCapability;
use fastcrypto_lean_testing::same;
use merlin::Transcript;
use proptest::collection::vec;
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

type Chunk = [u8; 32];

const BASE: usize = 16;
const H_LEN: usize = 8;
const DST_H: &[u8] = b"ristretto255_XMD:SHA-512_R255MAP_RO_fastcrypto-bppp-gen-h-01";
const DST_G: &[u8] = b"ristretto255_XMD:SHA-512_R255MAP_RO_fastcrypto-bppp-gen-g-01";
const RANGES: [Range; 4] = [Range::Bits8, Range::Bits16, Range::Bits32, Range::Bits64];

fn bits(range: &Range) -> usize {
    match range {
        Range::Bits8 => 8,
        Range::Bits16 => 16,
        Range::Bits32 => 32,
        Range::Bits64 => 64,
    }
}

fn hexes(chunks: &[Chunk]) -> Vec<String> {
    chunks.iter().map(hex::encode).collect()
}

/// `Generators::new(nm)`.
fn generators(nm: usize) -> (Chunk, Vec<Chunk>, Vec<Chunk>) {
    let generator = |dst: &[u8], i: usize| {
        RistrettoPoint::hash_to_ristretto255_with_dst(&[&(i as u64).to_le_bytes()], dst)
            .to_byte_array()
    };
    let mut h_vec = vec![pedersen::G.to_byte_array()];
    h_vec.extend((1..H_LEN).map(|i| generator(DST_H, i)));
    let g_vec = (0..nm).map(|i| generator(DST_G, i)).collect();
    (pedersen::H.to_byte_array(), h_vec, g_vec)
}

/// The norm length for `m` values of `range_bits` bits.
fn norm_length(range_bits: usize, m: usize) -> usize {
    (m * range_bits / 4).max(BASE).next_power_of_two()
}

/// A serialized proof, split into its elements.
struct Parts {
    c: Vec<Chunk>,
    rounds: Vec<Chunk>,
    l_final: Chunk,
    n_final: Vec<Chunk>,
}

fn proof_shape(mut l: usize, mut n: usize) -> (usize, usize) {
    let mut rounds = 0;
    while !(l <= 1 && l + n < 6) {
        l = l.div_ceil(2);
        n = n.div_ceil(2);
        rounds += 1;
    }
    (rounds, n)
}

fn split(proof: &[u8]) -> Parts {
    let chunks: Vec<Chunk> = proof
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    let (rounds, n_len) = (4..32)
        .map(|k| proof_shape(H_LEN, 1 << k))
        .find(|(r, n)| 4 + 2 * r + 1 + n == chunks.len())
        .expect("proof shape");
    Parts {
        c: chunks[..4].to_vec(),
        rounds: chunks[4..4 + 2 * rounds].to_vec(),
        l_final: chunks[4 + 2 * rounds],
        n_final: chunks[4 + 2 * rounds + 1..][..n_len].to_vec(),
    }
}

/// A Merlin transcript that records its entries in the form of `BpppHarness.entryString`.
struct Replay {
    transcript: Transcript,
    entries: Vec<String>,
    challenges: Vec<String>,
}

fn label_str(label: &[u8]) -> &str {
    std::str::from_utf8(label).unwrap()
}

impl Replay {
    fn new(label: &'static [u8]) -> Self {
        Self {
            transcript: Transcript::new(label),
            entries: vec![format!("m|dom-sep|{}", hex::encode(label))],
            challenges: vec![],
        }
    }

    fn message(&mut self, label: &'static [u8], data: &[u8]) {
        self.transcript.append_message(label, data);
        self.entries
            .push(format!("m|{}|{}", label_str(label), hex::encode(data)));
    }

    fn point(&mut self, label: &'static [u8], point: &Chunk) {
        self.transcript.append_message(label, point);
        self.entries
            .push(format!("p|{}|{}", label_str(label), hex::encode(point)));
    }

    fn scalar(&mut self, label: &'static [u8], scalar: &Chunk) {
        self.transcript.append_message(label, scalar);
        self.entries
            .push(format!("s|{}|{}", label_str(label), hex::encode(scalar)));
    }

    fn challenge(&mut self, label: &'static [u8]) {
        let mut bytes = [0; 64];
        self.transcript.challenge_bytes(label, &mut bytes);
        self.entries.push(format!("c|{}", label_str(label)));
        let challenge = RistrettoScalar::from_bytes_mod_order_wide(&bytes);
        self.challenges.push(hex::encode(challenge.to_byte_array()));
    }
}

/// The transcript of `RangeProof::verify_batch`.
fn replay(range_bits: usize, dst: &[u8], commitments: &[Chunk], parts: &Parts) -> Replay {
    let mut t = Replay::new(b"fastcrypto-bppp-range-proof-01");
    t.message(b"dst", dst);
    t.message(b"n_bits", &(range_bits as u64).to_le_bytes());
    t.message(b"m", &(commitments.len() as u64).to_le_bytes());
    t.message(b"dom-sep", b"bppp_circuit");
    for commitment in commitments {
        t.point(b"V", commitment);
    }
    t.point(b"C_L", &parts.c[0]);
    t.point(b"C_O", &parts.c[1]);
    t.challenge(b"alpha");
    t.point(b"C_R", &parts.c[2]);
    t.challenge(b"rho");
    t.challenge(b"lambda");
    t.challenge(b"beta");
    t.challenge(b"delta");
    t.point(b"C_S", &parts.c[3]);
    t.challenge(b"tau");
    t.message(b"dom-sep", b"norm_linear");
    for round in parts.rounds.chunks_exact(2) {
        t.point(b"X", &round[0]);
        t.point(b"R", &round[1]);
        t.challenge(b"gamma");
    }
    t.scalar(b"l_final", &parts.l_final);
    for scalar in &parts.n_final {
        t.scalar(b"n_final", scalar);
    }
    t
}

/// A statement and a proof of it, possibly tampered with.
#[derive(Clone, Debug)]
struct Instance {
    range: Range,
    dst: Vec<u8>,
    commitments: Vec<Chunk>,
    proof: Vec<u8>,
}

impl Instance {
    fn rust(&self) -> bool {
        let Ok(proof) = RangeProof::from_bytes(&self.proof) else {
            return false;
        };
        let commitments: Vec<PedersenCommitment> = self
            .commitments
            .iter()
            .map(|c| PedersenCommitment(RistrettoPoint::from_byte_array(c).unwrap()))
            .collect();
        proof
            .verify_batch(&commitments, &self.range, &self.dst)
            .is_ok()
    }

    fn lean(&self, lean: &LeanCapability<'static>) -> bool {
        let range_bits = bits(&self.range);
        let parts = split(&self.proof);
        let (g, h_vec, g_vec) = generators(norm_length(range_bits, self.commitments.len()));
        let t = replay(range_bits, &self.dst, &self.commitments, &parts);
        let input = vec![
            vec![hex::encode(&self.dst)],
            hexes(&self.commitments),
            hexes(&[g]),
            hexes(&h_vec),
            hexes(&g_vec),
            hexes(&parts.c),
            hexes(&parts.rounds),
            hexes(&[parts.l_final]),
            hexes(&parts.n_final),
            t.entries,
            t.challenges,
        ];
        lean.exported::<(u64, Vec<Vec<String>>), Result<bool, String>>("bppp_harness_verify_batch")
            .unwrap()
            .call(range_bits as u64, input)
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
            let shift = 64 - bits(&range);
            let values: Vec<u64> = values.iter().map(|v| v >> shift).collect();
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
                commitments: commitments.iter().map(|c| c.0.to_byte_array()).collect(),
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

/// The powers `CR_POWERS` and the powers of `C_O`, `C_L` and `C_R` in `circuit.rs`.
const CR_POWERS: [i32; 7] = [-1, 1, 2, 3, 5, 6, 7];
const COMMITMENT_POWERS: [i32; 3] = [0, 1, 2];

/// `blinding_vector`, in the order Rust draws from `rng`. Slots that are not drawn are zero.
fn blinding_vector(rng: &mut StdRng, e: i32) -> Vec<String> {
    let mut draw = || hex::encode(RistrettoScalar::rand(rng).to_byte_array());
    let mut r = vec![draw()];
    for a in CR_POWERS {
        let power = e + a;
        r.push(if power == -1 || CR_POWERS.contains(&(power + 1)) {
            draw()
        } else {
            hex::encode([0u8; 32])
        });
    }
    r
}

impl ProverInput {
    fn commitments(&self) -> Vec<Chunk> {
        self.values
            .iter()
            .zip(&self.blindings)
            .map(|(v, s)| {
                PedersenCommitment::new(&RistrettoScalar::from(*v), &Blinding(*s))
                    .0
                    .to_byte_array()
            })
            .collect()
    }

    fn rust(&self) -> Vec<u8> {
        let blindings: Vec<Blinding> = self.blindings.iter().map(|s| Blinding(*s)).collect();
        let mut rng = StdRng::seed_from_u64(self.seed);
        RangeProof::prove_batch(&self.values, &blindings, &self.range, &self.dst, &mut rng)
            .unwrap()
            .to_bytes()
    }

    /// The proof from the model. The transcript is replayed from the Rust proof `expected`.
    fn lean(&self, lean: &LeanCapability<'static>, expected: &[u8]) -> Vec<u8> {
        let range_bits = bits(&self.range);
        let nm = norm_length(range_bits, self.values.len());
        let (g, h_vec, g_vec) = generators(nm);
        let t = replay(range_bits, &self.dst, &self.commitments(), &split(expected));
        let mut rng = StdRng::seed_from_u64(self.seed);
        let [r_o, r_l, r_r] = COMMITMENT_POWERS.map(|e| blinding_vector(&mut rng, e));
        let n_s = (0..nm)
            .map(|_| hex::encode(RistrettoScalar::rand(&mut rng).to_byte_array()))
            .collect();
        let l_s = vec![hex::encode(RistrettoScalar::rand(&mut rng).to_byte_array())];
        let scalars = |xs: &[RistrettoScalar]| {
            xs.iter()
                .map(|x| hex::encode(x.to_byte_array()))
                .collect::<Vec<_>>()
        };
        let input = vec![
            vec![hex::encode(&self.dst)],
            self.values.iter().map(u64::to_string).collect(),
            scalars(&self.blindings),
            hexes(&[g]),
            hexes(&h_vec),
            hexes(&g_vec),
            hexes(&[pedersen::G.to_byte_array(), pedersen::H.to_byte_array()]),
            r_o,
            r_l,
            r_r,
            n_s,
            l_s,
            t.entries,
            t.challenges,
        ];
        lean.exported::<(u64, Vec<Vec<String>>), Result<Vec<String>, String>>(
            "bppp_harness_prove_batch",
        )
        .unwrap()
        .call(range_bits as u64, input)
        .unwrap()
        .unwrap()
        .iter()
        .flat_map(|chunk| hex::decode(chunk).unwrap())
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
            let shift = 64 - bits(&range);
            let values: Vec<u64> = values.iter().map(|v| v >> shift).collect();
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

fn shifted(point: &Chunk) -> Chunk {
    let point = RistrettoPoint::from_byte_array(point).unwrap();
    (point + RistrettoPoint::generator()).to_byte_array()
}

impl Instance {
    fn tamper(mut self, tamper: Tamper) -> Self {
        let parts = split(&self.proof);
        let num_points = 4 + parts.rounds.len();
        let num_scalars = 1 + parts.n_final.len();
        let set = |proof: &mut Vec<u8>, i: usize, chunk: Chunk| {
            proof[32 * i..32 * (i + 1)].copy_from_slice(&chunk);
        };
        match tamper {
            Tamper::Point(i) => {
                let i = i % num_points;
                let chunk: Chunk = self.proof[32 * i..32 * (i + 1)].try_into().unwrap();
                set(&mut self.proof, i, shifted(&chunk));
            }
            Tamper::Scalar(i) => {
                let i = num_points + i % num_scalars;
                let chunk: Chunk = self.proof[32 * i..32 * (i + 1)].try_into().unwrap();
                let scalar = RistrettoScalar::from_byte_array(&chunk).unwrap();
                let scalar = scalar + RistrettoScalar::from(1u64);
                set(&mut self.proof, i, scalar.to_byte_array());
            }
            Tamper::SwapRound(i) => {
                let i = 4 + 2 * (i % (parts.rounds.len() / 2));
                let x: Chunk = self.proof[32 * i..32 * (i + 1)].try_into().unwrap();
                let r: Chunk = self.proof[32 * (i + 1)..32 * (i + 2)].try_into().unwrap();
                set(&mut self.proof, i, r);
                set(&mut self.proof, i + 1, x);
            }
            Tamper::Commitment(i) => {
                let i = i % self.commitments.len();
                self.commitments[i] = shifted(&self.commitments[i]);
            }
            Tamper::ExtraCommitment => self
                .commitments
                .push(RistrettoPoint::generator().to_byte_array()),
            Tamper::Dst => self.dst.push(0),
            Tamper::Range(i) => {
                let others: Vec<Range> = RANGES
                    .into_iter()
                    .filter(|r| bits(r) != bits(&self.range))
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
    let commitment = |s: &str| -> Chunk { hex::decode(s).unwrap().try_into().unwrap() };
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
        proof: hex::decode(
            "00d5d5d1529f01cf6420ec103dace15476ca510f5b92ae6762bc25f4bd1249021219fad1752e829b54c9726bdb9253128ba6e82ca16fd8ea2595e26a536b4406621a5bbe5a65f5d917da8906719361ad8dcb5c9618861e1ccaee288bd7db8d5e9e5b0e4cb21110d789b367d90e778ec30faeda08c405e7b40a64c9f55e355105dad137e8eb12facf2017dd0887338d6d1416718a9ab599e36a5fc26844b2ce5f44c9c0a0e79d43c07257498c7d755a0fb1e36d620fb312db78f230c11795af452ec6fd20bdddcd078dd121fd667b1226e14f79027b1502b770e804c776ce2e617c2e34ae010e418b31f72222ae7e76d5107747b507355aaa17b89d113ff8ee16963d2647afb472778c27d1983e8e0741be8e3252ce46faa2973ce1f6e352f670484baa1173bae5e99c5f3f0ff65ee368d191f8519986017a8faf1e08d6310d0f0bdf52df2d0b75fdbbdd56eacce0a932270b24b242ec9efb49a062b1d8dd4a0032d10c7962108d26a9239e1103806279e12396a064585f6b878050a84bbe41058a3416edfe76b21e7ec4945454970e53fe7cfb47d49e87373ae22f5ae499b50238eb4f534c997a1e88772fdc181885e7089147978798c99c43867803f5d554015048dbb1bbaa9976da6a08d9457c049a4521e733a28994bb3060f17119940509",
        )
        .unwrap(),
    };
    assert!(instance.rust());
    assert!(instance.lean(&open()));
}
