// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Runs sequences of the BLS12-381 operations of Sui's `group_ops` Move natives (the functions of
//! `sui::bls12381`), plus multi-pairing, which BLS and Groth16 verification use. Like
//! `sui::group_ops::Element`, elements are kept as bytes, and are parsed the way the natives parse
//! them: with `from_byte_array` for bytes from the user, and with `from_trusted_byte_array` for
//! constants and outputs of earlier operations. The arguments of `mul` and `div` are in the natives'
//! order: `mul(s, e) = e * s` and `div(s, e) = e / s`. Since outputs are fed back as inputs, the
//! operations reach the cases that blst handles specially: the identity, the scalars 0, 1 and
//! r - 1, repeated points and negated points.
//!
//! Invariants: nothing panics; every output is the canonical encoding of a valid element, so
//! `from_byte_array` accepts it and byte equality (`group_ops::equal`) is element equality; an
//! operation fails exactly where the native fails (division by zero, hashing an empty message, MSM
//! inputs of different lengths, empty or above the length limit, sums above the term limit,
//! multi-pairing inputs of different lengths); MSM, sums and multi-pairing equal their naive
//! computation; the pairing is bilinear; and the outputs are consistent with each other.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::{
    G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar, G1_ELEMENT_BYTE_LENGTH,
    G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};
use fastcrypto::groups::{
    FromTrustedByteArray, GroupElement, HashToGroupElement, MultiScalarMul, Pairing,
};
use fastcrypto::serde_helpers::ToFromByteArray;
use hex_literal::hex;
use libfuzzer_sys::fuzz_target;

/// `group_ops_bls12381_msm_max_len` in Sui's protocol config.
const MSM_MAX_LENGTH: usize = 32;
/// `group_ops_bls12381_uncompressed_g1_sum_max_terms` in Sui's protocol config.
const SUM_MAX_TERMS: usize = 1200;
/// Bounds the work per input.
const MAX_OPS: usize = 64;
/// Pairings are slow, so multi-pairings have at most this many terms.
const MAX_PAIRINGS: usize = 4;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Group {
    Scalar,
    G1,
    G2,
    Gt,
}

#[derive(Arbitrary, Debug)]
enum Op {
    ScalarFromBytes([u8; SCALAR_LENGTH]),
    ScalarFromU64(u64),
    G1FromBytes([u8; G1_ELEMENT_BYTE_LENGTH]),
    G2FromBytes([u8; G2_ELEMENT_BYTE_LENGTH]),
    HashToG1(Vec<u8>),
    HashToG2(Vec<u8>),
    /// The indices are taken modulo the number of elements of the group.
    Add(Group, u8, u8),
    Sub(Group, u8, u8),
    /// A scalar index and an element index.
    Mul(Group, u8, u8),
    Div(Group, u8, u8),
    /// G1 if `true`, otherwise G2; pairs of (scalar index, element index), plus extra scalars to
    /// make the lengths differ.
    Msm(bool, Vec<(u8, u8)>, u8),
    /// A G1 index, a G2 index and a scalar index, to check bilinearity.
    Pairing(u8, u8, u8),
    /// Pairs of (G1 index, G2 index).
    MultiPairing(Vec<(u8, u8)>),
    G1ToUncompressed(u8),
    UncompressedToG1(u8),
    /// Indices of uncompressed elements, and how often to repeat the list.
    UncompressedSum(Vec<u8>, u8),
}

/// The elements built so far, as bytes, like `sui::group_ops::Element`.
struct State {
    scalars: Vec<[u8; SCALAR_LENGTH]>,
    g1: Vec<[u8; G1_ELEMENT_BYTE_LENGTH]>,
    g2: Vec<[u8; G2_ELEMENT_BYTE_LENGTH]>,
    gt: Vec<[u8; GT_ELEMENT_BYTE_LENGTH]>,
    uncompressed: Vec<[u8; 2 * G1_ELEMENT_BYTE_LENGTH]>,
}

impl State {
    /// The constants of `sui::bls12381`.
    fn new() -> Self {
        Self {
            scalars: vec![
                [0; SCALAR_LENGTH],
                hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            ],
            g1: vec![
                hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
            ],
            g2: vec![
                hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                hex!("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
            ],
            gt: vec![
                GTElement::zero().to_byte_array(),
                GTElement::generator().to_byte_array(),
            ],
            uncompressed: vec![],
        }
    }
}

fn pick<T: Copy>(items: &[T], index: u8) -> Option<T> {
    (!items.is_empty()).then(|| items[index as usize % items.len()])
}

/// `parse_trusted` in the natives. Outputs of earlier operations must always parse.
fn trusted<T: FromTrustedByteArray<N>, const N: usize>(bytes: &[u8; N]) -> T {
    T::from_trusted_byte_array(bytes).expect("an output of an operation does not parse")
}

/// Checks that an output is the canonical encoding of a valid element (`parse_untrusted` accepts
/// it), and returns its bytes.
fn output<T: ToFromByteArray<N> + PartialEq + std::fmt::Debug, const N: usize>(
    element: T,
) -> [u8; N] {
    let bytes = element.to_byte_array();
    let parsed = T::from_byte_array(&bytes).expect("an output is not a valid element");
    assert_eq!(parsed, element);
    assert_eq!(parsed.to_byte_array(), bytes);
    bytes
}

fn uncompressed_output(element: &G1Element) -> [u8; 2 * G1_ELEMENT_BYTE_LENGTH] {
    let bytes = G1ElementUncompressed::from(element).into_byte_array();
    let parsed = G1Element::try_from(&G1ElementUncompressed::from_trusted_byte_array(bytes))
        .expect("an uncompressed output is not valid");
    assert_eq!(&parsed, element);
    bytes
}

/// Checks the result of a division, which fails exactly for a zero scalar.
fn check_div<G: GroupElement<ScalarType = Scalar>>(
    s: Scalar,
    e: G,
    result: FastCryptoResult<G>,
) -> Option<G> {
    assert_eq!(result.is_err(), s == Scalar::zero());
    let quotient = result.ok()?;
    assert_eq!(quotient * s, e);
    Some(quotient)
}

/// Checks a binary operation on two elements of the same group and returns the encoded result.
fn add_or_sub<G, const N: usize>(a: &[u8; N], b: &[u8; N], add: bool) -> [u8; N]
where
    G: GroupElement + ToFromByteArray<N> + FromTrustedByteArray<N>,
{
    let (x, y): (G, G) = (trusted(a), trusted(b));
    if add {
        let sum = x + y;
        // Byte equality is element equality, so commuting gives the same bytes.
        assert_eq!(output(y + x), output(sum));
        assert_eq!(sum - y, x);
        output(sum)
    } else {
        let difference = x - y;
        assert_eq!(difference + y, x);
        assert_eq!(output(y - x), output(-difference));
        output(difference)
    }
}

fn msm<G, const N: usize>(scalars: &[[u8; SCALAR_LENGTH]], points: &[[u8; N]]) -> Option<[u8; N]>
where
    G: GroupElement<ScalarType = Scalar>
        + MultiScalarMul
        + ToFromByteArray<N>
        + FromTrustedByteArray<N>,
{
    // The checks of the native before it calls multi_scalar_mul.
    let rejected =
        scalars.is_empty() || scalars.len() != points.len() || points.len() > MSM_MAX_LENGTH;
    let scalars: Vec<Scalar> = scalars.iter().map(trusted).collect();
    let points: Vec<G> = points.iter().map(trusted).collect();
    let result = G::multi_scalar_mul(&scalars, &points);
    // multi_scalar_mul fails exactly on empty inputs and length mismatches. Sui treats any other
    // error as an invariant violation.
    assert_eq!(
        result.is_err(),
        scalars.is_empty() || scalars.len() != points.len()
    );
    if rejected {
        return None;
    }
    let result = result.unwrap();
    let naive = points
        .iter()
        .zip(&scalars)
        .fold(G::zero(), |acc, (p, s)| acc + *p * *s);
    assert_eq!(result, naive);
    Some(output(result))
}

fn run(state: &mut State, op: Op) {
    match op {
        Op::ScalarFromBytes(bytes) => {
            if let Ok(s) = Scalar::from_byte_array(&bytes) {
                assert_eq!(s.to_byte_array(), bytes);
                state.scalars.push(bytes);
            }
        }
        Op::ScalarFromU64(x) => {
            // scalar_from_u64 builds the big-endian bytes and trusts them.
            let mut bytes = [0u8; SCALAR_LENGTH];
            bytes[SCALAR_LENGTH - 8..].copy_from_slice(&x.to_be_bytes());
            let s: Scalar = trusted(&bytes);
            assert_eq!(s, Scalar::from(x as u128));
            state.scalars.push(output(s));
        }
        Op::G1FromBytes(bytes) => {
            if let Ok(p) = G1Element::from_byte_array(&bytes) {
                assert_eq!(p.to_byte_array(), bytes);
                state.g1.push(bytes);
            }
        }
        Op::G2FromBytes(bytes) => {
            if let Ok(p) = G2Element::from_byte_array(&bytes) {
                assert_eq!(p.to_byte_array(), bytes);
                state.g2.push(bytes);
            }
        }
        // The native rejects empty messages.
        Op::HashToG1(msg) => {
            if !msg.is_empty() {
                let p = G1Element::hash_to_group_element(&msg);
                assert_ne!(p, G1Element::zero());
                state.g1.push(output(p));
            }
        }
        Op::HashToG2(msg) => {
            if !msg.is_empty() {
                let p = G2Element::hash_to_group_element(&msg);
                assert_ne!(p, G2Element::zero());
                state.g2.push(output(p));
            }
        }
        Op::Add(group, i, j) | Op::Sub(group, i, j) => {
            let add = matches!(op, Op::Add(..));
            match group {
                Group::Scalar => {
                    if let (Some(a), Some(b)) = (pick(&state.scalars, i), pick(&state.scalars, j)) {
                        let r = add_or_sub::<Scalar, SCALAR_LENGTH>(&a, &b, add);
                        state.scalars.push(r);
                    }
                }
                Group::G1 => {
                    if let (Some(a), Some(b)) = (pick(&state.g1, i), pick(&state.g1, j)) {
                        let r = add_or_sub::<G1Element, G1_ELEMENT_BYTE_LENGTH>(&a, &b, add);
                        state.g1.push(r);
                    }
                }
                Group::G2 => {
                    if let (Some(a), Some(b)) = (pick(&state.g2, i), pick(&state.g2, j)) {
                        let r = add_or_sub::<G2Element, G2_ELEMENT_BYTE_LENGTH>(&a, &b, add);
                        state.g2.push(r);
                    }
                }
                Group::Gt => {
                    if let (Some(a), Some(b)) = (pick(&state.gt, i), pick(&state.gt, j)) {
                        let r = add_or_sub::<GTElement, GT_ELEMENT_BYTE_LENGTH>(&a, &b, add);
                        state.gt.push(r);
                    }
                }
            }
        }
        Op::Mul(group, i, j) | Op::Div(group, i, j) => {
            let mul = matches!(op, Op::Mul(..));
            let Some(s) = pick(&state.scalars, i) else {
                return;
            };
            let s: Scalar = trusted(&s);
            macro_rules! mul_or_div {
                ($elements:expr, $type:ty) => {
                    if let Some(e) = pick(&$elements, j) {
                        let e: $type = trusted(&e);
                        if mul {
                            let product = e * s;
                            if s != Scalar::zero() {
                                assert_eq!((product / s).unwrap(), e);
                            }
                            $elements.push(output(product));
                        } else if let Some(quotient) = check_div(s, e, e / s) {
                            $elements.push(output(quotient));
                        }
                    }
                };
            }
            match group {
                Group::Scalar => mul_or_div!(state.scalars, Scalar),
                Group::G1 => mul_or_div!(state.g1, G1Element),
                Group::G2 => mul_or_div!(state.g2, G2Element),
                Group::Gt => mul_or_div!(state.gt, GTElement),
            }
        }
        Op::Msm(in_g1, pairs, extra_scalars) => {
            let mut scalars = Vec::new();
            let mut points_g1 = Vec::new();
            let mut points_g2 = Vec::new();
            for (i, j) in pairs.iter().take(2 * MSM_MAX_LENGTH) {
                let (Some(s), Some(p), Some(q)) = (
                    pick(&state.scalars, *i),
                    pick(&state.g1, *j),
                    pick(&state.g2, *j),
                ) else {
                    return;
                };
                scalars.push(s);
                points_g1.push(p);
                points_g2.push(q);
            }
            for k in 0..extra_scalars % 4 {
                if let Some(s) = pick(&state.scalars, k) {
                    scalars.push(s);
                }
            }
            if in_g1 {
                if let Some(r) = msm::<G1Element, G1_ELEMENT_BYTE_LENGTH>(&scalars, &points_g1) {
                    state.g1.push(r);
                }
            } else if let Some(r) = msm::<G2Element, G2_ELEMENT_BYTE_LENGTH>(&scalars, &points_g2) {
                state.g2.push(r);
            }
        }
        Op::Pairing(i, j, k) => {
            if let (Some(p), Some(q), Some(s)) = (
                pick(&state.g1, i),
                pick(&state.g2, j),
                pick(&state.scalars, k),
            ) {
                let (p, q, s): (G1Element, G2Element, Scalar) =
                    (trusted(&p), trusted(&q), trusted(&s));
                let e = p.pairing(&q);
                assert_eq!((p * s).pairing(&q), e * s);
                assert_eq!(p.pairing(&(q * s)), e * s);
                state.gt.push(output(e));
            }
        }
        Op::MultiPairing(pairs) => {
            let mut a: Vec<G1Element> = Vec::new();
            let mut b: Vec<G2Element> = Vec::new();
            for (i, j) in pairs.iter().take(MAX_PAIRINGS) {
                let (Some(p), Some(q)) = (pick(&state.g1, *i), pick(&state.g2, *j)) else {
                    return;
                };
                a.push(trusted(&p));
                b.push(trusted(&q));
            }
            let naive = a
                .iter()
                .zip(&b)
                .fold(GTElement::zero(), |acc, (p, q)| acc + p.pairing(q));
            assert_eq!(G1Element::multi_pairing(&a, &b).unwrap(), naive);
            // A length mismatch is rejected.
            a.push(G1Element::generator());
            assert!(G1Element::multi_pairing(&a, &b).is_err());
            state.gt.push(output(naive));
        }
        Op::G1ToUncompressed(i) => {
            if let Some(p) = pick(&state.g1, i) {
                let p: G1Element = trusted(&p);
                state.uncompressed.push(uncompressed_output(&p));
            }
        }
        Op::UncompressedToG1(i) => {
            if let Some(u) = pick(&state.uncompressed, i) {
                let p = G1Element::try_from(&G1ElementUncompressed::from_trusted_byte_array(u))
                    .expect("an uncompressed output does not convert");
                assert_eq!(G1ElementUncompressed::from(&p).into_byte_array(), u);
                state.g1.push(output(p));
            }
        }
        Op::UncompressedSum(indices, repeat) => {
            let terms: Vec<[u8; 2 * G1_ELEMENT_BYTE_LENGTH]> = (0..=repeat)
                .flat_map(|_| indices.iter().filter_map(|i| pick(&state.uncompressed, *i)))
                .take(SUM_MAX_TERMS + 1)
                .collect();
            if terms.len() > SUM_MAX_TERMS {
                return;
            }
            let uncompressed: Vec<G1ElementUncompressed> = terms
                .iter()
                .map(|t| G1ElementUncompressed::from_trusted_byte_array(*t))
                .collect();
            let sum = G1ElementUncompressed::sum(&uncompressed)
                .expect("a sum of uncompressed outputs fails");
            let naive = uncompressed.iter().fold(G1Element::zero(), |acc, u| {
                acc + G1Element::try_from(u).unwrap()
            });
            assert_eq!(sum, naive);
            state.uncompressed.push(uncompressed_output(&sum));
        }
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut state = State::new();
    for op in ops.into_iter().take(MAX_OPS) {
        run(&mut state, op);
    }
});
