// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::schnorr::{Proof, Statement};
use fastcrypto::groups::ristretto255::{RistrettoPoint as G, RistrettoScalar as S};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use fastcrypto::nizk::DdhTupleNizk;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;

const DST: &[u8] = b"test dst";

fn random_point() -> G {
    G::generator() * S::rand(&mut thread_rng())
}

/// Prove `statement` with `witnesses`, check the proof with both verifiers and through a
/// serialization round trip, and return it.
fn prove_and_verify<T>(statement: &Statement<T>, witnesses: &[T::ScalarType]) -> Proof<T>
where
    T: MultiScalarMul + Serialize + DeserializeOwned,
    T::ScalarType: FiatShamirChallenge,
{
    let proof = statement.prove(witnesses, &mut thread_rng()).unwrap();
    assert_eq!(proof.commitments().len(), statement.num_constraints());
    assert_eq!(proof.responses().len(), statement.num_witnesses());
    assert!(statement.verify(&proof).is_ok());
    assert!(statement.verify_batched(&proof, &mut thread_rng()).is_ok());

    let deserialized: Proof<T> = bcs::from_bytes(&bcs::to_bytes(&proof).unwrap()).unwrap();
    assert_eq!(proof, deserialized);
    assert!(statement.verify(&deserialized).is_ok());
    proof
}

/// The special cases this construction is meant to subsume.
#[test]
fn test_instantiations() {
    let (g, h, k) = (random_point(), random_point(), random_point());
    let (x, r, s) = (
        S::rand(&mut thread_rng()),
        S::rand(&mut thread_rng()),
        S::rand(&mut thread_rng()),
    );

    // Discrete log: Y = x*G.
    let mut builder = Statement::builder(DST, 1);
    builder.add_constraint(&(g * x), [Some(g)]).unwrap();
    prove_and_verify(&builder.build().unwrap(), &[x]);

    // DDH tuple, which is the proof in fastcrypto::nizk with the same shape (A, B, z).
    let mut builder = Statement::builder(DST, 1);
    builder
        .add_constraint(&(g * x), [Some(g)])
        .unwrap()
        .add_constraint(&(h * x), [Some(h)])
        .unwrap();
    let proof = prove_and_verify(&builder.build().unwrap(), &[x]);
    assert_eq!((proof.commitments().len(), proof.responses().len()), (2, 1));
    assert!(
        DdhTupleNizk::create(&x, &g, &h, &(g * x), &(h * x), DST, &mut thread_rng())
            .verify(&g, &h, &(g * x), &(h * x), DST)
            .is_ok()
    );

    // The single shared response is what binds the two constraints together: a tuple which is not a
    // DDH tuple has no witness that satisfies both.
    let mut builder = Statement::builder(DST, 1);
    builder
        .add_constraint(&(g * x), [Some(g)])
        .unwrap()
        .add_constraint(&(h * (x + S::generator())), [Some(h)])
        .unwrap();
    let statement = builder.build().unwrap();
    assert!(statement.prove(&[x], &mut thread_rng()).is_err());

    // Pedersen opening: C = x*G + r*H.
    let mut builder = Statement::builder(DST, 2);
    builder
        .add_constraint(&(g * x + h * r), [Some(g), Some(h)])
        .unwrap();
    prove_and_verify(&builder.build().unwrap(), &[x, r]);

    // Witnesses shared across constraints that each use only some of them: two commitments to the
    // same `x` under different randomness, and a discrete log of `s`.
    let mut builder = Statement::builder(DST, 3);
    builder
        .add_constraint(&(g * x + h * r), [Some(g), Some(h), None])
        .unwrap()
        .add_constraint(&(g * x + h * s), [Some(g), None, Some(h)])
        .unwrap()
        .add_constraint(&(k * s), [None, None, Some(k)])
        .unwrap();
    prove_and_verify(&builder.build().unwrap(), &[x, r, s]);
}

/// The construction is generic over the group; the challenge derivation in particular must work for
/// groups whose Fiat-Shamir reduction requires a wide uniform buffer.
#[test]
fn test_other_group() {
    use fastcrypto::groups::bls12381::{G1Element, Scalar as BlsScalar};

    let g = G1Element::generator() * BlsScalar::rand(&mut thread_rng());
    let h = g * BlsScalar::rand(&mut thread_rng());
    let x = BlsScalar::rand(&mut thread_rng());

    let mut builder = Statement::builder(DST, 1);
    builder
        .add_constraint(&(g * x), [Some(g)])
        .unwrap()
        .add_constraint(&(h * x), [Some(h)])
        .unwrap();
    prove_and_verify(&builder.build().unwrap(), &[x]);
}

#[test]
fn test_invalid_proofs() {
    let (g, h, k) = (random_point(), random_point(), random_point());
    let (x, r) = (S::rand(&mut thread_rng()), S::rand(&mut thread_rng()));
    let (c, d) = (g * x + h * r, k * r);

    let build = |dst: &[u8], lhs: &G, bases: [Option<G>; 2]| {
        let mut builder = Statement::builder(dst, 2);
        builder
            .add_constraint(lhs, bases)
            .unwrap()
            .add_constraint(&d, [None, Some(k)])
            .unwrap();
        builder.build().unwrap()
    };
    let statement = build(DST, &c, [Some(g), Some(h)]);
    let proof = prove_and_verify(&statement, &[x, r]);

    // Both verifiers must reject a proof checked against any other statement...
    let rejected = |statement: Statement<G>, proof: &Proof<G>| {
        statement.verify(proof).is_err()
            && statement.verify_batched(proof, &mut thread_rng()).is_err()
    };
    assert!(rejected(
        build(b"other dst", &c, [Some(g), Some(h)]),
        &proof
    ));
    assert!(rejected(
        build(DST, &(c + G::generator()), [Some(g), Some(h)]),
        &proof
    ));
    assert!(rejected(
        build(DST, &c, [Some(g + G::generator()), Some(h)]),
        &proof
    ));
    assert!(rejected(build(DST, &c, [Some(h), Some(g)]), &proof));

    // ...a proof of the wrong shape...
    let short = Proof {
        commitments: proof.commitments().to_vec(),
        responses: proof.responses()[..1].to_vec(),
    };
    assert!(rejected(build(DST, &c, [Some(g), Some(h)]), &short));

    // ...and a proof where any single commitment has been tampered with.
    for i in 0..statement.num_constraints() {
        let mut commitments = proof.commitments().to_vec();
        commitments[i] += G::generator();
        let tampered = Proof {
            commitments,
            responses: proof.responses().to_vec(),
        };
        assert!(rejected(build(DST, &c, [Some(g), Some(h)]), &tampered));
    }
}

#[test]
fn test_invalid_inputs() {
    let (g, h) = (random_point(), random_point());
    let x = S::rand(&mut thread_rng());

    // A statement needs witnesses and at least one constraint.
    assert!(Statement::<G>::builder(DST, 0).build().is_err());
    assert!(Statement::<G>::builder(DST, 2).build().is_err());

    let mut builder = Statement::builder(DST, 2);

    // Each constraint needs exactly one base per witness, at least one of which is present.
    assert!(builder.add_constraint(&g, [Some(g)]).is_err());
    assert!(builder
        .add_constraint(&g, [Some(g), Some(h), Some(g)])
        .is_err());
    assert!(builder.add_constraint(&g, [None, None]).is_err());

    // A witness which is not constrained by any constraint.
    builder.add_constraint(&g, [Some(g), None]).unwrap();
    assert!(builder.build().is_err());

    // Proving needs one witness per column, and they must satisfy the statement.
    let mut builder = Statement::builder(DST, 1);
    builder.add_constraint(&(g * x), [Some(g)]).unwrap();
    let statement = builder.build().unwrap();
    assert!(statement.prove(&[], &mut thread_rng()).is_err());
    assert!(statement.prove(&[x, x], &mut thread_rng()).is_err());
    assert!(statement
        .prove(&[x + S::generator()], &mut thread_rng())
        .is_err());
}
