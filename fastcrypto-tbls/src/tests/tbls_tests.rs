// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dl_verification::verify_poly_evals;
use crate::polynomial::Poly;
use crate::tbls::{Share, UnindexedPartialSignatures};
use crate::types::ShareIndex;
use crate::{tbls::ThresholdBls, types::ThresholdBls12381MinSig};
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
use fastcrypto::groups::{bls12381, GroupElement};
use rand::prelude::*;
use std::num::NonZeroU16;

#[test]
fn test_tbls_e2e() {
    let t = 3;
    let private_poly = Poly::<bls12381::Scalar>::rand(t - 1, &mut thread_rng());
    let public_poly = private_poly.commit();

    let share1 = private_poly.eval(NonZeroU16::new(1).unwrap());
    let share2 = private_poly.eval(NonZeroU16::new(10).unwrap());
    let share3 = private_poly.eval(NonZeroU16::new(100).unwrap());
    let share4 = private_poly.eval(NonZeroU16::new(1000).unwrap());

    let msg = b"test";
    let sig1 = ThresholdBls12381MinSig::partial_sign(&share1, msg);
    let sig2 = ThresholdBls12381MinSig::partial_sign(&share2, msg);
    let sig3 = ThresholdBls12381MinSig::partial_sign(&share3, msg);
    let sig4 = ThresholdBls12381MinSig::partial_sign(&share4, msg);

    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig1).is_ok());
    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig2).is_ok());
    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig3).is_ok());
    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig4).is_ok());

    // Verify should fail with an invalid signature.
    assert!(
        ThresholdBls12381MinSig::partial_verify(&public_poly, b"other message", &sig1).is_err()
    );
    // Aggregate should fail if we don't have enough signatures.
    assert_eq!(
        ThresholdBls12381MinSig::aggregate(t, [sig1.clone(), sig2.clone()].iter()).unwrap_err(),
        FastCryptoError::NotEnoughInputs
    );
    // Even if duplicated
    assert_eq!(
        ThresholdBls12381MinSig::aggregate(t, [sig1.clone(), sig2.clone(), sig1.clone()].iter())
            .unwrap_err(),
        FastCryptoError::NotEnoughInputs
    );

    // Signatures should be the same no matter if calculated with the private key or from a
    // threshold of partial signatures.
    let full_sig =
        ThresholdBls12381MinSig::aggregate(t, [sig1.clone(), sig2.clone(), sig3.clone()].iter())
            .unwrap();
    assert!(ThresholdBls12381MinSig::verify(public_poly.c0(), msg, &full_sig).is_ok());
    assert_eq!(
        full_sig,
        ThresholdBls12381MinSig::partial_sign(
            &Share {
                index: NonZeroU16::new(1234).unwrap(),
                value: *private_poly.c0()
            },
            msg
        )
        .value
    );
    // duplicates shouldn't matter
    let another_sig = ThresholdBls12381MinSig::aggregate(
        t,
        [
            sig1.clone(),
            sig2.clone(),
            sig3.clone(),
            sig2.clone(),
            sig2.clone(),
        ]
        .iter(),
    )
    .unwrap();
    assert_eq!(full_sig, another_sig);

    // which subset of partial signatures we use shouldn't matter
    let another_sig =
        ThresholdBls12381MinSig::aggregate(t, [sig4.clone(), sig2.clone(), sig3.clone()].iter())
            .unwrap();
    assert_eq!(full_sig, another_sig);

    // if one of the partial sigs is invalid, the aggregated sig should be different and invalid
    let mut invalid_sig3 = sig3.clone();
    invalid_sig3.value = G1Element::generator();
    let another_sig =
        ThresholdBls12381MinSig::aggregate(t, [invalid_sig3, sig2, sig1].iter()).unwrap();
    assert_ne!(full_sig, another_sig);
    assert!(ThresholdBls12381MinSig::verify(public_poly.c0(), msg, &another_sig).is_err());
}

#[test]
fn test_partial_verify_batch() {
    let t = 3;
    let private_poly = Poly::<bls12381::Scalar>::rand(t - 1, &mut thread_rng());
    let public_poly = private_poly.commit();

    let share1 = private_poly.eval(NonZeroU16::new(1).unwrap());
    let share2 = private_poly.eval(NonZeroU16::new(10).unwrap());
    let share3 = private_poly.eval(NonZeroU16::new(100).unwrap());
    let shares = [share1, share2, share3];

    let msg = b"test";
    // no sigs should pass
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        [].iter(),
        &mut thread_rng()
    )
    .is_ok());
    // standard sigs should pass
    let sigs = ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), msg);
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        sigs.iter(),
        &mut thread_rng()
    )
    .is_ok());
    // even if repeated
    let mut sigs = ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), msg);
    sigs[0] = sigs[2].clone();
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        sigs.iter(),
        &mut thread_rng()
    )
    .is_ok());
    // different msg should fail
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        b"other message",
        sigs.iter(),
        &mut thread_rng()
    )
    .is_err());
    // invalid signatures according to the polynomial should fail
    let mut sigs = ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), msg);
    (sigs[0].index, sigs[1].index) = (sigs[1].index, sigs[0].index);
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        sigs.iter(),
        &mut thread_rng()
    )
    .is_err());
    // identity as the signature should fail
    let mut sigs = ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), msg);
    sigs[1].value = G1Element::zero();
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        sigs.iter(),
        &mut thread_rng()
    )
    .is_err());
    // generator as the signature should fail
    let mut sigs = ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), msg);
    sigs[1].value = G1Element::generator();
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        sigs.iter(),
        &mut thread_rng()
    )
    .is_err());
    // even if the sum of sigs is ok, should fail since not consistent with the polynomial
    let mut sigs = ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), msg);
    sigs[0].value -= G1Element::generator();
    sigs[1].value += G1Element::generator();
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        sigs.iter(),
        &mut thread_rng()
    )
    .is_err());
}

#[test]
fn test_verify_poly_evals() {
    let t = 3;
    let private_poly = Poly::<bls12381::Scalar>::rand(t - 1, &mut thread_rng());
    let public_poly: Poly<G2Element> = private_poly.commit();

    // no evals should pass
    assert!(verify_poly_evals(&[], &public_poly, &mut thread_rng()).is_ok());
    // standard evals should pass
    let shares = [1, 10, 100]
        .into_iter()
        .map(|i| private_poly.eval(NonZeroU16::new(i).unwrap()))
        .collect::<Vec<_>>();
    assert!(verify_poly_evals(&shares, &public_poly, &mut thread_rng()).is_ok());
    // even if repeated
    let shares = [1, 10, 10]
        .into_iter()
        .map(|i| private_poly.eval(NonZeroU16::new(i).unwrap()))
        .collect::<Vec<_>>();
    assert!(verify_poly_evals(&shares, &public_poly, &mut thread_rng()).is_ok());
    // invalid evals according to the polynomial should fail
    let mut shares = [1, 10, 100]
        .into_iter()
        .map(|i| private_poly.eval(NonZeroU16::new(i).unwrap()))
        .collect::<Vec<_>>();
    (shares[0].index, shares[1].index) = (shares[1].index, shares[0].index);
    assert!(verify_poly_evals(&shares, &public_poly, &mut thread_rng()).is_err());
    // identity as the eval should fail
    let mut shares = [1, 10, 100]
        .into_iter()
        .map(|i| private_poly.eval(NonZeroU16::new(i).unwrap()))
        .collect::<Vec<_>>();
    shares[0].value = Scalar::zero();
    assert!(verify_poly_evals(&shares, &public_poly, &mut thread_rng()).is_err());
    // generator as the eval should fail
    let mut shares = [1, 10, 100]
        .into_iter()
        .map(|i| private_poly.eval(NonZeroU16::new(i).unwrap()))
        .collect::<Vec<_>>();
    shares[0].value = Scalar::generator();
    assert!(verify_poly_evals(&shares, &public_poly, &mut thread_rng()).is_err());
    // even if the sum of evals is ok, should fail since not consistent with the polynomial
    let mut shares = [1, 10, 100]
        .into_iter()
        .map(|i| private_poly.eval(NonZeroU16::new(i).unwrap()))
        .collect::<Vec<_>>();
    shares[0].value += Scalar::generator();
    shares[1].value -= Scalar::generator();
    assert!(verify_poly_evals(&shares, &public_poly, &mut thread_rng()).is_err());
}

#[test]
fn test_unindexed() {
    let private_poly = Poly::<bls12381::Scalar>::rand(99, &mut thread_rng());
    let share_ids = (1..=1)
        .map(|i| ShareIndex::new(i).unwrap())
        .collect::<Vec<_>>();
    let shares = share_ids
        .iter()
        .map(|i| private_poly.eval(*i))
        .collect::<Vec<_>>();
    let msg = b"test";
    let sigs = shares
        .iter()
        .map(|s| ThresholdBls12381MinSig::partial_sign(s, msg))
        .collect::<Vec<_>>();

    let compact: UnindexedPartialSignatures<G1Element> = sigs.clone().into();
    let sigs2 = compact.add_indexes(&share_ids).unwrap();
    assert_eq!(sigs, sigs2);
}
