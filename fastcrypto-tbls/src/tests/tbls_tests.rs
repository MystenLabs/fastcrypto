// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::Poly;
use crate::tbls::Share;
use crate::{tbls::ThresholdBls, types::ThresholdBls12381MinSig};
use fastcrypto::groups::bls12381;
use rand::prelude::*;
use std::num::NonZeroU32;

#[test]
fn test_tbls_e2e() {
    let t = 3;
    let private_poly = Poly::<bls12381::Scalar>::rand(t - 1, &mut thread_rng());
    let public_poly = private_poly.commit();

    let share1 = private_poly.eval(NonZeroU32::new(1).unwrap());
    let share2 = private_poly.eval(NonZeroU32::new(10).unwrap());
    let share3 = private_poly.eval(NonZeroU32::new(100).unwrap());

    let msg = b"test";
    let sig1 = ThresholdBls12381MinSig::partial_sign(&share1, msg);
    let sig2 = ThresholdBls12381MinSig::partial_sign(&share2, msg);
    let sig3 = ThresholdBls12381MinSig::partial_sign(&share3, msg);

    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig1).is_ok());
    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig2).is_ok());
    assert!(ThresholdBls12381MinSig::partial_verify(&public_poly, msg, &sig3).is_ok());

    // Verify should fail with an invalid signature.
    assert!(
        ThresholdBls12381MinSig::partial_verify(&public_poly, b"other message", &sig1).is_err()
    );
    // Aggregate should fail if we don't have enough signatures.
    assert!(ThresholdBls12381MinSig::aggregate(t, &[sig1.clone(), sig2.clone()]).is_err());

    // Signatures should be the same no matter if calculated with the private key or from a
    // threshold of partial signatures.
    let full_sig = ThresholdBls12381MinSig::aggregate(t, &[sig1, sig2, sig3]).unwrap();
    assert!(ThresholdBls12381MinSig::verify(public_poly.c0(), msg, &full_sig).is_ok());
    assert_eq!(
        full_sig,
        ThresholdBls12381MinSig::partial_sign(
            &Share {
                index: NonZeroU32::new(1234).unwrap(),
                value: *private_poly.c0()
            },
            msg
        )
        .value
    );

    // Check batches
    let sigs = ThresholdBls12381MinSig::partial_sign_batch(&[share1, share2, share3], msg);
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        msg,
        &sigs,
        &mut thread_rng()
    )
    .is_ok());
    assert!(ThresholdBls12381MinSig::partial_verify_batch(
        &public_poly,
        b"other message",
        &sigs,
        &mut thread_rng()
    )
    .is_err());
}
