// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::fake_tbls_key_generator::*;
use tbls::sig::{SignatureScheme, ThresholdScheme};

const MSG: [u8; 4] = [1, 2, 3, 4];

#[test]
fn test_different_parameters() {
    let (_, bls_pk1, vss_pk1) = geneate_partial_key_pair(3, 1, 10);
    let (_, bls_pk2, vss_pk2) = geneate_partial_key_pair(3, 1, 5);
    let (_, bls_pk3, vss_pk3) = geneate_partial_key_pair(4, 1, 11);
    let (_, bls_pk4, vss_pk4) = geneate_partial_key_pair(3, 2, 10);

    assert_eq!(bls_pk1, bls_pk2);
    assert_eq!(bls_pk1, bls_pk3);
    assert_ne!(bls_pk1, bls_pk4);
    assert_eq!(vss_pk1, vss_pk2);
    assert_ne!(vss_pk1, vss_pk3);
    assert_ne!(vss_pk1, vss_pk4);

    let (bls_pk5, vss_pk5) = geneate_public_key(3, 1);
    assert_eq!(bls_pk1, bls_pk5);
    assert_eq!(vss_pk1, vss_pk5);

    let (_, pk) = geneate_full_key_pair(1);
    assert_eq!(bls_pk1, pk);
}

#[test]
fn test_e2e() {
    let (share1, bls_pk1, vss_pk1) = geneate_partial_key_pair(3, 100, 10);
    let (share2, _, _) = geneate_partial_key_pair(3, 100, 11);
    let (share3, _, _) = geneate_partial_key_pair(3, 100, 12);

    let sig1 = Scheme::partial_sign(&share1, &MSG).unwrap();
    let sig2 = Scheme::partial_sign(&share2, &MSG).unwrap();
    let sig3 = Scheme::partial_sign(&share3, &MSG).unwrap();

    Scheme::partial_verify(&vss_pk1, &MSG, &sig1).unwrap();
    Scheme::partial_verify(&vss_pk1, &MSG, &sig2).unwrap();
    Scheme::partial_verify(&vss_pk1, &MSG, &sig3).unwrap();

    let sigs = vec![sig1, sig2, sig3];
    let sig1 = Scheme::aggregate(3, &sigs).unwrap();
    Scheme::verify(&bls_pk1, &MSG, &sig1).unwrap();

    // Check that a signature is deterministically derived from the same private key.
    let (sk, _) = geneate_full_key_pair(100);
    let sig2 = Scheme::sign(&sk, &MSG).unwrap();
    assert_eq!(sig1, sig2);
}
