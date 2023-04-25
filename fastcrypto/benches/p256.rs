// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;
extern crate rand;

mod p256_benches {
    use super::*;
    use ark_ff::Fp256;
    use ark_ff::PrimeField as ArkPrimeField;
    use criterion::*;
    use elliptic_curve::group::GroupEncoding;
    use elliptic_curve::sec1::FromEncodedPoint;
    use elliptic_curve::sec1::UncompressedPoint;
    use elliptic_curve::PrimeField;
    use fastcrypto::encoding::{Encoding, Hex};
    use p256::{CompressedPoint, FieldBytes};
    use std::str::FromStr;

    fn add(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Add (secp256r1)");

        // p256
        let p = p256::ProjectivePoint::from_encoded_point(&p256::EncodedPoint::from_str("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5").unwrap()).unwrap();
        let q = p256::ProjectivePoint::from_encoded_point(&p256::EncodedPoint::from_str("047CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC4766997807775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1").unwrap()).unwrap();
        group.bench_function("p256", move |b| b.iter(|| &p + &q));

        // eccoxide
        let x = eccoxide::curve::sec2::p256r1::FieldElement::from_slice(
            &Hex::decode("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
                .unwrap(),
        )
        .unwrap();
        let y = eccoxide::curve::sec2::p256r1::FieldElement::from_slice(
            &Hex::decode("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
                .unwrap(),
        )
        .unwrap();
        let p = eccoxide::curve::sec2::p256r1::PointAffine::from_coordinate(&x, &y).unwrap();
        let p = eccoxide::curve::sec2::p256r1::Point::from_affine(&p);

        let x = eccoxide::curve::sec2::p256r1::FieldElement::from_slice(
            &Hex::decode("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978")
                .unwrap(),
        )
        .unwrap();
        let y = eccoxide::curve::sec2::p256r1::FieldElement::from_slice(
            &Hex::decode("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1")
                .unwrap(),
        )
        .unwrap();
        let q = eccoxide::curve::sec2::p256r1::PointAffine::from_coordinate(&x, &y).unwrap();
        let q = eccoxide::curve::sec2::p256r1::Point::from_affine(&q);
        group.bench_function("eccoxide", move |b| b.iter(|| &p + &q));

        // arkworks
        let x = ark_secp256r1::Fq::from_be_bytes_mod_order(
            &Hex::decode("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
                .unwrap(),
        );
        let y = ark_secp256r1::Fq::from_be_bytes_mod_order(
            &Hex::decode("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
                .unwrap(),
        );
        let p = ark_secp256r1::Affine::new(x, y);

        let x = ark_secp256r1::Fq::from_be_bytes_mod_order(
            &Hex::decode("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978")
                .unwrap(),
        );
        let y = ark_secp256r1::Fq::from_be_bytes_mod_order(
            &Hex::decode("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1")
                .unwrap(),
        );
        let q = ark_secp256r1::Affine::new(x, y);

        group.bench_function("arkworks", move |b| b.iter(|| p + &q));
    }

    fn mul(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Mul (secp256r1)");

        // p256
        let p = p256::ProjectivePoint::from_encoded_point(&p256::EncodedPoint::from_str("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5").unwrap()).unwrap();
        let s = p256::Scalar::from_repr(p256::FieldBytes::from([42u8; 32])).unwrap();
        group.bench_function("p256", move |b| b.iter(|| &p * &s));

        // eccoxide
        let x = eccoxide::curve::sec2::p256r1::FieldElement::from_slice(
            &Hex::decode("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
                .unwrap(),
        )
        .unwrap();
        let y = eccoxide::curve::sec2::p256r1::FieldElement::from_slice(
            &Hex::decode("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
                .unwrap(),
        )
        .unwrap();
        let p = eccoxide::curve::sec2::p256r1::PointAffine::from_coordinate(&x, &y).unwrap();
        let p = eccoxide::curve::sec2::p256r1::Point::from_affine(&p);
        let s = eccoxide::curve::sec2::p256r1::Scalar::from_bytes(&[42u8; 32]).unwrap();
        group.bench_function("eccoxide", move |b| b.iter(|| &p * &s));

        // // arkworks
        let x = ark_secp256r1::Fq::from_be_bytes_mod_order(
            &Hex::decode("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
                .unwrap(),
        );
        let y = ark_secp256r1::Fq::from_be_bytes_mod_order(
            &Hex::decode("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
                .unwrap(),
        );
        let p = ark_secp256r1::Affine::new(x, y);
        let s = ark_secp256r1::Fr::from(Fp256::from_le_bytes_mod_order(&[42u8; 32]));
        group.bench_function("arkworks", move |b| b.iter(|| p * &s));
    }

    criterion_group! {
        name = p256_benches;
        config = Criterion::default();
        targets = add, mul,
    }
}

criterion_main!(p256_benches::p256_benches,);
