// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::{Fq, Fq2, Fr as BlsFr};
use ark_bls12_381::{Fq12, G2Affine as BlsG2Affine};
use ark_bls12_381::{Fq6, G1Affine as BlsG1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use criterion::{criterion_group, Criterion};
use criterion::{measurement::Measurement, BenchmarkGroup};
use fastcrypto_zkp::bls12381::conversions::{
    bls_fq12_to_blst_fp12, bls_fq2_to_blst_fp2, bls_fq6_to_blst_fp6, bls_fq_to_blst_fp,
    bls_fr_to_blst_fr, bls_g1_affine_to_blst_g1_affine, bls_g2_affine_to_blst_g2_affine,
    blst_fp12_to_bls_fq12, blst_fp2_to_bls_fq2, blst_fp6_to_bls_fq6, blst_fp_to_bls_fq,
    blst_fr_to_bls_fr, blst_g1_affine_to_bls_g1_affine, blst_g2_affine_to_bls_g2_affine,
};
use std::ops::Mul;

fn convert_from_arkworks<M: Measurement>(grp: &mut BenchmarkGroup<M>) {
    let mut rng = ark_std::test_rng();
    let element = BlsFr::rand(&mut rng);
    grp.bench_with_input("BlsFr -> blst_fr", &element, |b, element| {
        b.iter(|| bls_fr_to_blst_fr(element));
    });

    let element = Fq::rand(&mut rng);
    grp.bench_with_input("Fq -> blst_fp", &element, |b, element| {
        b.iter(|| bls_fq_to_blst_fp(element));
    });

    let element = Fq2::rand(&mut rng);
    grp.bench_with_input("Fq2 -> blst_fp2", &element, |b, element| {
        b.iter(|| bls_fq2_to_blst_fp2(element));
    });

    let element = Fq6::rand(&mut rng);
    grp.bench_with_input("Fq6 -> blst_fp6", &element, |b, element| {
        b.iter(|| bls_fq6_to_blst_fp6(element));
    });

    let element = Fq12::rand(&mut rng);
    grp.bench_with_input("Fq12 -> blst_fp12", &element, |b, element| {
        b.iter(|| bls_fq12_to_blst_fp12(element));
    });

    let scalar = BlsFr::rand(&mut rng);
    let element = BlsG1Affine::generator().mul(scalar).into_affine();
    grp.bench_with_input("G1Affine -> blst_p1_affine", &element, |b, element| {
        b.iter(|| bls_g1_affine_to_blst_g1_affine(element));
    });

    let scalar = BlsFr::rand(&mut rng);
    let element = BlsG2Affine::generator().mul(scalar).into_affine();
    grp.bench_with_input("G2Affine -> blst_p2_affine", &element, |b, element| {
        b.iter(|| bls_g2_affine_to_blst_g2_affine(element));
    });
}

fn convert_from_blst<M: Measurement>(grp: &mut BenchmarkGroup<M>) {
    let mut rng = ark_std::test_rng();
    let bls = BlsFr::rand(&mut rng);
    let element = bls_fr_to_blst_fr(&bls);
    grp.bench_with_input("blst_fr -> BlsFr", &element, |b, element| {
        b.iter(|| blst_fr_to_bls_fr(element));
    });

    let bls = Fq::rand(&mut rng);
    let element = bls_fq_to_blst_fp(&bls);
    grp.bench_with_input("blst_fp -> Fp", &element, |b, element| {
        b.iter(|| blst_fp_to_bls_fq(element));
    });

    let bls = Fq2::rand(&mut rng);
    let element = bls_fq2_to_blst_fp2(&bls);
    grp.bench_with_input("blst_fp2 -> Fq2", &element, |b, element| {
        b.iter(|| blst_fp2_to_bls_fq2(element));
    });

    let bls = Fq6::rand(&mut rng);
    let element = bls_fq6_to_blst_fp6(&bls);
    grp.bench_with_input("blst_fp6 -> Fq6", &element, |b, element| {
        b.iter(|| blst_fp6_to_bls_fq6(element));
    });

    let bls = Fq12::rand(&mut rng);
    let element = bls_fq12_to_blst_fp12(&bls);
    grp.bench_with_input("blst_fp12 -> Fq12", &element, |b, element| {
        b.iter(|| blst_fp12_to_bls_fq12(element));
    });

    let scalar = BlsFr::rand(&mut rng);
    let bls = BlsG1Affine::generator().mul(scalar).into_affine();
    let element = bls_g1_affine_to_blst_g1_affine(&bls);
    grp.bench_with_input("blst_p1_affine -> G1Affine", &element, |b, element| {
        b.iter(|| blst_g1_affine_to_bls_g1_affine(element));
    });

    let scalar = BlsFr::rand(&mut rng);
    let bls = BlsG2Affine::generator().mul(scalar).into_affine();
    let element = bls_g2_affine_to_blst_g2_affine(&bls);
    grp.bench_with_input("blst_p2_affine -> G2Affine", &element, |b, element| {
        b.iter(|| blst_g2_affine_to_bls_g2_affine(element));
    });
}

fn to_from_arkworks(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Conversions Arkworks -> Blst");
    convert_from_arkworks(&mut group);
    group.finish();
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Conversions Blst -> Arkworks");
    convert_from_blst(&mut group);
    group.finish();
}

criterion_group! {
    name = conversion_benches;
    config = Criterion::default();
    targets =
       to_from_arkworks,
}
