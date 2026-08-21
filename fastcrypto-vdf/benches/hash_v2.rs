// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks for the v2 hash-to-class-group function.
//!
//! The `k` sweep measures the running time as a function of the number of small prime factors. For
//! `k >= 1` the size of the large prime factor is held fixed and the image has size
//! ~2^(2 lambda) / k!, and the `k = 0` baseline samples its single prime from a set of size
//! 2^(2 lambda) so that its image is ~2^(2 lambda) too. All the points in the sweep are therefore
//! comparable at roughly equal image size, and the sweep measures the speed-up from splitting `a`
//! into several factors rather than the speed-up from shrinking the output.
//!
//! The `v1` group measures the current default hash function for comparison. Note that the v1
//! default (two prime factors of equal size) is the same configuration as v2 with `k = 1`, so those
//! two should give the same timings.

use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use num_bigint::BigInt;
use num_traits::Num;
use rand::{thread_rng, RngCore};

use fastcrypto_vdf::class_group::discriminant::Discriminant;
use fastcrypto_vdf::class_group::hash_v2::hash_to_group_v2_with_custom_parameters;
use fastcrypto_vdf::class_group::QuadraticForm;

/// The security parameter used for all the benchmarks below.
const SECURITY_PARAMETER_IN_BITS: u64 = 128;

/// A 3072 bit discriminant, which is the size recommended for the VDF on Sui.
const DISCRIMINANT_3072: &str = "-3956718340719431033560816005739172412770466038703883350122595604635576709778731043309649272634605425735063624961596232735523376358742586480084965522907889249504047757258883253188259997112353246294323895993621766064597867526555590598296171109353515435289599237581716817331650248439511065683812661746851260538223197043808247010651962962398117206670503394901226393544809521031397039151671384417895714291888633743136733122871000628264376743806741659217599861141099968091237561343232177937280916663464976799422526037223295835103220909629798144507776992742385829474209304917863091971426479552645067278361106093545925188309289850090156462919761399169738282697646499095260815062205117198915610910901974886408275636330747461116245431578813689565691787676837733109337359377237752443898143986060895378572144245069588193342265623936118710486379006798704589510096698445426370143184307451927004120706539519891935325715903611926844068327127";

/// A 2400 bit discriminant, included to check that the running time does not depend on the size of
/// the discriminant.
const DISCRIMINANT_2400: &str = "-197094279717529776652945533421408519016291293185778176422038767173246838389717778782272450609952179792102389097362657787152898007436991089430517979761145200893975140029279440383697629952398509684430189989830512427761221044255503309237697000446508821686655886069366603792908696660367648281136978401042076354619587515552611650395121072487799107192700364331538210709886133279169829259881605487142555274403314509719321602412760314496712012939372327177464352472192738122541539747842405435171078768578664156285412471750348778431888800482596404122201686947621151032470989798594881908508768154982514267787085456831726879055929531619461354230569362180363281846948763424056650300352728927552479847814231289623672826128091486169286759";

fn discriminant_from(s: &str) -> Discriminant {
    Discriminant::try_from(BigInt::from_str_radix(s, 10).unwrap()).unwrap()
}

fn k_sweep_single<M: Measurement>(discriminant_string: &str, group: &mut BenchmarkGroup<M>) {
    let discriminant = discriminant_from(discriminant_string);
    let bits = discriminant.bits();

    for k in 0..=4u64 {
        // A single prime sampled from a set of size 2^lambda would only give an image of
        // 2^lambda, so the baseline is run with twice the security parameter to give it the same
        // image size as the rest of the sweep.
        let security_parameter_in_bits = if k == 0 {
            2 * SECURITY_PARAMETER_IN_BITS
        } else {
            SECURITY_PARAMETER_IN_BITS
        };

        // Skip parameters which are rejected, e.g. because the discriminant is too small for the
        // output to be guaranteed reduced.
        let mut probe_seed = [0u8; 32];
        thread_rng().fill_bytes(&mut probe_seed);
        if hash_to_group_v2_with_custom_parameters(
            &probe_seed,
            &discriminant,
            security_parameter_in_bits,
            k,
        )
        .is_err()
        {
            continue;
        }

        let discriminant = discriminant.clone();
        group.bench_function(format!("{} bits/k = {}", bits, k), move |b| {
            let mut seed = [0u8; 32];
            b.iter(|| {
                // A fresh seed for every evaluation: the running time depends on how many
                // candidates are rejected, so a fixed seed would measure a single lucky or
                // unlucky sample.
                thread_rng().fill_bytes(&mut seed);
                hash_to_group_v2_with_custom_parameters(
                    &seed,
                    &discriminant,
                    security_parameter_in_bits,
                    k,
                )
            })
        });
    }
}

fn hash_v2_k_sweep(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Hash v2, k sweep".to_string());
    k_sweep_single(DISCRIMINANT_3072, &mut group);
    k_sweep_single(DISCRIMINANT_2400, &mut group);
}

fn hash_v1_baseline(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Hash v1, default".to_string());
    for discriminant_string in [DISCRIMINANT_3072, DISCRIMINANT_2400] {
        let discriminant = discriminant_from(discriminant_string);
        let bits = discriminant.bits();
        group.bench_function(format!("{} bits", bits), move |b| {
            let mut seed = [0u8; 32];
            b.iter(|| {
                thread_rng().fill_bytes(&mut seed);
                QuadraticForm::hash_to_group_with_default_parameters(&seed, &discriminant)
            })
        });
    }
}

criterion_group! {
    name = hash_v2_benchmarks;
    config = Criterion::default().sample_size(100);
    targets = hash_v2_k_sweep, hash_v1_baseline
}

criterion_main!(hash_v2_benchmarks);
