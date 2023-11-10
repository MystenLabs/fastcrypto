// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;

use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion};
use fastcrypto_vdf::class_group::{Discriminant, QuadraticForm};
use fastcrypto_vdf::vdf::wesolowski::StrongVDF;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::Parameter;
use num_bigint::BigInt;
use num_traits::Num;
use rand::{thread_rng, RngCore};

struct VerificationInputs {
    iterations: u64,
    discriminant: String,
    result: String,
    proof: String,
}

fn verify_single<M: Measurement>(parameters: VerificationInputs, c: &mut BenchmarkGroup<M>) {
    let discriminant =
        Discriminant::try_from(-BigInt::from_str_radix(&parameters.discriminant, 16).unwrap())
            .unwrap();
    let discriminant_size = discriminant.bits();

    let result_bytes = hex::decode(parameters.result).unwrap();
    let result = QuadraticForm::from_bytes(&result_bytes, &discriminant).unwrap();

    let proof_bytes = hex::decode(parameters.proof).unwrap();
    let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();

    let input = QuadraticForm::generator(&discriminant);

    let vdf = StrongVDF::new(discriminant, parameters.iterations);
    c.bench_function(discriminant_size.to_string(), move |b| {
        b.iter(|| vdf.verify(&input, &result, &proof))
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF verify".to_string());

    //1024 bits
    verify_single(VerificationInputs {
            iterations: 4000000,
            discriminant: "cd711f181153e08e08e5ba156db0c4e9469de76f2bd6b64f068f5007918727f5eaa5f6a0e090f82682a4ebf87befdea8f1253265d700ee3ca6b0fdb2677c633c7f37b62f0e0c13b402def0ba9abaf15e4c53bfb6bda0c7a0cad4439864af3eb9af6d6c4b10286eb8ff5e2de5b009196bc60c3000fde8d4b89b7674e61bc2d23f".to_string(),
            result: "02007e64ab640cfd39daeaeab7400797917a2635fca5988ae1ba5e9a7a0b234faf361ae103d36d0838574524a5bc0a6b0bdd8f5e8c90774e92194df23fd5929b343bc7e47a1a07270949ae1b37505a63414aec987e06eabc6738d1ec02b32d6da3690100".to_string(),
            proof: "0200c879069103e13f66c38ac8f34a8ec48ec7033f442128de49c7adf0732359e4da4682bff7ad6a2ca2767a39f9eaf4dec9c80fb950d2cb603458738b3d0e17855e6bf0586455e99e75fa23f0ae59e1a922c1d5b18b234428766028f5856b872f720100".to_string(),
        }, &mut group);

    // 2048 bits
    verify_single(VerificationInputs {
            iterations: 4000000,
            discriminant: "f6901cd003679e2f451cda55b032fb49222a9b595b9e5948b793d2d7338d4da01937c637739e7f980d481b742c0fdc5255847ccc848359db822ed6ca7f33bdd54a207e24679c9f1f7e64be59e1bed7afbaa999770743984ed997c2c8187b5a80a0df200c040ac152dd6bb3bfdf3a7f151f2ddbd9debf6c841cebdc9f450cb42f51529ba04e6bda874b43461ed104b39257559bed53200d093f8e6c48f2b1c91e15e37ce695924eafd78fa4ba11e519f9a885399264d1a885d353ce128f1e044ef2feda125167e38ad5db7931b752847388c900868bc6bff2d83f7a6e055c618d3abc0ae104520df25508f40323c35d2d992303e12f1ae7bc44ffd5861d9f768f".to_string(),
            result: "0000d37421051f4f437a727a8d21825ef02a9c33744766947a59140d532756f231d42d8add13fe76e747b130a29becb75c3a3389ee1472325a479afb4275b7e9cf0cedc957e4409cfdea69e901fc8d810617381c0492de46e0387ee42eb3065468ceec55d17f072fa691341ff5b6d835abf35a47b90c127658c4bf4ec8ea6a4ae4177bd96aad7454c36e7bde4bb360a519c9d7b73ecd776d44d18d6441bc5fbe8724227c623477b5c307b89dcea707e1db547d4d0e8c7814e9f24ceedb55653585310100".to_string(),
            proof: "02000607e9272f517e3d7aaa2d3f5bcb5925b9e9c46e432b6b292223df502cc4487b5841d9c4f3746adfd1f058482220d38ddf4c6daf30d9cc0cf0cebb36a5b1ef9189e4ed78b022fae17b9fc2e16c6d3450df52877f67b3c7c06db17eb1f1ecb8c78310aa622935ff76abfb3bdf153604359438c1364269a80dd434149b658a6b6629ec86ba04a339b07b4ab71c1f2417c64a2cfa49138a62d0c02e753c1060df68a3f9ed04fc357742b6f927f7550ba79e52c429031ba3f353b9dd5fef6147c4190100".to_string(),
        }, &mut group);
}

fn sample_discriminant(c: &mut Criterion) {
    let bit_lengths = [128, 256, 512, 1024, 2048];

    let mut seed = [0u8; 32];

    let mut rng = thread_rng();

    for bit_length in bit_lengths {
        c.bench_with_input(
            BenchmarkId::new("Sample class group discriminant".to_string(), bit_length),
            &bit_length,
            |b, n| {
                b.iter(|| {
                    rng.try_fill_bytes(&mut seed).unwrap();
                    Discriminant::from_seed(&seed, *n).unwrap();
                })
            },
        );
    }
}

criterion_group! {
    name = vdf_benchmarks;
    config = Criterion::default().sample_size(100);
    targets = verify, sample_discriminant
}

criterion_main!(vdf_benchmarks);
