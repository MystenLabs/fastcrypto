// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, Criterion};
use fastcrypto_vdf::class_group::{Discriminant, QuadraticForm};
use fastcrypto_vdf::vdf::wesolowski::ClassGroupVDF;
use fastcrypto_vdf::vdf::VDF;
use num_bigint::BigInt;
use num_traits::Num;

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

    let vdf = ClassGroupVDF::new(discriminant, parameters.iterations);
    c.bench_function(discriminant_size.to_string(), move |b| {
        b.iter(|| vdf.verify(&input, &result, &proof))
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF verify");

    // Note that the number of iterations are quite low, but this has very little influence on the benchmark results.

    //1024 bits
    verify_single(VerificationInputs {
            iterations: 1000,
            discriminant: "cd711f181153e08e08e5ba156db0c4e9469de76f2bd6b64f068f5007918727f5eaa5f6a0e090f82682a4ebf87befdea8f1253265d700ee3ca6b0fdb2677c633c7f37b62f0e0c13b402def0ba9abaf15e4c53bfb6bda0c7a0cad4439864af3eb9af6d6c4b10286eb8ff5e2de5b009196bc60c3000fde8d4b89b7674e61bc2d23f".to_string(),
            result: "030039c78c39cff6c29052bfc1453616ec7a47251509b9dbc33d1036bebd4d12e6711a51deb327120310f96be04c90fd4c3b1dab9617c3133132b827abe7bb2348707da8164b964e1b95cd6a8eaf36ffb80bab1f750410e793daec8228b222bd00370100".to_string(),
            proof: "000075d043db5f619f5cb4e8ef7729c7cac154434c33d6e52dd086b90a52c7b1231890eda9d1365100e88993e332f0a99bb7763f215de2fb6b632445beeeff22b657dc90d4e110ed03eac10ec445117d211208c79dd4933ba58b8e17b4c54ef1824c0100".to_string(),
        }, &mut group);

    // 2048 bits
    verify_single(VerificationInputs {
            iterations: 1000,
            discriminant: "f6901cd003679e2f451cda55b032fb49222a9b595b9e5948b793d2d7338d4da01937c637739e7f980d481b742c0fdc5255847ccc848359db822ed6ca7f33bdd54a207e24679c9f1f7e64be59e1bed7afbaa999770743984ed997c2c8187b5a80a0df200c040ac152dd6bb3bfdf3a7f151f2ddbd9debf6c841cebdc9f450cb42f51529ba04e6bda874b43461ed104b39257559bed53200d093f8e6c48f2b1c91e15e37ce695924eafd78fa4ba11e519f9a885399264d1a885d353ce128f1e044ef2feda125167e38ad5db7931b752847388c900868bc6bff2d83f7a6e055c618d3abc0ae104520df25508f40323c35d2d992303e12f1ae7bc44ffd5861d9f768f".to_string(),
            result: "02001222c470df6df6e1321aa1c28279d0c64663c7f066888ff6cd854dcd5deb71f63dfe0b867675180fada390e0d7b1ff735b55fea2b88123a32d1e1239126b275578ea26a4a89e5ef290e2b7b8d072ab819d5b9422770339dc87fd4dc4ebf6add3e391067a557be4be5436355ab11035609d5a3dc71e95cf2a0dcbb228b85d9750a1dc670ac51822d7eff49b5cacd4a8cc485e53bbf7e44f95e7fd5ec55fca44eb91c4831b1e839d8b4c8453dce8be69698bc5cb8fa45120d201057e4d72a6746b0100".to_string(),
            proof: "03008b91b20ab570b701d394aa095d8c670d95a8a3b26af966e979a27acf417421360ea54014668a121139ab11fe92cc0a8d192a8a675f244f3016ed23a7a82d9dd70de089d5bcb5bb0c9535923b2656b19c8cf0cc6e0e4c800c44fc17e16a1b96572f6e0e0967709af259b854a51bec270e5cf73cc4efa93791ac6a84dc2ab77f02d0234ac60b2a04740644ac845204c67f9063ab139e9a0eb25c4417c892ca52299202d3854243d7eb58cc46a837745a1eb92699eb89138eec89467f7226380b040600".to_string(),
        }, &mut group);
}

criterion_group! {
    name = vdf_benchmarks;
    config = Criterion::default().sample_size(100);
    targets = verify,
}

criterion_main!(vdf_benchmarks);
