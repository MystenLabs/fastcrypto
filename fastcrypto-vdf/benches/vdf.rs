// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;

use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion};
use fastcrypto_vdf::class_group::discriminant::Discriminant;
use fastcrypto_vdf::class_group::QuadraticForm;
use fastcrypto_vdf::math::parameterized_group::Parameter;
use fastcrypto_vdf::vdf::wesolowski::DefaultVDF;
use fastcrypto_vdf::vdf::VDF;
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
    let result = bcs::from_bytes(&result_bytes).unwrap();

    let proof_bytes = hex::decode(parameters.proof).unwrap();
    let proof = bcs::from_bytes(&proof_bytes).unwrap();

    let input = QuadraticForm::generator(&discriminant);

    let vdf = DefaultVDF::new(discriminant.clone(), parameters.iterations);
    c.bench_function(discriminant_size.to_string(), move |b| {
        b.iter(|| vdf.verify(&input, &result, &proof))
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF verify".to_string());

    //1024 bits
    verify_single(VerificationInputs {
            iterations: 1000    ,
            discriminant: "cd711f181153e08e08e5ba156db0c4e9469de76f2bd6b64f068f5007918727f5eaa5f6a0e090f82682a4ebf87befdea8f1253265d700ee3ca6b0fdb2677c633c7f37b62f0e0c13b402def0ba9abaf15e4c53bfb6bda0c7a0cad4439864af3eb9af6d6c4b10286eb8ff5e2de5b009196bc60c3000fde8d4b89b7674e61bc2d23f".to_string(),
            result: "0040256cb7ee900af2bc1f6b48214aeabed12a3afbbdcedc8d5afed7ebaf11493cf4b51522f709b103eae1c03b4b6be9f0cca48be552ac8841326de30c18c611022a00401bb4eec1c0354851d54fbddc71d798dd2d4b7cd3db4042cb83d39d242619289b9291794cee5661e71e43ec6d49e218af7db4fc5ad437af3f0e7006b98e414fb5".to_string(),
            proof: "00400e511ea4cd3ca68c803fc325cf02fb05f98e428beb666d7b80b0cd3562b7ef06049b0895472a2c99708381f0e0f2935fa715a2ca6a3baf4d30f1af97e3996542004001acb56024a0094f39e3737862758e9aa379a2cbcd6e1c547839defec353e21a07db12139a9350da58db3f07865433d223cd87ce418ba66cfd00934c55ab5e1f".to_string(),
        }, &mut group);

    // 2048 bits
    verify_single(VerificationInputs {
            iterations: 1000,
            discriminant: "f6901cd003679e2f451cda55b032fb49222a9b595b9e5948b793d2d7338d4da01937c637739e7f980d481b742c0fdc5255847ccc848359db822ed6ca7f33bdd54a207e24679c9f1f7e64be59e1bed7afbaa999770743984ed997c2c8187b5a80a0df200c040ac152dd6bb3bfdf3a7f151f2ddbd9debf6c841cebdc9f450cb42f51529ba04e6bda874b43461ed104b39257559bed53200d093f8e6c48f2b1c91e15e37ce695924eafd78fa4ba11e519f9a885399264d1a885d353ce128f1e044ef2feda125167e38ad5db7931b752847388c900868bc6bff2d83f7a6e055c618d3abc0ae104520df25508f40323c35d2d992303e12f1ae7bc44ffd5861d9f768f".to_string(),
            result: "00802a5242cb58dd6f80ca89e09f79b94a5e1ae6f6def78ca6a863b5628bdb799c1311972122f00a7c59ce83d164e2adc66cb2f96e1006a21cea0daa48351a0127fa9fa9563ff7e191f51a88f8dba994c6878a6dd79282162de6dcf5b3b74bf7ace58f9f51b19697d1322409d78d1765f17ec985c0af25e4e722876370ec27c3fa820080e3adfb5aaa6bf0c6b4c710cef41d7656c3409d92fe287b2a5c6956bc32fed10e7f45374ec851f35b56adda657f3efdefd0d1f7125db0a1d61b25c9112d18206b9c714f0f87ad95e29b2262c1ed2115f4c1d1cc5ae26185271ff4081ef97048c319f3d7651fd6a06a61b8b9f071435c0f329f88b79a03b24c1bfb1492b4a51453".to_string(),
            proof: "00806225f36bb72ba4f478f487ff52ca4994a2710e72863b045f8330d7cf2c59613032e02398b6a3e12ec748d6a645e75c7e09d1904ecd919927685ad6449b145ac713e27e078177b16edcb9ec660c283cd681f92dc30dc5593934b6ef321c28d14a9ca968f7310292720014c2370b38213f4ae70760009a35a888ca2f9f3cb7619300801e0b7a624be0889d5b717f3efe67e21d4e899e7acdf29419e77b2e0dbd8108971be3d69e5f06c43a0d51552b15aa1bd8d9bd4c8618e914c7e7cafe58463dbc03c3125f167a71bd893aac6f43e584e9a2f05658a4b4612bb40f12669a1e2c1e81771125481f15292ddd90426a0f995eb5a3676491b780aa8fbb7f0c6c1f51e4c5".to_string(),
        }, &mut group);

    // 2400 bits
    verify_single(VerificationInputs {
        iterations: 1000,
        discriminant: "c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7".to_string(),
        result: "00966b02104b26a5258211aac2d1b9a428b49517b18ad54d53df4a7fa78a187e4e143f382b4beea5884c0ef293e5534ceecdaf589b56a297e01c7d5deee66af343b6591a042ccb04dfe8b90fd6a445f9f8550821936172ad04cd41d786bfe2e05d5c7ac225a5e6de4727f4d44b45b25a3834ecfb2be0cf3e0a3bc399b5776ad866003d163368c009c7cf0ebab3111f9ea7725d916d7569880096123bda1054d8abf8345879fef58f49e896a4c9e705c806524fb213956d9c3d4dbb526452715051dd69a706ca96a5657bd22deef10bc0cfe18c7025142b0541317d7b47e879ae8f00e67830eb5cd3cae7111b3b745240c8dc8dc88422e16e75e78a7b4687d5e9329becd9cbc26f109da7aa0d6c45f4edb87210d7febc06834bfd0f6ed7f261aedfd3bd0c3014bce1222fa43fe06e11ed".to_string(),
        proof: "00965f15f1616e2ce2d08825047aeb88deecfb41ac531c7aff0210fd57c9419688d5c05aaf35cff5371377bc739afc8d5aabee7caceecd6d9be5fa84f9f919ac24c3e8ac24b447dc8134aed367d21fdee9de708b43efc8667e4697e7d3afbd74174ac4554e7e0f17a51177a5e7f3418d58aa596e1f3183c0a52b2d5cf667f8c8825f0a84784fefdcffc6e95f142c0c5d54d3ed2a9677b8830096487f31cae27beba43bc003a323846b7531a244508629b304a2dc697252575fa4beaeb8d3f5d5eaa5f00f45be479aabbcf5c09cbce4b026c1d6ab1e2d3c8efdb72d4b5c17475c83c5ba56ffeaae5ddcd79699527e9540e90580df37d9929eab622c57655bfcb65d00d32d900fce4ce98743a516f2a04342de52ed8dd07c136afd89a3767745ab309707473022650b3c772eda27507585".to_string(),
    }, &mut group);

    // 3072 bits
    verify_single(VerificationInputs {
        iterations: 1000,
        discriminant: "ca25a5acb1857bd8defd2c2df2daf2b45c980c7051f325c6c1c988f70c69a1083b2fc2167d5bd49c459a67395c2adf26d2f55076c9e77bd777c1e4b195271f0d76bf4bf763a2b1d05b09627567d44175fcfa02ff7b44688b182aaafa17625c87c219e4855fdc1d574d6a5032fd640c5dc3fc2452ccb3c20e1b859e9a18384935ff94971f221983bc96aa7db8d3f311b45f27de6bd7401a7ffc020742f822089dd8b4c43e6ae1818124156830b0905ccfc2c3a87f999902a15ce5c58c5fd0d07e6fb182c0801c81fecab479b69a0a215f732fff8f15edb166508624549c56a7490358544e1f7e65f687262f005c37f66d44130efa98270abde4ee11e6d4a2ed2a051e943a3503f898f2fdcf2501291240af1520b2b0fe3aaa68448b99f0196ef66e2ebdb53d4269c7a8d3839f519f51276aec12d2983a3ce564af1a6ad81b2c555c963b3ed779c7177fdabaeb132456dc9b1151d367f867f899260d8b7c0fc3bbad1c1731b04a71286362830c5bc0fb37e5e06492e561f4f044d69a71ce41bfbf".to_string(),
        result: "00c068915b8f4d32ae5175b1dfa701328a774ee226b7372f6c4ab9d31635d70cae240e06d03934636cfd4a3565deeeec89208652601cdc012a891053396c62be292f1e147a485f2336f1ed74356c980564b071241279f665942ec208f80d6506df50eef8d780f638a5c11d1cbc861cfd83a1483556d002e5dd7e9bf9b6d56f10e02be1067d98498ed7a63fcd9dc086a80d3bf9d62828c8708aa4b19621001e22bb84865a39cfde6a982397ada6c4a912ff84f107cb468d99f49336992980ae29a2f400c0066df5529847d0b2c83b7f48d547c97e95f25350d89b7cf1cbb1e2ca3c87af66f8b882e9900b5f5f4a435e28a726484870677159d1424f2788197f42301dc15c20262e376d26e329b7915449a12be8eb86c5539e10d3ed373fa771404999013fc8e57c117d05edd1ab5fce9a7bbf72cc6724b3a1e55d0dc2e250f3c7447c30eadaaa1b857d000aa2084fc454d7c755f691807a86585a8697c4f42bbba5f2a494c7bb58a12c074696c02c2f9ae072946ffe7f44bf83233b10c34432fc572f46e1".to_string(),
        proof: "00c02f59b39416f3f7d4206c589c3df646ce2d62927942b565d7109e8e2f8523604f029b0470b9ce94ee6f0b426f8d6f299a31cfe926bea1c660cc23efabbb0a7853db0c9d13dffeb8e4cdd4862048cbca267f87492053eced3ecee4f9d382378bdb0c44adc847d4c0f09adf08a4e05addd3b22bf2c215c1929669c107c39e4c57ef2be48913ba4e585fef30e38a7f001c53df71dd7d17bb62814ea879d68916c827f1eb209e09a95fa661f6c513c7c979316b3bf5663ed1f1a3f2bd20a07c69c94b00c02709d5517799883520129b148925f3215c6e707bede8fe5a0f1066e09b8b193e79e27e9ce9a9f3001ddb539ba0fc95e77dbc2edea5aa083e88c9bd6e276a687dfdc71ddba3fac21e7768c7e4574078a0203ef3a676c846d7d944e650cfdec6fa6a9953d62dc272b2b20444ca4d8400b639bb6c47c4a2e9e79c68b00dbd5ed9ae7b6a569836099e6aae945accd9a49ee2032bfa26b5d9f12d1254d4a7ad0b8a960f3f9ab7a7d37a8e805e6fb14b2a200f5040436a887f9fe90eac07961d4c6dc7".to_string(),
    }, &mut group);
}

fn sample_discriminant(c: &mut Criterion) {
    let bit_lengths = [512, 1024, 2048, 2400, 3072];

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
