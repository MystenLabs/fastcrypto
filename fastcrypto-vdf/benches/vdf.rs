// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;

use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion};
use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
use fastcrypto_vdf::class_group::{Discriminant, QuadraticForm};
use fastcrypto_vdf::hash_prime::{hash_prime_with_index, verify_prime, DefaultPrimalityCheck};
use fastcrypto_vdf::vdf::wesolowski::CHALLENGE_SIZE;
use fastcrypto_vdf::vdf::wesolowski::{FastVerifier, StrongFiatShamir, StrongVDF};
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
    let result_copy = result.clone();

    let proof_bytes = hex::decode(parameters.proof).unwrap();
    let proof = QuadraticForm::from_bytes(&proof_bytes, &discriminant).unwrap();
    let proof_copy = proof.clone();

    let input = QuadraticForm::generator(&discriminant);
    let input_copy = input.clone();

    let vdf = StrongVDF::new(discriminant.clone(), parameters.iterations);
    c.bench_function(discriminant_size.to_string(), move |b| {
        b.iter(|| vdf.verify(&input, &result, &proof))
    });

    let vdf = StrongVDF::new(discriminant.clone(), parameters.iterations);
    let fast_verify: FastVerifier<
        QuadraticForm,
        StrongFiatShamir<QuadraticForm, CHALLENGE_SIZE, DefaultPrimalityCheck>,
        WindowedScalarMultiplier<QuadraticForm, BigInt, 256, 5>,
    > = FastVerifier::new(vdf, input_copy);
    c.bench_function(format!("{} fast", discriminant_size), move |b| {
        b.iter(|| fast_verify.verify(&result_copy, &proof_copy))
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

    // 1920 bits
    verify_single(VerificationInputs {
        iterations: 4000000,
        discriminant: "e37a9660bbf697dd07dac9f90fb938f568ba8a89925deca82a67297d8c53964a894522daf6befb8b7604c4e2de6f67743583ff319a9dc0c44c4e78676eb26adbfb45b18a91078276f750cec4079b1f20061a372b0818f5aae37f2a159d5cf4d371d15dacb72c54c9fe9b82133037e57d207573e38c0ba28eeba9d3c0d0cf1d32c87cd1cbe5c7601df176d63c0f474f7448fc20b15c4cd2f185b593a94d7848ed277875103fbc90d951040e29e0dcfc37f563bddca7b07a59d838afece110fe059e03370044fc7efb587fcb4ec683005136a501c6ed595f6a19b67c618054c50cbf5b321a6f22ff8d2b5bab88118c9147".to_string(),
        result: "010012ed29bcfe7a6939d29699ecd38c7e00e616e69409009ca47b720312af5f54cb2368133a1480defb053fa22c29ebba9b9cced63b3330a226087752e476cfac2fc342a7d56ec8f5f52782aa8239448bf9620b7d5ac4e69e3035e407126c2b31ee2d6cb264df1ba8b4d35e2abe1666bb39c3008aaf9d79d15389a7dffab30538ed359a3b7f0f6e6e69c5b43e303ea1c62b4f0c1ac7a8072ac5e27f57d9c965bb8a92e8a31da5dbdc4dc7f04e0f7dc31ca9f08936770100".to_string(),
        proof: "02001914203503394696de252a63529ca5cd748b97c6cc537f52369cce279f726201501ed29f139aa35311bb53d740ddfcf0022a600fe7ce044a2455b2e35d46093ec44b30f963c97ce8cd2248553a34932a3818f06dc2ac756cb6bec7eb23047714726c1de0362d8e61274d8a2826fe85ff2a93effec3371e1c762647ae73ea2e2c26253100f596fbe247950b6e6bd174dfdf780fed164e6723f912bbb5561df69d7c1f897ca12c5ac6113a329e28fbbde72301912c0201".to_string(),
    }, &mut group);

    // 2048 bits
    verify_single(VerificationInputs {
            iterations: 4000000,
            discriminant: "f6901cd003679e2f451cda55b032fb49222a9b595b9e5948b793d2d7338d4da01937c637739e7f980d481b742c0fdc5255847ccc848359db822ed6ca7f33bdd54a207e24679c9f1f7e64be59e1bed7afbaa999770743984ed997c2c8187b5a80a0df200c040ac152dd6bb3bfdf3a7f151f2ddbd9debf6c841cebdc9f450cb42f51529ba04e6bda874b43461ed104b39257559bed53200d093f8e6c48f2b1c91e15e37ce695924eafd78fa4ba11e519f9a885399264d1a885d353ce128f1e044ef2feda125167e38ad5db7931b752847388c900868bc6bff2d83f7a6e055c618d3abc0ae104520df25508f40323c35d2d992303e12f1ae7bc44ffd5861d9f768f".to_string(),
            result: "0000d37421051f4f437a727a8d21825ef02a9c33744766947a59140d532756f231d42d8add13fe76e747b130a29becb75c3a3389ee1472325a479afb4275b7e9cf0cedc957e4409cfdea69e901fc8d810617381c0492de46e0387ee42eb3065468ceec55d17f072fa691341ff5b6d835abf35a47b90c127658c4bf4ec8ea6a4ae4177bd96aad7454c36e7bde4bb360a519c9d7b73ecd776d44d18d6441bc5fbe8724227c623477b5c307b89dcea707e1db547d4d0e8c7814e9f24ceedb55653585310100".to_string(),
            proof: "02000607e9272f517e3d7aaa2d3f5bcb5925b9e9c46e432b6b292223df502cc4487b5841d9c4f3746adfd1f058482220d38ddf4c6daf30d9cc0cf0cebb36a5b1ef9189e4ed78b022fae17b9fc2e16c6d3450df52877f67b3c7c06db17eb1f1ecb8c78310aa622935ff76abfb3bdf153604359438c1364269a80dd434149b658a6b6629ec86ba04a339b07b4ab71c1f2417c64a2cfa49138a62d0c02e753c1060df68a3f9ed04fc357742b6f927f7550ba79e52c429031ba3f353b9dd5fef6147c4190100".to_string(),
        }, &mut group);

    // 2400 bits
    verify_single(VerificationInputs {
        iterations: 4000000,
        discriminant: "c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7".to_string(),
        result: "0000e4550022c7dcd0450ecdfe3dae929869de4f0ed9c4256a8967cb80bc7ee32fcae95648e25f862a60bbe465a643a0aa156db355d1f4d01b2e265f7c4d7fcbffa776efe146c880dc12ab8363fa5f8da15c36c4d7baae4fadb399b96b22e1c4269c11ff71f26443207d690e116c978f94fbc448ca572355afd92304760cd4b02535b74a52925ed6267405ea34e50a41c8407c758f8c7460b1e11d361df33cca3b911ef06c9ee24a0e13c73a28f8b5d1d70118eff5a5cd32b4056214eecb152d852f020ddcd6358f7b07e34051fcd871150090befbd2f007a370dce5bec744a409cf5b0100".to_string(),
        proof: "02002f5ef6c2fd9827362ded9a82a416c28356e75f4543c27d6ab97e032e2de02c81b0bf2cadd5bf1a426045870959eb3990afe104936d39d50b85566b21f0c0faed270c7f58f0a22b455a3ca4300175f7a70d26bd5762e95e36789848b8ea8c3de5870b270f24f34f3729a1a0b70c6f6379201b082749bb6c7e8b2c91b73b640d0a4cb1362e68a70541f5005be79ad63c6c1b3a4afdd03b7890b8ca3035830027097efad23892e3d9f68f2f0164b883ff26bb4ed73bbac4c7eb0d015194738a491ba8fdc300b625deb0771f44a933c1578ea0c871cd6343878b436f3fab97734e3f030201".to_string(),
    }, &mut group);

    // 3072 bits
    verify_single(VerificationInputs {
        iterations: 4000000,
        discriminant: "ca25a5acb1857bd8defd2c2df2daf2b45c980c7051f325c6c1c988f70c69a1083b2fc2167d5bd49c459a67395c2adf26d2f55076c9e77bd777c1e4b195271f0d76bf4bf763a2b1d05b09627567d44175fcfa02ff7b44688b182aaafa17625c87c219e4855fdc1d574d6a5032fd640c5dc3fc2452ccb3c20e1b859e9a18384935ff94971f221983bc96aa7db8d3f311b45f27de6bd7401a7ffc020742f822089dd8b4c43e6ae1818124156830b0905ccfc2c3a87f999902a15ce5c58c5fd0d07e6fb182c0801c81fecab479b69a0a215f732fff8f15edb166508624549c56a7490358544e1f7e65f687262f005c37f66d44130efa98270abde4ee11e6d4a2ed2a051e943a3503f898f2fdcf2501291240af1520b2b0fe3aaa68448b99f0196ef66e2ebdb53d4269c7a8d3839f519f51276aec12d2983a3ce564af1a6ad81b2c555c963b3ed779c7177fdabaeb132456dc9b1151d367f867f899260d8b7c0fc3bbad1c1731b04a71286362830c5bc0fb37e5e06492e561f4f044d69a71ce41bfbf".to_string(),
        result: "0300f8940e4673a811a0014cf7a542d502610edd5a68e51877a1c37270e10c691ad64f0b42a5439f1faf22e12329b7e2be4dd8bf6fa4811742d11ba15dac351d0b2baeef79f0ed5a6541ac3c6def8c8db9fcd6a8f951c0d6b212620df74914a115d781ca90b5d544e98f92ca06e05ff3bcdcc9273f7be0de44cebaebd7c3475bb39aae76512e3f0f3d0e3e76b311f5547f72cbeef9f8eef97c51802bde7678dbbeb2a19f111c78740b39cd6fc9d100b99fe88ac0ee84ebd4f27c3d11820f6473c6033915d5711e627f6f3432592059bee4663a97ad3ab82ec6fbaf026a20c7d83d911f7f651855304f880b194805eb46568a744a66dfd255b267988f5607657c8c6422f5d9c8654edede22d44b884d6665d6ddec5f7e11e148b906ecc081a94c84120100".to_string(),
        proof: "02001e5280dcd63c3eb2a4d3ab17fbec4815fe0934fecd7bad14c9dbd1b7c159493c97e909768c198e27b2bbeddfa083198f25f285984f7e77a714b4a7d6dd41ef51afc12047b02cc40fcf1c5fe9edca5dbb968f6995f601f57b0f0481ba50de2dda977893ac862b44955d75c6e6af78e7ae12c89044d468f33cbaf6cb9e7eec02ff7f464101b5b5ddfe99f70377b114567ee1edfcb996b0413551e101d9c3f775123f8f3f6003cf8689bad95ee30bc96e9806a550865c44d783800cc78c9c96da447b1c77a17804552717a396e158d60f3b999aa742883b44235dacc50d0af36be7d264abdfa39b93ddf536f2614a02b5151ceee0f00bdc93364b11d0795b587811e8be891e93ad81676bc0e46bd78eff535ec2cacdb80533a9d94916f57551a1610100".to_string(),
    }, &mut group);

    // 3800 bits
    verify_single(VerificationInputs {
        iterations: 4000000,
        discriminant: "a704c8996310d6e2ca3275125c34c3af970628bf51027beb2b44a8697cce1a9bcc3e4f79b8a8d5b653fcf8289eb3b4a7b09816439d5154251ab448b4ed496a397b6adecea5806dbc960535820162895c9806983b16e2f87fa4b58ee190564b7d87774ec6e4d2d167e4384feab7798a89a69f3771cf35644f746fce5512043e71e3fa5fc2fb34e95af93a69bea00237b41a3b29d15006adf435b13355de1114ed804e5087456b9ae4369b89fef2cd2429777e0c3b96540896dde20a5446dbd70fe0b15e2607d9288ba048a1aa9b7370ee13ed72cdacae56d88f7c9df9a24bb38cea2aa6ece63be091d6ef885b84de0d6a6d3fe1df39e34a9958e15d592956a861889db1db423b3fcdcc16fa038c2ea1d5965980e34fd016ae382521bbc71b6be7809da3883252102dc671d0804272ec2f2e771d975a183cb32b88784c1c052c548121c10a489dae9305f6593621f1648690e9ff903647681ac5da449469bdac2a095cf26144e537ecb0797a986036e9a93598b63aeadf24057c7b25de909ef8ed5bc6ca909e8fb63bdc7d05885f068ed8cb2891533fb1637eb9820314112fc76c56516b914b162edd808c0deeca9f34d63ba6fcac6f35d4dc8d6af92f18a90ec78c91aa24732630acaa568075fcf693641c90cbaa7a73f715e23c5f".to_string(),
        result: "0200c6082a2db6ba6814e7fa5e6425606de92764fd789622976bd22328c01ad4282fce27d51583b3c08bf0e819ec02c165fc62fc388ae3fbdce09c36d5881c5e8177fc052ada7a47cbc5d2f76d717c8348a8c05923f73c55df270e1645464d1460886991defe2771771d7af8a1b27bfd41c9bbe8bd982f23f9bcf2055e57a3ae203d6a4366dc6865e363ab28d1537ff5bc6853c8d2e4d3d1327f3dadb04993e8728f9ed6c69340be41de01647157dadbd6706aad21f80ffbb34991138175743a6468bb8a070cc73256a9d5e418129287681b045cf4659022e22cec1fbec5756af5d40f168818bfa6da0799a664911f0021970ad67180b66bc68fd74cfc1884324c4662cba4bcb6f83a60bec4f8f93775f9ae5863cac401fe985aa8bbb9a3f8f41554e0f341f004b7a59ceedcb5ad37ea14c1ca91ce7a807dae0be4c5d93d1558be33e50d79171112a403951ebb7cfbf9d5b6988e65fd52fc1d2edfc58331c56583a8fd862073002e06".to_string(),
        proof: "03005886cd413f310d5c9da909608ef818497df83f99ab130ca2e2c67f3ac6513496a78ba320c5a5accd2370669698276cad57111ef4096c8d24339e6f7db6b26750c5985eade844f148d8af6d9060a6930260ff099d8fa667e4b4b01623e2628bc57650b9064dddd97866cff43546f07304709427e73ca13adf400f1580a33bd61cb1891222a4a9f1a40dc28ce3d6fe6e47da36684ce31bdab5a8995b8a495075312a38334e75ee84f8bd5d9290b8996ec431a58ea0fc50eb58cb13643d20595f4cb272598ec0e1118cde85e329192e8c0f2e324a6ecec87139b626dfefa14d53cd515b5125ed9c50f1e342ac39080373ea77e1be6fdefe17105af76defd2af5d71b55c9880c141da3ef4e63be737ec79ead45947a14d90c2f50c36441f733a57fa8b22fa724b0abb9ee9e49644a7151a4982f7c1405ab694c5f32c4a87306a4677b4aaf201310ea30a7b138786ef769c8420bbbfb6802e9d78e894c8ca2b53efb87f405f04160100".to_string(),
    }, &mut group);
}

fn sample_discriminant(c: &mut Criterion) {
    let byte_lengths = [128, 240, 256];

    let mut seed = [0u8; 32];

    let mut rng = thread_rng();

    for byte_length in byte_lengths {
        c.bench_with_input(
            BenchmarkId::new("Sample class group discriminant".to_string(), byte_length),
            &byte_length,
            |b, n| {
                b.iter(|| {
                    rng.try_fill_bytes(&mut seed).unwrap();
                    Discriminant::from_seed(&seed, *n).unwrap();
                })
            },
        );
    }
}

fn verify_discriminant(c: &mut Criterion) {
    let byte_lengths = [16, 32, 64, 128, 240, 256, 300, 384, 475];
    let seed = [0u8; 32];

    for byte_length in byte_lengths {
        let (i, _) = hash_prime_with_index::<DefaultPrimalityCheck>(
            &seed,
            byte_length,
            &[0, 1, 8 * byte_length - 1],
        );

        c.bench_with_input(
            BenchmarkId::new("Verify discriminant".to_string(), byte_length),
            &byte_length,
            |b, n| {
                b.iter(|| {
                    verify_prime::<DefaultPrimalityCheck>(
                        &seed,
                        *n,
                        &[0, 1, 8 * byte_length - 1],
                        i,
                    )
                    .unwrap()
                })
            },
        );
    }
}

criterion_group! {
    name = vdf_benchmarks;
    config = Criterion::default().sample_size(10);
    targets = verify, sample_discriminant, verify_discriminant
}

criterion_main!(vdf_benchmarks);
