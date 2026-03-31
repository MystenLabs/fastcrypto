// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;

mod zklogin_benches {

    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use criterion::Criterion;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::error::FastCryptoError;
    use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};
    use fastcrypto::traits::KeyPair;
    use fastcrypto_zkp::bn254::utils::gen_address_seed;
    use fastcrypto_zkp::bn254::zk_login::ZkLoginInputs;
    use fastcrypto_zkp::bn254::zk_login::JWK;
    use fastcrypto_zkp::bn254::zk_login::{JwkId, OIDCProvider};
    use fastcrypto_zkp::bn254::zk_login_api::{ZkLoginEnv, CIRCUIT_CONFIG_V1, CIRCUIT_CONFIG_V2};
    use im::hashmap::HashMap as ImHashMap;

    /// Benchmark the `fastcrypto_zkp::bn254::zk_login_api::verify_zk_login` function and it's main
    /// sub-functions.
    fn verify_zk_login(c: &mut Criterion) {
        // The `verify_zk_login` function has three non-trivial sub-functions:
        // 1. `as_arkworks` - Convert the proof to an arkworks proof.
        // 2. `calculate_all_inputs_hash` - Calculate the poseidon hash of all inputs.
        // 3. `verify_zk_login_proof_with_fixed_vk` - Verify the proof.
        // This benchmark computes benchmarks for all three parts and the overall function.

        // Test values taken from `test_verify_zk_login_google`. See the test for more details on
        // the values.
        let user_salt = "206703048842351542647799591018316385612";
        let address_seed = gen_address_seed(
            user_salt,
            "sub",
            "106294049240999307923",
            "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com",
        )
        .unwrap();
        let input = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"8247215875293406890829839156897863742504615191361518281091302475904551111016\",\"6872980335748205979379321982220498484242209225765686471076081944034292159666\",\"1\"],\"b\":[[\"21419680064642047510915171723230639588631899775315750803416713283740137406807\",\"21566716915562037737681888858382287035712341650647439119820808127161946325890\"],[\"17867714710686394159919998503724240212517838710399045289784307078087926404555\",\"21812769875502013113255155836896615164559280911997219958031852239645061854221\"],[\"1\",\"0\"]],\"c\":[\"7530826803702928198368421787278524256623871560746240215547076095911132653214\",\"16244547936249959771862454850485726883972969173921727256151991751860694123976\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmRlODRhMmQ1NTJiNGM2ZjEiLCJ0eXAiOiJKV1QifQ\"}", &address_seed.to_string()).unwrap();
        let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
        let mut eph_pubkey = vec![0x00];
        eph_pubkey.extend(kp.public().as_ref());
        let mut map = ImHashMap::new();
        let content = JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "oUriU8GqbRw-avcMn95DGW1cpZR1IoM6L7krfrWvLSSCcSX6Ig117o25Yk7QWBiJpaPV0FbP7Y5-DmThZ3SaF0AXW-3BsKPEXfFfeKVc6vBqk3t5mKlNEowjdvNTSzoOXO5UIHwsXaxiJlbMRalaFEUm-2CKgmXl1ss_yGh1OHkfnBiGsfQUndKoHiZuDzBMGw8Sf67am_Ok-4FShK0NuR3-q33aB_3Z7obC71dejSLWFOEcKUVCaw6DGVuLog3x506h1QQ1r0FXKOQxnmqrRgpoHqGSouuG35oZve1vgCU4vLZ6EAgBAbC0KL35I7_0wUDSMpiAvf7iZxzJVbspkQ".to_string(),
            alg: "RS256".to_string(),
        };
        map.insert(
            JwkId::new(
                OIDCProvider::Google.get_config().iss,
                "6f7254101f56e41cf35c9926de84a2d552b4c6f1".to_string(),
            ),
            content.clone(),
        );
        let max_epoch = 10;
        let modulus = Base64UrlUnpadded::decode_vec(&content.n)
            .map_err(|_| {
                FastCryptoError::GeneralError("Invalid Base64 encoded jwk modulus".to_string())
            })
            .unwrap();

        // Benchmark the `as_arkworks` function called by `verify_zk_login`.
        let input_clone = input.clone();
        c.bench_function("verify_zk_login/as_arkworks", move |b| {
            b.iter(|| input_clone.get_proof().as_arkworks().unwrap())
        });

        // Benchmark the `calculate_all_inputs_hash` function called by `verify_zk_login`.
        let eph_pubkey_clone = eph_pubkey.clone();
        let input_clone = input.clone();
        let modulus_clone = modulus.clone();
        c.bench_function("verify_zk_login/calculate_all_inputs_hash", move |b| {
            b.iter(|| {
                input_clone
                    .calculate_all_inputs_hash(
                        &eph_pubkey_clone,
                        &modulus_clone,
                        max_epoch,
                        &CIRCUIT_CONFIG_V1,
                    )
                    .unwrap()
            });
        });
        let input_hashes = input
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, max_epoch, &CIRCUIT_CONFIG_V1)
            .unwrap();

        // Benchmark the `verify_zk_login_proof_with_fixed_vk` function called by `verify_zk_login`.
        let proof = input.get_proof().as_arkworks().unwrap();
        c.bench_function(
            "verify_zk_login/verify_zk_login_proof_with_fixed_vk",
            move |b| {
                b.iter(|| {
                    fastcrypto_zkp::bn254::zk_login_api::verify_zk_login_proof_with_fixed_vk(
                        &ZkLoginEnv::Test,
                        &proof,
                        &[input_hashes],
                        false,
                    )
                })
            },
        );

        // Benchmark the entire `verify_zk_login` function.
        c.bench_function("verify_zk_login", move |b| {
            b.iter(|| {
                fastcrypto_zkp::bn254::zk_login_api::verify_zk_login(
                    &input,
                    max_epoch,
                    &eph_pubkey,
                    &map,
                    &ZkLoginEnv::Test,
                )
            })
        });
    }

    /// Benchmark V2 proof verification for 8192-bit RSA keys
    fn verify_zk_login_v2(c: &mut Criterion) {
        // Test values captured from test_zklogin_v2
        let max_epoch = 10;
        let address_seed =
            "1930628255822123795956154519923524356793387287437090556144422698180443693114";

        let input = ZkLoginInputs::from_json(
            r#"{"proofPoints":{"a":["4913491815640002925508764814861178584881454035317776104347888483537912573177","17464247119089096977765585378460061328465709176842125201639874369409917083365","1"],"b":[["13623903508208593385147109129252793918112295419570003309520868038720322470557","21609423682403605552756457705069928412495291852654002331866073641632927420027"],["21392198638402084688930318789933313022805249822640479452861513428525783839707","1188996632803951473949030842369314644349566079256879538309939741515182911983"],["1","0"]],"c":["8847019028968200963788057481027139711885570926967685201543612972187276716667","14579483098715294861159755601821797996287919909580326110060065627124968449243","1"]},"issBase64Details":{"value":"wiaXNzIjoiaHR0cHM6Ly9qd3QtdGVzdGVyLm15c3RlbmxhYnMuY29tIiw","indexMod4":2},"headerBase64":"eyJraWQiOiJzdWkta2V5LWlkLTgxOTIiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9","addressSeed":"1930628255822123795956154519923524356793387287437090556144422698180443693114"}"#,
            address_seed,
        ).unwrap();

        let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
        let mut eph_pubkey = vec![0x00];
        eph_pubkey.extend(kp.public().as_ref());

        let mut map = ImHashMap::new();
        let content = JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "lViYJOuLB6EZenCimgyWrwOH_QBEkCZxSIEfcQgP5MrZkRlohbrTAN1YpXGRaqugp9A4mRzCmi9ddXscpRBSsLefdPJJLG8lQZ2qrw6X2-6HD5kDFd6-K7JZS-_GOEfr5xGEDm8_MS_SorbmneKspL0n4MPYWH8qke4OBFCwL6WzGBU9rqDuvhYmafmkvVvOtHIqekBxNrCud7Spv43BHdiBM0V-jUquuNM3oK97i_GVLjGfwrGRpR3tK4nva_ryiHh9Ajs68If7-ZhIoLJ05lRsHJJpqsloiEqlCZwhge9zEMnNkoaIzdQr-xLy0GPnr5W0gikjlSGYiInfx9ITADwK3W33xdOB7npM7lqJY73Njbuw8hBQicU8t0M0gvvWfmh1KDeA5IqffZgue-ka9Jj1nrYmZtd0JimQpPDUiGbLv69gQJZcLVQWf9z6mVC4gNm8VU2OafssnolrvNndC3wIm8AgqzVzn_DIOcMQdhIe8jTF3hu1_6R4Id3KoA5Hb3uI2H86-8RjhSG2wKb3zi44yKSmxEDhzl7i450PQX64JK4ftv5jb9vSw5unpikmVvGlGsuvrqWFuWKBcrcXLgyar8pGvRO8fR9ifDHSj-D2fBiLnhK0-iqsJeU8XnfJhUvKxSjXejwsoQeLqlgq9-PgCDP3dE61fkqGpJ1UZjZ44Q9Vh4YLCPAO6oX8btXSkwreuP5m0UtWgFsc-ynWbt6NYS7JlsMtJNWybM4_auqRdil_cPMwFsUgjocztGLeG304YH-GehmyBJyGKuDIiXL9RfLoZ35jKawrWJb4UqckKWV5kOKeXsXdKtMw96ABFumcnhrzxAsqwshS5a2lT8P7Cdd9g3T1JXI7JM1AnJU9_gPXmJoc3yEFNf-JxEf00URoy2xUusyyxYdTswLJp3NQP4VjrAGwnsp7gHKC-V-mJ21FpQCHsV0JQ-1x-E3du9hkpsjTtGkffetEsV8k9enbkudox7WIlsnPcA8y7aY4lnaBqLLSzaj2GOf4KTN4cRpcPzOmSvgcVVYYQXDjRw45X86P1WJG8UDl6Wkl044tAdQRuIxW8QVzBFWWxeXcoagOBKn1_DV0RKUX9Ud4LLauy81rUNfoAcnolz9nippTBEZA_4OOBvXhdngCYaoZyjAkmYdPhKIkghGhKoVVKiEJ1Ua6nUr3zB9WFlTO9lODeV9h0tgKGtKGu3UBeaRCQSMv9gZK-eGIpcqjsqK_rEf4htdDZUBzfOJ0VtCiFYUUBPiuJNuIf9xQGVDE7qZufK1irvGug8jvWSWzB4pGLP75PnPH7B9axnXrxssaIR90Y3Vr9ih_ptzcfNrwD_wiGHUTy698FHu2fXp51HbSEQ".to_string(),
            alg: "RS256".to_string(),
        };

        map.insert(
            JwkId::new(
                OIDCProvider::TestIssuerKey8192.get_config().iss,
                "sui-key-id-8192".to_string(),
            ),
            content.clone(),
        );
        let modulus = Base64UrlUnpadded::decode_vec(&content.n)
            .map_err(|_| {
                FastCryptoError::GeneralError("Invalid Base64 encoded jwk modulus".to_string())
            })
            .unwrap();

        // Benchmark the `as_arkworks` function called by `verify_zk_login`.
        let input_clone = input.clone();
        c.bench_function("verify_zk_login_v2/as_arkworks", move |b| {
            b.iter(|| input_clone.get_proof().as_arkworks().unwrap())
        });

        // Benchmark the `calculate_all_inputs_hash` function called by `verify_zk_login`.
        let eph_pubkey_clone = eph_pubkey.clone();
        let input_clone = input.clone();
        let modulus_clone = modulus.clone();
        c.bench_function("verify_zk_login_v2/calculate_all_inputs_hash", move |b| {
            b.iter(|| {
                input_clone
                    .calculate_all_inputs_hash(
                        &eph_pubkey_clone,
                        &modulus_clone,
                        max_epoch,
                        &CIRCUIT_CONFIG_V2,
                    )
                    .unwrap()
            });
        });
        let input_hashes = input
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, max_epoch, &CIRCUIT_CONFIG_V2)
            .unwrap();

        // Benchmark the `verify_zk_login_proof_with_fixed_vk` function called by `verify_zk_login`.
        let proof = input.get_proof().as_arkworks().unwrap();
        c.bench_function(
            "verify_zk_login_v2/verify_zk_login_proof_with_fixed_vk",
            move |b| {
                b.iter(|| {
                    fastcrypto_zkp::bn254::zk_login_api::verify_zk_login_proof_with_fixed_vk(
                        &ZkLoginEnv::Test,
                        &proof,
                        &[input_hashes],
                        true,
                    )
                })
            },
        );

        // Benchmark the entire `verify_zk_login` function.
        c.bench_function("verify_zk_login_v2", move |b| {
            b.iter(|| {
                fastcrypto_zkp::bn254::zk_login_api::verify_zk_login(
                    &input,
                    max_epoch,
                    &eph_pubkey,
                    &map,
                    &ZkLoginEnv::Test,
                )
            })
        });
    }

    criterion_group! {
        name = zklogin_benches;
        config = Criterion::default();
        targets = verify_zk_login, verify_zk_login_v2,
    }
}

criterion_main!(zklogin_benches::zklogin_benches,);
