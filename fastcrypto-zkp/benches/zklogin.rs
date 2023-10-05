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
    use fastcrypto_zkp::bn254::zk_login_api::ZkLoginEnv;
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
        let max_epoch = 10;
        let address_seed = gen_address_seed(
            user_salt,
            "sub",
            "106294049240999307923",
            "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com",
        )
        .unwrap();
        let input = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"8247215875293406890829839156897863742504615191361518281091302475904551111016\",\"6872980335748205979379321982220498484242209225765686471076081944034292159666\",\"1\"],\"b\":[[\"21419680064642047510915171723230639588631899775315750803416713283740137406807\",\"21566716915562037737681888858382287035712341650647439119820808127161946325890\"],[\"17867714710686394159919998503724240212517838710399045289784307078087926404555\",\"21812769875502013113255155836896615164559280911997219958031852239645061854221\"],[\"1\",\"0\"]],\"c\":[\"7530826803702928198368421787278524256623871560746240215547076095911132653214\",\"16244547936249959771862454850485726883972969173921727256151991751860694123976\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmRlODRhMmQ1NTJiNGM2ZjEiLCJ0eXAiOiJKV1QifQ\"}", &address_seed).unwrap();
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
                    .calculate_all_inputs_hash(&eph_pubkey_clone, &modulus_clone, max_epoch)
                    .unwrap()
            });
        });
        let input_hashes = input
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, max_epoch)
            .unwrap();

        // Benchmark the `verify_zk_login_proof_with_fixed_vk` function called by `verify_zk_login`.
        let proof = input.get_proof().as_arkworks().unwrap();
        c.bench_function(
            "verify_zk_login/verify_zk_login_proof_with_fixed_vk",
            move |b| {
                b.iter(|| {
                    fastcrypto_zkp::bn254::zk_login_api::verify_zk_login_proof_with_fixed_vk(
                        &ZkLoginEnv::Prod,
                        &proof,
                        &[input_hashes],
                    )
                })
            },
        );

        // Benchmark the entire `verify_zk_login` function.
        c.bench_function("verify_zk_login", move |b| {
            b.iter(|| {
                fastcrypto_zkp::bn254::zk_login_api::verify_zk_login(
                    &input,
                    10,
                    &eph_pubkey,
                    &map,
                    &ZkLoginEnv::Prod,
                )
            })
        });
    }

    criterion_group! {
        name = zklogin_benches;
        config = Criterion::default();
        targets = verify_zk_login,
    }
}

criterion_main!(zklogin_benches::zklogin_benches,);
