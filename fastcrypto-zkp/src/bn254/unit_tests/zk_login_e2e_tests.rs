// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::env;

use crate::bn254::utils::get_nonce;
use crate::bn254::utils::get_test_issuer_jwt_token;
use crate::bn254::zk_login::fetch_jwks;
use crate::bn254::{
    utils::{gen_address_seed, get_proof},
    zk_login::{JwkId, OIDCProvider, ZkLoginInputs, JWK},
    zk_login_api::{verify_zk_login, ZkLoginEnv},
};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use fastcrypto::jwt_utils::parse_and_validate_jwt;
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use im::HashMap as ImHashMap;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use test_strategy::proptest;
use test_strategy::Arbitrary;

const PROVER_DEV_SERVER_URL: &str = "https://prover-dev.mystenlabs.com/v1";

#[tokio::test]
async fn test_end_to_end_twitch() {
    // Use a fixed Twitch token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLCJleHAiOjE2OTIyODQzMzQsImlhdCI6MTY5MjI4MzQzNCwiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiwic3ViIjoiOTA0NDQ4NjkyIiwiYXpwIjoicnMxYmgwNjVpOXlhNHlkdmlmaXhsNGtzczB1aHB0Iiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb3lxdnEifQ.M54Sgs6aDu5Mprs_CgXeRbgiErC7oehj-h9oEcBqZFDADwd09zs9hbfDPqUjaNBB-_I6G7kn9e-zwPov8PUecI68kr3oyiCMWhKD-3h1FEu13MZv71B6jhIDMu1_UgI-RSrOQMRvdI8eL3qqD-KsvJuJH1Sz0w56PnB0xupUg-eSvgnMBAo6iTa0t1grX9qGy7U00i_oqn9J4jVGVVEbMhUWROJMjowWdOogJ4_VNqm67JHd_rMZ3xtjLabP6Nk1Gx-VjUbYceNADWUr5xpJveRtvb1FJvd0HSN4mab51zuSUnavCQw2OXbyoH8j6uuQAAKVhG-_Ht1hCvReycGXKw";
    let (max_epoch, eph_pubkey, zk_login_inputs) = get_test_inputs(parsed_token).await;
    // Make a map of jwk ids to jwks just for Twitch.
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(zk_login_inputs.get_iss().to_string(),"1".to_string()),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
            alg: "RS256".to_string(),},
    );

    // Verify it against test vk ok.
    let res = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Test,
    );
    assert!(res.is_ok());

    // Verify it against prod vk fails.
    let res_prod = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Prod,
    );
    assert!(res_prod.is_err());
}

#[tokio::test]
async fn test_end_to_end_kakao() {
    // Use a fixed Kakao token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJraWQiOiI5ZjI1MmRhZGQ1ZjIzM2Y5M2QyZmE1MjhkMTJmZWEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhYTZiZGRmMzkzYjU0ZDRlMGQ0MmFlMDAxNGVkZmQyZiIsInN1YiI6IjMwOTUxMzQzODkiLCJhdXRoX3RpbWUiOjE2OTcxNDYwMjIsImlzcyI6Imh0dHBzOi8va2F1dGgua2FrYW8uY29tIiwiZXhwIjoxNjk3MTY3NjIyLCJpYXQiOjE2OTcxNDYwMjIsIm5vbmNlIjoiaFRQcGdGN1hBS2JXMzdyRVVTNnBFVlpxbW9JIn0.ICP5Fz4Ves7HoFOixwvBeQSYBLWxFPtN6QTnMIv9d9zYnfkaXJ9VyqnaEE3BzY3dzHeWgKFps5Dmrm8Vn4WLmeRAvxDz7831g8Ln8-krTHIUcLzi91NGUPPyx6bIkCzxTqhIB4omatvXD7vAf_AlsqJJYMOIvLQxdpRq8-d_JyAfELE_aWVatXSwGIBYIi_91CEZ64nsHV1J4Wz_tVFc5vbPT4wZabBzepMPXcNHVtrtkuW96nWNygbpap1mSz4fEP9mdlTD2Oi2FHD2cX3rebqiEYTeZI5HySzo4NcN_4TcIgf5cFSapyglqCuulFBXCkIkF9lKN3Il6yJ9MD_N4w";
    let (max_epoch, eph_pubkey, zk_login_inputs) = get_test_inputs(parsed_token).await;

    // Make a map of jwk ids to jwks just for Twitch.
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            zk_login_inputs.get_iss().to_string(),
            "9f252dadd5f233f93d2fa528d12fea".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "qGWf6RVzV2pM8YqJ6by5exoixIlTvdXDfYj2v7E6xkoYmesAjp_1IYL7rzhpUYqIkWX0P4wOwAsg-Ud8PcMHggfwUNPOcqgSk1hAIHr63zSlG8xatQb17q9LrWny2HWkUVEU30PxxHsLcuzmfhbRx8kOrNfJEirIuqSyWF_OBHeEgBgYjydd_c8vPo7IiH-pijZn4ZouPsEg7wtdIX3-0ZcXXDbFkaDaqClfqmVCLNBhg3DKYDQOoyWXrpFKUXUFuk2FTCqWaQJ0GniO4p_ppkYIf4zhlwUYfXZEhm8cBo6H2EgukntDbTgnoha8kNunTPekxWTDhE5wGAt6YpT4Yw".to_string(),
            alg: "RS256".to_string(),},
    );

    // Verify it against test vk ok.
    let res = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Test,
    );
    assert!(res.is_ok());

    // Verify it against prod vk fails.
    let res_prod = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Prod,
    );
    assert!(res_prod.is_err());
}

#[tokio::test]
async fn test_end_to_end_apple() {
    // Use a fixed Apple token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJraWQiOiJXNldjT0tCIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoibmwuZGlna2FzLndhbGxldC5jbGllbnQiLCJleHAiOjE2OTc4MjEwNzQsImlhdCI6MTY5NzczNDY3NCwic3ViIjoiMDAxMzkzLjc0YTEzNTRlZjc0YjRiOGViMWQyMDdkMzRkNzE2OGQ2LjE2MjkiLCJub25jZSI6ImhUUHBnRjdYQUtiVzM3ckVVUzZwRVZacW1vSSIsImNfaGFzaCI6Inl4dlh3Y1VXaHFUa1dpazQtQWh1UXciLCJhdXRoX3RpbWUiOjE2OTc3MzQ2NzQsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.LmGVSJY8rOpvsNob4fEqUecm_Y1ZitbW3lIK64f2QjgNUqnIpkO5sV0wXlVzlRWwGI4k3qURbwtTQO7Dw7kORaQIhlLzA1cZNHU22aXdQyQ9FIHPFgQecuudk-_0dvHB1IqhGsmvLv_qLJBQiuB7MGztVeZsgDYtXFs4dw04LCht0DNTEh_ihBRcJZkxHR9K13ItDiVUH5fLIRlfT70VgZWNuaGkKYfxeWg9nMD6medJU7VawWvXPt48YGtxIYcZqv6hlZwW14qGx-F2qg64NWjCSqwdBk5wqyhzpJdnErP79ESgGxpskNIZNn1JEzspJtgAS7Pmc0peV0hyg9FHtg";
    // Make a map of jwk ids to jwks just for Apple.
    let (max_epoch, eph_pubkey, zk_login_inputs) = get_test_inputs(parsed_token).await;
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            zk_login_inputs.get_iss().to_string(),
            "W6WcOKB".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw".to_string(),
            alg: "RS256".to_string(),},
    );

    // Verify it against test vk ok.
    let res = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Test,
    );
    assert!(res.is_ok());

    // Verify it against prod vk fails.
    let res_prod = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Prod,
    );
    assert!(res_prod.is_err());
}

#[tokio::test]
async fn test_end_to_end_slack() {
    // Use a fixed Slack token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1CMk1BeUtTbjU1NWlzZDBFYmRoS3g2bmt5QWk5eExxOHJ2Q0ViX25PeVkifQ.eyJpc3MiOiJodHRwczpcL1wvc2xhY2suY29tIiwic3ViIjoiVTAzTVIwVDBRTVUiLCJhdWQiOiIyNDI2MDg3NTg4NjYxLjU3NDI0NTcwMzkzNDgiLCJleHAiOjE2OTgxNjU2ODAsImlhdCI6MTY5ODE2NTM4MCwiYXV0aF90aW1lIjoxNjk4MTY1MzgwLCJub25jZSI6ImhUUHBnRjdYQUtiVzM3ckVVUzZwRVZacW1vSSIsImF0X2hhc2giOiJabEVocTZlRWJsUFBaNVVaOXZkZjB3IiwiaHR0cHM6XC9cL3NsYWNrLmNvbVwvdGVhbV9pZCI6IlQwMkNKMktIQUtGIiwiaHR0cHM6XC9cL3NsYWNrLmNvbVwvdXNlcl9pZCI6IlUwM01SMFQwUU1VIn0.GzkVxav70jC5TAKffNi2bZoRjtT2kDBr5oY_dJpbIoDsFP6IGRQ8181y1aoSpeJAi0bhjdB-h9wFsJOo6eY3rWh5om3z3cA4zm4qOCjSHCup90s80LP4emw_oZRQ_Wj8Q0F4YTkrDLW4CYJZYn0kMo7efM9ChT8henKQP-Yz2n_-8VzrT2uudv7hRLyGKvgf0xGvDcs_UVbOKR_lFXLaksSPJgTEx48cLHA979e8aH68Zv7b4sWv4D1qUEAu4YuJkXQ573023zq5QDpUki0qSow2gaqxdNUW2XOSxqV9ImZcsXqea769kP2rJvNgNnur4hO6wB7I_ImXsIn70aU-lQ";
    // Make a map of jwk ids to jwks just for Apple.
    let (max_epoch, eph_pubkey, zk_login_inputs) = get_test_inputs(parsed_token).await;
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            zk_login_inputs.get_iss().to_string(),
            "mB2MAyKSn555isd0EbdhKx6nkyAi9xLq8rvCEb_nOyY".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "zQqzXfb677bpMKw0idKC5WkVLyqk04PWMsWYJDKqMUUuu_PmzdsvXBfHU7tcZiNoHDuVvGDqjqnkLPEzjXnaZY0DDDHvJKS0JI8fkxIfV1kNy3DkpQMMhgAwnftUiSXgb5clypOmotAEm59gHPYjK9JHBWoHS14NYEYZv9NVy0EkjauyYDSTz589aiKU5lA-cePG93JnqLw8A82kfTlrJ1IIJo2isyBGANr0YzR-d3b_5EvP7ivU7Ph2v5JcEUHeiLSRzIzP3PuyVFrPH659Deh-UAsDFOyJbIcimg9ITnk5_45sb_Xcd_UN6h5I7TGOAFaJN4oi4aaGD4elNi_K1Q".to_string(),
            alg: "RS256".to_string(),},
    );

    // Verify it against test vk ok.
    let res = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Test,
    );
    assert!(res.is_ok());

    // Verify it against prod vk fails.
    let res_prod = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Prod,
    );
    assert!(res_prod.is_err());
}

#[derive(Deserialize)]
struct TestData {
    jwt: String,
    kid: String,
    n: String,
    provider: String,
}

#[tokio::test]
async fn test_end_to_end_all_providers() {
    // All JWT generated against nonce hTPpgF7XAKbW37rEUS6pEVZqmoI. This is derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let file =
        std::fs::File::open("src/bn254/zklogin_test_vectors.json").expect("Unable to open file");
    let test_datum: Vec<TestData> = serde_json::from_reader(file).unwrap();
    for test_data in test_datum {
        println!("Testing provider: {:?}", test_data.provider);
        // Make a map of jwk ids to jwks just for Apple.
        let (max_epoch, eph_pubkey, zk_login_inputs) = get_test_inputs(&test_data.jwt).await;
        let mut map = ImHashMap::new();
        map.insert(
            JwkId::new(zk_login_inputs.get_iss().to_string(), test_data.kid),
            JWK {
                kty: "RSA".to_string(),
                e: "AQAB".to_string(),
                n: test_data.n,
                alg: "RS256".to_string(),
            },
        );

        // Verify it against test vk ok.
        let res = verify_zk_login(
            &zk_login_inputs,
            max_epoch,
            &eph_pubkey,
            &map,
            &ZkLoginEnv::Test,
        );
        assert!(res.is_ok());

        // Verify it against prod vk fails.
        let res_prod = verify_zk_login(
            &zk_login_inputs,
            max_epoch,
            &eph_pubkey,
            &map,
            &ZkLoginEnv::Prod,
        );
        assert!(res_prod.is_err());
    }
}

async fn get_test_inputs(parsed_token: &str) -> (u64, Vec<u8>, ZkLoginInputs) {
    let max_epoch = 10;
    let jwt_randomness = "100681567828351849884072155819400689117";
    // A dummy salt
    let user_salt = "129390038577185583942388216820280642146";

    // Generate an ephermeral key pair.
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());
    let kp_bigint = BigUint::from_bytes_be(&eph_pubkey).to_string();
    let url = &env::var("URL").unwrap_or_else(|_| PROVER_DEV_SERVER_URL.to_owned());
    println!("using URL: {:?}", url);

    // Get a proof from endpoint and serialize it.
    let reader = get_proof(
        parsed_token,
        max_epoch,
        jwt_randomness,
        &kp_bigint,
        user_salt,
        url,
    )
    .await
    .unwrap();
    let (sub, aud) = parse_and_validate_jwt(parsed_token).unwrap();
    // Get the address seed.
    let address_seed = gen_address_seed(user_salt, "sub", &sub, &aud).unwrap();
    let zk_login_inputs = ZkLoginInputs::from_reader(reader, &address_seed).unwrap();
    (max_epoch, eph_pubkey, zk_login_inputs)
}

#[derive(Debug, Serialize, Deserialize)]
struct TestIssuerJWTResponse {
    jwt: String,
}

#[derive(Arbitrary, Debug)]
struct TestInputStruct {
    // the epoch that last till 10000 years assuming epoch duration is ~24 hours.
    #[strategy(0..3650000u64)]
    max_epoch: u64,
    jwt_rand_bytes: [u8; 16],
    salt_bytes: [u8; 16],
    seed_ephemeral_kp: [u8; 32],
    sub: [u8; 32],
}

#[proptest(async = "tokio")]
async fn test_end_to_end_test_issuer(test_input: TestInputStruct) {
    // this test is mean to run a long time (~10 minutes on macbook)
    async {
        let jwt_randomness = BigUint::from_bytes_be(&test_input.jwt_rand_bytes).to_string();
        let user_salt = BigUint::from_bytes_be(&test_input.salt_bytes).to_string();
        let sub = BigUint::from_bytes_be(&test_input.sub).to_string();
        let max_epoch = test_input.max_epoch;

        // Generate an ephermeral key pair.
        let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed(test_input.seed_ephemeral_kp));
        let mut eph_pk_bytes = vec![0x00];
        eph_pk_bytes.extend(kp.public().as_ref());
        let kp_bigint = BigUint::from_bytes_be(&eph_pk_bytes).to_string();

        let client = reqwest::Client::new();

        // Get JWT from test issuer with nonce.
        let nonce = get_nonce(&eph_pk_bytes, max_epoch, &jwt_randomness).unwrap();
        println!("jwt_randomness: {:?}", jwt_randomness);
        println!("user_salt: {:?}", user_salt);
        println!("sub: {:?}", sub);
        println!("max_epoch: {:?}", max_epoch);
        println!("kp_bigint: {:?}", kp_bigint);
        println!("nonce: {:?}", nonce);
        let parsed_token = get_test_issuer_jwt_token(
            &client,
            &nonce,
            &OIDCProvider::TestIssuer.get_config().iss,
            &sub,
        )
        .await
        .unwrap()
        .jwt;

        // Get a proof from endpoint and serialize it.
        let url = &env::var("URL").unwrap_or_else(|_| PROVER_DEV_SERVER_URL.to_owned());
        println!("using URL: {:?}", url);
        let reader = get_proof(
            &parsed_token,
            max_epoch,
            &jwt_randomness,
            &kp_bigint,
            &user_salt,
            url,
        )
        .await
        .unwrap();
        let (sub, aud) = parse_and_validate_jwt(&parsed_token).unwrap();
        // Get the address seed.
        let address_seed = gen_address_seed(&user_salt, "sub", &sub, &aud).unwrap();
        let zk_login_inputs =
            ZkLoginInputs::from_reader(reader, &address_seed.to_string()).unwrap();

        // Make a map of jwk ids to jwks just for Microsoft.
        let iss = zk_login_inputs.get_iss();
        let jwks = fetch_jwks(&OIDCProvider::from_iss(iss).unwrap(), &client)
            .await
            .unwrap();
        let mut map = ImHashMap::new();
        for (id, jwk) in jwks {
            map.insert(id, jwk);
        }
        // Verify it against test vk ok.
        let res = verify_zk_login(
            &zk_login_inputs,
            max_epoch,
            &eph_pk_bytes,
            &map,
            &ZkLoginEnv::Test,
        );
        assert!(res.is_ok());
    }
    .await;
}
