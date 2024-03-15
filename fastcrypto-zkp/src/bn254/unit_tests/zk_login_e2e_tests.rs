// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::env;

use crate::bn254::zk_login::fetch_jwks;
use crate::bn254::FastCryptoError;
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

const PROVER_DEV_SERVER_URL: &str = "https://prover-dev.mystenlabs.com/v1";

#[tokio::test]
async fn test_end_to_end_google() {
    // Use a fixed Google token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA5YmNmODAyOGUwNjUzN2Q0ZDNhZTRkODRmNWM1YmFiY2YyYzBmMGEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNTc2OTgzMjM3NC1mYW1lY3FyaGUyZ2tlYnQ1ZnZxbXMyMjYzMDQ2bGo5Ni5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjI1NzY5ODMyMzc0LWZhbWVjcXJoZTJna2VidDVmdnFtczIyNjMwNDZsajk2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA2Mjk0MDQ5MjQwOTk5MzA3OTIzIiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJuYmYiOjE3MTA1MTkwNzksImlhdCI6MTcxMDUxOTM3OSwiZXhwIjoxNzEwNTIyOTc5LCJqdGkiOiI2NGU4MmU3ZWRiNDBlNmJkYTQwZDYzYmZlNTk3MTMyNTIxMTE1YWQ2In0.g1li6I3F5oP7t675xxTsLM47V6YOoOYTzxqzHi9TZXknohhGpQ-ovQ80hn0vboOAFto4hoqd8LLbIV1GrDh7Ma0vy_0S_bwgNJeOk4J9xkPvK8lAOo78k-pbhEcg5CMRBL2u6JeG2j6aGuXMaSdCh_vsPOPqQ-DBebV-P8-VX0oogR3qbjWU1R23vZvZO1SKWwEI4mxdV5V06ntVy3hGCmB6c_HAwdCwK8GktP_PFBOFEPC9cgqsNUqe9I9ce5fZ0DIuYX4GYEs5HfdFi_nyZGcMYZEegBYcmUEK5l0A7d7m3mC_v13q6z7Cc-b4hvZJiO1E9bW3ARVBN_BQmnkmCA";
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;
    // Make a map of jwk ids to jwks just for Twitch.
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(iss, "09bcf8028e06537d4d3ae4d84f5c5babcf2c0f0a".to_string()),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "vdtZ3cfuh44JlWkJRu-3yddVp58zxSHwsWiW_jpaXgpebo0an7qY2IEs3D7kC186Bwi0T7Km9mUcDbxod89IbtZuQQuhxlgaXB-qX9GokNLdqg69rUaealXGrCdKOQ-rOBlNNGn3M4KywEC98KyQAKXe7prs7yGqI_434rrULaE7ZFmLAzsYNoZ_8l53SGDiRaUrZkhxXOEhlv1nolgYGIH2lkhEZ5BlU53BfzwjO-bLeMwxJIZxSIOy8EBIMLP7eVu6AIkAr9MaDPJqeF7n7Cn8yv_qmy51bV-INRS-HKRVriSoUxhQQTbvDYYvJzHGYu_ciJ4oRYKkDEwxXztUew".to_string(),
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

#[tokio::test]
async fn test_end_to_end_twitch() {
    // Use a fixed Twitch token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLCJleHAiOjE2OTIyODQzMzQsImlhdCI6MTY5MjI4MzQzNCwiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiwic3ViIjoiOTA0NDQ4NjkyIiwiYXpwIjoicnMxYmgwNjVpOXlhNHlkdmlmaXhsNGtzczB1aHB0Iiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb3lxdnEifQ.M54Sgs6aDu5Mprs_CgXeRbgiErC7oehj-h9oEcBqZFDADwd09zs9hbfDPqUjaNBB-_I6G7kn9e-zwPov8PUecI68kr3oyiCMWhKD-3h1FEu13MZv71B6jhIDMu1_UgI-RSrOQMRvdI8eL3qqD-KsvJuJH1Sz0w56PnB0xupUg-eSvgnMBAo6iTa0t1grX9qGy7U00i_oqn9J4jVGVVEbMhUWROJMjowWdOogJ4_VNqm67JHd_rMZ3xtjLabP6Nk1Gx-VjUbYceNADWUr5xpJveRtvb1FJvd0HSN4mab51zuSUnavCQw2OXbyoH8j6uuQAAKVhG-_Ht1hCvReycGXKw";
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;
    // Make a map of jwk ids to jwks just for Twitch.
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(iss,"1".to_string()),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
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

#[tokio::test]
async fn test_end_to_end_kakao() {
    // Use a fixed Kakao token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJraWQiOiI5ZjI1MmRhZGQ1ZjIzM2Y5M2QyZmE1MjhkMTJmZWEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhYTZiZGRmMzkzYjU0ZDRlMGQ0MmFlMDAxNGVkZmQyZiIsInN1YiI6IjMwOTUxMzQzODkiLCJhdXRoX3RpbWUiOjE2OTcxNDYwMjIsImlzcyI6Imh0dHBzOi8va2F1dGgua2FrYW8uY29tIiwiZXhwIjoxNjk3MTY3NjIyLCJpYXQiOjE2OTcxNDYwMjIsIm5vbmNlIjoiaFRQcGdGN1hBS2JXMzdyRVVTNnBFVlpxbW9JIn0.ICP5Fz4Ves7HoFOixwvBeQSYBLWxFPtN6QTnMIv9d9zYnfkaXJ9VyqnaEE3BzY3dzHeWgKFps5Dmrm8Vn4WLmeRAvxDz7831g8Ln8-krTHIUcLzi91NGUPPyx6bIkCzxTqhIB4omatvXD7vAf_AlsqJJYMOIvLQxdpRq8-d_JyAfELE_aWVatXSwGIBYIi_91CEZ64nsHV1J4Wz_tVFc5vbPT4wZabBzepMPXcNHVtrtkuW96nWNygbpap1mSz4fEP9mdlTD2Oi2FHD2cX3rebqiEYTeZI5HySzo4NcN_4TcIgf5cFSapyglqCuulFBXCkIkF9lKN3Il6yJ9MD_N4w";
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;

    // Make a map of jwk ids to jwks just for Twitch.
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            iss,
            "9f252dadd5f233f93d2fa528d12fea".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "qGWf6RVzV2pM8YqJ6by5exoixIlTvdXDfYj2v7E6xkoYmesAjp_1IYL7rzhpUYqIkWX0P4wOwAsg-Ud8PcMHggfwUNPOcqgSk1hAIHr63zSlG8xatQb17q9LrWny2HWkUVEU30PxxHsLcuzmfhbRx8kOrNfJEirIuqSyWF_OBHeEgBgYjydd_c8vPo7IiH-pijZn4ZouPsEg7wtdIX3-0ZcXXDbFkaDaqClfqmVCLNBhg3DKYDQOoyWXrpFKUXUFuk2FTCqWaQJ0GniO4p_ppkYIf4zhlwUYfXZEhm8cBo6H2EgukntDbTgnoha8kNunTPekxWTDhE5wGAt6YpT4Yw".to_string(),
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

#[tokio::test]
async fn test_end_to_end_apple() {
    // Use a fixed Apple token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJraWQiOiJXNldjT0tCIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoibmwuZGlna2FzLndhbGxldC5jbGllbnQiLCJleHAiOjE2OTc4MjEwNzQsImlhdCI6MTY5NzczNDY3NCwic3ViIjoiMDAxMzkzLjc0YTEzNTRlZjc0YjRiOGViMWQyMDdkMzRkNzE2OGQ2LjE2MjkiLCJub25jZSI6ImhUUHBnRjdYQUtiVzM3ckVVUzZwRVZacW1vSSIsImNfaGFzaCI6Inl4dlh3Y1VXaHFUa1dpazQtQWh1UXciLCJhdXRoX3RpbWUiOjE2OTc3MzQ2NzQsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.LmGVSJY8rOpvsNob4fEqUecm_Y1ZitbW3lIK64f2QjgNUqnIpkO5sV0wXlVzlRWwGI4k3qURbwtTQO7Dw7kORaQIhlLzA1cZNHU22aXdQyQ9FIHPFgQecuudk-_0dvHB1IqhGsmvLv_qLJBQiuB7MGztVeZsgDYtXFs4dw04LCht0DNTEh_ihBRcJZkxHR9K13ItDiVUH5fLIRlfT70VgZWNuaGkKYfxeWg9nMD6medJU7VawWvXPt48YGtxIYcZqv6hlZwW14qGx-F2qg64NWjCSqwdBk5wqyhzpJdnErP79ESgGxpskNIZNn1JEzspJtgAS7Pmc0peV0hyg9FHtg";
    // Make a map of jwk ids to jwks just for Apple.
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            iss,
            "W6WcOKB".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw".to_string(),
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

#[tokio::test]
async fn test_end_to_end_slack() {
    // Use a fixed Slack token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1CMk1BeUtTbjU1NWlzZDBFYmRoS3g2bmt5QWk5eExxOHJ2Q0ViX25PeVkifQ.eyJpc3MiOiJodHRwczpcL1wvc2xhY2suY29tIiwic3ViIjoiVTAzTVIwVDBRTVUiLCJhdWQiOiIyNDI2MDg3NTg4NjYxLjU3NDI0NTcwMzkzNDgiLCJleHAiOjE2OTgxNjU2ODAsImlhdCI6MTY5ODE2NTM4MCwiYXV0aF90aW1lIjoxNjk4MTY1MzgwLCJub25jZSI6ImhUUHBnRjdYQUtiVzM3ckVVUzZwRVZacW1vSSIsImF0X2hhc2giOiJabEVocTZlRWJsUFBaNVVaOXZkZjB3IiwiaHR0cHM6XC9cL3NsYWNrLmNvbVwvdGVhbV9pZCI6IlQwMkNKMktIQUtGIiwiaHR0cHM6XC9cL3NsYWNrLmNvbVwvdXNlcl9pZCI6IlUwM01SMFQwUU1VIn0.GzkVxav70jC5TAKffNi2bZoRjtT2kDBr5oY_dJpbIoDsFP6IGRQ8181y1aoSpeJAi0bhjdB-h9wFsJOo6eY3rWh5om3z3cA4zm4qOCjSHCup90s80LP4emw_oZRQ_Wj8Q0F4YTkrDLW4CYJZYn0kMo7efM9ChT8henKQP-Yz2n_-8VzrT2uudv7hRLyGKvgf0xGvDcs_UVbOKR_lFXLaksSPJgTEx48cLHA979e8aH68Zv7b4sWv4D1qUEAu4YuJkXQ573023zq5QDpUki0qSow2gaqxdNUW2XOSxqV9ImZcsXqea769kP2rJvNgNnur4hO6wB7I_ImXsIn70aU-lQ";
    // Make a map of jwk ids to jwks just for Apple.
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            iss,
            "mB2MAyKSn555isd0EbdhKx6nkyAi9xLq8rvCEb_nOyY".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "zQqzXfb677bpMKw0idKC5WkVLyqk04PWMsWYJDKqMUUuu_PmzdsvXBfHU7tcZiNoHDuVvGDqjqnkLPEzjXnaZY0DDDHvJKS0JI8fkxIfV1kNy3DkpQMMhgAwnftUiSXgb5clypOmotAEm59gHPYjK9JHBWoHS14NYEYZv9NVy0EkjauyYDSTz589aiKU5lA-cePG93JnqLw8A82kfTlrJ1IIJo2isyBGANr0YzR-d3b_5EvP7ivU7Ph2v5JcEUHeiLSRzIzP3PuyVFrPH659Deh-UAsDFOyJbIcimg9ITnk5_45sb_Xcd_UN6h5I7TGOAFaJN4oi4aaGD4elNi_K1Q".to_string(),
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

#[tokio::test]
async fn test_end_to_end_microsoft() {
    // cargo test --features e2e -- --nocapture test_end_to_end_microsoft
    // Use a fixed Microsoft token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkZsR05mUnZHSW82MVJIckFUQmNucUZTb2RpOCJ9.eyJ2ZXIiOiIyLjAiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkL3YyLjAiLCJzdWIiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBTjdHb3g3RkVldDFfUkhvNk5FUnBzIiwiYXVkIjoiMmUzZTg3Y2ItYmYyNC00Mzk5LWFiOTgtNDgzNDNkNDU3MTI0IiwiZXhwIjoxNzEwMzY3MDc0LCJpYXQiOjE3MTAyODAzNzQsIm5iZiI6MTcxMDI4MDM3NCwidGlkIjoiOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkIiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJhaW8iOiJEdHpYN3h2bldwOTJma0RoeDJYbnRscUdFZjF4MzF6WXQxRzBFRHlDRUttYkthRHdocUF3WU1tZndkNElpUTZwMjdIbkVmRmcqdXVDQ3RkWEdycU9SVCpheWpZbVRrdUtCVUhGcCpOSThkVkx5RDAwZlNFbGVpZ3dXNlh1SE11VXJrZkFvVWI2V084SjR3ZkZqRENIZTlFaXg2bGduNFdNVkdKaUFWdkhaM3chd1NZa2E0NWNNRFlJOU1xamVLaXlFdyQkIn0.YMZZVSydM0KxiwPul-flLE02Lx7nzwXVaDFfiw5paiu6XH0E0c2exmFPftGqclnV7xhdQXfgtTRXOaDfZMVewtE0Ox_vuqigYBjb2OgsS9vlhDUmXfq_XimMoYMqL-Q5BogS-W0bW6oq9LoA-VHq8ABJRSqhnunWXrE92csWOAFhR_970qtgRVhM4n7CrbPBXuEwiRghEruJtmqbHyRYecyVJRoPTYKsAng1tJKCZSMhsVYlFCa2bJI6sOZAOdpToZBCpJJvFPKslZgbZRsT3pcqcDDJflnOeZIxOuOFg662msCQTNl0RJjZv6RyUrBu8klU30XqbHjCd-B8OVyHGw";
    // Make a map of jwk ids to jwks just for Microsoft.
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;
    let mut map = ImHashMap::new();
    let jwk_id = JwkId::new(iss, "FlGNfRvGIo61RHrATBcnqFSodi8".to_string());
    assert_eq!(jwk_id.iss, OIDCProvider::Microsoft.get_config().iss);
    map.insert(
        jwk_id,
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "nAbsEZqv4NRkRQzPX0cAuM6B-fGwolx944xVvp8AkXsY8GTGspTi9Ns2gt4xpd_F4GAOng0k6SWdfSINm0GmT2Hfl2O84iCko73r-m9g3mL_zju7QuZYYOmWgIORzuzRJynKbnE84AFaQ93TF5nP9gQa3EwfujW1TAq7zKh-s4IyodrGxBwct88chDLqcxpkgPRhvan-tikFO0tFj2QAIZUUkX-btZ50kDo1djQ12jmqgZymICsGVpA70zVpznj6AaaVpkMa8S2qEW0Jv3xOqI8E_JeTGpuS6a-emLSxV2exdHk0f_xpqEjBVaYj4Au5rdzlt5tzrrixgMm4wVzDMQ".to_string(),
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

#[tokio::test]
async fn test_end_to_end_aws() {
    // cargo test --features e2e -- --nocapture test_end_to_end_aws
    // Use a fixed AWS token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJraWQiOiJrRjRGZU40emQ2Vk5ZREFkeERGYTRcL3FqcWpNS29vbnJ5WVp1S1RONzZkRT0iLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiYjRlT2Q1NHNlNDB3NG8zaGRheWJJdyIsInN1YiI6ImI0NzgxNDM4LWIwNjEtNzA5ZS1iNzRkLWQ4NDU5Yzg0M2NhNCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9MUFNMQ2tDM0EiLCJjb2duaXRvOnVzZXJuYW1lIjoiYjQ3ODE0MzgtYjA2MS03MDllLWI3NGQtZDg0NTljODQzY2E0Iiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJhdWQiOiI2YzU2dDdyZTZla2dtdjIzbzd0bzhyMHNpYyIsImV2ZW50X2lkIjoiZDAwOGUyYzYtZWEwOS00NDJmLTliNGQtZmQwMzhkOWU5ODcwIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE3MTAzNDc3MDMsImV4cCI6MTcxMDM1MTMwMywiaWF0IjoxNzEwMzQ3NzAzLCJqdGkiOiJkNTdmMTNiOS1jYjkzLTQxMWEtYjkxYy0yMDIxNmFhZjMxNWQiLCJlbWFpbCI6ImpveUBteXN0ZW5sYWJzLmNvbSJ9.XRvM8REvtAIYrNCeby0IHieZpOSgUZ8AKDdQNsmY5NngGIS45Z9Cjy7cMp1YiVPdVG30IUjuzd6a1HfnR30y1tU805RedwdzIHSQyW3IQu4dHDtLLi00_ILUhDwcnWF6mckUyUGUSaV4-wwbS3bR5VUqliqwDXN_NR9Q5ALBZqsoOeSX3k8sXUjcnpR1sEisUIFTv1IlUKSBwXBhm_XQkVykFksUFB7sUOr5cOKdPLm8gvhCfp2rnZ-VjY-QhhHbhcJKgmy3QgHcKO9N1CjTMJ4v9jLhZ8JNffu16zfcFtxlVr-E91F2ls633RAMVRTgpoY0xiZv9lKNGEu-pY1lYQ";
    // Make a map of jwk ids to jwks just for AWS Tenant.
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(parsed_token).await;
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            iss,
            "kF4FeN4zd6VNYDAdxDFa4/qjqjMKoonryYZuKTN76dE=".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "uzJzyPjXUGrXwlTjEIxyvULbEdRloHI4wE794wukpIR8zPd13Rx1uH00BqGCCsjuzoooPoFByY4T8GSsS7ESgHzkLGBNyo6e0mYa8SkgaABdpwkWx7lvOjhhuZEWvbnfiM55lEVwI_Fqh7461zX0xnZreoOAMGTVUVMzHE-X36pxtw3BnG6pH_AY-2rFTrWZAu9VzbeXloaoqJzvZYVxbrY7jpPDIWV7NcXv_i3uMW9858pRrfdc3Omk76G4yyxJAImRnn76ZHJs1Atz4t-whvhk_KSLBFFd02AXSSzZ1CCS1LHDWPY8qQN8Hbql74sZKRfKNuJRVu9zfNf0EGleYQ".to_string(),
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

#[tokio::test]
async fn test_end_to_end_test_issuer() {
    // cargo test --features e2e -- --nocapture test_end_to_end_test_issuer
    // Use a fixed AWS token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let client = reqwest::Client::new();
    let parsed_token = get_jwt_token(
        &client,
        "hTPpgF7XAKbW37rEUS6pEVZqmoI",
        "https://oauth.sui.io",
        "12345",
    )
    .await
    .unwrap()
    .jwt;
    // Make a map of jwk ids to jwks just for Microsoft.
    let (max_epoch, eph_pubkey, zk_login_inputs, iss) = get_test_inputs(&parsed_token).await;
    let jwks = fetch_jwks(&OIDCProvider::from_iss(&iss).unwrap(), &client)
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

async fn get_test_inputs(parsed_token: &str) -> (u64, Vec<u8>, ZkLoginInputs, String) {
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
    let (sub, aud, iss) = parse_and_validate_jwt(parsed_token).unwrap();
    // Get the address seed.
    let address_seed = gen_address_seed(user_salt, "sub", &sub, &aud).unwrap();
    let zk_login_inputs = ZkLoginInputs::from_reader(reader, &address_seed).unwrap();
    (max_epoch, eph_pubkey, zk_login_inputs, iss)
}

/// Call the prover backend to get the zkLogin inputs based on jwt_token, max_epoch, jwt_randomness, eph_pubkey and salt.
async fn get_jwt_token(
    client: &reqwest::Client,
    nonce: &str,
    iss: &str,
    sub: &str,
) -> Result<TestIssuerJWTResponse, FastCryptoError> {
    let response = client
        .post(format!(
            "https://jwt-tester.mystenlabs.com/jwt?nonce={}&iss={}&sub={}",
            nonce, iss, sub
        ))
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let full_bytes = response
        .bytes()
        .await
        .map_err(|_| FastCryptoError::InvalidInput)?;

    println!("get_jwt_response response: {:?}", full_bytes);

    let get_jwt_response: TestIssuerJWTResponse =
        serde_json::from_slice(&full_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    Ok(get_jwt_response)
}

#[derive(Debug, Serialize, Deserialize)]
struct TestIssuerJWTResponse {
    jwt: String,
}
