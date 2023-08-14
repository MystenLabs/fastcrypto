// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::utils::get_nonce;
use crate::bn254::zk_login::{
    big_int_str_to_bytes, decode_base64_url, map_bytes_to_field, parse_jwks, trim,
    verify_extended_claim, Claim, JWTDetails, JWTHeader,
};
use crate::bn254::zk_login::{fetch_jwks, OIDCProvider};
use crate::bn254::zk_login_api::Environment;
use crate::bn254::{
    zk_login::{ZkLoginInputs, JWK},
    zk_login_api::verify_zk_login,
};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::error::FastCryptoError;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};
use fastcrypto::traits::KeyPair;
use im::hashmap::HashMap as ImHashMap;
use num_bigint::BigInt;

const GOOGLE_JWK_BYTES: &[u8] = r#"{
    "keys": [
      {
        "n": "4kGxcWQdTW43aszLmftsGswmwDDKdfcse-lKeT_zjZTB2KGw9E6LVY6IThJVxzYF6mcyU-Z5_jDAW_yi7D_gXep2rxchZvoFayXynbhxyfjK6RtJ6_k30j-WpsXCSAiNAkupYHUyDIBNocvUcrDJsC3U65l8jl1I3nW98X6d-IlAfEb2In2f0fR6d-_lhIQZjXLupjymJduPjjA8oXCUZ9bfAYPhGYj3ZELUHkAyDpZNrnSi8hFVMSUSnorAt9F7cKMUJDM4-Uopzaqcl_f-HxeKvxN7NjiLSiIYaHdgtTpCEuNvsch6q6JTsllJNr3c__BxrG4UMlJ3_KsPxbcvXw==",
        "use": "sig",
        "alg": "RS256",
        "e": "AQAB",
        "kid": "911e39e27928ae9f1e9d1e21646de92d19351b44",
        "kty": "RSA"
      },
      {
        "n": "pGMz603XOzO71r-LpW555Etbn2dXAtY4xToNE_Upr1EHxkHFnVnGPsbOeWzP8xU1IpAL56S3sTsbpCR_Ci_PYq8s4I3VWQM0u9w1D_e45S1KJTSex_aiMQ_cjTXb3Iekc00JIkMJhUaNnbsEt7PlOmnyFqvN-G3ZXVDfTuL2Wsn4tRMYf7YU3jgTVN2M_p7bcZYHhkEB-jzNeK7ub-6mOMkKdYWnk0jIoRfV63d32bub0pQpWv8sVmflgK2xKUSJVMZ7CM0FvJYJgF7y42KBPYc6Gm_UWE0uHazDgZgAvQQoNyEF_TRjVfGiihjPFYCPqvFcfLK4773JTD2fLZTgOQ==",
        "kid": "7c9c78e3b00e1bb092d246c887b11220c87b7d20",
        "e": "AQAB",
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig"
      },
      {
        "use": "sig",
        "kid": "fd48a75138d9d48f0aa635ef569c4e196f7ae8d6",
        "e": "AQAB",
        "n": "8KImylelEspnZ0X-ekZb9VPbUFhgB_yEPJuLKOhXOWJLVsU0hJP6B_mQOfVk0CHm66UsAhqV8qrINk-RXgwVaaFLMA827pbOOBhyvHsThcyo7AY5s6M7qbftFKKnkfVHO6c9TsQ9wpIfmhCVL3QgTlqlgFQWcNsY-qemSKpqvVi-We9I3kPvbTf0PKJ_rWA7GQQnU_GA5JRU46uvw4I1ODf0icNBHw7pWc7oTvmSl1G8OWABEyiFakcUG2Xd4qZnmWaKwLHBvifPuIyy2vK-yHH91mVZCuleVu53Vzj77RgUtF2EEuB-zizwC-fzaBmvnfx1kgQLsdK22J0Ivgu4Xw==",
        "kty": "RSA",
        "alg": "RS256"
      }
    ]
  }"#.as_bytes();

const TWITCH_JWK_BYTES: &[u8] = r#"{
    "keys":[{"alg":"RS256","e":"AQAB","kid":"1","kty":"RSA","n":"6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw","use":"sig"}]
  }"#.as_bytes();

const FACEBOOK_JWK_BYTES: &[u8] = r#"{
        "keys": [
           {
              "kid": "5931701331165f07f550ac5f0194942d54f9c249",
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "n": "-GuAIboTsRYNprJQOkdmuKXRx8ARnKXOC9Pajg4KxHHPt3OY8rXRmVeDxTj1-m9TfW6V-wJa_8ncBbbFE-aV-eBi_XeuIToBBvLZp1-UPIjitS8WCDrUhHiJnbvkIZf1B1YBIq_Ua81fzxhtjQ0jDftV2m5aavmJG4_94VG3Md7noQjjUKzxJyUNl4v_joMA6pIRCeeamvfIZorjcR4wVf-wR8NiZjjRbcjKBpc7ztc7Gm778h34RSe9-DLH6uicTROSYNa99pUwhn3XVfAv4hTFpLIcgHYadLZjsHfUvivr76uiYbxDZx6UTkK5jmi51b87u1b6iYmijDIMztzrIQ",
              "e": "AQAB"
           },
           {
              "kid": "a378585d826a933cc207ce31cad63c019a53095c",
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "n": "1aLDAmRq-QeOr1b8WbtpmD5D4CpE5S0YrNklM5BrRjuZ6FTG8AhqvyUUnAb7Dd1gCZgARbuk2yHOOca78JWX2ocAId9R4OV2PUoIYljDZ5gQJBaL6liMpolQjlqovmd7IpF8XZWudWU6Rfhoh-j6dd-8IHeJjBKMYij0CuA6HZ1L98vBW1ehEdnBZPfTe28H57hySzucnC1q1340h2E2cpCfLZ-vNoYQ4Qe-CZKpUAKOoOlC4tWCt2rLcsV_vXvmNlLv_UYGbJEFKS-I1tEwtlD71bvn9WWluE7L4pWlIolgzNyIz4yxe7G7V4jlvSSwsu1ZtIQzt5AtTC--5HEAyQ",
              "e": "AQAB"
           }
        ]
    }"#.as_bytes();

const BAD_JWK_BYTES: &[u8] = r#"{
        "keys":[{"alg":"RS256","e":"AQAB","kid":"1","kty":"RSA","n":"6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw","use":"wrong usage"}]
      }"#.as_bytes();

#[test]
fn test_verify_zk_login_google() {
    use crate::bn254::zk_login_api::Bn254Fr;
    use std::str::FromStr;

    let eph_pubkey = big_int_str_to_bytes(
        "84029355920633174015103288781128426107680789454168570548782290541079926444544",
    );
    assert!(ZkLoginInputs::from_json("{\"something\":{\"pi_a\":[\"17906300526443048714387222471528497388165567048979081127218444558531971001212\",\"16347093943573822555530932280098040740968368762067770538848146419225596827968\",\"1\"],\"pi_b\":[[\"604559992637298524596005947885439665413516028337069712707205304781687795569\",\"3442016989288172723305001983346837664894554996521317914830240702746056975984\"],[\"11525538739919950358574045244601652351196410355282682596092151863632911615318\",\"8054528381876103674715157136115660256860302241449545586065224275685056359825\"],[\"1\",\"0\"]],\"pi_c\":[\"12090542001353421590770702288155881067849038975293665701252531703168853963809\",\"8667909164654995486331191860419304610736366583628608454080754129255123340291\",\"1\"]},\"address_seed\":\"7577247629761003321376053963457717029490787816434302620024795358930497565155\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjkxMWUzOWUyNzkyOGFlOWYxZTlkMWUyMTY0NmRlOTJkMTkzNTFiNDQiLCJ0eXAiOiJKV1QifQ\"}").is_err());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"17906300526443048714387222471528497388165567048979081127218444558531971001212\",\"16347093943573822555530932280098040740968368762067770538848146419225596827968\",\"1\"],\"pi_b\":[[\"604559992637298524596005947885439665413516028337069712707205304781687795569\",\"3442016989288172723305001983346837664894554996521317914830240702746056975984\"],[\"11525538739919950358574045244601652351196410355282682596092151863632911615318\",\"8054528381876103674715157136115660256860302241449545586065224275685056359825\"],[\"1\",\"0\"]],\"pi_c\":[\"12090542001353421590770702288155881067849038975293665701252531703168853963809\",\"8667909164654995486331191860419304610736366583628608454080754129255123340291\",\"1\"]},\"address_seed\":\"7577247629761003321376053963457717029490787816434302620024795358930497565155\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjkxMWUzOWUyNzkyOGFlOWYxZTlkMWUyMTY0NmRlOTJkMTkzNTFiNDQiLCJ0eXAiOiJKV1QifQ\"}").unwrap().init().unwrap();
    assert_eq!(
        zklogin_inputs.get_kid(),
        "911e39e27928ae9f1e9d1e21646de92d19351b44".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_iss(),
        OIDCProvider::Google.get_config().0.to_string()
    );
    assert_eq!(
        zklogin_inputs.get_aud(),
        "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_address_params().aud,
        "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_address_params().iss,
        OIDCProvider::Google.get_config().0.to_string()
    );

    let mut map = ImHashMap::new();
    let content = JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "4kGxcWQdTW43aszLmftsGswmwDDKdfcse-lKeT_zjZTB2KGw9E6LVY6IThJVxzYF6mcyU-Z5_jDAW_yi7D_gXep2rxchZvoFayXynbhxyfjK6RtJ6_k30j-WpsXCSAiNAkupYHUyDIBNocvUcrDJsC3U65l8jl1I3nW98X6d-IlAfEb2In2f0fR6d-_lhIQZjXLupjymJduPjjA8oXCUZ9bfAYPhGYj3ZELUHkAyDpZNrnSi8hFVMSUSnorAt9F7cKMUJDM4-Uopzaqcl_f-HxeKvxN7NjiLSiIYaHdgtTpCEuNvsch6q6JTsllJNr3c__BxrG4UMlJ3_KsPxbcvXw".to_string(),
        alg: "RS256".to_string(),
    };

    map.insert(
        (
            "911e39e27928ae9f1e9d1e21646de92d19351b44".to_string(),
            OIDCProvider::Google.get_config().0.to_string(),
        ),
        content.clone(),
    );
    let modulus = Base64UrlUnpadded::decode_vec(&content.n).unwrap();
    assert_eq!(
        zklogin_inputs
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, 10000)
            .unwrap(),
        vec![Bn254Fr::from_str(
            "16145454131073363668578485057126520560259092161919376662788533820152738424329"
        )
        .unwrap()]
    );
    let res = verify_zk_login(&zklogin_inputs, 10000, &eph_pubkey, &map, Environment::Test);
    assert!(res.is_ok());
}

#[test]
fn test_verify_zk_login_twitch() {
    let eph_pubkey = big_int_str_to_bytes(
        "84029355920633174015103288781128426107680789454168570548782290541079926444544",
    );
    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"13091564805270242091988535637094928145526962426048248457544204014146120848061\",\"16720184877774297257067413263271993886875650921635894599271213076438028149121\",\"1\"],\"pi_b\":[[\"10315437641058147137376024432028897182269999873576264368551692657896041757048\",\"1508628913652029422583835336497010615341442910432485486157510667573899391209\"],[\"2615204984444202339450727742801445002386326248143849542511762200103437621802\",\"5849486215298305357746845827664545444623657491883886014999288709074461992087\"],[\"1\",\"0\"]],\"pi_c\":[\"14195277018213067909432749083395103683618329379082932858378933760763589481512\",\"15923172920578108290608652430421506204931592172775947506845238271513931833500\",\"1\"]},\"address_seed\":\"8309251037759855865804524144086603991988043161256515070528758422897128118794\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw\",\"index_mod_4\":2},{\"name\":\"aud\",\"value_base64\":\"yJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ\"}").unwrap().init().unwrap();
    assert_eq!(zklogin_inputs.get_kid(), "1".to_string());
    assert_eq!(
        zklogin_inputs.get_iss(),
        OIDCProvider::Twitch.get_config().0.to_string()
    );
    assert_eq!(
        zklogin_inputs.get_aud(),
        "rs1bh065i9ya4ydvifixl4kss0uhpt".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_address_params().aud,
        "rs1bh065i9ya4ydvifixl4kss0uhpt".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_address_params().iss,
        zklogin_inputs.get_iss()
    );
    assert_eq!(
        zklogin_inputs.get_address_seed(),
        "8309251037759855865804524144086603991988043161256515070528758422897128118794"
    );

    let mut map = ImHashMap::new();
    map.insert(("1".to_string(), OIDCProvider::Twitch.get_config().0.to_string()), JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
        alg: "RS256".to_string(),
    });
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, Environment::Test);
    assert!(res.is_ok());
}

#[test]
fn test_verify_zk_login_facebook() {
    // TODO
}

#[test]
fn test_parsed_masked_content() {
    let header = JWTHeader::new("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ").unwrap();
    assert_eq!(header.alg, "RS256");
    assert_eq!(header.typ, "JWT");

    // Invalid base64
    assert_eq!(
        JWTHeader::new("").unwrap_err(),
        FastCryptoError::InvalidInput
    );
    const VALID_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ";

    // iss not found
    assert_eq!(
        JWTDetails::new(VALID_HEADER, &[]).unwrap_err(),
        FastCryptoError::GeneralError("Invalid claim".to_string())
    );

    // missing claim
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &[Claim {
                name: "iss".to_string(),
                value_base64: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                index_mod_4: 2
            }]
        )
        .unwrap_err(),
        FastCryptoError::GeneralError("Invalid claim".to_string())
    );

    // unknown claim name
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &[Claim {
                name: "unknown".to_string(),
                value_base64: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                index_mod_4: 2
            }]
        )
        .unwrap_err(),
        FastCryptoError::GeneralError("iss not found in claims".to_string())
    );

    // bad index_mod_4
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &[
                Claim {
                    name: "iss".to_string(),
                    value_base64: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                    index_mod_4: 2
                },
                Claim {
                    name: "aud".to_string(),
                    value_base64: "yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC"
                        .to_string(),
                    index_mod_4: 2
                }
            ]
        )
        .unwrap_err(),
        FastCryptoError::GeneralError("Invalid UTF8 string".to_string())
    );

    // first claim is not iss
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &[Claim {
                name: "aud".to_string(),
                value_base64: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                index_mod_4: 2
            }]
        )
        .unwrap_err(),
        FastCryptoError::GeneralError("iss not found in claims".to_string())
    );

    // second claim is not aud
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &[
                Claim {
                    name: "iss".to_string(),
                    value_base64: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                    index_mod_4: 2
                },
                Claim {
                    name: "iss".to_string(),
                    value_base64: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                    index_mod_4: 2
                }
            ]
        )
        .unwrap_err(),
        FastCryptoError::GeneralError("aud not found in claims".to_string())
    );
}

#[test]
fn test_decode_base64() {
    assert_eq!(
        decode_base64_url("", &0).unwrap_err(),
        FastCryptoError::GeneralError("Base64 string smaller than 2".to_string())
    );
    assert_eq!(
        decode_base64_url("yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC", &0).unwrap_err(),
        FastCryptoError::GeneralError("Invalid last_char_offset".to_string())
    );
    assert!(decode_base64_url("yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC", &1).is_ok());
    assert_eq!(
        decode_base64_url("yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC", &2).unwrap_err(),
        FastCryptoError::GeneralError("Invalid UTF8 string".to_string())
    );
    assert_eq!(
        decode_base64_url("yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC", &3).unwrap_err(),
        FastCryptoError::GeneralError("Invalid first_char_offset".to_string())
    );
}

#[test]
fn test_verify_extended_claim() {
    // does not end with , or }
    assert_eq!(
        verify_extended_claim("\"iss\":\"https://accounts.google.com\"", "iss").unwrap_err(),
        FastCryptoError::GeneralError("Invalid extended claim".to_string())
    );

    // Unexpected claim name
    assert_eq!(
        verify_extended_claim("\"iss\":\"https://accounts.google.com\",", "aud").unwrap_err(),
        FastCryptoError::InvalidInput
    );

    // Malformed json
    assert_eq!(
        verify_extended_claim("iss\":\"https://accounts.google.com\"", "iss").unwrap_err(),
        FastCryptoError::GeneralError("Invalid extended claim".to_string())
    );
    assert_eq!(
        verify_extended_claim("\"iss\"\"https://accounts.google.com\"", "iss").unwrap_err(),
        FastCryptoError::GeneralError("Invalid extended claim".to_string())
    );
}

#[test]
fn test_hash_to_field() {
    // Test generated against typescript implementation.
    assert!(map_bytes_to_field("sub", 2).is_err());
    assert_eq!(
        map_bytes_to_field("yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC", 133)
            .unwrap()
            .to_string(),
        "19198909745930267855439585988170070469004479286780644790990940640914248274464"
    );
    assert_eq!(map_bytes_to_field("CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC", 133).unwrap().to_string(), "6914089902564896687047107167562960781243311797290496295481879371814854678998");
    assert_eq!(map_bytes_to_field("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ", 150).unwrap().to_string(), "11195180390614794854381992733393925748746563026948577817495625199891112836762");
}

#[test]
fn test_jwk_parse() {
    assert_eq!(
        trim("wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww==".to_string()),
        "wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww"
    );

    parse_jwks(GOOGLE_JWK_BYTES, OIDCProvider::Google)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0 .1, OIDCProvider::Google.get_config().0);
        });

    parse_jwks(TWITCH_JWK_BYTES, OIDCProvider::Twitch)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0 .1, OIDCProvider::Twitch.get_config().0);
        });

    parse_jwks(FACEBOOK_JWK_BYTES, OIDCProvider::Facebook)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0 .1, OIDCProvider::Facebook.get_config().0);
        });

    assert!(parse_jwks(BAD_JWK_BYTES, OIDCProvider::Twitch).is_err());

    assert!(parse_jwks(
        r#"{
        "something":[]
      }"#
        .as_bytes(),
        OIDCProvider::Twitch
    )
    .is_err());
}

#[tokio::test]
async fn test_get_jwks() {
    let res = fetch_jwks().await;
    assert!(res.is_ok());
    assert!(!res.unwrap().is_empty());
}

#[test]
fn test_get_nonce() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pk_bytes = vec![0x00];
    eph_pk_bytes.extend(kp.public().as_ref());
    let pk_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &eph_pk_bytes);
    assert_eq!(
        pk_bigint.to_string(),
        "84029355920633174015103288781128426107680789454168570548782290541079926444544"
    );
    let nonce = get_nonce(&eph_pk_bytes, 10, "100681567828351849884072155819400689117");
    assert_eq!(nonce, "hTPpgF7XAKbW37rEUS6pEVZqmoI");
}
