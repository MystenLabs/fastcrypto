// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::str::FromStr;

use crate::bn254::utils::get_nonce;
use crate::bn254::zk_login::{
    decode_base64_url, hash_ascii_str_to_field, hash_to_field, parse_jwks, trim,
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
use num_bigint::BigUint;

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

    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    assert!(ZkLoginInputs::from_json("{\"something\":{\"pi_a\":[\"17906300526443048714387222471528497388165567048979081127218444558531971001212\",\"16347093943573822555530932280098040740968368762067770538848146419225596827968\",\"1\"],\"pi_b\":[[\"604559992637298524596005947885439665413516028337069712707205304781687795569\",\"3442016989288172723305001983346837664894554996521317914830240702746056975984\"],[\"11525538739919950358574045244601652351196410355282682596092151863632911615318\",\"8054528381876103674715157136115660256860302241449545586065224275685056359825\"],[\"1\",\"0\"]],\"pi_c\":[\"12090542001353421590770702288155881067849038975293665701252531703168853963809\",\"8667909164654995486331191860419304610736366583628608454080754129255123340291\",\"1\"]},\"address_seed\":\"7577247629761003321376053963457717029490787816434302620024795358930497565155\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjkxMWUzOWUyNzkyOGFlOWYxZTlkMWUyMTY0NmRlOTJkMTkzNTFiNDQiLCJ0eXAiOiJKV1QifQ\"}").is_err());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"19787893228347416264175863455553559620428641614896993159007341506168718628112\",\"9525429549286657723959098685731622393483997723182834572003815901856723580461\",\"1\"],\"pi_b\":[[\"3493347571535213714356485688393536339935225306901617492672730508554674104240\",\"16985532751431776840148620485065973908539904507322892849232044565343489766128\"],[\"13893319072314620992397619679873669034526557780388381368678976150917704243179\",\"640742494801049238290284649145440140989242166770354858908399041461288677398\"],[\"1\",\"0\"]],\"pi_c\":[\"21862480547331092832339784749917351442633352096270524226556828302437894726278\",\"12611981741824395163083120319401608319346495925967864800017660949138781692880\",\"1\"]},\"address_seed\":\"15909817818955140159551330044992054478592339431921061309213971300613403932293\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjdjOWM3OGUzYjAwZTFiYjA5MmQyNDZjODg3YjExMjIwYzg3YjdkMjAiLCJ0eXAiOiJKV1QifQ\"}").unwrap().init().unwrap();
    assert_eq!(
        zklogin_inputs.get_kid(),
        "7c9c78e3b00e1bb092d246c887b11220c87b7d20".to_string()
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
    assert_eq!(
        zklogin_inputs.get_address_seed(),
        "15909817818955140159551330044992054478592339431921061309213971300613403932293"
    );
    let mut map = HashMap::new();
    let content = JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "pGMz603XOzO71r-LpW555Etbn2dXAtY4xToNE_Upr1EHxkHFnVnGPsbOeWzP8xU1IpAL56S3sTsbpCR_Ci_PYq8s4I3VWQM0u9w1D_e45S1KJTSex_aiMQ_cjTXb3Iekc00JIkMJhUaNnbsEt7PlOmnyFqvN-G3ZXVDfTuL2Wsn4tRMYf7YU3jgTVN2M_p7bcZYHhkEB-jzNeK7ub-6mOMkKdYWnk0jIoRfV63d32bub0pQpWv8sVmflgK2xKUSJVMZ7CM0FvJYJgF7y42KBPYc6Gm_UWE0uHazDgZgAvQQoNyEF_TRjVfGiihjPFYCPqvFcfLK4773JTD2fLZTgOQ".to_string(),
        alg: "RS256".to_string(),
    };

    map.insert(
        (
            "7c9c78e3b00e1bb092d246c887b11220c87b7d20".to_string(),
            OIDCProvider::Google.get_config().0.to_string(),
        ),
        content.clone(),
    );
    let modulus = Base64UrlUnpadded::decode_vec(&content.n).unwrap();
    assert_eq!(
        zklogin_inputs
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, 10)
            .unwrap(),
        vec![Bn254Fr::from_str(
            "9496323448584064558296338231676268184078052204097371080436367115432777673272"
        )
        .unwrap()]
    );
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, Environment::Test);
    assert!(res.is_ok());
}

#[test]
fn test_verify_zk_login_twitch() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"13051843614423432670927014216106415297302637061714876201698143724579485057433\",\"4502868464003469408525038047182455632737577658719986979336848385442638461715\",\"1\"],\"pi_b\":[[\"3766376969677702623227635810414794209012765519614143648451277080679068806865\",\"15274848924865252629859978623879023835428524488301134035498591572116063831502\"],[\"7946138017363758578225489333393267390091071305689481146893911497411367587561\",\"2088365154316551099212086738010689343716611426876233601699514012876088160321\"],[\"1\",\"0\"]],\"pi_c\":[\"5241274211994340733749437701839810664498991243102320350483342489924082173589\",\"15038895168244503564969393433273344359013838973322340723065298413943589759359\",\"1\"]},\"address_seed\":\"15454157267374145582481438333218897413377268576773635507925280300337575904853\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw\",\"index_mod_4\":2},{\"name\":\"aud\",\"value_base64\":\"yJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ\"}").unwrap().init().unwrap();
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
        "15454157267374145582481438333218897413377268576773635507925280300337575904853"
    );

    let mut map = HashMap::new();
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
fn test_hash_ascii_str_to_field() {
    // Test generated against typescript implementation.
    assert_eq!(
        hash_ascii_str_to_field("test@gmail.com", 30)
            .unwrap()
            .to_string(),
        "13606676331558803166736332982602687405662978305929711411606106012181987145625"
    );
}

#[test]
fn test_hash_to_field() {
    // Test generated against typescript implementation.
    assert_eq!(
        hash_to_field(
            &[
                BigUint::from_str("32").unwrap(),
                BigUint::from_str("25").unwrap(),
                BigUint::from_str("73").unwrap()
            ],
            8,
            16
        )
        .unwrap()
        .to_string(),
        "11782828208033177576380997957942702678240059658740659662920410026149313654840".to_string()
    );
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
    let nonce = get_nonce(&eph_pk_bytes, 10, "100681567828351849884072155819400689117").unwrap();
    assert_eq!(nonce, "hTPpgF7XAKbW37rEUS6pEVZqmoI");
}
