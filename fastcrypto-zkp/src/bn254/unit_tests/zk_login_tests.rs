// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::bn254::poseidon::hash;
use crate::bn254::utils::{
    big_int_str_to_bytes, gen_address_seed, gen_address_seed_with_salt_hash, get_nonce,
    get_zk_login_address,
};
use crate::bn254::zk_login::{
    convert_base, decode_base64_url, hash_ascii_str_to_field, hash_to_field, parse_jwks, to_field,
    trim, verify_extended_claim, Claim, JWTDetails, JwkId,
};
use crate::bn254::zk_login::{fetch_jwks, OIDCProvider};
use crate::bn254::zk_login_api::ZkLoginEnv;
use crate::bn254::zk_login_api::{verify_zk_login_id, verify_zk_login_iss, Bn254Fr};
use crate::bn254::{
    zk_login::{ZkLoginInputs, JWK},
    zk_login_api::verify_zk_login,
};
use ark_bn254::Fr;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::jwt_utils::JWTHeader;
use fastcrypto::traits::KeyPair;
use im::hashmap::HashMap as ImHashMap;
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
        "keys":[{"alg":"ES256","e":"AQAB","kid":"1","kty":"RSA","n":"6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw","use":"wrong usage"}]
      }"#.as_bytes();

#[tokio::test]
async fn test_verify_zk_login_google() {
    let user_salt = "206703048842351542647799591018316385612";

    // Generate an ephermeral key pair.
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    // Get the address seed.
    let address_seed = gen_address_seed(
        user_salt,
        "sub",
        "106294049240999307923",
        "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com",
    )
    .unwrap();

    // Get a proof from endpoint and serialize it.
    let zk_login_inputs = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"8247215875293406890829839156897863742504615191361518281091302475904551111016\",\"6872980335748205979379321982220498484242209225765686471076081944034292159666\",\"1\"],\"b\":[[\"21419680064642047510915171723230639588631899775315750803416713283740137406807\",\"21566716915562037737681888858382287035712341650647439119820808127161946325890\"],[\"17867714710686394159919998503724240212517838710399045289784307078087926404555\",\"21812769875502013113255155836896615164559280911997219958031852239645061854221\"],[\"1\",\"0\"]],\"c\":[\"7530826803702928198368421787278524256623871560746240215547076095911132653214\",\"16244547936249959771862454850485726883972969173921727256151991751860694123976\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmRlODRhMmQ1NTJiNGM2ZjEiLCJ0eXAiOiJKV1QifQ\"}", &address_seed).unwrap();
    assert_eq!(
        zk_login_inputs.get_kid(),
        "6f7254101f56e41cf35c9926de84a2d552b4c6f1".to_string()
    );
    assert_eq!(
        zk_login_inputs.get_iss(),
        OIDCProvider::Google.get_config().iss
    );
    assert_eq!(zk_login_inputs.get_address_seed(), address_seed);
    assert_eq!(
        get_zk_login_address(
            zk_login_inputs.get_address_seed(),
            &OIDCProvider::Google.get_config().iss
        )
        .unwrap()
        .to_vec(),
        Hex::decode("0xa64ae946d5efd2dea396cb2fe81837f028c32f2b2f211176b65a3a152deb35a2").unwrap()
    );

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
        content,
    );
    let res = verify_zk_login(&zk_login_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Prod);
    assert!(res.is_ok());
}

#[test]
fn test_parse_jwt_details() {
    let header = JWTHeader::new("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ").unwrap();
    assert_eq!(header.kid, "1");

    // Invalid base64
    assert_eq!(
        JWTHeader::new("").unwrap_err(),
        FastCryptoError::InvalidInput
    );
    const VALID_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ";

    // missing claim
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &Claim {
                value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                index_mod_4: 2
            }
        )
        .unwrap()
        .iss,
        OIDCProvider::Twitch.get_config().iss
    );

    // bad index_mod_4
    assert_eq!(
        JWTDetails::new(
            VALID_HEADER,
            &Claim {
                value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_string(),
                index_mod_4: 4
            }
        )
        .unwrap_err(),
        FastCryptoError::GeneralError("Invalid first_char_offset".to_string())
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
fn test_convert_base() {
    assert_eq!(
        convert_base(
            &[
                BigUint::from_str("1").unwrap(),
                BigUint::from_str("2").unwrap(),
                BigUint::from_str("3").unwrap(),
                BigUint::from_str("4").unwrap(),
            ],
            4,
            4
        )
        .unwrap(),
        vec![
            Bn254Fr::from_str("1").unwrap(),
            Bn254Fr::from_str("2").unwrap(),
            Bn254Fr::from_str("3").unwrap(),
            Bn254Fr::from_str("4").unwrap(),
        ]
    );

    assert_eq!(
        convert_base(
            &[
                BigUint::from_str("1").unwrap(),
                BigUint::from_str("2").unwrap(),
                BigUint::from_str("3").unwrap(),
                BigUint::from_str("4").unwrap(),
            ],
            4,
            8
        )
        .unwrap(),
        vec![
            Bn254Fr::from_str("18").unwrap(),
            Bn254Fr::from_str("52").unwrap(),
        ]
    );

    assert_eq!(
        convert_base(
            &[
                BigUint::from_str("1").unwrap(),
                BigUint::from_str("2").unwrap(),
                BigUint::from_str("3").unwrap(),
                BigUint::from_str("4").unwrap(),
            ],
            4,
            16
        )
        .unwrap(),
        vec![Bn254Fr::from_str("4660").unwrap(),]
    );

    assert_eq!(
        convert_base(
            &[
                BigUint::from_str("1").unwrap(),
                BigUint::from_str("2").unwrap(),
                BigUint::from_str("3").unwrap(),
                BigUint::from_str("4").unwrap(),
            ],
            4,
            6
        )
        .unwrap(),
        vec![
            Bn254Fr::from_str("1").unwrap(),
            Bn254Fr::from_str("8").unwrap(),
            Bn254Fr::from_str("52").unwrap()
        ]
    );

    assert_eq!(
        convert_base(
            &[
                BigUint::from_str("7").unwrap(),
                BigUint::from_str("1").unwrap(),
                BigUint::from_str("8").unwrap(),
                BigUint::from_str("2").unwrap(),
            ],
            4,
            7
        )
        .unwrap(),
        vec![
            Bn254Fr::from_str("1").unwrap(),
            Bn254Fr::from_str("99").unwrap(),
            Bn254Fr::from_str("2").unwrap()
        ]
    );

    assert_eq!(
        convert_base(&[BigUint::from_str("1").unwrap(),], 1, 6).unwrap(),
        vec![Bn254Fr::from_str("1").unwrap(),]
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

    assert_eq!(
        hash_ascii_str_to_field("test@gmail.com", 32)
            .unwrap()
            .to_string(),
        "10404231015713323946367565043703223078961469658905861259850380980432751872181"
    );
    assert_eq!(
        hash_ascii_str_to_field("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ", 248)
            .unwrap()
            .to_string(),
        "10859137172532636243875876865378218840892896099608302223608404291948352005840"
    );
}

#[test]
fn test_hash_to_field() {
    let v = [
        BigUint::from_str("32").unwrap(),
        BigUint::from_str("25").unwrap(),
        BigUint::from_str("73").unwrap(),
    ];

    assert_eq!(
        hash_to_field(&v, 8, 16).unwrap().to_string(),
        "19904721247081466064775016944536603990869066672076269915271149427650748384560".to_string()
    );

    assert_eq!(
        hash_to_field(&v, 8, 24).unwrap().to_string(),
        "12957933350199698616059824573728499566767221415248116668293168872342238553232".to_string()
    );

    assert_eq!(
        hash_to_field(&v, 8, 248).unwrap().to_string(),
        "12957933350199698616059824573728499566767221415248116668293168872342238553232".to_string()
    );
}

#[test]
fn test_jwk_parse() {
    assert_eq!(
        trim("wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww==".to_string()),
        "wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww"
    );

    parse_jwks(GOOGLE_JWK_BYTES, &OIDCProvider::Google)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Google.get_config().iss);
        });

    parse_jwks(TWITCH_JWK_BYTES, &OIDCProvider::Twitch)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Twitch.get_config().iss);
        });

    parse_jwks(FACEBOOK_JWK_BYTES, &OIDCProvider::Facebook)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Facebook.get_config().iss);
        });

    assert!(parse_jwks(BAD_JWK_BYTES, &OIDCProvider::Twitch).is_err());

    assert!(parse_jwks(
        r#"{
        "something":[]
      }"#
        .as_bytes(),
        &OIDCProvider::Twitch
    )
    .is_err());
}

#[tokio::test]
async fn test_get_jwks() {
    let client = reqwest::Client::new();
    for p in [
        OIDCProvider::Facebook,
        OIDCProvider::Google,
        OIDCProvider::Twitch,
        OIDCProvider::Slack,
        OIDCProvider::Kakao,
        OIDCProvider::Apple,
    ] {
        let res = fetch_jwks(&p, &client).await;
        assert!(res.is_ok());
        res.unwrap().iter().for_each(|e| {
            assert_eq!(e.0.iss, p.get_config().iss);
            assert_eq!(e.1.alg, "RS256".to_string());
        });
    }
}

#[test]
fn test_get_nonce() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pk_bytes = vec![0x00];
    eph_pk_bytes.extend(kp.public().as_ref());
    let nonce = get_nonce(&eph_pk_bytes, 10, "100681567828351849884072155819400689117").unwrap();
    assert_eq!(nonce, "hTPpgF7XAKbW37rEUS6pEVZqmoI");
}

#[test]
fn test_get_provider() {
    for p in [
        OIDCProvider::Google,
        OIDCProvider::Twitch,
        OIDCProvider::Facebook,
    ] {
        assert_eq!(p, OIDCProvider::from_iss(&p.get_config().iss).unwrap());
    }
    assert!(OIDCProvider::from_iss("Amazon").is_err());
}

#[test]
fn test_gen_seed() {
    let address_seed = gen_address_seed(
        "248191903847969014646285995941615069143",
        "sub",
        "904448692",
        "rs1bh065i9ya4ydvifixl4kss0uhpt",
    )
    .unwrap();
    assert_eq!(
        address_seed,
        "16657007263003735230240998439420301694514420923267872433517882233836276100450".to_string()
    );
}

#[test]
fn test_verify_zk_login() {
    // Test vector from [test_verify_zk_login_google]
    let address =
        hex::decode("1c6b623a2f2c91333df730c98d220f11484953b391a3818680f922c264cc0c6b").unwrap();
    let name = "sub";
    let value = "106294049240999307923";
    let aud = "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com";
    let salt = "6588741469050502421550140105345050859";
    let iss = "https://accounts.google.com";
    let salt_hash = hash(vec![to_field(salt).unwrap()]).unwrap().to_string();
    assert!(verify_zk_login_id(&address, name, value, aud, iss, &salt_hash).is_ok());

    let address_seed = gen_address_seed_with_salt_hash(&salt_hash, name, value, aud).unwrap();
    assert!(verify_zk_login_iss(&address, &address_seed, iss).is_ok());

    let other_iss = "https://some.other.issuer.com";
    assert_eq!(
        verify_zk_login_id(&address, name, value, aud, other_iss, &salt_hash),
        Err(FastCryptoError::InvalidProof)
    );
    assert_eq!(
        verify_zk_login_iss(&address, &address_seed, other_iss),
        Err(FastCryptoError::InvalidProof)
    );

    let too_long_kc_name = "subsubsubsubsubsubsubsubsubsubsubsub";
    assert_eq!(
        verify_zk_login_id(
            &address,
            too_long_kc_name,
            value,
            aud,
            other_iss,
            &salt_hash
        ),
        Err(FastCryptoError::GeneralError("in_arr too long".to_string()))
    );

    let too_long_kc_value = "106294049240999307923106294049240999307923106294049240999307923106294049240999307923106294049240999307923106294049240999307923";
    assert_eq!(
        verify_zk_login_id(
            &address,
            name,
            too_long_kc_value,
            aud,
            other_iss,
            &salt_hash
        ),
        Err(FastCryptoError::GeneralError("in_arr too long".to_string()))
    );
}

#[test]
fn test_all_inputs_hash() {
    let jwt_sha2_hash_0 = Fr::from_str("248987002057371616691124650904415756047").unwrap();
    let jwt_sha2_hash_1 = Fr::from_str("113498781424543581252500776698433499823").unwrap();
    let masked_content_hash = Fr::from_str(
        "14900420995580824499222150327925943524564997104405553289134597516335134742309",
    )
    .unwrap();
    let payload_start_index = Fr::from_str("103").unwrap();
    let payload_len = Fr::from_str("564").unwrap();
    let eph_public_key_0 = Fr::from_str("17932473587154777519561053972421347139").unwrap();
    let eph_public_key_1 = Fr::from_str("134696963602902907403122104327765350261").unwrap();
    let max_epoch = Fr::from_str("10000").unwrap();
    let num_sha2_blocks = Fr::from_str("11").unwrap();
    let key_claim_name_f = Fr::from_str(
        "18523124550523841778801820019979000409432455608728354507022210389496924497355",
    )
    .unwrap();
    let addr_seed = Fr::from_str(
        "15604334753912523265015800787270404628529489918817818174033741053550755333691",
    )
    .unwrap();

    let hash = hash(vec![
        jwt_sha2_hash_0,
        jwt_sha2_hash_1,
        masked_content_hash,
        payload_start_index,
        payload_len,
        eph_public_key_0,
        eph_public_key_1,
        max_epoch,
        num_sha2_blocks,
        key_claim_name_f,
        addr_seed,
    ])
    .unwrap();
    assert_eq!(
        hash.to_string(),
        "2487117669597822357956926047501254969190518860900347921480370492048882803688".to_string()
    );
}
#[test]
fn test_alternative_iss_for_google() {
    let input = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"7566241567720780416751598994698310678767195459947224622023785587667176814058\",\"18104499930818305143361187733659014043953751050617136254447624192327280445771\",\"1\"],\"b\":[[\"11369230593957954942221175389182778816136534144714579815927653075736806430994\",\"11928003240637992017698644299021052465098754853899210401706726930513411198353\"],[\"2597127058046351054449743605218058440565462021354202666955356076272028963802\",\"3385145993275542896693643488618289924488296318344621918448585222369718288892\"],[\"1\",\"0\"]],\"c\":[\"395141536511114303768253959602639884294254888080713473665269769443249414257\",\"21430657725804540809568084344756144327539843580919730138594118365564728808275\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ\"}", "4959624758616676340947699768172740454110375485415332267384397278368360470616").unwrap();
    let invalid_proof_input = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"1\",\"18104499930818305143361187733659014043953751050617136254447624192327280445771\",\"1\"],\"b\":[[\"1\",\"11928003240637992017698644299021052465098754853899210401706726930513411198353\"],[\"2597127058046351054449743605218058440565462021354202666955356076272028963802\",\"3385145993275542896693643488618289924488296318344621918448585222369718288892\"],[\"1\",\"0\"]],\"c\":[\"395141536511114303768253959602639884294254888080713473665269769443249414257\",\"21430657725804540809568084344756144327539843580919730138594118365564728808275\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ\"}", "4959624758616676340947699768172740454110375485415332267384397278368360470616").unwrap();
    let _ = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"18104499930818305143361187733659014043953751050617136254447624192327280445771\",\"1\"],\"b\":[[\"11369230593957954942221175389182778816136534144714579815927653075736806430994\",\"11928003240637992017698644299021052465098754853899210401706726930513411198353\"],[\"2597127058046351054449743605218058440565462021354202666955356076272028963802\",\"3385145993275542896693643488618289924488296318344621918448585222369718288892\"],[\"1\",\"0\"]],\"c\":[\"395141536511114303768253959602639884294254888080713473665269769443249414257\",\"21430657725804540809568084344756144327539843580919730138594118365564728808275\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ\"}", "4959624758616676340947699768172740454110375485415332267384397278368360470616").is_err();
    let _ = ZkLoginInputs::from_json("{\"proofPoints\":{\"a\":[\"18104499930818305143361187733659014043953751050617136254447624192327280445771\",\"1\"],\"b\":[[\"11369230593957954942221175389182778816136534144714579815927653075736806430994\",\"11928003240637992017698644299021052465098754853899210401706726930513411198353\"],[\"2597127058046351054449743605218058440565462021354202666955356076272028963802\",\"3385145993275542896693643488618289924488296318344621918448585222369718288892\"],[\"1\",\"0\"]],\"c\":[\"395141536511114303768253959602639884294254888080713473665269769443249414257\",\"21430657725804540809568084344756144327539843580919730138594118365564728808275\",\"1\"]},\"issBase64Details\":{\"value\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"indexMod4\":1},\"headerBase64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ\"}", "bad seed").is_err();

    let mut eph_pubkey_bytes = vec![0];
    eph_pubkey_bytes.extend(
        big_int_str_to_bytes(
            "3598866369818193253063936208363210863933653800990958031560302098730308306242903464",
        )
        .unwrap(),
    );
    let mut all_jwk = ImHashMap::new();
    all_jwk.insert(
        JwkId::new(
            OIDCProvider::Google.get_config().iss,
            "c9afda3682ebf09eb3055c1c4bd39b751fbf8195".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw".to_string(),
            alg: "RS256".to_string(),
        },
    );

    let res = verify_zk_login(
        &input,
        10000,
        &eph_pubkey_bytes,
        &all_jwk,
        &ZkLoginEnv::Test,
    );
    assert!(res.is_ok());

    let invalid_res = verify_zk_login(
        &invalid_proof_input,
        10000,
        &eph_pubkey_bytes,
        &all_jwk,
        &ZkLoginEnv::Test,
    );
    assert!(invalid_res.is_err());
}
