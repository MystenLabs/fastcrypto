// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::bn254::utils::{gen_address_seed, get_nonce, get_proof, get_salt, get_zk_login_address};
use crate::bn254::zk_login::{
    convert_base, decode_base64_url, hash_ascii_str_to_field, hash_to_field, parse_jwks, trim,
    verify_extended_claim, Claim, JWTDetails, JWTHeader, JwkId,
};
use crate::bn254::zk_login::{fetch_jwks, OIDCProvider};
use crate::bn254::zk_login_api::{Bn254Fr, ZkLoginEnv};
use crate::bn254::{
    zk_login::{ZkLoginInputs, JWK},
    zk_login_api::verify_zk_login,
};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::jwt_utils::parse_and_validate_jwt;
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
        "keys":[{"alg":"RS256","e":"AQAB","kid":"1","kty":"RSA","n":"6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw","use":"wrong usage"}]
      }"#.as_bytes();

#[tokio::test]
async fn test_verify_zk_login_google() {
    let user_salt = "206703048842351542647799591018316385612";

    // Generate an ephermeral key pair.
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());
    let kp_bigint = BigUint::from_bytes_be(&eph_pubkey).to_string();

    // Get the address seed.
    let address_seed = gen_address_seed(
        user_salt,
        "sub",
        "106294049240999307923",
        "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com",
    )
    .unwrap();

    let parsed_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjdjMGI2OTEzZmUxMzgyMGEzMzMzOTlhY2U0MjZlNzA1MzVhOWEwYmYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNTc2OTgzMjM3NC1mYW1lY3FyaGUyZ2tlYnQ1ZnZxbXMyMjYzMDQ2bGo5Ni5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjI1NzY5ODMyMzc0LWZhbWVjcXJoZTJna2VidDVmdnFtczIyNjMwNDZsajk2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA2Mjk0MDQ5MjQwOTk5MzA3OTIzIiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJuYmYiOjE2OTUwNTUyMjQsImlhdCI6MTY5NTA1NTUyNCwiZXhwIjoxNjk1MDU5MTI0LCJqdGkiOiJjYjVjYTRkYmI2M2MzOTNkOGE3Mjc3ZDQ2YzFhODg1NTY4NmViMGE2In0.LAhVUmNeH9JuD85f_5wy5t1p5hAKIC0n-zW4Bn4oMuzdwIckcZ0F2iuXKqf00JWX5SQFdUEXaSKK38dnhAwYbUUkl4o5_06PmQY4PnMfOh9bcBzybXfo_jBuL0LCi-9CJG_hU-tTQLqjUk9yUui_xOOeCHU0hH1DSKdm64c1oaAAmuHuu67-btc1ECtaqCF_-_IL_uNIhnzlc0XI3h0aMgind-duAUAaIeMBvSXrseOQ1g-kOufXP-0VW5Fvx8vha1xv0OHowLhr0V7eYG-5-3kbiQskE6h8J7mnN5FLHD6_uafb5FqJQnHaHCvqi_Nixypc9hDEqudSlhzW1h2afw";

    let max_epoch = 10;
    let jwt_randomness = "100681567828351849884072155819400689117";

    // Get a proof from endpoint and serialize it.
    let reader = get_proof(
        parsed_token,
        max_epoch,
        jwt_randomness,
        &kp_bigint,
        user_salt,
    )
    .await
    .unwrap();
    // Get a proof from endpoint and serialize it.
    let zk_login_inputs = ZkLoginInputs::from_reader(reader, &address_seed).unwrap();
    assert_eq!(
        zk_login_inputs.get_kid(),
        "7c0b6913fe13820a333399ace426e70535a9a0bf".to_string()
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
        n: "lWXY0XOj_ikSIDIvGOhfuRhQJAAj6BWsbbZ6P-PXRclzV32-QLB4GZHPPcH37Lou5pQsTQPvTETAfCLnglIRSbP8x1zA5tUakRlm5RiGF4kcWh5k60x8u0Uslx-d6EueKuY-KLHUVDuMULlHkYAScIdYnXz-Cnr6PFZj8RQezzdPVPH53Q8a_Z9b-vpGzsMS5gszITb-72OQNokojXdPVctl5WzSx-JnWbJxPiwHx_dSWgmTnyiYrZLqrqfampGdroaamtIXy0W8CAe0uCqcD1LunpfX-Q-RD1IycxnEaXSuUKhNhCcxtHWrozEyeD23Zja2WlcvHdYuTzyrvrvS9Q".to_string(),
        alg: "RS256".to_string(),
    };

    map.insert(
        JwkId::new(
            OIDCProvider::Google.get_config().iss,
            "7c0b6913fe13820a333399ace426e70535a9a0bf".to_string(),
        ),
        content,
    );
    let res = verify_zk_login(&zk_login_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Prod);
    assert!(res.is_ok());
}

#[test]
fn test_parse_jwt_details() {
    let header = JWTHeader::new("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ").unwrap();
    assert_eq!(header.alg, "RS256");
    assert_eq!(header.typ, "JWT");

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

#[tokio::test]
async fn test_end_to_end_twitch() {
    // Use a fixed Twitch token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLCJleHAiOjE2OTIyODQzMzQsImlhdCI6MTY5MjI4MzQzNCwiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiwic3ViIjoiOTA0NDQ4NjkyIiwiYXpwIjoicnMxYmgwNjVpOXlhNHlkdmlmaXhsNGtzczB1aHB0Iiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb3lxdnEifQ.M54Sgs6aDu5Mprs_CgXeRbgiErC7oehj-h9oEcBqZFDADwd09zs9hbfDPqUjaNBB-_I6G7kn9e-zwPov8PUecI68kr3oyiCMWhKD-3h1FEu13MZv71B6jhIDMu1_UgI-RSrOQMRvdI8eL3qqD-KsvJuJH1Sz0w56PnB0xupUg-eSvgnMBAo6iTa0t1grX9qGy7U00i_oqn9J4jVGVVEbMhUWROJMjowWdOogJ4_VNqm67JHd_rMZ3xtjLabP6Nk1Gx-VjUbYceNADWUr5xpJveRtvb1FJvd0HSN4mab51zuSUnavCQw2OXbyoH8j6uuQAAKVhG-_Ht1hCvReycGXKw";
    let max_epoch = 10;
    let jwt_randomness = "100681567828351849884072155819400689117";

    // Get salt based on the Twitch token.
    let user_salt = get_salt(parsed_token).await.unwrap();

    // Generate an ephermeral key pair.
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());
    let kp_bigint = BigUint::from_bytes_be(&eph_pubkey).to_string();

    // Get a proof from endpoint and serialize it.
    let reader = get_proof(
        parsed_token,
        max_epoch,
        jwt_randomness,
        &kp_bigint,
        &user_salt,
    )
    .await
    .unwrap();
    let (sub, aud) = parse_and_validate_jwt(parsed_token).unwrap();
    // Get the address seed.
    let address_seed = gen_address_seed(&user_salt, "sub", &sub, &aud).unwrap();
    let zk_login_inputs = ZkLoginInputs::from_reader(reader, &address_seed).unwrap();
    // Make a map of jwk ids to jwks just for Twitch.
    let mut map = ImHashMap::new();
    map.insert(
        JwkId::new(
            OIDCProvider::Twitch.get_config().iss,
            "1".to_string(),
        ),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
            alg: "RS256".to_string(),
        },
    );

    // Verify it against final vk.
    let res = verify_zk_login(
        &zk_login_inputs,
        max_epoch,
        &eph_pubkey,
        &map,
        &ZkLoginEnv::Prod,
    );
    assert!(res.is_ok());
}
