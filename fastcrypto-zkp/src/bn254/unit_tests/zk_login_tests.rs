// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::zk_login::OAuthProvider::{Google, Twitch};
use crate::bn254::zk_login::{
    big_int_str_to_bytes, decode_base64_url, map_bytes_to_field, parse_jwks, trim,
    verify_extended_claim, Claim, JWTHeader, ParsedMaskedContent,
};
use crate::bn254::{
    zk_login::{OAuthProviderContent, ZkLoginInputs},
    zk_login_api::verify_zk_login,
};
use fastcrypto::error::FastCryptoError;
use im::hashmap::HashMap as ImHashMap;

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

#[test]
fn test_verify_groth16_in_bytes_google() {
    let eph_pubkey = big_int_str_to_bytes(
        "56151737484251736814483548229439134346260227666297800205999380540545421916794",
    );
    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"21873110949718272176264499735051118510902652173449346226388645893968555905454\",\"9365690448451448553918847987625925585660927132009682965576314935347286975528\",\"1\"],\"pi_b\":[[\"15958796868294059768344785719001504259904252886111915738476099643330239502720\",\"5199780263797497491150666057763076365993388827750563298709399606326966788526\"],[\"12251020242741083412146363549260633868128775234600208395200954294062312280014\",\"14706191700752148070300113544073417958401225568211414370186962841591249968729\"],[\"1\",\"0\"]],\"pi_c\":[\"12535507296151794095352527984139224545671930452049988269896859223168464793732\",\"14295848621099014282744065804163532747912895097343096119343520196101998703625\",\"1\"]},\"address_seed\":\"7577247629761003321376053963457717029490787816434302620024795358930497565155\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjkxMWUzOWUyNzkyOGFlOWYxZTlkMWUyMTY0NmRlOTJkMTkzNTFiNDQiLCJ0eXAiOiJKV1QifQ\"}").unwrap().init().unwrap();
    let mut map = ImHashMap::new();
    map.insert(("911e39e27928ae9f1e9d1e21646de92d19351b44".to_string(), Google.get_config().0.to_string()), OAuthProviderContent {
        kty: "RSA".to_string(),
        kid: "911e39e27928ae9f1e9d1e21646de92d19351b44".to_string(),
        e: "AQAB".to_string(),
        n: "4kGxcWQdTW43aszLmftsGswmwDDKdfcse-lKeT_zjZTB2KGw9E6LVY6IThJVxzYF6mcyU-Z5_jDAW_yi7D_gXep2rxchZvoFayXynbhxyfjK6RtJ6_k30j-WpsXCSAiNAkupYHUyDIBNocvUcrDJsC3U65l8jl1I3nW98X6d-IlAfEb2In2f0fR6d-_lhIQZjXLupjymJduPjjA8oXCUZ9bfAYPhGYj3ZELUHkAyDpZNrnSi8hFVMSUSnorAt9F7cKMUJDM4-Uopzaqcl_f-HxeKvxN7NjiLSiIYaHdgtTpCEuNvsch6q6JTsllJNr3c__BxrG4UMlJ3_KsPxbcvXw".to_string(),
        alg: "RS256".to_string(),
    });
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map);
    assert!(res.is_ok());
}

// TODO: revive when JWK is added in Sui.
// #[test]
// fn test_verify_groth16_in_bytes_twitch() {
//     let eph_pubkey = big_int_str_to_bytes(
//         "56151737484251736814483548229439134346260227666297800205999380540545421916794",
//     );
//     let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"21873110949718272176264499735051118510902652173449346226388645893968555905454\",\"9365690448451448553918847987625925585660927132009682965576314935347286975528\",\"1\"],\"pi_b\":[[\"15958796868294059768344785719001504259904252886111915738476099643330239502720\",\"5199780263797497491150666057763076365993388827750563298709399606326966788526\"],[\"12251020242741083412146363549260633868128775234600208395200954294062312280014\",\"14706191700752148070300113544073417958401225568211414370186962841591249968729\"],[\"1\",\"0\"]],\"pi_c\":[\"12535507296151794095352527984139224545671930452049988269896859223168464793732\",\"14295848621099014282744065804163532747912895097343096119343520196101998703625\",\"1\"]},\"address_seed\":\"7577247629761003321376053963457717029490787816434302620024795358930497565155\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjkxMWUzOWUyNzkyOGFlOWYxZTlkMWUyMTY0NmRlOTJkMTkzNTFiNDQiLCJ0eXAiOiJKV1QifQ\"}").unwrap().init().unwrap();
//     let mut map = ImHashMap::new();
//     map.insert(("1".to_string(), Twitch.get_config().0.to_string()), OAuthProviderContent {
//         kty: "RSA".to_string(),
//         kid: "1".to_string(),
//         e: "AQAB".to_string(),
//         n: "4kGxcWQdTW43aszLmftsGswmwDDKdfcse-lKeT_zjZTB2KGw9E6LVY6IThJVxzYF6mcyU-Z5_jDAW_yi7D_gXep2rxchZvoFayXynbhxyfjK6RtJ6_k30j-WpsXCSAiNAkupYHUyDIBNocvUcrDJsC3U65l8jl1I3nW98X6d-IlAfEb2In2f0fR6d-_lhIQZjXLupjymJduPjjA8oXCUZ9bfAYPhGYj3ZELUHkAyDpZNrnSi8hFVMSUSnorAt9F7cKMUJDM4-Uopzaqcl_f-HxeKvxN7NjiLSiIYaHdgtTpCEuNvsch6q6JTsllJNr3c__BxrG4UMlJ3_KsPxbcvXw".to_string(),
//         alg: "RS256".to_string(),
//     });
//     let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map);
//     assert!(res.is_ok());
// }

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
        ParsedMaskedContent::new(VALID_HEADER, &[]).unwrap_err(),
        FastCryptoError::GeneralError("Invalid claim".to_string())
    );

    // aud not found
    assert_eq!(
        ParsedMaskedContent::new(
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
        ParsedMaskedContent::new(
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
        ParsedMaskedContent::new(
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
        FastCryptoError::GeneralError("Invalid masked content".to_string())
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
        FastCryptoError::GeneralError("Invalid masked content".to_string())
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
fn test_map_to_field() {
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

    assert_eq!(parse_jwks(GOOGLE_JWK_BYTES, Google).unwrap().len(), 3);
    assert_eq!(parse_jwks(TWITCH_JWK_BYTES, Twitch).unwrap().len(), 1);
}
