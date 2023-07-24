// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::map_to_field;
use crate::bn254::zk_login::OAuthProvider::{Google, Twitch};
use crate::bn254::zk_login::{
    big_int_str_to_bytes, decode_base64_url, parse_jwks, trim, verify_extended_claim, Claim,
    JWTHeader, ParsedMaskedContent,
};
use crate::bn254::{
    zk_login::{AuxInputs, OAuthProvider, OAuthProviderContent, PublicInputs, ZkLoginProof},
    zk_login_api::verify_zk_login,
};
use fastcrypto::error::FastCryptoError;
use im::hashmap::HashMap as ImHashMap;

const GOOGLE_JWK_BYTES: &[u8] = r#"{
    "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "alg": "RS256",
          "kid": "c9afda3682ebf09eb3055c1c4bd39b751fbf8195",
          "use": "sig",
          "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw"
        },
        {
          "alg": "RS256",
          "use": "sig",
          "n": "1qrQCTst3RF04aMC9Ye_kGbsE0sftL4FOtB_WrzBDOFdrfVwLfflQuPX5kJ-0iYv9r2mjD5YIDy8b-iJKwevb69ISeoOrmL3tj6MStJesbbRRLVyFIm_6L7alHhZVyqHQtMKX7IaNndrfebnLReGntuNk76XCFxBBnRaIzAWnzr3WN4UPBt84A0KF74pei17dlqHZJ2HB2CsYbE9Ort8m7Vf6hwxYzFtCvMCnZil0fCtk2OQ73l6egcvYO65DkAJibFsC9xAgZaF-9GYRlSjMPd0SMQ8yU9i3W7beT00Xw6C0FYA9JAYaGaOvbT87l_6ZkAksOMuvIPD_jNVfTCPLQ==",
          "e": "AQAB",
          "kty": "RSA",
          "kid": "6083dd5981673f661fde9dae646b6f0380a0145c"
        }
      ]
  }"#.as_bytes();

const TWITCH_JWK_BYTES: &[u8] = r#"{
    "keys":[{"alg":"RS256","e":"AQAB","kid":"1","kty":"RSA","n":"6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw","use":"sig"}]
  }"#.as_bytes();

#[test]
fn test_verify_groth16_in_bytes_google() {
    let mut eph_pubkey = big_int_str_to_bytes("17932473587154777519561053972421347139");
    eph_pubkey.extend(big_int_str_to_bytes(
        "134696963602902907403122104327765350261",
    ));

    const TEST_KID: &str = "c9afda3682ebf09eb3055c1c4bd39b751fbf8195";
    let aux_inputs = AuxInputs::from_json("{\"claims\": [{\"name\": \"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\": 1},{\"name\": \"aud\",\"value_base64\": \"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\": 1}], \"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ\",\"addr_seed\": \"15604334753912523265015800787270404628529489918817818174033741053550755333691\",\"max_epoch\": 10000,\"key_claim_name\": \"sub\",\"modulus\": \"24501106890748714737552440981790137484213218436093327306276573863830528169633224698737117584784274166505493525052788880030500250025091662388617070057693555892212025614452197230081503494967494355047321073341455279175776092624566907541405624967595499832566905567072654796017464431878680118805774542185299632150122052530877100261682728356139724202453050155758294697161107805717430444408191365063957162605112787073991150691398970840390185880092832325216009234084152827135531285878617366639283552856146367480314853517993661640450694829038343380576312039548353544096265483699391507882147093626719041048048921352351403884619\"}").unwrap().init().unwrap();
    let public_inputs = PublicInputs::from_json(
        "[\"6049184272607241856912886413680599526372437331989542437266935645748489874658\"]",
    )
    .unwrap();

    assert_eq!(aux_inputs.get_max_epoch(), 10000);
    assert_eq!(
        aux_inputs.get_address_seed(),
        "15604334753912523265015800787270404628529489918817818174033741053550755333691"
    );
    assert_eq!(aux_inputs.get_iss(), OAuthProvider::Google.get_config().0);
    assert_eq!(
        aux_inputs.get_aud(),
        "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com"
    );
    assert_eq!(aux_inputs.get_key_claim_name(), "sub");
    assert_eq!(aux_inputs.get_kid(), TEST_KID);
    assert_eq!(aux_inputs.get_mod(), "24501106890748714737552440981790137484213218436093327306276573863830528169633224698737117584784274166505493525052788880030500250025091662388617070057693555892212025614452197230081503494967494355047321073341455279175776092624566907541405624967595499832566905567072654796017464431878680118805774542185299632150122052530877100261682728356139724202453050155758294697161107805717430444408191365063957162605112787073991150691398970840390185880092832325216009234084152827135531285878617366639283552856146367480314853517993661640450694829038343380576312039548353544096265483699391507882147093626719041048048921352351403884619");
    assert_eq!(
        aux_inputs.calculate_all_inputs_hash(&eph_pubkey).unwrap(),
        public_inputs.get_all_inputs_hash().unwrap()
    );

    let mut map = ImHashMap::new();
    map.insert((TEST_KID.to_string(), Google.get_config().0.to_string()), OAuthProviderContent {
        kty: "RSA".to_string(),
        kid: TEST_KID.to_string(),
        e: "AQAB".to_string(),
        n: "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw".to_string(),
        alg: "RS256".to_string(),
    });
    let proof = ZkLoginProof::from_json("{\"pi_a\":[\"21079899190337156604543197959052999786745784780153100922098887555507822163222\",\"4490261504756339299022091724663793329121338007571218596828748539529998991610\",\"1\"],\"pi_b\":[[\"9379167206161123715528853149920855132656754699464636503784643891913740439869\",\"15902897771112804794883785114808675393618430194414793328415185511364403970347\"],[\"16152736996630746506267683507223054358516992879195296708243566008238438281201\",\"15230917601041350929970534508991793588662911174494137634522926575255163535339\"],[\"1\",\"0\"]],\"pi_c\":[\"8242734018052567627683363270753907648903210541694662698981939667442011573249\",\"1775496841914332445297048246214170486364407018954976081505164205395286250461\",\"1\"],\"protocol\":\"groth16\"}");
    assert!(proof.is_ok());
    let res = verify_zk_login(
        &proof.unwrap(),
        &public_inputs,
        &aux_inputs,
        &eph_pubkey,
        &map,
    );
    assert!(res.is_ok());
}

#[test]
fn test_verify_groth16_in_bytes_twitch() {
    let mut eph_pubkey = big_int_str_to_bytes("17932473587154777519561053972421347139");
    eph_pubkey.extend(big_int_str_to_bytes(
        "134696963602902907403122104327765350261",
    ));
    let aux_inputs = AuxInputs::from_json("{\"claims\":[{\"name\": \"iss\",\"value_base64\": \"wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw\",\"index_mod_4\": 2     },{\"name\": \"aud\",\"value_base64\": \"yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC\",\"index_mod_4\": 1}],\"header_base64\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ\",\"addr_seed\": \"18704353972820279499196832783883157878280522634176394693508060053542990860397\",   \"max_epoch\": 10000,\"key_claim_name\": \"sub\",\"modulus\": \"29584508445356008889845267980505093503375439259749620943404021520463333925791823787854637986725604249075338223707087145400343940878353492428289420309978060548116589201208844416027772690277158239820043587577191204733372062526546165382385491203581708579354007308101776609837604633876932723191352425015951165606420826212084566356749532802619014158140227417781995864324396969703870653300311928497704373150532338687663444677910609365123056747321631910862597087829149037858457007019073259229864068519186398691475937234253291322606806349186490894620279606094962475240526774193684946100117999885854009961035928969402039575583\"}").unwrap().init().unwrap();
    let public_inputs = PublicInputs::from_json(
        "[\"17466137871302348802176618957727679727566476655921498778525221619744941215202\"]",
    )
    .unwrap();

    let public_inputs_invalid = PublicInputs::from_json(
        "[\"17466137871302348802176618957727679727566476655921498778525221619744941215202\", \"17466137871302348802176618957727679727566476655921498778525221619744941215202\"]",
    ).unwrap();
    assert!(public_inputs_invalid.get_all_inputs_hash().is_err());

    assert_eq!(aux_inputs.get_max_epoch(), 10000);
    assert_eq!(
        aux_inputs.get_address_seed(),
        "18704353972820279499196832783883157878280522634176394693508060053542990860397"
    );
    assert_eq!(aux_inputs.get_iss(), OAuthProvider::Twitch.get_config().0);
    assert_eq!(aux_inputs.get_key_claim_name(), "sub");
    assert_eq!(aux_inputs.get_aud(), "d31icql6l8xzpa7ef31ztxyss46ock");
    assert_eq!(aux_inputs.get_kid(), "1");
    assert_eq!(aux_inputs.get_mod(), "29584508445356008889845267980505093503375439259749620943404021520463333925791823787854637986725604249075338223707087145400343940878353492428289420309978060548116589201208844416027772690277158239820043587577191204733372062526546165382385491203581708579354007308101776609837604633876932723191352425015951165606420826212084566356749532802619014158140227417781995864324396969703870653300311928497704373150532338687663444677910609365123056747321631910862597087829149037858457007019073259229864068519186398691475937234253291322606806349186490894620279606094962475240526774193684946100117999885854009961035928969402039575583");
    assert_eq!(
        aux_inputs.calculate_all_inputs_hash(&eph_pubkey).unwrap(),
        public_inputs.get_all_inputs_hash().unwrap()
    );

    let mut map = ImHashMap::new();
    map.insert(("1".to_string(), Twitch.get_config().0.to_string()), OAuthProviderContent {
        kty: "RSA".to_string(),
        kid: "1".to_string(),
        e: "AQAB".to_string(),
        n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
        alg: "RS256".to_string(),
    });
    let proof = ZkLoginProof::from_json("{   \"pi_a\": [     \"14609816250208775088998769033922823275418989011294962335042447516759468155261\",     \"20377558696931353568738668428784363385404286135420274775798451001900237387711\",     \"1\"   ],   \"pi_b\": [     [       \"13205564493500587952133306511249429194738679332267485407336676345714082870630\",       \"20796060045071998078434479958974217243296767801927986923760870304883706846959\"     ],     [       \"18144611315874106283809557225033182618356564976139850467162456490949482704538\",       \"4318715074202832054732474611176035084202678394565328538059624195976255391002\"     ],     [       \"1\",       \"0\"     ]   ],   \"pi_c\": [     \"4215643272645108456341625420022677634747189283615115637991603989161283548307\",     \"5549730540188640204480179088531560793048476496379683802205245590402338452458\",     \"1\"   ],   \"protocol\": \"groth16\"}");
    assert!(proof.is_ok());

    let res = verify_zk_login(
        &proof.unwrap(),
        &public_inputs,
        &aux_inputs,
        &eph_pubkey,
        &map,
    );
    assert!(res.is_ok());
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
        ParsedMaskedContent::new(VALID_HEADER, &[]).unwrap_err(),
        FastCryptoError::GeneralError("iss not found in claims".to_string())
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
        FastCryptoError::GeneralError("aud not found in claims".to_string())
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
        FastCryptoError::GeneralError("Invalid claim name".to_string())
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
    assert!(map_to_field("sub", 2).is_err());
    assert_eq!(
        map_to_field("sub", 10).unwrap().to_string(),
        "18523124550523841778801820019979000409432455608728354507022210389496924497355"
    );
    assert_eq!(
        map_to_field("yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC", 133)
            .unwrap()
            .to_string(),
        "19198909745930267855439585988170070469004479286780644790990940640914248274464"
    );
    assert_eq!(map_to_field("CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC", 133).unwrap().to_string(), "6914089902564896687047107167562960781243311797290496295481879371814854678998");
    assert_eq!(map_to_field("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ", 150).unwrap().to_string(), "11195180390614794854381992733393925748746563026948577817495625199891112836762");
}

#[test]
fn test_jwk_parse() {
    assert_eq!(
        trim("wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww==".to_string()),
        "wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww"
    );

    assert_eq!(parse_jwks(GOOGLE_JWK_BYTES, Google).unwrap().len(), 2);
    assert_eq!(parse_jwks(TWITCH_JWK_BYTES, Twitch).unwrap().len(), 1);
}
