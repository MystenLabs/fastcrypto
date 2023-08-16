// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::str::FromStr;

use crate::bn254::utils::{get_enoki_address, get_nonce};
use crate::bn254::zk_login::{
    decode_base64_url, hash_ascii_str_to_field, hash_to_field, parse_jwks, trim,
    verify_extended_claim, Claim, JWTDetails, JWTHeader,
};
use crate::bn254::zk_login::{fetch_jwks, OIDCProvider};
use crate::bn254::zk_login_api::ZkLoginEnv;
use crate::bn254::{
    zk_login::{ZkLoginInputs, JWK},
    zk_login_api::verify_zk_login,
};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding as OtherEncoding};
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

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"4169504874401756960902573657806649547799902200557854504390915631723967576424\",\"18665360143042979657974479594360541428779995665200717488408301927557636784001\",\"1\"],\"pi_b\":[[\"4190982973503787187215833966444881896490238759852310712484328743034325450002\",\"13961689533496148166195507272593938714345330199311603823531778460871822941733\"],[\"8667724092102706800296481061599598851325940196970007892616205771280439047800\",\"10953429141986591272557238778177272493565418087371365641332421149411387960841\"],[\"1\",\"0\"]],\"pi_c\":[\"8134813789792782328004140831898929066280169330521012844840217819458697957354\",\"2413221756697001634635278094308467092060083404493223540976829788972611042841\",\"1\"]},\"address_seed\":\"19509697479448296403420673595157414978688381950012191268181947137083103804113\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjdjOWM3OGUzYjAwZTFiYjA5MmQyNDZjODg3YjExMjIwYzg3YjdkMjAiLCJ0eXAiOiJKV1QifQ\"}").unwrap().init().unwrap();
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
        "19509697479448296403420673595157414978688381950012191268181947137083103804113"
    );
    assert_eq!(
        get_enoki_address(
            zklogin_inputs.get_address_seed(),
            zklogin_inputs.get_address_params()
        )
        .to_vec(),
        Hex::decode("0xe21a10621dfc4aeda576141951527450b41cd2a54ab3586994362393b18e26fc").unwrap()
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
            "6470551385883269437362767266627536617163173243418744804736794511574177712392"
        )
        .unwrap()]
    );
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, ZkLoginEnv::Test);
    assert!(res.is_ok());
}

#[test]
fn test_verify_zk_login_twitch() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"19509439357688413199669022796225539258072174653501762782075286761070625831193\",\"20120503733945644082227722545851656398373988272428505660006551813854995822985\",\"1\"],\"pi_b\":[[\"1117994151330468447369450231245311912834573222446261879261674806722923452900\",\"7733936506019730416081557210097197370249464644638417179324894468664184447039\"],[\"2555383383487836544112017329237682823404520910874548397340830670912146360219\",\"16728643212261900382695858553380389189418195572563825008074203570429841922928\"],[\"1\",\"0\"]],\"pi_c\":[\"16601420651419492780459833556057641874870339072643102337908730119218447099772\",\"16764291910173534768202214397426400695948741956099214716087835684238558068409\",\"1\"]},\"address_seed\":\"18404400811258979351843554038529324719581180024248900217069822820095974835369\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw\",\"index_mod_4\":2},{\"name\":\"aud\",\"value_base64\":\"yJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ\"}").unwrap().init().unwrap();
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
        "18404400811258979351843554038529324719581180024248900217069822820095974835369"
    );
    assert_eq!(
        get_enoki_address(
            zklogin_inputs.get_address_seed(),
            zklogin_inputs.get_address_params()
        )
        .to_vec(),
        Hex::decode("0x171342d3274658f0641885cd019282336e3f48fd050d610241909dd14bb24d65").unwrap()
    );

    let mut map = HashMap::new();
    map.insert(("1".to_string(), OIDCProvider::Twitch.get_config().0.to_string()), JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
        alg: "RS256".to_string(),
    });
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, ZkLoginEnv::Test);
    assert!(res.is_ok());
}

#[test]
fn test_verify_zk_login_facebook() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"11906838442390958947956981941412847123726876942446732183131650721221185200415\",\"13477947960136562774712544330249233431481214258421198481503341839965229181441\",\"1\"],\"pi_b\":[[\"195283665225488233857568361471137028161450380486605042191036163099058537322\",\"21160918906651583322398345961182438829201720266338988247146384325166285027013\"],[\"5056810726385344895153919381342810734795382500127162339510513422213030592198\",\"2052421677419437749436133028803547336046283023917821033707060737419829163114\"],[\"1\",\"0\"]],\"pi_c\":[\"14739199144858043017013900215488708741774378306569808471678552294302294661097\",\"14198628060838424500665994481036804766418315409334469541533831317279068896764\",\"1\"]},\"address_seed\":\"9170870217795363726833321704645580846260479365166849913550847438937458025900\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIs\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"ImF1ZCI6IjIzMzMwNzE1NjM1MjkxNyIs\",\"index_mod_4\":0}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjU5MzE3MDEzMzExNjVmMDdmNTUwYWM1ZjAxOTQ5NDJkNTRmOWMyNDkifQ\"}").unwrap().init().unwrap();
    assert_eq!(
        zklogin_inputs.get_kid(),
        "5931701331165f07f550ac5f0194942d54f9c249".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_iss(),
        OIDCProvider::Facebook.get_config().0.to_string()
    );
    assert_eq!(zklogin_inputs.get_aud(), "233307156352917".to_string());
    assert_eq!(
        zklogin_inputs.get_address_params().aud,
        "233307156352917".to_string()
    );
    assert_eq!(
        zklogin_inputs.get_address_params().iss,
        zklogin_inputs.get_iss()
    );
    assert_eq!(
        zklogin_inputs.get_address_seed(),
        "9170870217795363726833321704645580846260479365166849913550847438937458025900"
    );

    assert_eq!(
        get_enoki_address(
            zklogin_inputs.get_address_seed(),
            zklogin_inputs.get_address_params()
        )
        .to_vec(),
        Hex::decode("0x5b10433166b4c4a32fcac2b3d073d90d4e0ad6c4bd33f79f982cc46d5b963e5c").unwrap()
    );

    let mut map = HashMap::new();
    map.insert(("5931701331165f07f550ac5f0194942d54f9c249".to_string(), OIDCProvider::Facebook.get_config().0.to_string()), JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "-GuAIboTsRYNprJQOkdmuKXRx8ARnKXOC9Pajg4KxHHPt3OY8rXRmVeDxTj1-m9TfW6V-wJa_8ncBbbFE-aV-eBi_XeuIToBBvLZp1-UPIjitS8WCDrUhHiJnbvkIZf1B1YBIq_Ua81fzxhtjQ0jDftV2m5aavmJG4_94VG3Md7noQjjUKzxJyUNl4v_joMA6pIRCeeamvfIZorjcR4wVf-wR8NiZjjRbcjKBpc7ztc7Gm778h34RSe9-DLH6uicTROSYNa99pUwhn3XVfAv4hTFpLIcgHYadLZjsHfUvivr76uiYbxDZx6UTkK5jmi51b87u1b6iYmijDIMztzrIQ".to_string(),
        alg: "RS256".to_string(),
    });
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, ZkLoginEnv::Test);
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

    parse_jwks(GOOGLE_JWK_BYTES, &OIDCProvider::Google)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0 .1, OIDCProvider::Google.get_config().0);
        });

    parse_jwks(TWITCH_JWK_BYTES, &OIDCProvider::Twitch)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0 .1, OIDCProvider::Twitch.get_config().0);
        });

    parse_jwks(FACEBOOK_JWK_BYTES, &OIDCProvider::Facebook)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0 .1, OIDCProvider::Facebook.get_config().0);
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
            assert_eq!(e.0 .1, p.get_config().0);
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
