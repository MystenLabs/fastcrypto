// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::bn254::utils::{get_enoki_address, get_nonce};
use crate::bn254::zk_login::{
    decode_base64_url, hash_ascii_str_to_field, hash_to_field, parse_jwks, trim,
    verify_extended_claim, Claim, JWTDetails, JWTHeader, JwkId,
};
use crate::bn254::zk_login::{fetch_jwks, OIDCProvider};
use crate::bn254::zk_login_api::Bn254Fr;
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

#[test]
fn test_verify_zk_login_google() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    assert!(ZkLoginInputs::from_json("{\"something\":{\"pi_a\":[\"17906300526443048714387222471528497388165567048979081127218444558531971001212\",\"16347093943573822555530932280098040740968368762067770538848146419225596827968\",\"1\"],\"pi_b\":[[\"604559992637298524596005947885439665413516028337069712707205304781687795569\",\"3442016989288172723305001983346837664894554996521317914830240702746056975984\"],[\"11525538739919950358574045244601652351196410355282682596092151863632911615318\",\"8054528381876103674715157136115660256860302241449545586065224275685056359825\"],[\"1\",\"0\"]],\"pi_c\":[\"12090542001353421590770702288155881067849038975293665701252531703168853963809\",\"8667909164654995486331191860419304610736366583628608454080754129255123340291\",\"1\"]},\"address_seed\":\"7577247629761003321376053963457717029490787816434302620024795358930497565155\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjkxMWUzOWUyNzkyOGFlOWYxZTlkMWUyMTY0NmRlOTJkMTkzNTFiNDQiLCJ0eXAiOiJKV1QifQ\"}").is_err());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"16082379985244139257081251352758755486156282972982603863007685291104503933311\",\"924319019028863167372401695750240170246182797458677233202254140761845272417\",\"1\"],\"pi_b\":[[\"13577250540115265266613311991485643078228707057086458534580175835039018572685\",\"12376053001358370647205175062199127322673512803490888228095245375811974804326\"],[\"14035295319062970519340182968766274788478314052702678112524794155602573477951\",\"21275817745084002159703389733799570288229406275961853650678828923527832512195\"],[\"1\",\"0\"]],\"pi_c\":[\"21768939217356454092644810716610021526414672327340826974534017558007065128740\",\"19849276141337612251288394025918481446172401959982365719577887942308529252632\",\"1\"]},\"address_seed\":\"21150353671819850968488494085061363586427266461520959449438048630829862383214\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjdjOWM3OGUzYjAwZTFiYjA5MmQyNDZjODg3YjExMjIwYzg3YjdkMjAiLCJ0eXAiOiJKV1QifQ\"}").unwrap().init().unwrap();
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
        "21150353671819850968488494085061363586427266461520959449438048630829862383214"
    );
    assert_eq!(
        get_enoki_address(
            zklogin_inputs.get_address_seed(),
            zklogin_inputs.get_address_params()
        )
        .to_vec(),
        Hex::decode("0x7bf6145cfe0592c0428ed8ce9612077b9ca1e5bc60308a90990bc952d13ccce8").unwrap()
    );

    let mut map = ImHashMap::new();
    let content = JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "pGMz603XOzO71r-LpW555Etbn2dXAtY4xToNE_Upr1EHxkHFnVnGPsbOeWzP8xU1IpAL56S3sTsbpCR_Ci_PYq8s4I3VWQM0u9w1D_e45S1KJTSex_aiMQ_cjTXb3Iekc00JIkMJhUaNnbsEt7PlOmnyFqvN-G3ZXVDfTuL2Wsn4tRMYf7YU3jgTVN2M_p7bcZYHhkEB-jzNeK7ub-6mOMkKdYWnk0jIoRfV63d32bub0pQpWv8sVmflgK2xKUSJVMZ7CM0FvJYJgF7y42KBPYc6Gm_UWE0uHazDgZgAvQQoNyEF_TRjVfGiihjPFYCPqvFcfLK4773JTD2fLZTgOQ".to_string(),
        alg: "RS256".to_string(),
    };

    map.insert(
        JwkId::new(
            OIDCProvider::Google.get_config().0.to_string(),
            "7c9c78e3b00e1bb092d246c887b11220c87b7d20".to_string(),
        ),
        content.clone(),
    );
    let modulus = Base64UrlUnpadded::decode_vec(&content.n).unwrap();

    assert_eq!(
        zklogin_inputs
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, 10)
            .unwrap(),
        vec![Bn254Fr::from_str(
            "19190136882259072389509967010336890361732579901899057561984458564815999051862"
        )
        .unwrap()]
    );
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Test);
    assert!(res.is_ok());

    // Do not verify against the prod vk.
    let res1 = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Prod);
    assert!(res1.is_err());
}

#[test]
fn test_verify_zk_login_twitch() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"2639684184680217707167754014000719722348206659392422133035933088167295844621\",\"15411697389380103098050765723042580180772223011905582881833041447034179685161\",\"1\"],\"pi_b\":[[\"18356546416649273600365508068279984662879338153955858345242905260545040887165\",\"14180424108251071134157931909030745068063443512539428703047837797454965825626\"],[\"13156473667176810581893653079638435272252026941153836815590225135710650196382\",\"21239978751364084281206642892186667820382067271473352046319441969708281386102\"],[\"1\",\"0\"]],\"pi_c\":[\"10224668151896969767148853455746517578322339166888897843411999928700401320418\",\"10920763695594894441298491254988284677195769983974208707015444852382653532723\",\"1\"]},\"address_seed\":\"21483285397923302977910340636259412155696585453250993383687293995976400590480\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw\",\"index_mod_4\":2},{\"name\":\"aud\",\"value_base64\":\"yJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLC\",\"index_mod_4\":1}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ\"}").unwrap().init().unwrap();
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
        "21483285397923302977910340636259412155696585453250993383687293995976400590480"
    );
    assert_eq!(
        get_enoki_address(
            zklogin_inputs.get_address_seed(),
            zklogin_inputs.get_address_params()
        )
        .to_vec(),
        Hex::decode("0x18642facd3dcc683f24490f5adb576eb02fc12073c46c9006dbe854cdbfbb899").unwrap()
    );

    let mut map = ImHashMap::new();
    let content = JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw".to_string(),
        alg: "RS256".to_string(),
    };
    let modulus = Base64UrlUnpadded::decode_vec(&content.n).unwrap();

    map.insert(
        JwkId::new(
            OIDCProvider::Twitch.get_config().0.to_string(),
            "1".to_string(),
        ),
        content,
    );

    assert_eq!(
        zklogin_inputs
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, 10)
            .unwrap(),
        vec![Bn254Fr::from_str(
            "5856188553771750715373571553753599041029773450105736907486194952973723348883"
        )
        .unwrap()]
    );
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Test);
    assert!(res.is_ok());

    // Do not verify against the prod vk.
    let res1 = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Prod);
    assert!(res1.is_err());
}

#[test]
fn test_verify_zk_login_facebook() {
    let kp = Ed25519KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let mut eph_pubkey = vec![0x00];
    eph_pubkey.extend(kp.public().as_ref());

    let zklogin_inputs = ZkLoginInputs::from_json("{\"proof_points\":{\"pi_a\":[\"16500559452186857499124905145218965727454398652759898506130123782737180551024\",\"1403037760258969546586768446760882646660554376880919683180395342618686906382\",\"1\"],\"pi_b\":[[\"12463789295781828009345316567938834871413393951281528901930690034950665391292\",\"16301756414332383815173890006998407782812302695665089990395506495445072039950\"],[\"19728141070117461173622838505925353541939789875408954541048815956055929576938\",\"21239411122885193204521373031249830589601614530017004204270959331789128729582\"],[\"1\",\"0\"]],\"pi_c\":[\"16094781461241847235951763701104954579675913864156691777860223519371049858114\",\"7705218318167899339727292541697723794048510769012014737743407264594062927068\",\"1\"]},\"address_seed\":\"1487011095754058868957639998432654337555495215275691418230823914445177483005\",\"claims\":[{\"name\":\"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIs\",\"index_mod_4\":1},{\"name\":\"aud\",\"value_base64\":\"ImF1ZCI6IjIzMzMwNzE1NjM1MjkxNyIs\",\"index_mod_4\":0}],\"header_base64\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjU5MzE3MDEzMzExNjVmMDdmNTUwYWM1ZjAxOTQ5NDJkNTRmOWMyNDkifQ\"}").unwrap().init().unwrap();
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
        "1487011095754058868957639998432654337555495215275691418230823914445177483005"
    );

    assert_eq!(
        get_enoki_address(
            zklogin_inputs.get_address_seed(),
            zklogin_inputs.get_address_params()
        )
        .to_vec(),
        Hex::decode("0x5e3733bf03f715a87b641553fce0f8b22bcb6385ce78cc05ddecd55929a5a304").unwrap()
    );

    let mut map = ImHashMap::new();
    let content = JWK {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "-GuAIboTsRYNprJQOkdmuKXRx8ARnKXOC9Pajg4KxHHPt3OY8rXRmVeDxTj1-m9TfW6V-wJa_8ncBbbFE-aV-eBi_XeuIToBBvLZp1-UPIjitS8WCDrUhHiJnbvkIZf1B1YBIq_Ua81fzxhtjQ0jDftV2m5aavmJG4_94VG3Md7noQjjUKzxJyUNl4v_joMA6pIRCeeamvfIZorjcR4wVf-wR8NiZjjRbcjKBpc7ztc7Gm778h34RSe9-DLH6uicTROSYNa99pUwhn3XVfAv4hTFpLIcgHYadLZjsHfUvivr76uiYbxDZx6UTkK5jmi51b87u1b6iYmijDIMztzrIQ".to_string(),
        alg: "RS256".to_string(),
    };
    let modulus = Base64UrlUnpadded::decode_vec(&content.n).unwrap();
    assert_eq!(
        zklogin_inputs
            .calculate_all_inputs_hash(&eph_pubkey, &modulus, 10)
            .unwrap(),
        vec![Bn254Fr::from_str(
            "731385750760775862842838160347366432653065169777359995738835424407706939501"
        )
        .unwrap()]
    );

    map.insert(
        JwkId::new(
            OIDCProvider::Facebook.get_config().0.to_string(),
            "5931701331165f07f550ac5f0194942d54f9c249".to_string(),
        ),
        content,
    );
    let res = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Test);
    assert!(res.is_ok());

    // Do not verify against the prod vk.
    let res1 = verify_zk_login(&zklogin_inputs, 10, &eph_pubkey, &map, &ZkLoginEnv::Prod);
    assert!(res1.is_err());
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
            assert_eq!(content.0.iss, OIDCProvider::Google.get_config().0);
        });

    parse_jwks(TWITCH_JWK_BYTES, &OIDCProvider::Twitch)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Twitch.get_config().0);
        });

    parse_jwks(FACEBOOK_JWK_BYTES, &OIDCProvider::Facebook)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Facebook.get_config().0);
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
            assert_eq!(e.0.iss, p.get_config().0);
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
