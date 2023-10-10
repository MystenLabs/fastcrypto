// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::{
    utils::{gen_address_seed, get_proof, get_salt},
    zk_login::{JwkId, OIDCProvider, ZkLoginInputs, JWK},
    zk_login_api::{verify_zk_login, ZkLoginEnv},
};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use fastcrypto::{ed25519::Ed25519KeyPair, jwt_utils::parse_and_validate_jwt, traits::KeyPair};
use im::HashMap as ImHashMap;
use num_bigint::BigUint;

const DEFAULT_PROVER_SERVER_URL: &str = "http://185.209.177.123:7000/v1";
const DEFAULT_SALT_SERVER_URL: &str = "http://185.209.177.123:3000/get_salt";

#[tokio::test]
async fn test_end_to_end_twitch() {
    // Use a fixed Twitch token obtained with nonce hTPpgF7XAKbW37rEUS6pEVZqmoI
    // Derived based on max_epoch = 10, kp generated from seed = [0; 32], and jwt_randomness 100681567828351849884072155819400689117.
    // let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLCJleHAiOjE2OTIyODQzMzQsImlhdCI6MTY5MjI4MzQzNCwiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiwic3ViIjoiOTA0NDQ4NjkyIiwiYXpwIjoicnMxYmgwNjVpOXlhNHlkdmlmaXhsNGtzczB1aHB0Iiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb3lxdnEifQ.M54Sgs6aDu5Mprs_CgXeRbgiErC7oehj-h9oEcBqZFDADwd09zs9hbfDPqUjaNBB-_I6G7kn9e-zwPov8PUecI68kr3oyiCMWhKD-3h1FEu13MZv71B6jhIDMu1_UgI-RSrOQMRvdI8eL3qqD-KsvJuJH1Sz0w56PnB0xupUg-eSvgnMBAo6iTa0t1grX9qGy7U00i_oqn9J4jVGVVEbMhUWROJMjowWdOogJ4_VNqm67JHd_rMZ3xtjLabP6Nk1Gx-VjUbYceNADWUr5xpJveRtvb1FJvd0HSN4mab51zuSUnavCQw2OXbyoH8j6uuQAAKVhG-_Ht1hCvReycGXKw";
    let parsed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJhdWQiOiJyczFiaDA2NWk5eWE0eWR2aWZpeGw0a3NzMHVocHQiLCJleHAiOjE2OTIyODQzMzQsImlhdCI6MTY5MjI4MzQzNCwiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiwic3ViIjoiOTA0NDQ4NjkyIiwiYXpwIjoicnMxYmgwNjVpOXlhNHlkdmlmaXhsNGtzczB1aHB0Iiwibm9uY2UiOiJoVFBwZ0Y3WEFLYlczN3JFVVM2cEVWWnFtb0kiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb3lxdnEifQ.M54Sgs6aDu5Mprs_CgXeRbgiErC7oehj-h9oEcBqZFDADwd09zs9hbfDPqUjaNBB-_I6G7kn9e-zwPov8PUecI68kr3oyiCMWhKD-3h1FEu13MZv71B6jhIDMu1_UgI-RSrOQMRvdI8eL3qqD-KsvJuJH1Sz0w56PnB0xupUg-eSvgnMBAo6iTa0t1grX9qGy7U00i_oqn9J4jVGVVEbMhUWROJMjowWdOogJ4_VNqm67JHd_rMZ3xtjLabP6Nk1Gx-VjUbYceNADWUr5xpJveRtvb1FJvd0HSN4mab51zuSUnavCQw2OXbyoH8j6uuQAAKVhG-_Ht1hCvReycGXKw";
    let max_epoch = 10;
    let jwt_randomness = "100681567828351849884072155819400689117";

    // Get salt based on the Twitch token.
    let user_salt = get_salt(parsed_token, DEFAULT_SALT_SERVER_URL)
        .await
        .unwrap();

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
        DEFAULT_PROVER_SERVER_URL,
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
