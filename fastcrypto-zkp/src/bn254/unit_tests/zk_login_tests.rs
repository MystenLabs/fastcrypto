// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::bn254::utils::{
    gen_address_seed, gen_address_seed_with_salt_hash, get_nonce, get_zk_login_address,
};
use crate::bn254::zk_login::{
    base64_to_bitarray, big_int_array_to_bits, bitarray_to_bytearray, convert_base,
    decode_base64_url, hash_ascii_str_to_field, hash_to_field, parse_jwks, parse_v2_ext_iss,
    poseidon_zk_login, trim, verify_extended_claim, Claim, JWTDetails, JwkId, OIDCProvider,
    VersionedZkLoginInputs, ZkLoginInputs, ZkLoginInputsV2, JWK,
};
use crate::bn254::zk_login_api::{
    verify_zk_login, verify_zk_login_extended, verify_zk_login_id, verify_zk_login_iss, Bn254Fr,
    ZkLoginEnv,
};
use crate::zk_login_utils::Bn254FrElement;
use ark_bn254::{Fq, Fr};
use ark_ff::PrimeField;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Blake2b256, HashFunction, Sha256};
use fastcrypto::jwt_utils::JWTHeader;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding as _};
use imbl::hashmap::HashMap as ImHashMap;
use num_bigint::BigUint;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

#[path = "../../groth16/test_utils.rs"]
mod test_utils;

use test_utils::arb_byte_mutation;

//
// Helper functions
//

/// A V1 proof of the production prover for a Google JWT, as the prover returns it, without the
/// address seed. The proof is for [GOOGLE_EPH_PK], [GOOGLE_MAX_EPOCH] and [GOOGLE_ADDRESS_SEED],
/// and the JWT was signed by the key [GOOGLE_KID] with modulus [GOOGLE_N].
const GOOGLE_INPUTS: &str = r#"{"proofPoints":{"a":["8247215875293406890829839156897863742504615191361518281091302475904551111016","6872980335748205979379321982220498484242209225765686471076081944034292159666","1"],"b":[["21419680064642047510915171723230639588631899775315750803416713283740137406807","21566716915562037737681888858382287035712341650647439119820808127161946325890"],["17867714710686394159919998503724240212517838710399045289784307078087926404555","21812769875502013113255155836896615164559280911997219958031852239645061854221"],["1","0"]],"c":["7530826803702928198368421787278524256623871560746240215547076095911132653214","16244547936249959771862454850485726883972969173921727256151991751860694123976","1"]},"issBase64Details":{"value":"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC","indexMod4":1},"headerBase64":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmRlODRhMmQ1NTJiNGM2ZjEiLCJ0eXAiOiJKV1QifQ"}"#;

/// The address seed of the user: the hash of the key claim `sub` = [GOOGLE_SUB], the audience
/// [GOOGLE_AUD] and the salt [GOOGLE_SALT]. And the user's address for the issuer Google.
const GOOGLE_ADDRESS_SEED: &str =
    "13319968244245342702944364608316777772547259798425697923099390355538529931211";
const GOOGLE_SUB: &str = "106294049240999307923";
const GOOGLE_AUD: &str = "25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com";
const GOOGLE_SALT: &str = "206703048842351542647799591018316385612";
const GOOGLE_ADDRESS: &str = "a64ae946d5efd2dea396cb2fe81837f028c32f2b2f211176b65a3a152deb35a2";

/// The ephemeral Ed25519 public key with its flag 0x00, and the max epoch of the proof.
const GOOGLE_EPH_PK: &str = "00b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";
const GOOGLE_MAX_EPOCH: u64 = 10;

/// The key id and the base64url modulus of the Google key that signed the JWT.
const GOOGLE_KID: &str = "6f7254101f56e41cf35c9926de84a2d552b4c6f1";
const GOOGLE_N: &str = "oUriU8GqbRw-avcMn95DGW1cpZR1IoM6L7krfrWvLSSCcSX6Ig117o25Yk7QWBiJpaPV0FbP7Y5-DmThZ3SaF0AXW-3BsKPEXfFfeKVc6vBqk3t5mKlNEowjdvNTSzoOXO5UIHwsXaxiJlbMRalaFEUm-2CKgmXl1ss_yGh1OHkfnBiGsfQUndKoHiZuDzBMGw8Sf67am_Ok-4FShK0NuR3-q33aB_3Z7obC71dejSLWFOEcKUVCaw6DGVuLog3x506h1QQ1r0FXKOQxnmqrRgpoHqGSouuG35oZve1vgCU4vLZ6EAgBAbC0KL35I7_0wUDSMpiAvf7iZxzJVbspkQ";

/// The SHA-256 digest of the BCS encoding of the parsed [GOOGLE_INPUTS], which is the encoding in
/// Sui transactions.
const GOOGLE_INPUTS_BCS_SHA256: &str =
    "f6278ef3a3f2c43d8ca21543f9e4ff7fbd1b7ce085e38db07697820e9e0c41c5";

/// A V1 proof of the development prover, verified with the insecure verifying key: the inputs, the
/// address seed, the ephemeral public key with its flag 0x00, the max epoch, and the key id and
/// modulus of the key that signed the JWT.
const TEST_ENV_INPUTS: &str = r#"{"proofPoints":{"a":["7566241567720780416751598994698310678767195459947224622023785587667176814058","18104499930818305143361187733659014043953751050617136254447624192327280445771","1"],"b":[["11369230593957954942221175389182778816136534144714579815927653075736806430994","11928003240637992017698644299021052465098754853899210401706726930513411198353"],["2597127058046351054449743605218058440565462021354202666955356076272028963802","3385145993275542896693643488618289924488296318344621918448585222369718288892"],["1","0"]],"c":["395141536511114303768253959602639884294254888080713473665269769443249414257","21430657725804540809568084344756144327539843580919730138594118365564728808275","1"]},"issBase64Details":{"value":"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC","indexMod4":1},"headerBase64":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ"}"#;
const TEST_ENV_ADDRESS_SEED: &str =
    "4959624758616676340947699768172740454110375485415332267384397278368360470616";
const TEST_ENV_EPH_PK: &str =
    "0079686aa4ca7d8b8730615205effecb4023183f2434b00ff4f439bdf1c0b37f281da8";
const TEST_ENV_MAX_EPOCH: u64 = 10000;
const TEST_ENV_KID: &str = "c9afda3682ebf09eb3055c1c4bd39b751fbf8195";
const TEST_ENV_N: &str = "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw";

/// The issuer of the proofs above.
const GOOGLE_ISS: &str = "https://accounts.google.com";

/// The JSON of [GOOGLE_INPUTS], to change before parsing it.
fn google_json() -> serde_json::Value {
    serde_json::from_str(GOOGLE_INPUTS).unwrap()
}

fn parse_google(json: &serde_json::Value) -> Result<ZkLoginInputs, FastCryptoError> {
    ZkLoginInputs::from_json(&json.to_string(), GOOGLE_ADDRESS_SEED)
}

fn google_inputs() -> ZkLoginInputs {
    parse_google(&google_json()).unwrap()
}

fn jwks(iss: &str, kid: &str, n: &str) -> ImHashMap<JwkId, JWK> {
    let mut jwks = ImHashMap::new();
    jwks.insert(
        JwkId::new(iss.to_string(), kid.to_string()),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: n.to_string(),
            alg: "RS256".to_string(),
        },
    );
    jwks
}

/// Verifies V1 inputs with the production key.
fn verify_prod(
    inputs: &ZkLoginInputs,
    max_epoch: u64,
    eph_pk: &[u8],
    jwks: &ImHashMap<JwkId, JWK>,
) -> Result<(), FastCryptoError> {
    verify_zk_login(inputs, max_epoch, eph_pk, jwks, &ZkLoginEnv::Prod)
}

/// Verifies V1 inputs with the parameters of the Google proof and the production key.
fn verify_google(inputs: &ZkLoginInputs) -> Result<(), FastCryptoError> {
    verify_prod(
        inputs,
        GOOGLE_MAX_EPOCH,
        &Hex::decode(GOOGLE_EPH_PK).unwrap(),
        &jwks(GOOGLE_ISS, GOOGLE_KID, GOOGLE_N),
    )
}

fn bn254_modulus<F: PrimeField>() -> BigUint {
    F::MODULUS.into()
}

/// Adds an integer to a decimal string.
fn add(decimal: &str, n: &BigUint) -> String {
    (BigUint::from_str(decimal).unwrap() + n).to_string()
}

/// The decimal string of `-x` in Fq.
fn negate(decimal: &str) -> String {
    (-Fq::from_str(decimal).unwrap()).to_string()
}

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

const PARTIAL_INVALID_JWK_BYTES: &[u8] = r#"{
    "keys":[
        {
            "alg":"ES256",
            "e":"AQAB",
            "kid":"1",
            "kty":"RSA",
            "n":"6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw",
            "use":"sig"
        },
        {
            "kid": "a378585d826a933cc207ce31cad63c019a53095c",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "1aLDAmRq-QeOr1b8WbtpmD5D4CpE5S0YrNklM5BrRjuZ6FTG8AhqvyUUnAb7Dd1gCZgARbuk2yHOOca78JWX2ocAId9R4OV2PUoIYljDZ5gQJBaL6liMpolQjlqovmd7IpF8XZWudWU6Rfhoh-j6dd-8IHeJjBKMYij0CuA6HZ1L98vBW1ehEdnBZPfTe28H57hySzucnC1q1340h2E2cpCfLZ-vNoYQ4Qe-CZKpUAKOoOlC4tWCt2rLcsV_vXvmNlLv_UYGbJEFKS-I1tEwtlD71bvn9WWluE7L4pWlIolgzNyIz4yxe7G7V4jlvSSwsu1ZtIQzt5AtTC--5HEAyQ",
            "e": "AQAB"
        }
    ]}"#.as_bytes();

/// A real response of the dev-v2 prover for the zklogin-circuits@98f83f0 circuit.
/// The JWT came from jwt-tester with its 8192-bit key `sui-key-id-8192`.
/// Wallet inputs: test/vectors/sampleWalletInputs.json (max epoch 10) with a random salt.
const DEV_V2_PROVER_RESPONSE: &str = r##"{"proofPoints":{"a":["3672349573138177599136904591772136128615295541414131525892912980311258613017","5467361857313536954177754187819314022656953804432145065103436331598939779249","1"],"b":[["3621969240695771382761921829801197197415465177139332043220269132643989232448","5424528374566235872088110579249089143759049625077902960702667499406875490381"],["6994112895913652805541628232059927104007885466568574872314282220414329649022","12013973278309517198105543956882880226502234878355137608655172590538533080238"],["1","0"]],"c":["6723038257690032669372610946335699590412556043141499607227581732061744475653","18277134152597580402304962298141919281459611366933030893849925862357869941859","1"]},"extIss":"\"iss\":\"https://jwt-tester.mystenlabs.com\",","headerBase64":"eyJraWQiOiJzdWkta2V5LWlkLTgxOTIiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9","addressSeed":"0x6cf4834879b9d06e73191ab9403b84dfdb2a113815b40ae1c5b55d1f7e6208f0"}"##;

/// Modulus of the jwt-tester key `sui-key-id-8192`.
const JWT_TESTER_8192_N: &str = "lViYJOuLB6EZenCimgyWrwOH_QBEkCZxSIEfcQgP5MrZkRlohbrTAN1YpXGRaqugp9A4mRzCmi9ddXscpRBSsLefdPJJLG8lQZ2qrw6X2-6HD5kDFd6-K7JZS-_GOEfr5xGEDm8_MS_SorbmneKspL0n4MPYWH8qke4OBFCwL6WzGBU9rqDuvhYmafmkvVvOtHIqekBxNrCud7Spv43BHdiBM0V-jUquuNM3oK97i_GVLjGfwrGRpR3tK4nva_ryiHh9Ajs68If7-ZhIoLJ05lRsHJJpqsloiEqlCZwhge9zEMnNkoaIzdQr-xLy0GPnr5W0gikjlSGYiInfx9ITADwK3W33xdOB7npM7lqJY73Njbuw8hBQicU8t0M0gvvWfmh1KDeA5IqffZgue-ka9Jj1nrYmZtd0JimQpPDUiGbLv69gQJZcLVQWf9z6mVC4gNm8VU2OafssnolrvNndC3wIm8AgqzVzn_DIOcMQdhIe8jTF3hu1_6R4Id3KoA5Hb3uI2H86-8RjhSG2wKb3zi44yKSmxEDhzl7i450PQX64JK4ftv5jb9vSw5unpikmVvGlGsuvrqWFuWKBcrcXLgyar8pGvRO8fR9ifDHSj-D2fBiLnhK0-iqsJeU8XnfJhUvKxSjXejwsoQeLqlgq9-PgCDP3dE61fkqGpJ1UZjZ44Q9Vh4YLCPAO6oX8btXSkwreuP5m0UtWgFsc-ynWbt6NYS7JlsMtJNWybM4_auqRdil_cPMwFsUgjocztGLeG304YH-GehmyBJyGKuDIiXL9RfLoZ35jKawrWJb4UqckKWV5kOKeXsXdKtMw96ABFumcnhrzxAsqwshS5a2lT8P7Cdd9g3T1JXI7JM1AnJU9_gPXmJoc3yEFNf-JxEf00URoy2xUusyyxYdTswLJp3NQP4VjrAGwnsp7gHKC-V-mJ21FpQCHsV0JQ-1x-E3du9hkpsjTtGkffetEsV8k9enbkudox7WIlsnPcA8y7aY4lnaBqLLSzaj2GOf4KTN4cRpcPzOmSvgcVVYYQXDjRw45X86P1WJG8UDl6Wkl044tAdQRuIxW8QVzBFWWxeXcoagOBKn1_DV0RKUX9Ud4LLauy81rUNfoAcnolz9nippTBEZA_4OOBvXhdngCYaoZyjAkmYdPhKIkghGhKoVVKiEJ1Ua6nUr3zB9WFlTO9lODeV9h0tgKGtKGu3UBeaRCQSMv9gZK-eGIpcqjsqK_rEf4htdDZUBzfOJ0VtCiFYUUBPiuJNuIf9xQGVDE7qZufK1irvGug8jvWSWzB4pGLP75PnPH7B9axnXrxssaIR90Y3Vr9ih_ptzcfNrwD_wiGHUTy698FHu2fXp51HbSEQ";

//
// Parsing tests
//

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
        decode_base64_url("aa", &1).unwrap_err(),
        FastCryptoError::GeneralError("Invalid UTF8 string".to_string())
    );

    assert_eq!(
        decode_base64_url("", &0).unwrap_err(),
        FastCryptoError::GeneralError("Base64 string smaller than 2".to_string())
    );
    assert_eq!(
        decode_base64_url("yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC", &0).unwrap_err(),
        FastCryptoError::GeneralError("Invalid last_char_offset".to_string())
    );
    assert!(decode_base64_url("yJhdWQiOiJkMzFpY3FsNmw4eHpwYTdlZjMxenR4eXNzNDZvY2siLC", &1).is_ok());
    // Whole groups of four characters.
    assert_eq!(decode_base64_url("YWJj", &0).unwrap(), "abc");
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
fn test_base64_to_bitarray() {
    let input = "a";
    let expected = vec![0, 1, 1, 0, 1, 0];
    assert_eq!(base64_to_bitarray(input).unwrap(), expected);

    let input = ".";
    assert!(base64_to_bitarray(input).is_err());
}

#[test]
fn test_bitarray_to_bytearray() {
    let input = vec![0, 0, 0, 0, 0, 1, 1, 1];
    assert_eq!(bitarray_to_bytearray(&input).unwrap(), vec![7]);

    let input = vec![0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1];
    assert_eq!(bitarray_to_bytearray(&input).unwrap(), vec![7, 11]);

    assert!(bitarray_to_bytearray(&[0; 15]).is_err());
    assert!(bitarray_to_bytearray(&[0; 16]).is_ok());
    assert!(bitarray_to_bytearray(&[0; 17]).is_err());
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
fn test_parse_v2_ext_iss() {
    for (ext_iss, iss) in [
        (r#""iss":"A","#, "A"),
        (r#""iss":"A"}"#, "A"),
        (" \"iss\" :\t\"A\" ,", "A"),
        (
            r#""iss":"https:\/\/www.facebook.com","#,
            "https://www.facebook.com",
        ),
    ] {
        assert_eq!(parse_v2_ext_iss(ext_iss).unwrap(), iss, "{ext_iss}");
    }
    // V2 rejects each of these. It accepts only one member, named `iss`.
    for ext_iss in [
        r#""iss":"A""#,
        r#""iss":"A","iss":"B","#,
        r#""sub":"x","iss":"A","#,
        r#""iss":"A","sub":"x"}"#,
        r#""iss":{"iss":"A"},"#,
        r#""iss":1,"#,
        r#""iss":"A"},"x":{,"#,
        r#""aud":"A","#,
        "",
    ] {
        assert!(parse_v2_ext_iss(ext_iss).is_err(), "{ext_iss}");
    }
    // V1 still accepts other members.
    assert_eq!(
        verify_extended_claim(r#""sub":"x","iss":"A","#, "iss").unwrap(),
        "A"
    );
}

#[test]
fn test_jwk_parse() {
    assert_eq!(
        trim("wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww==".to_string()),
        "wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww"
    );

    parse_jwks(GOOGLE_JWK_BYTES, &OIDCProvider::Google, true)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Google.get_config().iss);
        });

    parse_jwks(TWITCH_JWK_BYTES, &OIDCProvider::Twitch, true)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Twitch.get_config().iss);
        });

    parse_jwks(FACEBOOK_JWK_BYTES, &OIDCProvider::Facebook, true)
        .unwrap()
        .iter()
        .for_each(|content| {
            assert_eq!(content.0.iss, OIDCProvider::Facebook.get_config().iss);
        });

    assert!(parse_jwks(BAD_JWK_BYTES, &OIDCProvider::Twitch, false).is_err());

    // if skip flag is false, handle in legacy, error on an invalid jwk
    assert!(parse_jwks(PARTIAL_INVALID_JWK_BYTES, &OIDCProvider::Twitch, false).is_err());
    // if skip flag is true, skip an invalid jwk, and return the valid ones, returns ok.
    assert!(parse_jwks(PARTIAL_INVALID_JWK_BYTES, &OIDCProvider::Twitch, true).is_ok());

    assert!(parse_jwks(
        r#"{
        "something":[]
      }"#
        .as_bytes(),
        &OIDCProvider::Twitch,
        true
    )
    .is_err());
}

#[test]
fn test_get_provider_to_from_iss_to_from_str() {
    for p in [
        OIDCProvider::Facebook,
        OIDCProvider::Google,
        OIDCProvider::Twitch,
        OIDCProvider::Slack,
        OIDCProvider::Kakao,
        OIDCProvider::Apple,
        OIDCProvider::Microsoft,
        OIDCProvider::AwsTenant(("us-east-1".to_string(), "us-east-1_LPSLCkC3A".to_string())),
        OIDCProvider::KarrierOne,
        OIDCProvider::Credenza3,
        OIDCProvider::Playtron,
        OIDCProvider::Threedos,
        OIDCProvider::Onefc,
        OIDCProvider::FanTV,
        OIDCProvider::AwsTenant(("eu-west-3".to_string(), "eu-west-3_gGVCx53Es".to_string())), // Trace
        OIDCProvider::AwsTenant(("eu-north-1".to_string(), "eu-north-1_Bpct2JyBg".to_string())), // test gammaprime
        OIDCProvider::AwsTenant(("eu-north-1".to_string(), "eu-north-1_4HdQTpt3E".to_string())), // gammaprime
        OIDCProvider::TestIssuer,
        OIDCProvider::TestIssuerKey8192,
        OIDCProvider::Arden,
        OIDCProvider::EveFrontier,
        OIDCProvider::TestEveFrontier,
    ] {
        // to/from iss
        assert_eq!(p, OIDCProvider::from_iss(&p.get_config().iss).unwrap());
        // to/from string
        assert_eq!(p, OIDCProvider::from_str(&p.to_string()).unwrap());
    }
    assert!(OIDCProvider::from_iss("random").is_err());
    assert!(OIDCProvider::from_str("random").is_err());
}

/// parse_jwks parses the responses of OIDC providers: invalid JSON, or JSON of another shape, is
/// an error.
#[test]
fn test_parse_jwks_invalid() {
    let deeply_nested = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    for bytes in [
        &b""[..],
        b"not json",
        &[0xff, 0xfe],
        b"[]",
        br#"{"keys":1}"#,
        br#"{"keys":[1,"a",null]}"#,
        br#"{"keys":[{}]}"#,
        deeply_nested.as_bytes(),
    ] {
        for skip_on_invalid_jwk in [true, false] {
            assert!(parse_jwks(bytes, &OIDCProvider::Google, skip_on_invalid_jwk).is_err());
        }
    }

    // No keys is an error only when invalid keys are skipped.
    assert!(parse_jwks(br#"{"keys":[]}"#, &OIDCProvider::Google, true).is_err());
    assert_eq!(
        parse_jwks(br#"{"keys":[]}"#, &OIDCProvider::Google, false),
        Ok(vec![])
    );
}

/// JwkId::new maps the issuers of all Microsoft tenants to the common issuer, since the tenants
/// share Microsoft's keys. It keeps other issuers.
#[test]
fn test_jwk_id() {
    let microsoft = OIDCProvider::Microsoft.get_config().iss;
    // (issuer, issuer of the key id)
    for (iss, expected) in [
        (
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            microsoft.as_str(),
        ),
        (
            "https://login.microsoftonline.com/any/path/v2.0",
            microsoft.as_str(),
        ),
        (
            "https://login.microsoftonline.com/tenant/v1.0",
            "https://login.microsoftonline.com/tenant/v1.0",
        ),
        (GOOGLE_ISS, GOOGLE_ISS),
    ] {
        assert_eq!(JwkId::new(iss.to_string(), "kid".to_string()).iss, expected);
    }
}

/// Non-standard, pinned: from_iss matches AWS issuers with a regular expression that isn't
/// anchored, so it also maps strings that contain the issuer of an AWS tenant, and Microsoft
/// issuers by their prefix and suffix. Keys are looked up by the exact issuer, see
/// [test_verify_zk_login_tampered].
#[test]
fn test_provider_from_iss_lenient() {
    let aws = OIDCProvider::AwsTenant(("us-east-1".to_string(), "us-east-1_LPSLCkC3A".to_string()));
    for iss in [
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_LPSLCkC3A",
        "prefix https://cognito-idp.us-east-1.amazonaws.com/us-east-1_LPSLCkC3A/suffix",
    ] {
        assert_eq!(OIDCProvider::from_iss(iss), Ok(aws.clone()));
    }
    assert_eq!(
        OIDCProvider::from_iss("https://login.microsoftonline.com/any/path/v2.0"),
        Ok(OIDCProvider::Microsoft)
    );
    for iss in [
        "https://accounts.google.com/",
        "accounts.google.com",
        "https://login.microsoftonline.com/tenant",
    ] {
        assert!(OIDCProvider::from_iss(iss).is_err());
    }
}

//
// Hashing tests
//

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
fn test_big_int_array_to_bits() {
    let input = vec![BigUint::from(7u8)];
    assert!(big_int_array_to_bits(&input, 2).is_err());
    assert_eq!(big_int_array_to_bits(&input, 3).unwrap(), vec![1, 1, 1]);
    assert_eq!(big_int_array_to_bits(&input, 4).unwrap(), vec![0, 1, 1, 1]);
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
fn test_gen_seed() {
    let address_seed = gen_address_seed(
        "248191903847969014646285995941615069143",
        "sub",
        "904448692",
        "rs1bh065i9ya4ydvifixl4kss0uhpt",
    )
    .unwrap();
    assert_eq!(
        address_seed.to_string(),
        "16657007263003735230240998439420301694514420923267872433517882233836276100450".to_string()
    );
}

#[test]
fn test_get_nonce() {
    let eph_pk = Hex::decode(GOOGLE_EPH_PK).unwrap();
    let nonce = get_nonce(&eph_pk, 10, "100681567828351849884072155819400689117").unwrap();
    assert_eq!(nonce, "hTPpgF7XAKbW37rEUS6pEVZqmoI");
}

#[test]
fn test_v2_public_inputs_hash_matches_circuit_fixture() {
    // https://github.com/MystenLabs/zklogin-circuits/blob/98f83f08ef018ffe1ec4f606a4b3db82d4dbba7b/test/circuits/sha256-transcripts.circom.test.js#L244-L326
    let input = ZkLoginInputsV2 {
        proof_points: super::ZkLoginProof {
            a: vec![],
            b: vec![],
            c: vec![],
        },
        ext_iss: "\"iss\":\"https://issuer.example\",".to_string(),
        header_base64: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJlbmNobWFyay1rZXkiLCJ0eXAiOiJKV1QifQ"
            .to_string(),
        address_seed: BigUint::from_str(
            "46548047783484547733969084694273676712292427372185332440625037714802126242682",
        )
        .unwrap()
        .to_bytes_be()
        .try_into()
        .unwrap(),
        jwt_details: JWTDetails::default(),
    };
    let mut eph_pubkey = vec![0];
    eph_pubkey.extend(
        Hex::decode("123456789abcdef00112233445566778899aabbccddeeff00fedcba987654321").unwrap(),
    );
    let modulus =
        ((BigUint::from(1u8) << 2047usize) + BigUint::from(0x123456789abcdefu64)).to_bytes_be();
    let max_epoch = 0x1020304050607080;
    let transcript = input
        .encode_public_inputs_transcript(&eph_pubkey, &modulus, max_epoch)
        .unwrap();
    assert_eq!(transcript.len(), 1591);

    let hash = input
        .calculate_all_inputs_hash(&eph_pubkey, &modulus, max_epoch)
        .unwrap();

    assert_eq!(
        hash.to_string(),
        "10055516041686918213620150782216842656718491033112874618228320470549855286755"
    );
}

//
// Address tests
//

#[test]
fn test_verify_zk_login_id_and_iss() {
    // Test vector from [test_verify_zk_login_google]
    let address =
        hex::decode("1c6b623a2f2c91333df730c98d220f11484953b391a3818680f922c264cc0c6b").unwrap();
    let name = "sub";
    let value = "106294049240999307923";
    let aud = "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com";
    let salt = "6588741469050502421550140105345050859";
    let iss = "https://accounts.google.com";
    let salt_hash = poseidon_zk_login(&[(&Bn254FrElement::from_str(salt).unwrap()).into()])
        .unwrap()
        .to_string();
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

/// The address is the Blake2b-256 hash of the zkLogin flag 0x05, the length of the issuer as one
/// byte, the issuer and the address seed padded to 32 bytes. The length wraps around above 255
/// bytes, but the encoding stays unique since the seed has a fixed length. [verify_zk_login_iss]
/// reduces the seed modulo r, like other decimal strings.
#[test]
fn test_zk_login_address() {
    let address = |iss: &str, padded_seed: &[u8]| -> [u8; 32] {
        Blake2b256::digest([&[0x05, iss.len() as u8], iss.as_bytes(), padded_seed].concat()).digest
    };
    let seed = Bn254FrElement::from_str(GOOGLE_ADDRESS_SEED).unwrap();
    let seed_plus_r = add(GOOGLE_ADDRESS_SEED, &bn254_modulus::<Fr>());
    let long_iss = "x".repeat(300);
    for iss in [GOOGLE_ISS, "", long_iss.as_str()] {
        let expected = address(iss, seed.padded());
        assert_eq!(get_zk_login_address(&seed, iss).unwrap(), expected);
        for seed in [GOOGLE_ADDRESS_SEED, &seed_plus_r] {
            assert_eq!(verify_zk_login_iss(&expected, seed, iss), Ok(()));
        }
        assert_eq!(
            verify_zk_login_iss(&expected, "1", iss),
            Err(FastCryptoError::InvalidProof)
        );
        assert_eq!(
            verify_zk_login_iss(&expected, "01", iss),
            Err(FastCryptoError::InvalidInput)
        );
    }

    // The seed 1 is padded with 31 zero bytes.
    let one = Bn254FrElement::from_str("1").unwrap();
    assert_eq!(
        (one.padded(), one.unpadded()),
        (&[[0; 31].as_slice(), &[1]].concat()[..], &[1][..])
    );
    assert_eq!(
        get_zk_login_address(&one, GOOGLE_ISS).unwrap(),
        address(GOOGLE_ISS, one.padded())
    );
}

//
// V1 verification tests
//

#[test]
fn test_verify_zk_login_google() {
    assert_eq!(
        gen_address_seed(GOOGLE_SALT, "sub", GOOGLE_SUB, GOOGLE_AUD).unwrap(),
        GOOGLE_ADDRESS_SEED
    );
    let inputs = google_inputs();
    assert_eq!(inputs.get_kid(), GOOGLE_KID);
    assert_eq!(inputs.get_iss(), OIDCProvider::Google.get_config().iss);
    assert_eq!(inputs.get_address_seed().to_string(), GOOGLE_ADDRESS_SEED);
    assert_eq!(
        get_zk_login_address(inputs.get_address_seed(), inputs.get_iss()).unwrap(),
        Hex::decode(GOOGLE_ADDRESS).unwrap().as_slice()
    );
    assert_eq!(verify_google(&inputs), Ok(()));

    // Not with the insecure verifying key.
    assert!(verify_zk_login(
        &inputs,
        GOOGLE_MAX_EPOCH,
        &Hex::decode(GOOGLE_EPH_PK).unwrap(),
        &jwks(GOOGLE_ISS, GOOGLE_KID, GOOGLE_N),
        &ZkLoginEnv::Test,
    )
    .is_err());
}

#[test]
fn test_verify_zk_login_test_env() {
    let parse = |json: &serde_json::Value| {
        ZkLoginInputs::from_json(&json.to_string(), TEST_ENV_ADDRESS_SEED).unwrap()
    };
    let verify = |inputs: &ZkLoginInputs, env| {
        verify_zk_login(
            inputs,
            TEST_ENV_MAX_EPOCH,
            &Hex::decode(TEST_ENV_EPH_PK).unwrap(),
            &jwks(GOOGLE_ISS, TEST_ENV_KID, TEST_ENV_N),
            env,
        )
    };
    let json: serde_json::Value = serde_json::from_str(TEST_ENV_INPUTS).unwrap();
    assert_eq!(verify(&parse(&json), &ZkLoginEnv::Test), Ok(()));
    assert!(verify(&parse(&json), &ZkLoginEnv::Prod).is_err());

    // Other points: a and b with x = 1.
    let mut other_points = json.clone();
    other_points["proofPoints"]["a"][0] = "1".into();
    other_points["proofPoints"]["b"][0][0] = "1".into();
    assert!(verify(&parse(&other_points), &ZkLoginEnv::Test).is_err());

    // Points with a wrong number of coordinates parse, but don't verify.
    for (point, path) in [("a", None), ("b", None), ("b", Some(0)), ("c", None)] {
        let mut json = json.clone();
        let coordinates = &mut json["proofPoints"][point];
        let coordinates = match path {
            Some(i) => &mut coordinates[i],
            None => coordinates,
        };
        coordinates.as_array_mut().unwrap().pop();
        assert_eq!(
            verify(&parse(&json), &ZkLoginEnv::Test),
            Err(FastCryptoError::InvalidInput)
        );
    }

    assert!(ZkLoginInputs::from_json(TEST_ENV_INPUTS, "bad seed").is_err());
}

/// Sui transactions carry [ZkLoginInputs] in BCS, where field elements are decimal strings. BCS
/// skips the parsed JWT details, so [ZkLoginInputs::init] must run after decoding: without it, the
/// issuer and the key id are empty and verification fails.
#[test]
fn test_zk_login_inputs_bcs() {
    let bytes = bcs::to_bytes(&google_inputs()).unwrap();
    assert_eq!(
        Hex::encode(Sha256::digest(&bytes).digest),
        GOOGLE_INPUTS_BCS_SHA256
    );

    let mut inputs: ZkLoginInputs = bcs::from_bytes(&bytes).unwrap();
    assert_eq!((inputs.get_iss(), inputs.get_kid()), ("", ""));
    assert!(verify_google(&inputs).is_err());

    inputs.init().unwrap();
    assert_eq!(
        (inputs.get_iss(), inputs.get_kid()),
        (GOOGLE_ISS, GOOGLE_KID)
    );
    assert_eq!(bcs::to_bytes(&inputs).unwrap(), bytes);
    assert_eq!(verify_google(&inputs), Ok(()));
}

/// Changing any of the inputs of a valid proof makes verification fail.
#[test]
fn test_verify_zk_login_tampered() {
    let inputs = google_inputs();
    let eph_pk = Hex::decode(GOOGLE_EPH_PK).unwrap();
    let jwks = jwks(GOOGLE_ISS, GOOGLE_KID, GOOGLE_N);
    assert_eq!(
        verify_prod(&inputs, GOOGLE_MAX_EPOCH, &eph_pk, &jwks),
        Ok(())
    );

    // Another max epoch, or another ephemeral key or flag.
    assert!(verify_prod(&inputs, GOOGLE_MAX_EPOCH + 1, &eph_pk, &jwks).is_err());
    for index in [0, 1, eph_pk.len() - 1] {
        let mut other = eph_pk.clone();
        other[index] ^= 1;
        assert!(verify_prod(&inputs, GOOGLE_MAX_EPOCH, &other, &jwks).is_err());
    }

    // Another address seed.
    let other_seed = add(GOOGLE_ADDRESS_SEED, &BigUint::from(1u8));
    let other = ZkLoginInputs::from_json(GOOGLE_INPUTS, &other_seed).unwrap();
    assert!(verify_prod(&other, GOOGLE_MAX_EPOCH, &eph_pk, &jwks).is_err());

    // Another modulus for the key id, no key for it, or a modulus that isn't base64url.
    let mut other_n = GOOGLE_N.to_string();
    other_n.replace_range(10..11, "A");
    assert_ne!(other_n, GOOGLE_N);
    for (jwks, error) in [
        (self::jwks(GOOGLE_ISS, GOOGLE_KID, &other_n), None),
        (
            self::jwks(GOOGLE_ISS, "other kid", GOOGLE_N),
            Some(format!("JWK not found ({GOOGLE_ISS} - {GOOGLE_KID})")),
        ),
        (
            self::jwks("https://other.issuer", GOOGLE_KID, GOOGLE_N),
            Some(format!("JWK not found ({GOOGLE_ISS} - {GOOGLE_KID})")),
        ),
        (
            self::jwks(GOOGLE_ISS, GOOGLE_KID, "!"),
            Some("Invalid Base64 encoded jwk modulus".to_string()),
        ),
    ] {
        let result = verify_prod(&inputs, GOOGLE_MAX_EPOCH, &eph_pk, &jwks);
        assert!(result.is_err());
        if let Some(error) = error {
            assert_eq!(result, Err(FastCryptoError::GeneralError(error)));
        }
    }

    // Another header, with the same key id.
    let mut json = google_json();
    let header = format!(r#"{{"alg":"RS256","kid":"{GOOGLE_KID}","typ":"JWT","x":1}}"#);
    json["headerBase64"] = Base64UrlUnpadded::encode_string(header.as_bytes()).into();
    assert!(verify_google(&parse_google(&json).unwrap()).is_err());

    // Points of the proof swapped.
    let mut json = google_json();
    let a = json["proofPoints"]["a"].clone();
    json["proofPoints"]["a"] = json["proofPoints"]["c"].clone();
    json["proofPoints"]["c"] = a;
    assert!(verify_google(&parse_google(&json).unwrap()).is_err());
}

/// Several encodings of the same inputs verify. Decimal strings are reduced modulo the size of the
/// field, so the address seed plus r and a coordinate plus p parse to the same inputs, with the
/// same BCS encoding. The points are in Jacobian coordinates (x z^2, y z^3, z), so scaling them
/// with z gives the same point but another BCS encoding. And (-A, -B, C) is another proof of the
/// same statement. Sui caches verified inputs by their BCS encoding.
#[test]
fn test_verify_zk_login_equivalent_encodings() {
    let bcs = bcs::to_bytes(&google_inputs()).unwrap();
    let p = bn254_modulus::<Fq>();
    let a = google_json()["proofPoints"]["a"].clone();
    let [x, y] = [0, 1].map(|i| Fq::from_str(a[i].as_str().unwrap()).unwrap());
    let z = Fq::from(2u8);

    let seed_plus_r = add(GOOGLE_ADDRESS_SEED, &bn254_modulus::<Fr>());
    let mut x_plus_p = google_json();
    x_plus_p["proofPoints"]["a"][0] = add(a[0].as_str().unwrap(), &p).into();
    let mut scaled = google_json();
    scaled["proofPoints"]["a"] = serde_json::json!([
        (x * z * z).to_string(),
        (y * z * z * z).to_string(),
        z.to_string()
    ]);
    let mut negated = google_json();
    negated["proofPoints"]["a"][1] = negate(a[1].as_str().unwrap()).into();
    for i in 0..2 {
        let b_y = negated["proofPoints"]["b"][1][i]
            .as_str()
            .unwrap()
            .to_string();
        negated["proofPoints"]["b"][1][i] = negate(&b_y).into();
    }

    // (inputs, whether their BCS encoding is that of the original inputs)
    for (inputs, same_bcs) in [
        (
            ZkLoginInputs::from_json(GOOGLE_INPUTS, &seed_plus_r).unwrap(),
            true,
        ),
        (parse_google(&x_plus_p).unwrap(), true),
        (parse_google(&scaled).unwrap(), false),
        (parse_google(&negated).unwrap(), false),
    ] {
        assert_eq!(verify_google(&inputs), Ok(()));
        assert_eq!(bcs::to_bytes(&inputs).unwrap() == bcs, same_bcs);
    }

    // Scaling (x z, y z, z) is not the same point, and z = 0 is the identity.
    for a in [
        serde_json::json!([(x * z).to_string(), (y * z).to_string(), z.to_string()]),
        serde_json::json!([x.to_string(), y.to_string(), "0"]),
    ] {
        let mut json = google_json();
        json["proofPoints"]["a"] = a;
        assert!(verify_google(&parse_google(&json).unwrap()).is_err());
    }
}

/// The base64 value of the issuer claim drops bits of its first and last characters that belong to
/// neighbouring characters in the JWT, without checking them, so several values give the same
/// issuer. V1 verification hashes the value itself, so only the value from the JWT verifies.
#[test]
fn test_verify_zk_login_iss_dropped_bits() {
    let value = google_json()["issBase64Details"]["value"]
        .as_str()
        .unwrap()
        .to_string();
    // With index 1, the top 2 bits of the first character are dropped: 'y' and 'S' are 110010 and
    // 010010. The value has 49 characters, so the last 4 bits are dropped too: 'C' and 'D' are
    // 000010 and 000011.
    assert!(value.starts_with('y') && value.ends_with('C') && value.len() == 49);
    for other in [format!("S{}", &value[1..]), format!("{}D", &value[..48])] {
        let mut json = google_json();
        json["issBase64Details"]["value"] = other.into();
        let inputs = parse_google(&json).unwrap();
        assert_eq!(inputs.get_iss(), GOOGLE_ISS);
        assert!(verify_google(&inputs).is_err());
    }
}

/// The ephemeral public key with its flag has 33 to 47 bytes, the base64 header at most 248
/// characters and the modulus at most 2048 bits. Non-standard, pinned: base64 moduli with leading
/// zero bytes verify, but not padded ones.
#[test]
fn test_verify_zk_login_input_limits() {
    let inputs = google_inputs();
    let jwks = jwks(GOOGLE_ISS, GOOGLE_KID, GOOGLE_N);

    // (ephemeral public key length, expected error)
    for (len, error) in [
        (0, FastCryptoError::InputTooShort(33)),
        (32, FastCryptoError::InputTooShort(33)),
        (48, FastCryptoError::InputTooLong(47)),
    ] {
        assert_eq!(
            verify_prod(&inputs, GOOGLE_MAX_EPOCH, &vec![0; len], &jwks),
            Err(error)
        );
    }
    for len in [33, 47] {
        let result = verify_prod(&inputs, GOOGLE_MAX_EPOCH, &vec![0; len], &jwks);
        assert_eq!(
            result,
            Err(FastCryptoError::GeneralError(
                "Groth16 proof verify failed".to_string()
            ))
        );
    }

    // A header of 250 base64 characters.
    let kid = "k".repeat(151);
    let header = format!(r#"{{"alg":"RS256","kid":"{kid}","typ":"JWT"}}"#);
    let header = Base64UrlUnpadded::encode_string(header.as_bytes());
    assert_eq!(header.len(), 250);
    let mut json = google_json();
    json["headerBase64"] = header.into();
    assert_eq!(
        verify_prod(
            &parse_google(&json).unwrap(),
            GOOGLE_MAX_EPOCH,
            &Hex::decode(GOOGLE_EPH_PK).unwrap(),
            &self::jwks(GOOGLE_ISS, &kid, GOOGLE_N)
        ),
        Err(FastCryptoError::GeneralError("Header too long".to_string()))
    );

    // (modulus, whether verification succeeds)
    let eph_pk = Hex::decode(GOOGLE_EPH_PK).unwrap();
    for (n, verifies) in [
        (format!("AAAA{GOOGLE_N}"), true),
        (format!("{GOOGLE_N}="), false),
        // 4n, which has 2050 bits.
        (format!("A{GOOGLE_N}"), false),
        (String::new(), false),
    ] {
        let result = verify_prod(
            &inputs,
            GOOGLE_MAX_EPOCH,
            &eph_pk,
            &self::jwks(GOOGLE_ISS, GOOGLE_KID, &n),
        );
        assert_eq!(result.is_ok(), verifies, "{n}");
    }
}

//
// V2 verification tests
//

#[test]
fn test_v2_inputs_use_extended_issuer_wire_format() {
    // The JSON format of the V2 prover response:
    // https://github.com/MystenLabs/zklogin-circuits/blob/98f83f08ef018ffe1ec4f606a4b3db82d4dbba7b/src/lib/proverResponse.ts#L4-L10
    let seed_hex = "0xcaffb21b7c12688e53c35f7466517bffe25060520ec2f6be90c6871b687ab64b";
    let json = r#"{
        "proofPoints":{"a":[],"b":[],"c":[]},
        "extIss":"\"iss\":\"https://issuer.example\",",
        "headerBase64":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleSJ9",
        "addressSeed":"0xcaffb21b7c12688e53c35f7466517bffe25060520ec2f6be90c6871b687ab64b"
    }"#;
    let mut input: ZkLoginInputsV2 = serde_json::from_str(json).unwrap();
    input.init().unwrap();
    assert_eq!(input.jwt_details.iss, "https://issuer.example");
    assert_eq!(input.validated_iss_and_kid().unwrap().1, "key");
    assert_eq!(Hex::encode_with_format(input.address_seed), seed_hex);

    // The address seed serializes back to the same 0x-prefixed hex string.
    let value = serde_json::to_value(&input).unwrap();
    assert_eq!(value["addressSeed"], seed_hex);

    let mut input: ZkLoginInputsV2 =
        serde_json::from_str(&json.replace("issuer", "issuér")).unwrap();
    assert!(input.init().is_err());

    // Reject a short seed and the byte-array format.
    let short = json.replace(seed_hex, &seed_hex[..64]);
    assert!(serde_json::from_str::<ZkLoginInputsV2>(&short).is_err());
    let array = json.replace(&format!("\"{seed_hex}\""), "[0,1,2]");
    assert!(serde_json::from_str::<ZkLoginInputsV2>(&array).is_err());
}

#[test]
fn test_verify_dev_v2_prover_response() {
    let iss = "https://jwt-tester.mystenlabs.com";
    let eph_pubkey = Base64::decode("ALnG7hYw7z5xEUSmSNsGu7IoT3J0z77lP/zuUDzBpJIA").unwrap();
    let max_epoch = 10;
    let mut all_jwk = ImHashMap::new();
    all_jwk.insert(
        JwkId::new(iss.to_string(), "sui-key-id-8192".to_string()),
        JWK {
            kty: "RSA".to_string(),
            e: "AQAB".to_string(),
            n: JWT_TESTER_8192_N.to_string(),
            alg: "RS256".to_string(),
        },
    );
    let parse = |json: &str| {
        VersionedZkLoginInputs::V2(serde_json::from_str(json).unwrap())
            .init()
            .unwrap()
    };
    let verify = |inputs: &VersionedZkLoginInputs, max_epoch: u64, env: &ZkLoginEnv| {
        verify_zk_login_extended(inputs, max_epoch, &eph_pubkey, &all_jwk, env)
    };

    let inputs = parse(DEV_V2_PROVER_RESPONSE);
    assert_eq!(inputs.get_iss(), iss);
    assert_eq!(
        Hex::encode(inputs.get_address_seed()),
        "6cf4834879b9d06e73191ab9403b84dfdb2a113815b40ae1c5b55d1f7e6208f0"
    );
    assert!(verify(&inputs, max_epoch, &ZkLoginEnv::Test).is_ok());

    // No production V2 key exists yet.
    assert!(verify(&inputs, max_epoch, &ZkLoginEnv::Prod).is_err());

    // A different max epoch changes the public input.
    assert!(verify(&inputs, max_epoch + 1, &ZkLoginEnv::Test).is_err());

    // A different address seed changes the public input.
    let mut tampered: serde_json::Value = serde_json::from_str(DEV_V2_PROVER_RESPONSE).unwrap();
    tampered["addressSeed"] = format!("0x{}", "00".repeat(32)).into();
    let tampered = parse(&tampered.to_string());
    assert!(verify(&tampered, max_epoch, &ZkLoginEnv::Test).is_err());

    // A different ephemeral public key changes the public input.
    let mut other_eph_pubkey = eph_pubkey.clone();
    other_eph_pubkey[1] ^= 1;
    assert!(verify_zk_login_extended(
        &inputs,
        max_epoch,
        &other_eph_pubkey,
        &all_jwk,
        &ZkLoginEnv::Test
    )
    .is_err());

    // A different modulus under the same JWK id changes the public input.
    let other_jwk: ImHashMap<JwkId, JWK> = all_jwk
        .iter()
        .map(|(id, jwk)| {
            let mut n = jwk.n.clone().into_bytes();
            n[100] = if n[100] == b'A' { b'B' } else { b'A' };
            let jwk = JWK {
                n: String::from_utf8(n).unwrap(),
                ..jwk.clone()
            };
            (id.clone(), jwk)
        })
        .collect();
    assert!(verify_zk_login_extended(
        &inputs,
        max_epoch,
        &eph_pubkey,
        &other_jwk,
        &ZkLoginEnv::Test
    )
    .is_err());
}

/// The extended issuer claim of V2 has 1 to 174 ASCII bytes, the base64 header at most 317
/// characters and the modulus at most 8192 bits.
#[test]
fn test_v2_input_limits() {
    let json: serde_json::Value = serde_json::from_str(DEV_V2_PROVER_RESPONSE).unwrap();
    let with = |key: &str, value: String| {
        let mut json = json.clone();
        json[key] = value.into();
        serde_json::from_value::<ZkLoginInputsV2>(json).unwrap()
    };
    // `"iss":"` and `",` around the issuer.
    let ext_iss = |iss_len| format!(r#""iss":"{}","#, "x".repeat(iss_len));
    assert_eq!(ext_iss(165).len(), 174);

    // (extended issuer claim, whether it is accepted)
    for (ext_iss, accepted) in [
        (ext_iss(165), true),
        (ext_iss(166), false),
        (String::new(), false),
        (r#""iss":"é","#.to_string(), false),
    ] {
        assert_eq!(with("extIss", ext_iss).init().is_ok(), accepted);
    }

    let eph_pk = Base64::decode("ALnG7hYw7z5xEUSmSNsGu7IoT3J0z77lP/zuUDzBpJIA").unwrap();
    let modulus = Base64UrlUnpadded::decode_vec(JWT_TESTER_8192_N).unwrap();
    assert_eq!(modulus.len(), 1024);
    // (inputs, modulus, expected error). The transcript checks the claim and the header again.
    for (inputs, modulus, error) in [
        (
            with("headerBase64", "A".repeat(318)),
            modulus.clone(),
            FastCryptoError::GeneralError("Header too long".to_string()),
        ),
        (
            with("extIss", String::new()),
            modulus.clone(),
            FastCryptoError::InvalidInput,
        ),
        (
            with("extIss", ext_iss(166)),
            modulus.clone(),
            FastCryptoError::InvalidInput,
        ),
        (
            with("extIss", ext_iss(10)),
            [vec![1], modulus.clone()].concat(),
            FastCryptoError::InputTooLong(1024),
        ),
    ] {
        assert!(inputs.clone().init().is_err() || modulus.len() > 1024);
        assert_eq!(
            inputs.calculate_all_inputs_hash(&eph_pk, &modulus, 10),
            Err(error)
        );
    }
    // Leading zero bytes count towards the length limit, but not in the transcript.
    let inputs = with("extIss", ext_iss(10));
    assert_eq!(
        inputs.calculate_all_inputs_hash(&eph_pk, &[vec![0], modulus[1..].to_vec()].concat(), 10),
        inputs.calculate_all_inputs_hash(&eph_pk, &modulus[1..], 10)
    );
}

//
// Proptests
//

/// A change to the Google proof, its inputs or its key. Some keep their meaning.
#[derive(Clone, Debug)]
enum Change {
    /// Sets one of the coordinates of a, b and c, see [coordinate].
    Coordinate(Index, String),
    /// Adds k p to a coordinate, which doesn't change it.
    CoordinatePlusP(Index, u8),
    AddressSeed(String),
    /// Adds k r to the address seed, which doesn't change it.
    AddressSeedPlusR(u8),
    /// Sets a character of the issuer claim, the header or the modulus.
    ClaimCharacter(Index, char),
    HeaderCharacter(Index, char),
    ModulusCharacter(Index, char),
    IndexMod4(u8),
    MaxEpoch(u64),
    EphPkByte(Index, u8),
}

fn arb_change() -> impl Strategy<Value = Change> {
    let decimal = prop_oneof!["[1-9][0-9]{0,77}", "[0-9+-]{0,3}"];
    let base64url = prop_oneof![
        proptest::char::range('A', 'Z'),
        proptest::char::range('a', 'z'),
        proptest::char::range('0', '9'),
        Just('-'),
        Just('_'),
        Just('='),
    ];
    prop_oneof![
        (any::<Index>(), decimal.clone()).prop_map(|(i, s)| Change::Coordinate(i, s)),
        (any::<Index>(), 1..3u8).prop_map(|(i, k)| Change::CoordinatePlusP(i, k)),
        decimal.prop_map(Change::AddressSeed),
        (1..3u8).prop_map(Change::AddressSeedPlusR),
        (any::<Index>(), base64url.clone()).prop_map(|(i, c)| Change::ClaimCharacter(i, c)),
        (any::<Index>(), base64url.clone()).prop_map(|(i, c)| Change::HeaderCharacter(i, c)),
        (any::<Index>(), base64url).prop_map(|(i, c)| Change::ModulusCharacter(i, c)),
        (0..5u8).prop_map(Change::IndexMod4),
        prop_oneof![Just(GOOGLE_MAX_EPOCH), any::<u64>()].prop_map(Change::MaxEpoch),
        (any::<Index>(), any::<u8>()).prop_map(|(i, b)| Change::EphPkByte(i, b)),
    ]
}

/// One of the 12 coordinates of the points a, b and c of a proof in JSON.
fn coordinate<'a>(json: &'a mut serde_json::Value, index: &Index) -> &'a mut serde_json::Value {
    let points = &mut json["proofPoints"];
    match index.index(12) {
        i @ 0..=2 => &mut points["a"][i],
        i @ 3..=8 => &mut points["b"][(i - 3) / 2][(i - 3) % 2],
        i => &mut points["c"][i - 9],
    }
}

/// Sets a character of a string.
fn set_char(s: &str, index: &Index, c: char) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    let index = index.index(chars.len());
    chars[index] = c;
    chars.into_iter().collect()
}

proptest! {
    // Each case may verify a Groth16 proof, which is slow in debug builds.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Changes to the Google proof never make verification panic, and it only verifies if the
    /// inputs keep their meaning: the same BCS encoding, max epoch, ephemeral key and modulus.
    #[test]
    fn test_verify_zk_login_changed(change in arb_change()) {
        let mut json = google_json();
        let mut seed = GOOGLE_ADDRESS_SEED.to_string();
        let mut n = GOOGLE_N.to_string();
        let mut max_epoch = GOOGLE_MAX_EPOCH;
        let mut eph_pk = Hex::decode(GOOGLE_EPH_PK).unwrap();
        match &change {
            Change::Coordinate(index, value) => {
                *coordinate(&mut json, index) = value.clone().into()
            }
            Change::CoordinatePlusP(index, k) => {
                let c = coordinate(&mut json, index);
                *c = add(c.as_str().unwrap(), &(bn254_modulus::<Fq>() * BigUint::from(*k))).into();
            }
            Change::AddressSeed(value) => seed = value.clone(),
            Change::AddressSeedPlusR(k) => {
                seed = add(&seed, &(bn254_modulus::<Fr>() * BigUint::from(*k)))
            }
            Change::ClaimCharacter(index, c) => {
                let value = json["issBase64Details"]["value"].as_str().unwrap().to_string();
                json["issBase64Details"]["value"] = set_char(&value, index, *c).into();
            }
            Change::HeaderCharacter(index, c) => {
                let value = json["headerBase64"].as_str().unwrap().to_string();
                json["headerBase64"] = set_char(&value, index, *c).into();
            }
            Change::ModulusCharacter(index, c) => n = set_char(&n, index, *c),
            Change::IndexMod4(index) => json["issBase64Details"]["indexMod4"] = (*index).into(),
            Change::MaxEpoch(value) => max_epoch = *value,
            Change::EphPkByte(index, value) => {
                let index = index.index(eph_pk.len());
                eph_pk[index] = *value;
            }
        }

        let Ok(inputs) = ZkLoginInputs::from_json(&json.to_string(), &seed) else {
            return Ok(());
        };
        let result = verify_zk_login(
            &inputs,
            max_epoch,
            &eph_pk,
            &jwks(GOOGLE_ISS, GOOGLE_KID, &n),
            &ZkLoginEnv::Prod,
        );
        if result.is_ok() {
            prop_assert_eq!(bcs::to_bytes(&inputs).unwrap(), bcs::to_bytes(&google_inputs()).unwrap());
            prop_assert_eq!(max_epoch, GOOGLE_MAX_EPOCH);
            prop_assert_eq!(eph_pk, Hex::decode(GOOGLE_EPH_PK).unwrap());
            prop_assert_eq!(
                BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(&n).unwrap()),
                BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(GOOGLE_N).unwrap())
            );
        }
    }

    /// Changes to the BCS encoding of the Google inputs, as in a Sui transaction, never make
    /// decoding, [ZkLoginInputs::init] or verification panic, and only the original inputs verify.
    #[test]
    fn test_verify_zk_login_bcs_changed(mutations in vec(arb_byte_mutation(), 1..4)) {
        let original = bcs::to_bytes(&google_inputs()).unwrap();
        let mut bytes = original.clone();
        for mutation in &mutations {
            mutation.apply(&mut bytes);
        }
        if let Ok(mut inputs) = bcs::from_bytes::<ZkLoginInputs>(&bytes) {
            if inputs.init().is_ok() && verify_google(&inputs).is_ok() {
                prop_assert_eq!(bcs::to_bytes(&inputs).unwrap(), original);
            }
        }
    }

    /// Changes to a JWK response never make [parse_jwks] panic, and it only returns RSA keys with
    /// the exponent 65537 for the provider's issuer.
    #[test]
    fn test_parse_jwks_changed(mutations in vec(arb_byte_mutation(), 1..4)) {
        let mut bytes = GOOGLE_JWK_BYTES.to_vec();
        for mutation in &mutations {
            mutation.apply(&mut bytes);
        }
        for skip_on_invalid_jwk in [true, false] {
            if let Ok(jwks) = parse_jwks(&bytes, &OIDCProvider::Google, skip_on_invalid_jwk) {
                for (id, jwk) in jwks {
                    prop_assert_eq!(id.iss, GOOGLE_ISS);
                    prop_assert_eq!((jwk.kty, jwk.e, jwk.alg), ("RSA".to_string(), "AQAB".to_string(), "RS256".to_string()));
                }
            }
        }
    }
}
