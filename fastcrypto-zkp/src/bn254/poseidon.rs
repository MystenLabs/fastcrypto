// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::Fr;
use fastcrypto::error::FastCryptoError;
use once_cell::sync::OnceCell;
use poseidon_ark::Poseidon;
use std::fmt::Debug;
use std::fmt::Formatter;

/// Wrapper struct for Poseidon hash instance.
pub struct PoseidonWrapper {
    instance: Poseidon,
}

impl Debug for PoseidonWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoseidonWrapper").finish()
    }
}

impl Default for PoseidonWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl PoseidonWrapper {
    /// Initialize a Poseidon hash function.
    pub fn new() -> Self {
        Self {
            instance: Poseidon::new(),
        }
    }

    /// Calculate the hash of the given inputs.
    pub fn hash(&self, inputs: Vec<Fr>) -> Result<Fr, FastCryptoError> {
        self.instance
            .hash(inputs)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

/// Calculate the poseidon hash of the field element inputs. If the input
/// length is <= 16, calculate H(inputs), if it is <= 32, calculate H(H(inputs[0..16]), H(inputs[16..32])), otherwise return an error.
pub fn to_poseidon_hash(inputs: Vec<Fr>) -> Result<Fr, FastCryptoError> {
    static POSEIDON: OnceCell<PoseidonWrapper> = OnceCell::new();
    let poseidon_ref = POSEIDON.get_or_init(PoseidonWrapper::new);
    if inputs.len() <= 16 {
        poseidon_ref.hash(inputs)
    } else if inputs.len() <= 32 {
        let hash1 = poseidon_ref.hash(inputs[0..16].to_vec())?;
        let hash2 = poseidon_ref.hash(inputs[16..].to_vec())?;
        poseidon_ref.hash([hash1, hash2].to_vec())
    } else {
        Err(FastCryptoError::GeneralError(format!(
            "Yet to implement: Unable to hash a vector of length {}",
            inputs.len()
        )))
    }
}

#[cfg(test)]
mod test {
    use super::PoseidonWrapper;
    use crate::bn254::{poseidon::to_poseidon_hash, zk_login::Bn254Fr};
    use ark_bn254::Fr;
    use std::str::FromStr;

    fn to_bigint_arr(vals: Vec<u8>) -> Vec<Bn254Fr> {
        vals.iter()
            .map(|x| Bn254Fr::from_str(&x.to_string()).unwrap())
            .collect()
    }

    #[test]
    fn poseidon_test() {
        let poseidon = PoseidonWrapper::new();
        let input1 = Fr::from_str("134696963602902907403122104327765350261").unwrap();
        let input2 = Fr::from_str("17932473587154777519561053972421347139").unwrap();
        let input3 = Fr::from_str("10000").unwrap();
        let input4 = Fr::from_str(
            "50683480294434968413708503290439057629605340925620961559740848568164438166",
        )
        .unwrap();
        let hash = poseidon.hash(vec![input1, input2, input3, input4]).unwrap();
        assert_eq!(
            hash,
            Fr::from_str(
                "2272550810841985018139126931041192927190568084082399473943239080305281957330"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_to_poseidon_hash() {
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![1]))
                .unwrap()
                .to_string(),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![1, 2]))
                .unwrap()
                .to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
            ]))
            .unwrap()
            .to_string(),
            "4203130618016961831408770638653325366880478848856764494148034853759773445968"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
            ]))
            .unwrap()
            .to_string(),
            "9989051620750914585850546081941653841776809718687451684622678807385399211877"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29
            ]))
            .unwrap()
            .to_string(),
            "4123755143677678663754455867798672266093104048057302051129414708339780424023"
        );

        assert!(to_poseidon_hash(to_bigint_arr(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32
        ]))
        .is_err());
    }

    #[test]
    fn test_all_inputs_hash() {
        let poseidon = PoseidonWrapper::new();
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

        let hash = poseidon
            .hash(vec![
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
            "2487117669597822357956926047501254969190518860900347921480370492048882803688"
                .to_string()
        );
    }
}
