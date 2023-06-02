// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::Fr;
use light_poseidon::Poseidon;
use light_poseidon::PoseidonHasher;
use std::fmt::Debug;
use std::fmt::Formatter;
/// Wrapper struct for Poseidon hash instance.
pub struct PoseidonWrapper {
    instance: Poseidon<Fr>,
}

impl Debug for PoseidonWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoseidonWrapper").finish()
    }
}

impl PoseidonWrapper {
    /// Initialize a Poseidon hash function with the given size.
    pub fn new(size: usize) -> Self {
        Self {
            instance: Poseidon::<Fr>::new_circom(size).unwrap(),
        }
    }

    /// Calculate the hash of the given inputs.
    pub fn hash(&mut self, inputs: &[Fr]) -> Fr {
        self.instance.hash(inputs).unwrap()
    }
}
#[cfg(test)]
mod test {
    use crate::bn254::zk_login::calculate_merklized_hash;

    use super::PoseidonWrapper;
    use ark_bn254::Fr;
    use std::str::FromStr;
    #[test]
    fn poseidon_test() {
        // TODO (joyqvq): add more test vectors here from circom.js
        // Test vector generated from circom.js
        // Poseidon([134696963602902907403122104327765350261n,
        // 17932473587154777519561053972421347139n,
        // 10000,
        // 50683480294434968413708503290439057629605340925620961559740848568164438166n])
        // = 2272550810841985018139126931041192927190568084082399473943239080305281957330n
        let mut poseidon = PoseidonWrapper::new(4);
        let input1 = Fr::from_str("134696963602902907403122104327765350261").unwrap();
        let input2 = Fr::from_str("17932473587154777519561053972421347139").unwrap();
        let input3 = Fr::from_str("10000").unwrap();
        let input4 = Fr::from_str(
            "50683480294434968413708503290439057629605340925620961559740848568164438166",
        )
        .unwrap();
        let hash = poseidon.hash(&[input1, input2, input3, input4]);
        assert_eq!(
            hash,
            Fr::from_str(
                "2272550810841985018139126931041192927190568084082399473943239080305281957330"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_merklized_hash() {
        let masked_content = b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ.=yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC===========================================================================================================CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC==========================================================================================================================================================================================================================================================================================================\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\xd8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(
            calculate_merklized_hash(masked_content).unwrap(),
            "14900420995580824499222150327925943524564997104405553289134597516335134742309"
        );
    }

    #[test]
    fn test_all_inputs_hash() {
        let mut poseidon = PoseidonWrapper::new(11);
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

        let hash = poseidon.hash(&[
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
        ]);
        assert_eq!(
            hash.to_string(),
            "2487117669597822357956926047501254969190518860900347921480370492048882803688"
                .to_string()
        );
    }
}
