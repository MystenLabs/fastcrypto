// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::Fr;
use light_poseidon::Poseidon;
use light_poseidon::PoseidonHasher;
/// Wrapper struct for Poseidon hash instance.
pub struct PoseidonWrapper {
    instance: Poseidon<Fr>,
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
    use super::PoseidonWrapper;
    use ark_bn254::Fr;
    use std::str::FromStr;
    #[test]
    fn poseidon_test() {
        // Test vector generated from circomjs
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
}
