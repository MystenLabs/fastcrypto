// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains a implementation of a verifiable delay function (VDF), using Wesolowski's
//! construction with ideal class groups.

use fastcrypto::error::FastCryptoResult;

pub mod wesolowski;

/// This represents a Verifiable Delay Function (VDF) construction.
pub trait VDF {
    /// The type of the input to the VDF.
    type InputType;

    /// The type of the output from the VDF.
    type OutputType;

    /// The type of the proof of correctness for this VDF.
    type ProofType;

    /// Evaluate this VDF and return the output and a proof of correctness.
    fn evaluate(
        &self,
        input: &Self::InputType,
    ) -> FastCryptoResult<(Self::OutputType, Self::ProofType)>;

    /// Verify the output and proof from a VDF.
    fn verify(
        &self,
        input: &Self::InputType,
        output: &Self::OutputType,
        proof: &Self::ProofType,
    ) -> FastCryptoResult<()>;
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::vdf::wesolowski::DefaultVDF;
    use crate::vdf::VDF;
    use crate::ToBytes;
    use fastcrypto::hash::{HashFunction, Sha256};
    use num_bigint::BigInt;
    use num_traits::Num;

    #[test]
    fn vdf_e2e_test_1024() {
        // This test runs an e2e test of the VDF protocol as it is supposed to be run on SUI with a smaller discriminant
        // and a smaller number of iterations.

        // Fixed 1024 bit discriminant. In production this should be bigger.
        let discriminant_bytes = "fdf4aa9b7f49b85fc71f6fbf31a3d51e6828afb9d06165f5814bb5142485853abb52f50b7c8a937bba09ce75b51a639886d997d561b7a654f1a9e6b66645d76fad093381d464eccf28d599fb5a938bb99101c30e374f5f786c9232f56d0118826d113400b080bb4737018b088af5203a18da25d106fffdad7e8f660e141dd11f";
        let discriminant =
            Discriminant::try_from(-BigInt::from_str_radix(discriminant_bytes, 16).unwrap())
                .unwrap();

        // Number of iterations for the VDF
        let t = 500;

        // VDF construction
        let vdf = DefaultVDF::new(discriminant.clone(), t);

        // Add some randomness
        let mut combined_randomness = Vec::new();
        let some_randomness = b"some randomness";
        combined_randomness =
            Sha256::digest([&combined_randomness, some_randomness.as_ref()].concat()).to_vec();
        let more_randomness = b"more randomness";
        combined_randomness =
            Sha256::digest([&combined_randomness, more_randomness.as_ref()].concat()).to_vec();
        assert_eq!(
            combined_randomness,
            hex::decode("2ef29e01809053dcfc89e7acad77e13c2bf03b5a9a0bbfea555a1423f1f1ae23")
                .unwrap()
        );

        // Compute the VDF input from the combined randomness
        let input = QuadraticForm::hash_to_group_with_default_parameters(
            &combined_randomness,
            &discriminant,
        )
        .unwrap();
        assert_eq!(input.to_bytes(), hex::decode("003d1daa654704dd48f4d9f841ffe9b7dc89ef998ff05f32f0f6e3534c471f47c7cded2041d78d0e6d485bf6074f47bda32a132334c5b3791b530e2999d7410072fdb7dd5859c497f0711b87c4fc787208d1969bd9f661958ae9646fbf5c735a3fdb07c32d33991d38879723cdb1ebbb1ecbf4b5d9e549e92b9c3b791407f05ccb9ea0d82c2982a5c6264cc293c6e328eb07ae7094336e89b01c74b115646a775019bfb7d413449378488c1e5e67e32160c6d3").unwrap());

        // Compute the output of the VDF
        let (output, proof) = vdf.evaluate(&input).unwrap();
        assert_eq!(output.to_bytes(), hex::decode("004013829c9d086b35690a80ee0e68212db9737f65e203fd793277952c5213c3bf5e2fcc8cc01001f13c309b1edae3c9ef551d0fc371d0f2dd17944919a75d82db340040f0fd1a66112bb398a7577d1637955ce1c53c127a00d657d5138f7379ae57206b86715164c313f66ea4f0519149d1799f149d35c6a9d5a97a27ba376c336525ff").unwrap());
        assert_eq!(proof.to_bytes(), hex::decode("00405747c1e3d2af1d2b091f7366cbeff4c9836dc0b5bb6e6032053af6aa589348d000abb10250540258d9bf70ed81810b6d4229af8567b51eb8a08b6d72d9e52f880040203a9dbb321818cbac6f9ca011af9544b91c94b357f924e5d29cf94d5e28b9148d8e7febbb495a76d1d159c8785a6c01120a124f08c72a140e812c58eaa70de1").unwrap());

        // Verify the output and proof
        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // Try with another input. This should fail.
        let another_input = QuadraticForm::hash_to_group_with_default_parameters(
            b"some other randomness",
            &discriminant,
        )
        .unwrap();

        // Verify the output and proof
        assert!(vdf.verify(&another_input, &output, &proof).is_err());
    }
}
