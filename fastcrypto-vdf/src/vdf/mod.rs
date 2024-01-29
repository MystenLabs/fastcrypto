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
    use crate::class_group::{Discriminant, QuadraticForm};
    use crate::vdf::wesolowski::StrongVDF;
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

        // Parameter for the hash to quadratic form
        let k = 4;

        // VDF construction
        let vdf = StrongVDF::new(discriminant.clone(), t);

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
        let input = QuadraticForm::from_seed(&combined_randomness, &discriminant, k);
        assert_eq!(input.to_bytes(), hex::decode("003f0dd96f00382016209d7073d324903c1c769d1c68beeeaeb88c22252236d4a6f60cee389f3c9ebfc9b599556d850d02eb3aeabb0c330e7e8e07a882e77b3cff005f009643dcf5bc3584db554f8352a8178cae3e0aa2e6358c5321ae160a632fdc61c0888d918a510361e3542ed1ad27908683e89aa1ddf03b76abf174071fead13845470bcf0957ee97f3695fcfdcbe330f59d5e7d30672fdab30c4afe2d1ad91").unwrap());

        // Compute the output of the VDF
        let (output, proof) = vdf.evaluate(&input).unwrap();
        assert_eq!(output.to_bytes(), hex::decode("00406f3b8eb978b15578b3b2417c8d9b69e717f95bafde1d8ea2f8ad95233700cb695674f844d0b200d10858ee8cef0d41435bbddcfb8374d16a6991cd092d3862880040d8d398a74e60c35578d6412e9ba609ba5cacf5d5b9b4e45fc69312b5a427ee8a2ab11196536713258a42ca67ee248bc0eeee1a6047479e94a6bda2bc29253f0f").unwrap());
        assert_eq!(proof.to_bytes(), hex::decode("00407bcbbe400b2c9cd3b311a8be17509ccad8d18d45ff9c934aea798d908ca0ccb46a805b637ee51df0338f8d28ae5ea90c0d209ebb2d4e1c97cea16e51ce157a4900408666e9ce6e5a6d294f7b66f5c8feefa5bf7e5a6e8d98b084a0205f4179ac79b4f04efa641bafad779e035276ff44ee02c4dced65dc68d60bab6815202328fe5f").unwrap());

        // Verify the output and proof
        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // Try with another input. This should fail.
        let another_input = QuadraticForm::from_seed(b"some other randomness", &discriminant, k);

        // Verify the output and proof
        assert!(vdf.verify(&another_input, &output, &proof).is_err());
    }
}
