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
        assert_eq!(bcs::to_bytes(&input).unwrap(), hex::decode("011041d799290e531b79b3c53423132aa3bd474f07f65b486d0e8dd74120edcdc7471f474c53e3f6f0325ff08f99ef89dcb7e9ff41f8d9f448dd044765aa1d000000ff1d2d399fde1c98a1e173b7876cbbec2b4840e6af88959bea4e8be34f7691cc6b8f51f814d71c396c3db3d9395a7dd6d3275f6134a30ff8eb86c463d416b61a264a0b34e144144e32dc6878c7e266ccd23cf824c0a58ca340909b16756a9e092664692ef78d87033b78e48e0f683ba6a72248020000012a423a448b756444d05554ca5ef57b8f164daeadd774fef0b4e7c9ae51bf29b27cc89b3798d0f3c09147284c725f38f2eb8c2e0cbe0c908f9139431a1fcc2718e23cfd8c54d6cf53f705d00f64f1e7c5118cdf157ac5036848316c9fb722d97e47a80a553147966be41ea2414fe767750b4c9e42e36430c56614bc05ae5dc567a98568d84c40b81360428a8c8178a9cabc17893f83dcc942f4dc7d04785f00456b23edaa803b0b0000").unwrap());

        // Compute the output of the VDF
        let (output, proof) = vdf.evaluate(&input).unwrap();
        assert_eq!(bcs::to_bytes(&output).unwrap(), hex::decode("011034db825da719499417ddf2d071c30f1d55efc9e3da1e9b303cf10110c08ccc2f5ebfc313522c95773279fd03e2657f73b92d21680eee800a69356b089d9c8213ff1001da9acc93c845d885562a5639ca62eb60862eb66eae0f5b9109ec3c9bae8e7994dfa851868c70ec2aa829ff85edc33a1ea36ac8e982a858674cd4ee99e5020f01119a85ed005757d4435bda3e92178f8ef4c517976a6120fc15f1e11834b346d678dd572aff9a917ff3a6c0233a63a40e9c4440008d3ff479fc316d33f66084f24303000000").unwrap());
        assert_eq!(bcs::to_bytes(&proof).unwrap(), hex::decode("01105c35c1e267879e808aa5c4d83acfa3546bb1090aebd7698002db742cb1cb39f10c537f186c52a9cc1d3d341ce6f9b30e47220a4ab26617cd320719f6082bb0710110472ec71f82be715872fd7957faea4b87083ecb3c7abe1b1970c1c5b8f9109897484b6711c0e871a2a683f968794c6705ff2dccfb1ab935c831f8f6022fe266460110bb68b6c0bbdb2e09730db70fc908dacf3032368fe6d9a0e56ec7b3d46aa94b6dbb1b01c3454b887b850d5f9f1bd5bfb667faf7e7d5b7cad98840878beca3dc99").unwrap());

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

    #[test]
    fn cli_test() {
        let d_bytes = hex::decode("ff20278a665865d8633bd6eee07fa6aab37da0d7c0551020c019bee9b735b5e2d150f09394b54a7af3b387d4f6538b9b1933345a8dfada20d0f4bd2c2605bbb8e8808666933443f37b6b7d95f15d30e8eff9e1e5599c43518c68c506ddf28272677686ecdfb2a756b50e5501b73bef9fb603379c6a016f8b439d201913164cb06cff").unwrap();
        let discriminant = bcs::from_bytes::<Discriminant>(&d_bytes).unwrap();
        let seed = hex::decode("abcd").unwrap();
        let input =
            QuadraticForm::hash_to_group_with_default_parameters(&seed, &discriminant).unwrap();
        // 01107347ea73ddaadbd6eaa83c812752a91bf8927b276a36088796142a6f9b20d2320b1ae8e7327c9e88256911ecf9866f7d8777aa9d8092124f59ddd42716010000ff1d8785c669b57983d0e646adf9312981dbc191395321809d60351585876da0f4259e97d61a4659c2801c8c1ec0dd20a67fe69782b81917e787a212f22d0a4b71f6c1ff41cd303a5d084d244c12b026e3a195826cd99a08377b6a121687d7372fec7c741dd4197bcae5139a87233058d619e5460a00012a529137ff7e92f0d9eeedb39007b17a0b0a8eb20fae8650a6609016287de91f286c8f058f63fc7779b8897a7ff42a9b5e83ed8bf1f18d95caec65d4921b24959732443b14cb3b8c77e46cc8279a44f1a1330711acbe72821f8e3390b708935d18fce7a9afbaf3a796a50cb567e7b7ec619af2bb71eeab31750e26e9509412e153a3e80f52e068b90b9c33ada6d31119d71b61e0bb535b4337b46e5b45f4893296252615ea66fc4c18
        println!("Input: {:?}", hex::encode(bcs::to_bytes(&input).unwrap()));
        let (output, proof) = DefaultVDF::new(discriminant.clone(), 1000)
            .evaluate(&input)
            .unwrap();
        println!("Input: {:?}", hex::encode(bcs::to_bytes(&output).unwrap()));
        println!("Input: {:?}", hex::encode(bcs::to_bytes(&proof).unwrap()));
    }
}
