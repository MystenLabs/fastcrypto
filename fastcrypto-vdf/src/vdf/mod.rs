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
    use fastcrypto::hash::{HashFunction, Sha256};

    use crate::class_group::discriminant::DISCRIMINANT_3072;
    use crate::class_group::QuadraticForm;
    use crate::vdf::wesolowski::DefaultVDF;
    use crate::vdf::VDF;

    #[test]
    fn vdf_e2e_test() {
        // This test runs an e2e test of the VDF-based randomness protocol with a 3072 bit discriminant.
        // Number of iterations for the VDF
        let iterations = 100;
        let vdf = DefaultVDF::new(DISCRIMINANT_3072.clone(), iterations);

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
            &DISCRIMINANT_3072,
        )
        .unwrap();
        assert_eq!(bcs::to_bytes(&input).unwrap(), hex::decode("2300b094d4facc4b552df23714f5d09a6ddfde4f0d06163b7fda1fc022ebafa5be196f4d33fc3bce80649d3e64cb6d1497bf65f6b40ffcf5ca3211889b994019cf4dfa8697b0f69a70c5ee14ef438cf0e50b2f93786f506fde02412ad75a441ab785dbe34ce00cb829962e4216f964fb8c53852cc86e0977428322ef7d505e10c37260a9ebeb0cc66ddb59901556bc4a6fa9bc0f9d8159c3319f3a2e1781912000917a12054126a728b46dc6849cda81648e0f34200824a050fd1e01382bf4cfa17019ae2f6f48cfbe6e4ef84e1b00361ed6a4892e4b5db94e8847e0c7050637d668c5cbef08fc60fde9b5d68a02af4c5ed7f7ba99f3b68eb59fa2ea8a282b705124ec5577f166130a0c043823ea1a3fd495643dfbe8d294a9f034d91f8c8e76689a676ebe1ded776bdf7fd1e4050a84b8cead2e6adcd0ae7d12a6e221cb6579eb54911d3ce9739048924f3451c07b203ab811a9506d4d134b335eab6e84c49983f405f3d5b2040c522922e501086c19db5a82a4c7134a7cad5738bc884b382e4b3cfca0521a0e7eacd0d053855dcbb6fa897f122cc2b49df60d4d3424d37a01764b77b65b5f5472365ae3b82a3cb7f9f7a13d4a6ca100c4").unwrap());

        // Compute the output of the VDF
        let (output, proof) = vdf.evaluate(&input).unwrap();
        assert_eq!(bcs::to_bytes(&output).unwrap(), hex::decode("c001532225cbc82be245b2571c83babcc61ab86234465a7e91e000b14b1a3426cef72a90e5db733523ba5593200c35281b77156eaa978b7ad1c5eac1336ca8e74b1341ae072b9fd620d24ff33590903668ac6d5f53fb6ac32d7c0cd380c790418f68e64505aeb82f40d6e9bcf3642850c440bc458c0465965ce384c7d6d11570d3499e265a38e4e52580e54580fccd28b1dbb9d32a7bca5e59dc9d083c6c6642df20a160da447c78f2695d424984531a1de5a35cd13ba496cf9c0adec749d31d2bbfc001f2d872ba990524a2756e74224f1162bcbceafb2222a2ca19255511f775ceb74a4bc6a36848377201b62b3bc12332781e20097612005d642033866bca926d9242bb2d0a6d305b0e46e9715340b64012271d3fe2c614ab9dca9d2f81a18ba8f49b5b9945fd4b3af743d4c7f2ac0906266ae4c26915bfcbe9ec6a1a17420c442e3cb00422efb70467188e124a56e171004521360f2da80323a2b9d327c43931327a59a711986116333010e743d9ff1c3de811281e5eba84e49c33a78d60e27b065fc101008af0c8fa3fe81a2bbdcdbc3040727f3797121254d48b182ca4a4cd698f0523057b4b223a94253a75842fe823085e8a55b2cb639e4799256f03252ded38eb93a544ca93b89f72c358098b0badedda13de0d3c99c8a33e3b6fa4d894b4031e5400872453086b36cb28d02497c3e2f1e4c6a0b4344b4dc94f4b39481cef8ea05d170f0159f06d7ffcbc99e214d62a1297153a58c41d11dacae5b409b5e6023159897bb773e0a146b7785dc772bc2c61a75aa9b30765027fc1a36bf31113799d2644").unwrap());
        assert_eq!(bcs::to_bytes(&proof).unwrap(), hex::decode("0101010180032cf35709e1301d02b40a0dbe3dadfe6ec1eeba8fb8060a1decd0c7a126ea3f27fadcad81435601b0e0abca5c89173ef639e5a88043aa29801e6799e430b509e479b57af981f9ddd48d3a8d5919f99258081557a08270bb441233c78030a01e03ec199b5e3eef5ccc9b1a3d4841cbe4ff529c22a8cd1b1b0075338d864e3890942df6b007d2c3e3a8ef1ce7490c6bbec5372adfcbf8704a1ffc9a69db8d9cdc54762f019036e450e457325eef74b794f3f16ff327d68079a5b9de49163d7323937374f8a785a8f9afe84d6a71b336e4de00f239ee3af1d7604a3985e610e1603bd0e1a4998e19fa0c8920ffd8d61b0a87eeee50ac7c03ff7c4708a34f3bc92fd0103758c954ee34032cee2c78ad8cdc79a35dbc810196b7bf6833e1c45c83b09c0d1b78bc6f8753e10770e7045b08d50b4aa16a75b27a096d5ec1331f1fd0a44e95a8737c20240c90307b5497d3470393c2a00da0649e86d13e820591296c644fc1eef9e7c6ca4967c5e19df3153cd7fbd598c271e11c10397349ddc8cc8452ec").unwrap());

        // Verify the output and proof
        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // Derive randomness from the output
        let randomness = Sha256::digest(bcs::to_bytes(&output).unwrap());

        let expected =
            hex::decode("edc12df54fdcb9ca51422c52125d617bdf6482f4c4d6d0d1d96063ee3f2a6746")
                .unwrap();
        assert_eq!(randomness.to_vec(), expected);
    }
}
