// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;
use std::ops::ShlAssign;

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use num_bigint::BigUint;
use num_integer::Integer;

use crate::class_group::QuadraticForm;
use crate::math::hash_prime::hash_prime;
use crate::math::parameterized_group::ParameterizedGroupElement;
use crate::vdf::VDF;

/// Default size in bytes of the Fiat-Shamir challenge used in proving and verification.
///
/// From Wesolowski (2018), "Efficient verifiable delay functions" (https://eprint.iacr.org/2018/623),
/// we get that the challenge must be a random prime among the first 2^{2k} primes where k is the
/// security parameter in bits. Setting k = 128, and recalling that the prime number theorem states
/// that the n-th prime number is approximately n * ln(n), we can estimate the number of bits required
/// to represent the n-th prime as log2(n * ln(n)). For n = 2^{2*128}, this is approximately 264 bits
/// = 33 bytes. This is also the challenge size used by chiavdf.
pub const DEFAULT_CHALLENGE_SIZE_IN_BYTES: usize = 33;

/// An implementation of Wesolowski's VDF construction (https://eprint.iacr.org/2018/623) over a
/// group of unknown order.
pub struct WesolowskisVDF<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>> {
    group_parameter: G::ParameterType,
    iterations: u64,
    challenge: fn(&Self, &G, &G) -> BigUint,
    _scalar_multiplier: PhantomData<M>,
}

impl<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>> WesolowskisVDF<G, M> {
    /// Create a new VDF using the group defined by the given group parameter. Evaluating this VDF
    /// will require computing `2^iterations * input` which requires `iterations` group operations.
    pub fn new(group_parameter: G::ParameterType, iterations: u64) -> Self {
        Self {
            group_parameter,
            iterations,
            challenge: compute_challenge,
            _scalar_multiplier: PhantomData::<M>,
        }
    }

    /// Create a new VDF with a custom challenge function. This is useful for testing.
    #[cfg(test)]
    fn new_with_custom_challenge(
        group_parameter: G::ParameterType,
        iterations: u64,
        challenge: fn(&Self, &G, &G) -> BigUint,
    ) -> Self {
        Self {
            group_parameter,
            iterations,
            challenge,
            _scalar_multiplier: PhantomData::<M>,
        }
    }
}

impl<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>> VDF for WesolowskisVDF<G, M> {
    type InputType = G;
    type OutputType = G;
    type ProofType = G;

    fn evaluate(&self, input: &G) -> FastCryptoResult<(G, G)> {
        if !input.is_in_group(&self.group_parameter) || self.iterations == 0 {
            return Err(InvalidInput);
        }

        // Compute output = 2^iterations * input
        let output = input.clone().repeated_doubling(self.iterations);

        let multiplier = M::new(input.clone(), G::zero(&self.group_parameter));

        // Algorithm from page 3 on https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
        let challenge = (self.challenge)(self, input, &output);
        let mut quotient_remainder = (BigUint::from(0u8), BigUint::from(2u8));
        let mut proof = multiplier.mul(&quotient_remainder.0);
        for _ in 1..self.iterations {
            quotient_remainder.1.shl_assign(1);
            quotient_remainder = quotient_remainder.1.div_mod_floor(&challenge);
            proof = proof.double() + &multiplier.mul(&quotient_remainder.0);
        }

        Ok((output, proof))
    }

    fn verify(&self, input: &G, output: &G, proof: &G) -> FastCryptoResult<()> {
        if !input.is_in_group(&self.group_parameter)
            || !output.is_in_group(&self.group_parameter)
            || !proof.is_in_group(&self.group_parameter)
        {
            return Err(InvalidInput);
        }

        let challenge = (self.challenge)(self, input, output);
        let r = BigUint::modpow(
            &BigUint::from(2u8),
            &BigUint::from(self.iterations),
            &challenge,
        );
        let multiplier = M::new(input.clone(), G::zero(&self.group_parameter));

        if multiplier.two_scalar_mul(&r, proof, &challenge) != *output {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

/// Implementation of Wesolowski's VDF construction over an imaginary class group using a strong
/// Fiat-Shamir implementation.
pub type DefaultVDF =
    WesolowskisVDF<QuadraticForm, WindowedScalarMultiplier<QuadraticForm, BigUint, 256, 5>>;

fn compute_challenge<G: ParameterizedGroupElement, M: ScalarMultiplier<G, BigUint>>(
    vdf: &WesolowskisVDF<G, M>,
    input: &G,
    output: &G,
) -> BigUint {
    let seed = bcs::to_bytes(&(input, output, vdf.iterations, &vdf.group_parameter))
        .expect("Failed to serialize Fiat-Shamir input");
    hash_prime(
        &seed,
        DEFAULT_CHALLENGE_SIZE_IN_BYTES,
        &[0, 8 * DEFAULT_CHALLENGE_SIZE_IN_BYTES - 1],
    )
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::{Discriminant, DISCRIMINANT_3072};
    use crate::class_group::QuadraticForm;
    use crate::vdf::wesolowski::{DefaultVDF, WesolowskisVDF};
    use crate::vdf::VDF;
    use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
    use fastcrypto::hash::{HashFunction, Sha256};
    use num_bigint::{BigInt, BigUint};
    use num_traits::Num;
    use std::str::FromStr;

    #[test]
    fn test_prove_and_verify() {
        let challenge = hex::decode("99c9e5e3a4449a4b4e15").unwrap();
        let iterations = 1000u64;
        let discriminant = Discriminant::from_seed(&challenge, 512).unwrap();

        let input = QuadraticForm::generator(&discriminant);

        let vdf = DefaultVDF::new(discriminant.clone(), iterations);
        let (output, proof) = vdf.evaluate(&input).unwrap();

        // Regression tests
        assert_eq!(bcs::to_bytes(&output).unwrap(), hex::decode("2024ff799e22587cc344b83ace4ce2d814d52aba7dd711591fd407e31a55822a1e20051fa84e09b4bd5a6ee02b6fae24db625863ae31cfaf962f2f490d92dd372e3f2101714cc516048bd26c8788ead8318dcaa0c3fe615ece8164cf56a4bdea90c8fc6f").unwrap());
        assert_eq!(bcs::to_bytes(&proof).unwrap(), hex::decode("2051242499ff4467ba4d9bd858d6609b3a29736a80e09aa3edc6fa4ca49292daae20c066a1b52a8c5a0ff230224fc403dec11ee156e523f22b78ab8abc9706ae38c52100b4c56b5d7815425677bbe0ddc924d6277a237e4c5317b10a1a36039148d1d19c").unwrap());

        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // A modified output or proof fails to verify
        let modified_output = &output + &QuadraticForm::generator(&discriminant);
        let modified_proof = &proof + &QuadraticForm::generator(&discriminant);
        assert!(vdf.verify(&input, &modified_output, &proof).is_err());
        assert!(vdf.verify(&input, &output, &modified_proof).is_err());
    }

    #[test]
    fn chia_test_vector() {
        // Test vector from challenge_chain_sp_vdf in block 0 on chiavdf (https://chia.tt/info/block/0xd780d22c7a87c9e01d98b49a0910f6701c3b95015741316b3fda042e5d7b81d2)
        let challenge_hex = "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb";

        let expected_discriminant = Discriminant::try_from(BigInt::from_str("-178333777053301117117702583998161755803539768255026550238546398959430362085160891839143870686333959898768973627501543050673299722162920809872631876535963079708632677960753403482168047846781718043417502562521413075070055588055373173898058979019814085260390558743330450388913014891726165953277341036916349194527").unwrap()).unwrap();
        let discriminant =
            Discriminant::from_seed(&hex::decode(challenge_hex).unwrap(), 1024).unwrap();
        assert_eq!(expected_discriminant, discriminant);

        let iterations = 4194304u64;
        let input = QuadraticForm::generator(&discriminant);

        // Expected output and proof
        let output = QuadraticForm::from_a_b_and_discriminant(
            BigInt::from_str("5229738340597739241737971536347978272715235210410923937567237618049037412166200077244995787131087550307523694727956250097277310766933336068474825405652036").unwrap(),
            BigInt::from_str("-3096696303705675681560871524238217371290270541873900921742966946679899781296678313618277916864547545067742976652559823874869615853670880196986766000673113").unwrap(),
            &discriminant,
        ).unwrap();

        let proof = QuadraticForm::from_a_b_and_discriminant(
            BigInt::from_str("269045224950172139388701381657611623403690061497324483767769709486526106374289433207532765507632104438556574675400375880648266212459081029470628330651968").unwrap(),
            BigInt::from_str("-138011067542034487860643678409953738631107554007673747141459530097427412192013567645959803101754265070201162396361305697197871510988607320533641929367439").unwrap(),
            &discriminant,
        ).unwrap();

        let vdf = WesolowskisVDF::<
            QuadraticForm,
            WindowedScalarMultiplier<QuadraticForm, BigUint, 256, 5>,
        >::new_with_custom_challenge(
            discriminant.clone(),
            iterations,
            |_, _, _| {
                // Hard-coded challenge
                BigUint::from_str_radix(
                    "a8d8728e9942a994a3a1aa3d2fa21549aa1a7b37d3c315c6e705bda590689c640f",
                    16,
                )
                .unwrap()
            },
        );

        assert!(vdf.verify(&input, &output, &proof).is_ok());
    }

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
        let input = QuadraticForm::hash_to_group(&combined_randomness, &DISCRIMINANT_3072).unwrap();
        assert_eq!(bcs::to_bytes(&input).unwrap(), hex::decode("bc01009ed67199c633da0faa75a8ed0ff5c3ae7c278c79aad85953cdf86d57101b1ee941e5239b7d614e5b16eac269c460f16d57a12c75b52c48fac643a1c4918fab86805fe08fcd6b38093a17143cca7550fd018b8bc6871fb441b406bec7a7f3a61c3b2a5aa9daca5f9a6fa474b270688de643323de1acc8073a3418bc1681a614c1abb5fa56b61a7d6df4260547c9f613c5f0dbd7cb91a478ac94b1cce6b1f4784dc161ec3c85bf02cf99fd460b0b25a44d1990dacd1fe7a43b797611ea0210645fef3905f7e1accf97bd3b868a8a99d4a1a546e5a55e20f343fc2724829f1770591b50a73c93ec9b8c01ce1fa6b84eddd5a7ddd077110e21b8e058bf2fed2592a5449db177ec0e32595b20bda5779c2f346b01df8c0d277d9d3a7fe0a04e67b210be60334efdadb7abc5ac001b71509c2d487d9d26443527c1b8b02dfcffc50ef98020f569cdf6fffca5870b0e502493fceee35b79eed99e2c758a0aff4c86b2af0dd223e270ecf84eb7405fe35a9e37d6b080efa3c59806c2ceffa82f38502f9d37b6c298cf07534347cd9ee436406784bd7e0a57d380dd3923ddca13d86f3b2c83a135f125f9429a6802247a0e926b54144d74e4e8f66f0303cdc91843ce7e1fb9c6276c000512c0709c7fbfde2b80e66db77222447ef6b4da4a698e011c6de95ad88738aea465c158288a54223c7f7152577cc48691af57e2631e3224b7c94e2a4c5034db35bbf9e807753fa51da8798bf63b7e6ebd857ca4cf01fcab7a33e63fa89eb386e2ef98046c44491bdf8d62ede2af4ab79ccac88e404abb649b92f49c9f9abcf2216bb628e96400a75a66c12b6ff1c6dae498dd4183ad989921ebc6a1be73127741333671eb72cd25eabc69fecc3c50da06b4a3af155264d4e39e8c681b8c5555d4cab748ed15d119527820e01854fa203c2deba3a67620d47733919e8c71d659e60e86db69905ebdc4dbeda67f77291c2202b2116a05f227f963a97eb8c87104b2df349f01f251aa22bbd41541998ce755309b98d9597d7ee26b6acaef1869885c775e6ceb710c36c07e401e17a8ccb838e33f64e43e4db3491b5cef6e800c4e494610ab81a8b489263b86976160d7d0106cab79bf2a2fce5b01e8f9d1fb069a98e814c94f10d9917b7ea27209bc822b35741f56a9aeadb75a7eae6a8cbd7df08e079db64fd48655f42c24c14bb6c72e744206a3e15deee45cab74d589deb1055e0e69fe508a2ef356dc4e2caaaf89f44a520722490374eade8573429d0d6d16e3c681853f96759cc6e3ea3aaad55284282abd40686281ff944c6a507086143cf76d0f7f93b486d552fa4698656cff8a325fea84943333645b29ee11c99555b2076a09466f6e602db663e1bd45c523a12a7fcd2328d5139d14b25561b94f62f69d436c5d4c92b01ae3a91baa1b5781bd0bf2156e1d0042ab2cbc6e10f4389868fc41d05b19bfe3dfcaacb0478b3dce887da8435c9d49f457fd54e129133e5ce87c39acb9206213daec867fca35e6b612c523fb9fba959542a777ea74").unwrap());

        // Compute the output of the VDF
        let (output, proof) = vdf.evaluate(&input).unwrap();
        assert_eq!(bcs::to_bytes(&output).unwrap(), hex::decode("c001503be6eff558a40ba145da5aa9d1270367f32cde44c1601846cdd3d0911abce8ab6adb6b82682b45107545e9ae1efca44dd6f3ba8d95a687652b94f479f6b1a37156c44194d6bc5f266098b75251b12de6fa67de6aea14250c0481694db5f24db5e3c89da3354aafc10c4bd0371f9a175d1b5b193190c4c1089ed7a95dc07f1ce29021b55f3aaa7eb65725d61277f0996b783c005a919ba121d81f211f63d188ac525056235504fe4858765dc6498362d98e8540287a0ff78424c18de53abe46c0014f847bd49f599960fe3c3b7cfc571cd854c7d21b0e9984070f7e168c872a6e6480d8fd37d30602f57a237b83ae961e6a4acb94b78c32d04f06058bda037d6ad313c81f823db25c53c265b02a29008f727f95010c82b0cf8745e77a7f4000dac929ba83a4594482b4e6ff59c93a78df5c816f244914329c145e288fd3fd4800a1cc2df23f386112e569608e6de40ee65fe870960b4e3fee4bb188d8db0dd5df3c2384eb24a797eb20cf8524d563663ccde866a405e2713cfafdb760e50c77a797c10100a31fc5ca0a91aa788d5f5df17a1433f1a0e6e4da440ce935b1b48dc6868c8fc00d7ee725ce21797a6c4440af02570466081479e99eee1a5b509a3e1ac2e000ed386c35d9fadd130df2a292fa5f9aa2c195c48c9d11e58ac98c8dbd2169721ed2d2c9f5544de17deeaa9655360ed7baa46820f5e008af1e3f028d819dee3fee50ab55b266385dfc8f65f7f0c1b6149e5295bfefb83b14db3a30b2cefd1495ba4e5ae39d2b729f9644fc28764d03243fad3e61145ed83cbf2708b60c0b7cac7148").unwrap());
        assert_eq!(bcs::to_bytes(&proof).unwrap(), hex::decode("0101010180032cf35709e1301d02b40a0dbe3dadfe6ec1eeba8fb8060a1decd0c7a126ea3f27fadcad81435601b0e0abca5c89173ef639e5a88043aa29801e6799e430b509e479b57af981f9ddd48d3a8d5919f99258081557a08270bb441233c78030a01e03ec199b5e3eef5ccc9b1a3d4841cbe4ff529c22a8cd1b1b0075338d864e3890942df6b007d2c3e3a8ef1ce7490c6bbec5372adfcbf8704a1ffc9a69db8d9cdc54762f019036e450e457325eef74b794f3f16ff327d68079a5b9de49163d7323937374f8a785a8f9afe84d6a71b336e4de00f239ee3af1d7604a3985e610e1603bd0e1a4998e19fa0c8920ffd8d61b0a87eeee50ac7c03ff7c4708a34f3bc92fd0103758c954ee34032cee2c78ad8cdc79a35dbc810196b7bf6833e1c45c83b09c0d1b78bc6f8753e10770e7045b08d50b4aa16a75b27a096d5ec1331f1fd0a44e95a8737c20240c90307b5497d3470393c2a00da0649e86d13e820591296c644fc1eef9e7c6ca4967c5e19df3153cd7fbd598c271e11c10397349ddc8cc8452ec").unwrap());

        // Verify the output and proof
        assert!(vdf.verify(&input, &output, &proof).is_ok());

        // Derive randomness from the output
        let randomness = Sha256::digest(bcs::to_bytes(&output).unwrap());
        let expected =
            hex::decode("f9ea418d988bbe5b13839bb5958aa78d43cc9f57b3dc9d84cebc7c1f5b1a338e")
                .unwrap();
        assert_eq!(randomness.to_vec(), expected);
    }
}
