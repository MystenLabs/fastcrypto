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
        let mut proof = G::zero(&self.group_parameter);
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
