// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::{Shl, Shr};

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::crt::solve_congruence_equation_system;
use crate::math::hash_prime::is_probable_prime;
use crate::math::jacobi;
use crate::math::modular_sqrt::modular_square_root;

/// The security parameter for the hash function in bits. The image will be at least
/// 2^{2*SECURITY_PARAMETER} large to ensure that the hash function is collision resistant.
const SECURITY_PARAMETER_IN_BITS: u64 = 128;

/// This lower limit ensures that the default, secure parameters set below give valid results,
/// namely a reduced quadratic form.
const MINIMAL_DISCRIMINANT_SIZE: u64 = 600;

/// The image size of the hash function will be "Number of primes of size at most
/// DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES" * DEFAULT_PRIME_FACTORS, so these have been set such that
/// the image is ~260 bits. See [n_bit_primes] for the details of this computation.
const DEFAULT_PRIME_FACTORS: u64 = 2;

/// The default size of the prime factors should be set such that it is not possible for an
/// adversary to precompute the VDF on all quadratic forms with the first coordinate being the
/// primes of this size. This is an issue because if an adversary can precompute (a1, _, _)^T and
/// (a2, _, _)^T then it is possible to compute (a1*a2, _, _)^T as the composition (a1, _, _)^T *
/// (a2, _, _)^T.
const DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES: u64 = 17;

impl QuadraticForm {
    /// Generate a random quadratic form from a seed with the given discriminant. This method is
    /// deterministic, and it is a random oracle on a large subset of the class group.
    ///
    /// This method returns an [InvalidInput] error if the discriminant is so small that there are
    /// no secure parameters, and it may also happen if the discriminant is not a prime.
    pub fn hash_to_group_with_default_parameters(
        seed: &[u8],
        discriminant: &Discriminant,
    ) -> FastCryptoResult<Self> {
        if discriminant.bits() <= MINIMAL_DISCRIMINANT_SIZE {
            return Err(InvalidInput);
        }
        hash_to_group_with_custom_parameters(
            seed,
            discriminant,
            DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES,
            DEFAULT_PRIME_FACTORS,
        )
    }
}

/// Generate a random quadratic form from a seed with the given discriminant and custom parameters.
///
/// The output will be a uniformly random element from the set of points (a,b,c) where a = p_1 ... p_k
/// for some primes p_i < 2^lambda.
///
/// If the discriminant is not a negative prime, an [InvalidInput] error may be returned.
///
/// The parameters must be chosen carefully to ensure that the function is secure and for all
/// use cases, [hash_to_group] should be used.
fn hash_to_group_with_custom_parameters(
    seed: &[u8],
    discriminant: &Discriminant,
    prime_factor_size_in_bytes: u64,
    prime_factors: u64,
) -> FastCryptoResult<QuadraticForm> {
    // Ensure that the image is sufficiently large
    debug_assert!(
        prime_factors as f64 * n_bit_primes(prime_factor_size_in_bytes * 8)
            >= 2.0 * SECURITY_PARAMETER_IN_BITS as f64
    );

    // Ensure that the prime factors are so large that the corresponding quadratic form cannot be precomputed.
    debug_assert!(
        n_bit_primes(prime_factor_size_in_bytes * 8) >= SECURITY_PARAMETER_IN_BITS as f64
    );

    // Ensure that the result will be reduced
    debug_assert!(
        discriminant.as_bigint().abs().sqrt().shr(1)
            > BigInt::one().shl(prime_factors * prime_factor_size_in_bytes)
    );

    // Sample a and b such that a < sqrt(|discriminant|)/2 has exactly prime_factors prime factors and b is the square root of the discriminant modulo a.
    let (a, mut b) = sample_modulus(
        seed,
        discriminant,
        prime_factor_size_in_bytes,
        prime_factors,
    )?;

    // b must be odd but may be negative
    if b.is_even() {
        b -= &a;
    }

    QuadraticForm::from_a_b_and_discriminant(a, b, discriminant)
}

/// Sample a product of `prime_factors` primes each of size `prime_factor_size_in_bytes` and return
/// this along with the square root of the discriminant modulo `a`. If the discriminant is not a
/// prime, an [InvalidInput] error may be returned.
fn sample_modulus(
    seed: &[u8],
    discriminant: &Discriminant,
    prime_factor_size_in_bytes: u64,
    prime_factors: u64,
) -> FastCryptoResult<(BigInt, BigInt)> {
    // Seed a rng with the hash of the seed
    let mut rng = ChaCha8Rng::from_seed(Sha256::digest(seed).digest);
    let mut factors = Vec::with_capacity(prime_factors as usize);
    let mut square_roots = Vec::with_capacity(prime_factors as usize);

    for _ in 0..prime_factors {
        let mut factor;
        loop {
            factor = sample_odd_number(prime_factor_size_in_bytes, &mut rng);

            if factors.contains(&factor) {
                continue;
            }

            // The primality check does not try divisions with small primes, so we do it here. This speeds up
            // the algorithm significantly.
            if PRIMES.iter().any(|p| factor.is_multiple_of(p)) {
                continue;
            }

            if jacobi::jacobi(discriminant.as_bigint(), &factor)
                .expect("factor is odd and positive")
                == 1
                && is_probable_prime(factor.magnitude())
            {
                // Found a valid factor
                break;
            }
        }
        // This only fails if the discriminant is not prime.
        let square_root = modular_square_root(discriminant.as_bigint(), &factor, false)
            .map_err(|_| InvalidInput)?;
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root = solve_congruence_equation_system(&square_roots, &factors)
        .expect("The factors are distinct primes");

    Ok((result, square_root))
}

/// Returns an approximation of the log2 of the number of primes smaller than 2^n.
fn n_bit_primes(n: u64) -> f64 {
    // The Prime Number Theorem states that the number of primes smaller than n is close to n / ln(n),
    // so the number of primes smaller than 2^n is approximately:
    //
    // log2(2^n / ln 2^n) = n - log2(ln 2^n)
    //                    = n - log2(n ln 2)
    //                    = n - log2(n) - log2(ln 2)
    n as f64 - (n as f64).log2() - 2f64.ln().log2()
}

/// Sample a random odd number smaller than 2^{8*size_in_bytes}.
fn sample_odd_number<R: Rng>(size_in_bytes: u64, rng: &mut R) -> BigInt {
    let mut bytes = vec![0u8; size_in_bytes as usize];
    rng.fill_bytes(&mut bytes);
    bytes[0] |= 1;
    BigInt::from_bytes_le(Sign::Plus, &bytes)
}

lazy_static! {
    /// The odd primes smaller than 100.
    pub static ref PRIMES: Vec<BigInt> = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97,
    ]
    .into_iter()
    .map(BigInt::from)
    .collect();
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use num_traits::Num;
    use rand::thread_rng;
    use rand::RngCore;

    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::hash::hash_to_group_with_custom_parameters;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::ParameterizedGroupElement;

    #[test]
    fn test_qf_from_seed() {
        let mut seed = [0u8; 32];
        let discriminant = Discriminant::from_seed(&seed, 1024).unwrap();

        for _ in 0..10 {
            let qf = hash_to_group_with_custom_parameters(&seed, &discriminant, 17, 2).unwrap();
            assert!(qf.is_reduced_assuming_normal());
            assert!(qf.is_in_group(&discriminant));
            seed[0] += 1;
        }

        for _ in 0..10 {
            let qf = hash_to_group_with_custom_parameters(&seed, &discriminant, 17, 4).unwrap();
            assert!(qf.is_reduced_assuming_normal());
            assert!(qf.is_in_group(&discriminant));
            seed[0] += 1;
        }
    }

    #[test]
    fn qf_from_seed_sanity_tests() {
        let discriminant = Discriminant::from_seed(b"discriminant seed", 800).unwrap();
        let base_qf =
            hash_to_group_with_custom_parameters(b"qf seed", &discriminant, 17, 3).unwrap();
        assert!(base_qf.is_in_group(&discriminant));

        // Same seed, same discriminant, same k
        let other_qf =
            hash_to_group_with_custom_parameters(b"qf seed", &discriminant, 17, 3).unwrap();
        assert_eq!(base_qf, other_qf);

        // Smaller k
        let other_qf =
            hash_to_group_with_custom_parameters(b"qf seed", &discriminant, 17, 2).unwrap();
        assert_ne!(base_qf, other_qf);

        // Larger k
        let other_qf =
            hash_to_group_with_custom_parameters(b"qf seed", &discriminant, 17, 4).unwrap();
        assert_ne!(base_qf, other_qf);

        let mut seed = [0u8; 32];
        for _ in 0..10 {
            // Different seed
            thread_rng().fill_bytes(&mut seed);
            let other_qf =
                hash_to_group_with_custom_parameters(&seed, &discriminant, 17, 3).unwrap();
            assert_ne!(base_qf, other_qf);
        }

        let other_discriminant = Discriminant::from_seed(b"other discriminant seed", 800).unwrap();

        // Same seed, same k, other discriminant
        let other_qf =
            hash_to_group_with_custom_parameters(b"qf seed", &other_discriminant, 17, 2).unwrap();
        assert_ne!(base_qf, other_qf);
    }

    #[test]
    fn qf_from_seed_regression_tests() {
        let discriminant = Discriminant::from_trusted_bigint(-BigInt::from_str_radix("c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7", 16).unwrap());

        let qf = hash_to_group_with_custom_parameters(b"seed", &discriminant, 34, 1).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("2272124e6ab4f8d7ba031217017485e79421d4e56fff43d5aa632a78bf4ffe68a6984922402d5f3fe5d21fd017b87a9409bda5f16fb6349a59bc0ba959f826c2f8f951ae89bf8a026db023918de8bc9b3a76b6572536c19e22ea0f870272dde155bca2f31da8d353ff782736a57a2218393e89e0be6cf6a97e144ef4e6c766a5f8afe506cea47083f70a49ad38dd95cab912f54729ab5ba1bee583ac4b642884df802d41492d13e4c898a63fe120c84ebae686cb1760895f0ffadf3cd46cbf54e4d3998cd0a68b40eb0ffa03df792f8f23b47499c143e6a72c5af9f2f6e626b362c85f7f045d351124dcd7cbdf210fd206c6ad05a502680b093579bbd29c5ef81bc92f90ac34c28292375dd6ed79d272530e22e201ce893304c551b85651a97185e5b8e0433e3bb4583c2bd74eecee64021d59b846b9a55e8dea1888a5d8560e5cc54b58a52e35bac5525e76f8257c2bcaa6").unwrap());

        let qf = hash_to_group_with_custom_parameters(b"seed", &discriminant, 17, 2).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("2300a0f9131173334d92c14bbc1d83d411168de882cb1e387b48a5194006c58632e9a9c33269cc033517c7d6b299377c647ba53aded9e27341dd4b941716b9e5191144864791c162fd9e52c5572ff85beae15ebdd9a2ab8a024dbaa59598e97587ae8ecb848611552c21b4a7a32ee1a69dc968dbc37b67774712a9ca92d630113853952ec9d55c737738c59bfcd452ab7f45d1c8df8ce405f55de4392d85d96428a8f1b547b44a11a2b418f5b4ccbd5385723fd34e60a7e3a4b8ac812addf27ace931c3450f989eae8c382e1f9181914e96a35902e6ef5fe972b7d0a1562d7274a68256de34a228c5260df099baa42a13cc011713dd246f149cb085b5002701e95c1a9c7b61467aefab791d9793bfed8c3ebfb251fe0d8f578b165d79b2cb8109cd6b62f84405f659668b9580fffd6f7631f66079ec18846a9e9feb75c128e318914ff93fcb24152ba7c655131af3a75832b37a5024c8095a13faadd23723b90c586ec").unwrap());

        let qf = hash_to_group_with_custom_parameters(b"seed", &discriminant, 68, 1).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("445bb192c1106b9b7dd9789cb0882c652db9b2d32ee59feb059ffaa8ff392d38b5878e79503bbea893624e847ebe0da2c38606620fc157d00cbb911a634d6c510665b8edff4408b2d1f92ee84acd0d43fead1d7fe8cb353e47b280480e432a8d0327d3059d6f213c30cc87e79f22e1325136c9fbeb76347e9ad989925045f373675c9bb580b2daf03529e9010088751b17498f404f0fa45456e75f49240bdca7b5d587376406ac2c674c4be7a89ef96616e79a1275f980cb6f1622b44657dc26799cfa0eb50e755a04296701a5904251de540ec26246d6571f17b9bc6ecdecc40f66e99fd0a5cf088f73fae967cc985640d5d627a23997d2928c74e888a9aeae55a6e89932e534ffe1d0ba56817c7e0c20ae3379df01b055d8f03085cabbf5608309924bc754d23bd3141766d47c07cdcd93842fe4fb03ea15e23dfbeebc15393c41556d36bd1d3093701e8c7b91e10b7c70d39970091dd6bfefe034faacdb3a8158ce33711d5483d8b91793438d46b9dcd7eaf9a6").unwrap());

        let qf = hash_to_group_with_custom_parameters(b"seed", &discriminant, 34, 2).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("44377b7cf8cb36c4bc0742ffeaf3816b6798bf915b9c8c584a77d65e30973863e43a5af5a252a7ff7615d2d889c026daf82a92833b5becd99ad2d250e5eb91b4ae1f98803d66fec045495392669db030e29e8c58c4bdbd98c27360e9f003ecfee16dfdacbc1c81805bb5a82aba9203483016dd141fd0c18abf1f88cc9116480d9444da2feecbfb0685051b844cfda19fa0d6967a2571ac626a2c1185ca83bc9c854a610595f665753f246cffe90100e184a2ed6c29954f1f43a0f97e961e8ff8d6965d32ad8f76171ba3e756de8795f97606445fa7d7ccaa542056e6216cc54c28396909e0fa6416e8ff2b104ca28e8d372e07834605ca99a394e6a6c19b310786157e7a0e9142edf919022303d6a1399d6bb1c181746be656b66bfded01ed4113cfd9df14ad97117c9700919d9e2aaa2fee589c414307bfefba619daaf654dfa418fb1c088b88574cc6abb344b0715f488782fbd64c6cccf7956b9e7ce9898325ee46fdd2f565609317dce1a74983343355d23f31dd28801e6322c01edcf41508fcf9c001f9702b6ef237d69f183af99436a9f86a07ee").unwrap());

        let qf = hash_to_group_with_custom_parameters(b"seed", &discriminant, 17, 4).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("44658cdcc513982dd4e5446a7d41aebce6f8cbd523475b4d1a8547b8b43434fa9eca9b9032844356752b4f4032bfb6b102ee7e0c20b98041414870180baa248f3f596df2df6601c8abfbef53cc4c19cecb3476845f3ebecbb375b652fadf21092ab5324bb1d788285bf6387cc0465333cc303757ef041eb116af12e5df3def1a72d562f58416c566df63456539e57febed5929d96631b8c8ddda294009c5bea70870ed0546d0ea1a67c0e9ffe8017b36740e2ae3f722074cec6cb13f33c47c144dff7ee118dbb07bd3415c91c1295a123724f24fe2bdb5c0565dd90395901d6776407b25f5fe773c54b9e0cb30500718f790d62de3b04de64cbde739d9c2572d0d155971b49e9de123b5d6a3d9f9bcfaefe1954d62302780f800c0a28ae84f2ea717194d649dae838d49454735ef3198c467dc65a81cb39d7c85ae31587df9abb985519d87065267ba1dd93384f8ec27251c8f06bd973ae284bdbb4251fc47ff928a67ac1eb40dc9182c83d0deeb9f9f455311b3b95e6c40bc60be82aa82885db585200e0fc8f0142b426db1cf45fb95f3919279a78a").unwrap());
    }

    #[test]
    fn qf_default_hash_test() {
        let discriminant = Discriminant::from_trusted_bigint(-BigInt::from_str_radix("c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7", 16).unwrap());

        let qf =
            QuadraticForm::hash_to_group_with_default_parameters(b"seed", &discriminant).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("2300a0f9131173334d92c14bbc1d83d411168de882cb1e387b48a5194006c58632e9a9c33269cc033517c7d6b299377c647ba53aded9e27341dd4b941716b9e5191144864791c162fd9e52c5572ff85beae15ebdd9a2ab8a024dbaa59598e97587ae8ecb848611552c21b4a7a32ee1a69dc968dbc37b67774712a9ca92d630113853952ec9d55c737738c59bfcd452ab7f45d1c8df8ce405f55de4392d85d96428a8f1b547b44a11a2b418f5b4ccbd5385723fd34e60a7e3a4b8ac812addf27ace931c3450f989eae8c382e1f9181914e96a35902e6ef5fe972b7d0a1562d7274a68256de34a228c5260df099baa42a13cc011713dd246f149cb085b5002701e95c1a9c7b61467aefab791d9793bfed8c3ebfb251fe0d8f578b165d79b2cb8109cd6b62f84405f659668b9580fffd6f7631f66079ec18846a9e9feb75c128e318914ff93fcb24152ba7c655131af3a75832b37a5024c8095a13faadd23723b90c586ec").unwrap());
    }
}
