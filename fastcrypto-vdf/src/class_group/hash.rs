// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::crt::solve_congruence_equation_system;
use crate::math::hash_prime::is_probable_prime;
use crate::math::jacobi;
use crate::math::modular_sqrt::modular_square_root;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;
use num_bigint::{BigInt, UniformBigInt};
use num_integer::Integer;
use num_traits::Signed;
use rand::distributions::uniform::UniformSampler;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::{AddAssign, ShlAssign, Shr};

impl QuadraticForm {
    /// Generate a random quadratic form from a seed with the given discriminant. This method is deterministic and it is
    /// a random oracle on a large subset of the class group, namely the group elements whose `a` coordinate is a
    /// product of `k` primes all smaller than `(sqrt(|discriminant|)/2)^{1/k}`.
    ///
    /// Increasing `k` speeds-up the function (at least up to some break even point), but it also decreases the size of
    /// the range of the hash function, so `k` must be picked no larger than the `k` computed in [largest_allowed_k]. If
    /// it is larger, an [InvalidInput] error is returned. If in doubt, use the [hash_to_group_with_default_parameters]
    /// instead.
    ///
    /// The algorithm is taken from https://eprint.iacr.org/2024/295.pdf.
    pub fn hash_to_group(
        seed: &[u8],
        discriminant: &Discriminant,
        k: u16,
    ) -> FastCryptoResult<Self> {
        // Sample a and b such that a < sqrt(|discriminant|)/2 and b is the square root of the discriminant modulo a.
        let (a, mut b) = sample_modulus(discriminant, seed, k)?;

        // b must be odd but may be negative
        if b.is_even() {
            b -= &a;
        }

        Ok(QuadraticForm::from_a_b_and_discriminant(a, b, discriminant)
            .expect("a and b are constructed such that this never fails"))
    }

    /// Generate a random quadratic form from a seed with the given discriminant. This method is deterministic, and it
    /// is a random oracle on a large subset of the class group. This method picks a default `k` parameter and calls the
    /// [hash_to_group](QuadraticForm::hash_to_group) function with this `k`.
    pub fn hash_to_group_with_default_parameters(
        seed: &[u8],
        discriminant: &Discriminant,
    ) -> FastCryptoResult<Self> {
        let k = get_default_k(discriminant.bits() as usize);
        Self::hash_to_group(seed, discriminant, k)
    }
}

fn get_default_k(discriminant_bits: usize) -> u16 {
    // This is chosen to ensure that the range of the hash function is large (at least 2^256) but also that the
    // performance is near optimal, based on benchmarks.
    if discriminant_bits <= 2048 {
        16
    } else {
        32
    }
}

/// Increasing `k` reduces the range of the hash function for a given discriminant. This function returns a choice of
/// `k` such that the range is at least `2^256`, and chooses this it as large as possible. Consult the paper for
/// details.
fn largest_allowed_k(discriminant: &Discriminant) -> u16 {
    let bits = discriminant.bits();
    let lambda = 256.0;
    let log_b = bits as f64 / 2.0 - 1.0;
    let numerator = log_b - lambda;
    let denominator = (log_b * 2.0_f64.ln()).log2() + 1.0;
    (numerator / denominator).floor() as u16
}

/// Sample a product of `k` primes and return this along with the square root of the discriminant modulo `a`. If `k` is
/// larger than the largest allowed `k` (as computed in [largest_allowed_k]) for the given discriminant, an
/// [InvalidInput] error is returned.
fn sample_modulus(
    discriminant: &Discriminant,
    seed: &[u8],
    k: u16,
) -> FastCryptoResult<(BigInt, BigInt)> {
    // This heuristic bound ensures that the range of the hash function has size at least 2^256.
    if discriminant.bits() < 800 || k > largest_allowed_k(discriminant) {
        return Err(InvalidInput);
    }

    // If a is smaller than this bound and |b| < a, the form is guaranteed to be reduced.
    let mut bound: BigInt = discriminant.as_bigint().abs().sqrt().shr(1);
    if k > 1 {
        bound = bound.nth_root(k as u32);
    }

    // Seed a rng with the hash of the seed
    let mut rng = ChaCha8Rng::from_seed(Sha256::digest(seed).digest);
    let mut factors = Vec::with_capacity(k as usize);
    let mut square_roots = Vec::with_capacity(k as usize);

    for _ in 0..k {
        let mut factor;
        loop {
            factor = sample_odd_number(&bound, &mut rng);

            if factors.contains(&factor) {
                continue;
            }

            // The primality check does not try divisions with small primes, so we do it here. This speeds up the
            // algorithm significantly.
            if !trial_division(&factor, &PRIMES) {
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
        let square_root = modular_square_root(discriminant.as_bigint(), &factor, false)
            .expect("Legendre symbol checked above");
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root = solve_congruence_equation_system(&square_roots, &factors)
        .expect("The factors are distinct primes");

    Ok((result, square_root))
}

/// Sample a random odd number in [1, bound)
fn sample_odd_number<R: Rng>(bound: &BigInt, rng: &mut R) -> BigInt {
    let mut a = UniformBigInt::new(BigInt::from(1), bound.clone().shr(1)).sample(rng);
    a.shl_assign(1);
    a.add_assign(1);
    a
}

/// The odd primes smaller than 100.
const PRIMES: [u64; 24] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// Perform trial division on `n` with the given primes. Returns true if neither of the divisors divide `n`
fn trial_division(n: &BigInt, divisors: &[u64]) -> bool {
    for p in divisors {
        if n.is_multiple_of(&BigInt::from(*p)) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::Parameter;
    use num_bigint::BigInt;
    use num_traits::Num;
    use rand::thread_rng;
    use rand::RngCore;

    #[test]
    fn test_qf_from_seed() {
        let mut seed = [0u8; 32];
        let discriminant = Discriminant::from_seed(&seed, 1024).unwrap();

        for _ in 0..10 {
            let qf = QuadraticForm::hash_to_group(&seed, &discriminant, 1).unwrap();
            assert!(qf.is_reduced_assuming_normal());
            assert_eq!(qf.discriminant(), discriminant);
            seed[0] += 1;
        }

        for _ in 0..10 {
            let qf = QuadraticForm::hash_to_group(&seed, &discriminant, 4).unwrap();
            assert!(qf.is_reduced_assuming_normal());
            assert_eq!(qf.discriminant(), discriminant);
            seed[0] += 1;
        }
    }

    #[test]
    fn qf_from_seed_sanity_tests() {
        let discriminant = Discriminant::from_seed(b"discriminant seed", 800).unwrap();
        let base_qf = QuadraticForm::hash_to_group(b"qf seed", &discriminant, 6).unwrap();
        assert_eq!(base_qf.discriminant(), discriminant);

        // Same seed, same discriminant, same k
        let other_qf = QuadraticForm::hash_to_group(b"qf seed", &discriminant, 6).unwrap();
        assert_eq!(base_qf, other_qf);

        // Smaller k
        let other_qf = QuadraticForm::hash_to_group(b"qf seed", &discriminant, 5).unwrap();
        assert_ne!(base_qf, other_qf);

        // Larger k
        let other_qf = QuadraticForm::hash_to_group(b"qf seed", &discriminant, 7).unwrap();
        assert_ne!(base_qf, other_qf);

        let mut seed = [0u8; 32];
        for _ in 0..10 {
            // Different seed
            thread_rng().fill_bytes(&mut seed);
            let other_qf = QuadraticForm::hash_to_group(&seed, &discriminant, 6).unwrap();
            assert_ne!(base_qf, other_qf);
        }

        let other_discriminant = Discriminant::from_seed(b"other discriminant seed", 800).unwrap();
        // Same seed, same k, other discriminant
        let other_qf = QuadraticForm::hash_to_group(b"qf seed", &other_discriminant, 6).unwrap();
        assert_ne!(base_qf, other_qf);
    }

    #[test]
    fn qf_from_seed_regression_tests() {
        let discriminant = Discriminant::try_from(-BigInt::from_str_radix("c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7", 16).unwrap()).unwrap();

        let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 64).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("8b0104397d87d59220ec1bbbf79f471689ad0a48f67625abed478749b2f110d79990684b782160a7e00288c240160d10da0198298fd68f7e3fa0964975f1816d5bb38c978ea1bc9fb5aaefa62971435de9565801c80e545b497d00783c0d518722311c6fa7e924bff4f4765f6f3c6b3de8dcf1c314e7ea8df998de524af394e5cec7dfc867cf07f7eb501dfc279102ff304620732b3d44d3ceeadbd054e20eb953eed85ac684044b1192c1ccaeb9ba79695b28204e7148e8560e4b782c6b20ea20123bda9061eed1920d7ff1fd9741220ee1fac09f596524a12aa993734f2fa4ccf792d46c3bf8320073def0c938e6fb608b8866f70fc380f1a37f3fd9c52935837f5ff06ef6ab882599460e7b950ab17a75602a0b29523ab99c4d030923244a5a9e0431759c59a33a471641c013dadaebdc711baf3a05320330959f13b88c6619c64201bc10517c0bbc69524e6d3345eaeade453ea1ebe8b4ce41068e321399c41e8a90831f9713aa2df564423dfa2fe36e65ccf8157c9ebd24f4ac545482b1a609b7bce94316af8e53cbe191ba073b312a60831ea1f657a92ded17350710ed960309f9853536dd6c8dc45ed0069b1feb7e4acbc7adcf15252e96d5c35e37afbd5b6c413c8511e8225b0f938ae03225b5f2a856aed3551f424795b08807fdc0e38566acdebd699e4db85cf216e3467e9ca3d6c82cfaf77d8446e612de64b1fd3a5df8c5a982df1470daf56f3a15787b35439769c6003693c9b88bf14962b40995931baad12c0e00ac9456556deee599db40209dffe5ebf04f193776ba1dbf3c6fa1a81daafb80ec83e9ce0f8365b8f8fffedf13fe1c2d34d12c2bc5c3c223dd1ea6158645d229e65ccf774c04e4aa4715a67d20f2a20752553c30410651990bbb27d1be95c8b690c7a4edd6450ecbeef312e862944c3eeac7ad25541c14aa6c3da7c14bb4ab6119be67dda0ff244b18711c3da20570ecc1536c3c5cfe297bce254df07fe52d05f54d59272d1fe8c6b30c0eb60a6154b86c71e48379a109986a3632dea79fa0e77fe49931abae8a9188163dc388e772342c0f66d90791a3dd8e337211884aea2b7c2f7920862ade85b6e93d4b1e6afe44a0bf62ed509917cde6ef93a8f6dcd763831652e5c193b7b7ed7d9bb937d1ca1870").unwrap());

        let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 32).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("91010131e81a0ad42da693099a5c3756a494a32be2f80055634b6ffad271b03a1da3d4fd94d310d63ba16dcfaff8ec034215db89aac493573a399d3ecd0db3418234a96ad8cd92f93b3f9d5964e1e7b6d89c4ea7cecaf8a8b86d3ea039b5b47d76cba90539317efc131a8d25b14c2effe966ffdde5151babfe3f5604c1edbc82132c66a8941edd2fa3392b101770d3e0cb90c19702e4aa2da476751cc4ff0a848db4dfbe56ee3e9f09922b3f55c8a0374a2c296fc5a73fc259375d2a931c8e1515cb872005ed5a50ee85ee663b6130254d389c4092d945490e92deeaf27f91d684509ec1b9dd718f01a041d3ade398fac284c3b220950c8832d030d6b0236fa5e6626f63ec0be64f66d82cdcb45f70a169a2c0fff664d1c37f8fafc0153b9f6aeeff986bf056ec5953fc362fcb229a359053f1393a6cbdecc8a0b3e5853be996b0d0ba7a660c00ed6728f4762f01009c8b8ad12b493e8f3e3e9d58837e42372586101e585d40a1715271afe41fe435a57921bd9acd4fcbadfd4e4396812727c3c5fe100296e01d3baa8d9bbc37904080dfcb4860ba8476ac1a0af200244fc8028e71ff7b3a58a85341cb0cdf9e03009c53fa427eea51d6703ddba90c70752d84d76685cb64596f335f74445d15d6463516126d2d3fc32871d472192a555847da6dbccb08396013a444c2f900de32ae5df6bdd8bdc7e870eef02f5a953194d831baaa8f653fc59fb3513b0c3ec5206dd3c41c0ee72f70ddba4d3ae0245928ceb1b0d8f59f5133d0f7647187094652cf6773aab2d05fa0a0b161ba19ae4f954c2d80bfdacb0c51ee2d5ad1b25240e348b4472db239d2dbc6864af6e1425d88a94b3ce8a8f6d754799c59609ab095a469cda07869fff1ad558fe0517a6c35018d224ca52af18537e460345e38a579af48b1043392312d8ed9c868f72993d092843c939817102e89db737c3509eea800be399800de35570a0d255369b9c49013e208c598570a6c888424651ed5b371bedfc571c30e39d971d262bdf3a4b4d60b5f29ec7fac14b8fcb4c654d346c7313113c027605bce2c2464827ff44f1b839be19025014cf8d291455bc67aa4277edd4e3ded467778611d3f7da4e3002eef718a5110b000af428dc3be5e59e89ec798f56310b099464e7c765b8f1c84f1e67205feb6376338925be58657093046").unwrap());

        let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 16).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("9401031797d54ddb89c329b525b1aa6e3f1e193d93056b3c19d34b422c0f65212f9abacb807116fff67eeac9e73c8aa6e57a8eecea4e3fb78551d277831baf6e657afbfe99c063af48fd67a6f9b48174f9f4207caaba39eb90bbe09318597473fb281bc3e95ea6dc8ad773c826d4a97452253f7c7662593bee386d0d1d4a7596ea810661e0391c0ab005642dc1dcc33649340c408dc194022d85bd17b5e06fc59ab741554454d0450e12b4007c0aae9bb68ca4d9f1edac4fcd1577d8a4b23ea5d487f11acee384e71e4c6037b17cd60c496c099be926d21b52bfabccfe4e402abac837b9b0818ef0e4172039baf9d46a3c2864866870df86e8f1e3bd813a53b2d217d0234bfe67f245398aad77f8db7cde11c259f247ae96d5af982ddf8cf7dad2b0225eece2de9ee00c83fb8cb32ba7f77599033b4a2ad35712ab0cc6eb69d67cfde5b6647fca0ebb9b3a7db0092bd8a31c509dfea38d961fe24ad5fa68f73ae5bd5b42538cfe62874e8a8d0f72f52492524791ad51d70e433dcd988033ab4be061cdab0b9b7d960625cde8430dd16e02b2bb1ff510231f59262dd93a796ccf99825f3f1144e58667303509950300a78b3c507be066b2aa31ed2cbbc4de664d27561825164240eb639860a561c0bd8abe11790dc875f2a13c6171c9eda777a03f5a4258b99639ded20b938c5c494223aa72e9d612471ae0e54967af8730bd54a32e408511adcab4816a95b1c9924f56adaf60be01715c02fb80b35f531cf1298f661fe8e40cf1f800444a291e26303e79291db8900067069fe203e97376b88f6ada38ece7e04f87241fd1bb395076621c0a339cb283ca960a8252d95f4d4fe0c3435943285ca9de7df811fd1642862a9fdacb258ed05e27cbf7001b7804a0421f5ae0eca95dce9aa5c6d8b873ee0eb696db556d4e12c246eacf93c1e6f2feee2a73301540101cf2154c94cc2ef7a656e0d65aa78316756b875d27100d151b1cbf5dabb185429ed20693a7a395703f99e27e88c7b5b919fec492e59299b8bb1abcf451ac7f0ec4789dbf4a95835a5da0569f83440045a654e28d313212dd56b01627c6edf27f261dd75336bda675f698887771b9afd28ca8b3379cbbcffb373cb8803738e48fd5f286f77c40c1bc94e47eccefce38be9de1be9a22751634bf6cd2cf4a").unwrap());

        let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 8).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("950166d2bf1d0ad57988b9b6a789fc2acab4ae89fa080022a9cc9566a5c0b67cf4f6d1a2a7ad0d4488ecea1c59cec64de1d424273065e2186a08a8ee37fc8f7a2cc34a167224133f78e47eceb3dc9781655289ed9c988f5267f5ba3fb1173d7f52071e9b9a3bf196b6db657c227245222b6871c04e2956d37543d8b3f422722c486b10e82bff46b35c15415e1dbbf5b0f84159dd961aef8502fed697e8c66401370be358a98d8648f0385bf2a72705767f8a37b8c3bd0a0c7824944b4ff1b109094d6fa19e063d5a3ec1a8475f9820bbc9ce10cb45095de0daeaa227277a87d6aefff2068c8cbd95358b54a4ed151a86858362b91f86b283707239c2d4661a847917508fe3ec8df2f928879b4a3ebea2373daa233314fd1c36f4ee264f1e1913c54bc388f6b911f9ba322bd33361db6988acf37589332459068175ede93967f8ea9442e77117e22d7d8c53a42b1a3279c357068df9584ac2b6024b952a9ba7011469a37cd470d9d8443bde67c696b2cee2cd55ad5da2d34c9b63f132bc2c4182f415d72c8343ab313ba4ad527ab886badec927fc0f1d829f894a3a34a32df40200d70e22e98c42fa7b109e6c3fcc6a36f423efee520d588e0fb4a78e2bb997f3c6162c3cec1363150406e3142b4716f8c148e91d0d4cc818cb330b0bbd14ecfe39145ee71b36018366f417774554181437d1787458cc8fd3f0c25a27696de5e285209fcfe2cad01be819c1c16027903033114e56a049e4a57f5afe8d87e6032c107a77caeec944aeb3e707af8a446e17b07aa2e6c551eb768037ad96ca1f28939cd8154cd7f98abed95ae96920f88a820d1cdc4ed8bff892bede47606bd4c6c3f4431256ecf3ff3aeecd668aa4a1da0c90a14562e172bf32c281a83f688cda5fcb756c9d353c9a665744ba94332212f87ab512ae36778cf0e760c35500158163accb440b24713a48b789c03da2e348b99234277055dce5d92a05b9587a4cd283739c7ae4c8552d4d7088946ce693de313f955eee31c1f5d2aa3087dd9d3629ab9c95ab0ee7659b1e0a49d4bb6a441f821b88b88d7cec5fd225f6dcd076608b1f80c6561c43b747bebdbc3e636bb29e7675474b50").unwrap());

        let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 4).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("960102d12a2199c0d002e25d9f3ab2972ca4a625d272801e86da11690b28ce005e83ac8f58d6ff97945d2e15a6fba11dd37b3ada8ef8cc2e8fe505fcc470dbd76562992c9ac14f02febcd05ee14dae7f611cce78676d1301dfc97c8c2c0d49ee00a5d6bd9ab50540a533518c7cf58f7756a74595ae10a759d0cd6e72f557193a1a7d7a68ec180bb985aef1f1f64ed10637041069d343de99e001f9e5bf7c4c79a58012dcbf3c8c062dd4971ab88176c6dfd1ce314d85f98c31ba67c1dd99ce3f7d2a04be56deaec618436e6cc5fc68d9417d955478f04dfc0af4e85726e3f1c0a7d9613d3b994035efbd1fcc90a2186895f43732b787b717211b882227496de79dd3cb6d3387ee8041a6d9a9dfa83af3fbbe57e89b408077241fe0aef8dd585982205c7d846921421ffcc84e455cd60fa9c15f13b31d5e1a96f4ed37506571baf9eb935f8b7aa184b94ea3662db78cda03164e34490c7cf2e74c4cc68793e855b0c0d1e3a4c7683102a114480629f5373bcac4ea28e6a0601a3baa02034e12ac78243002acf5441c693308133fbff6e1aa6e5ab5c904cf41f94febd3a2847b54e516c9ca42bbc08695cd3ab07f4d1ca8d41108bf552cdbdebdd3a3cfcb3d296245b86ec788c4315f8ce03565e5bc6cf27babc4585874ee1cc64dd487fc7c43a1c82ab47783d05c7a7347cd6efe0645a746ce3a131649a8047a832665232be81d006da67ed832691ba8d32e9374b2f38a40d127dd677d011f2d9840b27b4817bb3bd98083c7260dc8ec9ccc75ab19512a05a6e36cf27518415b2f65adc79fab3cbf71836b07a6395870c4b55d8d973266a0658e497effe0ecf23a2109b68a8d8b6c8d33d122122f9787a3d63b0c85b2698156d759cfb4d8a1fb656ca002d9c84c7ec74fddccbe097c73a36fc8a4f51b29374970e16c8da0ad99cc0d18e48323376757205a6efc").unwrap());
    }

    #[test]
    fn qf_default_hash_test() {
        let discriminant = Discriminant::try_from(-BigInt::from_str_radix("c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7", 16).unwrap()).unwrap();

        let qf =
            QuadraticForm::hash_to_group_with_default_parameters(b"seed", &discriminant).unwrap();
        assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("91010131e81a0ad42da693099a5c3756a494a32be2f80055634b6ffad271b03a1da3d4fd94d310d63ba16dcfaff8ec034215db89aac493573a399d3ecd0db3418234a96ad8cd92f93b3f9d5964e1e7b6d89c4ea7cecaf8a8b86d3ea039b5b47d76cba90539317efc131a8d25b14c2effe966ffdde5151babfe3f5604c1edbc82132c66a8941edd2fa3392b101770d3e0cb90c19702e4aa2da476751cc4ff0a848db4dfbe56ee3e9f09922b3f55c8a0374a2c296fc5a73fc259375d2a931c8e1515cb872005ed5a50ee85ee663b6130254d389c4092d945490e92deeaf27f91d684509ec1b9dd718f01a041d3ade398fac284c3b220950c8832d030d6b0236fa5e6626f63ec0be64f66d82cdcb45f70a169a2c0fff664d1c37f8fafc0153b9f6aeeff986bf056ec5953fc362fcb229a359053f1393a6cbdecc8a0b3e5853be996b0d0ba7a660c00ed6728f4762f01009c8b8ad12b493e8f3e3e9d58837e42372586101e585d40a1715271afe41fe435a57921bd9acd4fcbadfd4e4396812727c3c5fe100296e01d3baa8d9bbc37904080dfcb4860ba8476ac1a0af200244fc8028e71ff7b3a58a85341cb0cdf9e03009c53fa427eea51d6703ddba90c70752d84d76685cb64596f335f74445d15d6463516126d2d3fc32871d472192a555847da6dbccb08396013a444c2f900de32ae5df6bdd8bdc7e870eef02f5a953194d831baaa8f653fc59fb3513b0c3ec5206dd3c41c0ee72f70ddba4d3ae0245928ceb1b0d8f59f5133d0f7647187094652cf6773aab2d05fa0a0b161ba19ae4f954c2d80bfdacb0c51ee2d5ad1b25240e348b4472db239d2dbc6864af6e1425d88a94b3ce8a8f6d754799c59609ab095a469cda07869fff1ad558fe0517a6c35018d224ca52af18537e460345e38a579af48b1043392312d8ed9c868f72993d092843c939817102e89db737c3509eea800be399800de35570a0d255369b9c49013e208c598570a6c888424651ed5b371bedfc571c30e39d971d262bdf3a4b4d60b5f29ec7fac14b8fcb4c654d346c7313113c027605bce2c2464827ff44f1b839be19025014cf8d291455bc67aa4277edd4e3ded467778611d3f7da4e3002eef718a5110b000af428dc3be5e59e89ec798f56310b099464e7c765b8f1c84f1e67205feb6376338925be58657093046").unwrap());
    }
}
