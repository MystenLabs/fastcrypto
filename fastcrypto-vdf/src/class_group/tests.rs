// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::Parameter;
use crate::ParameterizedGroupElement;
use crate::ToBytes;
use num_bigint::BigInt;
use num_traits::Num;
use rand::{thread_rng, RngCore};

#[test]
fn test_multiplication() {
    let discriminant = Discriminant::from_seed(b"discriminant seed", 800).unwrap();
    let generator = QuadraticForm::generator(&discriminant);
    let mut current = QuadraticForm::zero(&discriminant);
    for i in 0..1000 {
        assert_eq!(current, generator.mul(&BigInt::from(i)));
        current = current + &generator;
    }
}

#[test]
fn test_composition() {
    // The order of the class group (the class number) for -223 is 7 (see https://mathworld.wolfram.com/ClassNumber.html).
    let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
    let g = QuadraticForm::generator(&discriminant);

    for i in 1..=6 {
        assert_ne!(QuadraticForm::zero(&discriminant), g.mul(&BigInt::from(i)));
    }
    assert_eq!(QuadraticForm::zero(&discriminant), g.mul(&BigInt::from(7)));
}

#[test]
fn test_discriminant_to_from_bytes() {
    assert!(Discriminant::try_from_be_bytes(&[0x01]).is_err());
    assert!(Discriminant::try_from_be_bytes(&[0x07]).is_ok());

    let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
    let bytes = discriminant.to_bytes();
    let discriminant2 = Discriminant::try_from_be_bytes(&bytes).unwrap();
    assert_eq!(discriminant, discriminant2);

    let discriminant = Discriminant::from_seed(&[0x01, 0x02, 0x03], 512).unwrap();
    let bytes = discriminant.to_bytes();
    let discriminant2 = Discriminant::try_from_be_bytes(&bytes).unwrap();
    assert_eq!(discriminant, discriminant2);
}

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
    assert_eq!(qf.to_bytes(), hex::decode("008b04397d87d59220ec1bbbf79f471689ad0a48f67625abed478749b2f110d79990684b782160a7e00288c240160d10da0198298fd68f7e3fa0964975f1816d5bb38c978ea1bc9fb5aaefa62971435de9565801c80e545b497d00783c0d518722311c6fa7e924bff4f4765f6f3c6b3de8dcf1c314e7ea8df998de524af394e5cec7dfc867cf07f7eb501dfc270111ff304620732b3d44d3ceeadbd054e20eb953eed85ac684044b1192c1ccaeb9ba79695b28204e7148e8560e4b782c6b20ea20123bda9061eed1920d7ff1fd9741220ee1fac09f596524a12aa993734f2fa4ccf792d46c3bf8320073def0c938e6fb608b8866f70fc380f1a37f3fd9c52935837f5ff06ef6ab882599460e7b950ab17a75602a0b29523ab99c4d030923244a5a9e0431759c59a33a471641c013dadaebdc711baf3a05320330959f13b88c6619c64201bc10517c0bbc69524e6d3345eaeade453ea1ebe8b4ce41068e321399c41e8a90831f9713aa2df564423dfa2fe36e65ccf8157c9ebd24f4ac545482b1a609b7bce94316af8e53cbe191ba073b312a60831ea1f657a92ded17350710ed").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 32).unwrap();
    assert_eq!(qf.to_bytes(), hex::decode("00910131e81a0ad42da693099a5c3756a494a32be2f80055634b6ffad271b03a1da3d4fd94d310d63ba16dcfaff8ec034215db89aac493573a399d3ecd0db3418234a96ad8cd92f93b3f9d5964e1e7b6d89c4ea7cecaf8a8b86d3ea039b5b47d76cba90539317efc131a8d25b14c2effe966ffdde5151babfe3f5604c1edbc82132c66a8941edd2fa3392b101770d3e0cb90c10117e4aa2da476751cc4ff0a848db4dfbe56ee3e9f09922b3f55c8a0374a2c296fc5a73fc259375d2a931c8e1515cb872005ed5a50ee85ee663b6130254d389c4092d945490e92deeaf27f91d684509ec1b9dd718f01a041d3ade398fac284c3b220950c8832d030d6b0236fa5e6626f63ec0be64f66d82cdcb45f70a169a2c0fff664d1c37f8fafc0153b9f6aeeff986bf056ec5953fc362fcb229a359053f1393a6cbdecc8a0b3e5853be996b0d0ba7a660c00ed6728f4762f01009c8b8ad12b493e8f3e3e9d58837e42372586101e585d40a1715271afe41fe435a57921bd9acd4fcbadfd4e4396812727c3c5fe100296e01d3baa8d9bbc37904080dfcb4860ba8476ac1a0af200244fc8028e71ff7b3a58a85341cb0cdf").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 16).unwrap();
    assert_eq!(qf.to_bytes(), hex::decode("0094031797d54ddb89c329b525b1aa6e3f1e193d93056b3c19d34b422c0f65212f9abacb807116fff67eeac9e73c8aa6e57a8eecea4e3fb78551d277831baf6e657afbfe99c063af48fd67a6f9b48174f9f4207caaba39eb90bbe09318597473fb281bc3e95ea6dc8ad773c826d4a97452253f7c7662593bee386d0d1d4a7596ea810661e0391c0ab005642dc1dcc33649340c408dc101142d85bd17b5e06fc59ab741554454d0450e12b4007c0aae9bb68ca4d9f1edac4fcd1577d8a4b23ea5d487f11acee384e71e4c6037b17cd60c496c099be926d21b52bfabccfe4e402abac837b9b0818ef0e4172039baf9d46a3c2864866870df86e8f1e3bd813a53b2d217d0234bfe67f245398aad77f8db7cde11c259f247ae96d5af982ddf8cf7dad2b0225eece2de9ee00c83fb8cb32ba7f77599033b4a2ad35712ab0cc6eb69d67cfde5b6647fca0ebb9b3a7db0092bd8a31c509dfea38d961fe24ad5fa68f73ae5bd5b42538cfe62874e8a8d0f72f52492524791ad51d70e433dcd988033ab4be061cdab0b9b7d960625cde8430dd16e02b2bb1ff510231f59262dd93a796ccf99825f3f1144e58667303509").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 8).unwrap();
    assert_eq!(qf.to_bytes(), hex::decode("009566d2bf1d0ad57988b9b6a789fc2acab4ae89fa080022a9cc9566a5c0b67cf4f6d1a2a7ad0d4488ecea1c59cec64de1d424273065e2186a08a8ee37fc8f7a2cc34a167224133f78e47eceb3dc9781655289ed9c988f5267f5ba3fb1173d7f52071e9b9a3bf196b6db657c227245222b6871c04e2956d37543d8b3f422722c486b10e82bff46b35c15415e1dbbf5b0f84159dd961aef0105fed697e8c66401370be358a98d8648f0385bf2a72705767f8a37b8c3bd0a0c7824944b4ff1b109094d6fa19e063d5a3ec1a8475f9820bbc9ce10cb45095de0daeaa227277a87d6aefff2068c8cbd95358b54a4ed151a86858362b91f86b283707239c2d4661a847917508fe3ec8df2f928879b4a3ebea2373daa233314fd1c36f4ee264f1e1913c54bc388f6b911f9ba322bd33361db6988acf37589332459068175ede93967f8ea9442e77117e22d7d8c53a42b1a3279c357068df9584ac2b6024b952a9ba7011469a37cd470d9d8443bde67c696b2cee2cd55ad5da2d34c9b63f132bc2c4182f415d72c8343ab313ba4ad527ab886badec927fc0f1d829f894a3a34a32d").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 4).unwrap();
    assert_eq!(qf.to_bytes(), hex::decode("009602d12a2199c0d002e25d9f3ab2972ca4a625d272801e86da11690b28ce005e83ac8f58d6ff97945d2e15a6fba11dd37b3ada8ef8cc2e8fe505fcc470dbd76562992c9ac14f02febcd05ee14dae7f611cce78676d1301dfc97c8c2c0d49ee00a5d6bd9ab50540a533518c7cf58f7756a74595ae10a759d0cd6e72f557193a1a7d7a68ec180bb985aef1f1f64ed10637041069d343de9900e0f9e5bf7c4c79a58012dcbf3c8c062dd4971ab88176c6dfd1ce314d85f98c31ba67c1dd99ce3f7d2a04be56deaec618436e6cc5fc68d9417d955478f04dfc0af4e85726e3f1c0a7d9613d3b994035efbd1fcc90a2186895f43732b787b717211b882227496de79dd3cb6d3387ee8041a6d9a9dfa83af3fbbe57e89b408077241fe0aef8dd585982205c7d846921421ffcc84e455cd60fa9c15f13b31d5e1a96f4ed37506571baf9eb935f8b7aa184b94ea3662db78cda03164e34490c7cf2e74c4cc68793e855b0c0d1e3a4c7683102a114480629f5373bcac4ea28e6a0601a3b").unwrap());
}

#[test]
fn qf_default_hash_test() {
    let discriminant = Discriminant::try_from(-BigInt::from_str_radix("c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7", 16).unwrap()).unwrap();

    let qf = QuadraticForm::hash_to_group_with_default_parameters(b"seed", &discriminant).unwrap();
    assert_eq!(qf.to_bytes(), hex::decode("00910131e81a0ad42da693099a5c3756a494a32be2f80055634b6ffad271b03a1da3d4fd94d310d63ba16dcfaff8ec034215db89aac493573a399d3ecd0db3418234a96ad8cd92f93b3f9d5964e1e7b6d89c4ea7cecaf8a8b86d3ea039b5b47d76cba90539317efc131a8d25b14c2effe966ffdde5151babfe3f5604c1edbc82132c66a8941edd2fa3392b101770d3e0cb90c10117e4aa2da476751cc4ff0a848db4dfbe56ee3e9f09922b3f55c8a0374a2c296fc5a73fc259375d2a931c8e1515cb872005ed5a50ee85ee663b6130254d389c4092d945490e92deeaf27f91d684509ec1b9dd718f01a041d3ade398fac284c3b220950c8832d030d6b0236fa5e6626f63ec0be64f66d82cdcb45f70a169a2c0fff664d1c37f8fafc0153b9f6aeeff986bf056ec5953fc362fcb229a359053f1393a6cbdecc8a0b3e5853be996b0d0ba7a660c00ed6728f4762f01009c8b8ad12b493e8f3e3e9d58837e42372586101e585d40a1715271afe41fe435a57921bd9acd4fcbadfd4e4396812727c3c5fe100296e01d3baa8d9bbc37904080dfcb4860ba8476ac1a0af200244fc8028e71ff7b3a58a85341cb0cdf").unwrap());
}
