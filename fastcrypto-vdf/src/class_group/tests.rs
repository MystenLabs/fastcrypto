// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::Parameter;
use crate::ParameterizedGroupElement;
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
fn test_serde() {
    let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
    let expected = QuadraticForm::generator(&discriminant) * &BigInt::from(123);
    let bytes = bcs::to_bytes(&expected).unwrap();
    let actual = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_discriminant_to_from_bytes() {
    assert!(bcs::from_bytes::<Discriminant>(&bcs::to_bytes(&BigInt::from(1)).unwrap()).is_err());
    assert!(bcs::from_bytes::<Discriminant>(&bcs::to_bytes(&BigInt::from(-7)).unwrap()).is_ok());

    let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
    let bytes = bcs::to_bytes(&discriminant).unwrap();
    let discriminant2 = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(discriminant, discriminant2);

    let discriminant = Discriminant::from_seed(&[0x01, 0x02, 0x03], 512).unwrap();
    let bytes = bcs::to_bytes(&discriminant).unwrap();
    let discriminant2 = bcs::from_bytes(&bytes).unwrap();
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
    assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("012327fc1d50ebf707cf67c8dfc7cee594f34a52de98f98deae714c3f1dce83d6b3c6f5f76f4f4bf24e9a76f1c312287510d3c78007d495b540ec8015856e95d437129a6efaab59fbca18e978cb35b6d81f1754996a03f7e8fd68f299801da100d1640c28802e0a76021784b689099d710f1b2498747edab2576f6480aad8916479ff7bb1bec2092d5877d390400ff4413eff8cae812d256a8095ee17c9fd5cec4f8456e1e34ac7150e9bc164348f6594e7dabab530bdb426183ea07339a911cd005c2bd9b0ad255ec68e07c6f75e13b66eccd71f9be314b17145ec1ba211515bacc92b1ad9643f483aeef43febd39e6997347ec606acffccdfac550e48e23142525ec3fbee9b8c55ca6638acefb61a5b5dbdcf6fcb26346c5add6f4d59f8a854ef56a84f1b966da775409910fa0807ccad63a26c0805c0e7f3cf0089977749f0419c7360f218cffcd07c4932b6d08335bd0b08c6c56d55edb9aa6603f051ef1ddbe68020e80f26d2e119e6f25c4eddf15df94d387b4f1a917b78eb1dfd7a49686454651333e6deeb4fb7b39a52711ac46f11dab2f2415312cbbc2d48cdfb9cf01667018cad137b99b7dedb7b793c1e552168363d7dcf6a893efe6cd179950ed62bfa044fe6a1e4b3de9b685de2a8620792f7c2bea4a881172338edda39107d9660f2c3472e788c33d1688918aaeab3199e47fe7a09fa7de32366a9809a17983e4716cb854610ab60e0cb3c6e81f2d27594df5052de57ff04d25ce7b29fe5c3c6c53c1ec7005a23d1c71184b24ffa0dd67be1961abb44bc1a73d6caa141c5425adc7ea3e4c9462e812f3eecb0e45d6eda4c790b6c895bed127bb0b99510641303c555207a2f2207da61547aae4044c77cf5ce629d2458615a61edd23c2c3c52b2cd1342d1cfe13dffefff8b865830fcee983ec80fbaa1da8a16f3cbf1dba7637194ff0ebe5ff9d2040db99e5ee6d555694ac000e2cd1aa1b939509b46249f18bb8c9933600c6699743357b78153a6ff5da7014df82a9c5f85d3afdb164de12e646847df7fa2cc8d6a39c7e46e316f25cb84d9e69bddeac6685e3c0fd0788b09547421f55d3ae56a8f2b52532e08a930f5b22e811853c416c5bbdaf375ec3d5962e2515cfadc7cb4a7eeb1f9b06d05ec48d6cdd363585f9090000").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 32).unwrap();
    assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("0125c190cbe0d37017102b39a32fdd1e94a8662c1382bcedc104563ffeab1b15e5ddff66e9ff2e4cb1258d1a13fc7e313905a9cb767db4b539a03e6db8a8f8cacea74e9cd8b6e7e164599d3f3bf992cdd86aa9348241b30dcd3e9d393a5793c4aa89db154203ecf8afcf6da13bd610d394fdd4a31d3ab071d2fa6f4b635500f8e22ba394a456375c9a0993a62dd40a1ae83101000000ff4621f334beac57a7c584008e71fd37b0dbff0df5e553897b459fb734207fbf6fc843647255c4e21f69fdef013a3cd8d87e69bcb1025234b0326542de865aca1be01b508ead8e5ebfa2a7e1ef79dac8bd817ca762c1c170c1b6d42e757463fffed0890bd79812fff39985452f4f6916c47a1a4c5f37134293c5c60eac6fca65dd34d0c903aca613a90f946700119560c4ea3f5070803c2e9b09003f5d965e8fa04b23d32799b019f4139c909d195a90dc4f29cf2fcd77f36adf4d3c7b3d05671c522cbe5ffe708e22463e61af7b296e800d15216df1b6ba266dbf63c7b2dacf9ec499117a11afa512fadf7834eaea71e36cd5a2c8a63dc0583a90d6d3b5c85f37aac0d46df660c111a941204b727bf5003be38a895bd2551b0001684630095786e55b92386337b6fe0572e6f1841c8f5b767c4e4699b01063f598c79ee8595ebec38d42af00b010518a71ef2e00e3a47d3f1d61787746ed3d4edd7e27a47ac65b4591d2f84c012590e19b831b4ff47f8264242cce5b6027c0133131c746d354c6b4fcb814ac7fec295f0bd6b4a4f3bd62d271d9390ec371c5dfbe71b3d51e652484886c0a5798c508e21390c4b96953250d0a5735de009839be00a8ee09357c73db892e101798933c8492d09329f768c8d98e2d31923304b148af79a5385e3460e43785f12aa54c228d01356c7a51e08f55adf1ff6978a0cd69a495b09a60599c7954d7f6a8e83c4ba9885d42e1f64a86c6dbd239b22d47b448e34052b2d15a2dee510ccbdabf802d4c954fae19ba61b1a0a05fd0b2aa7367cf524609877164f7d033519ff5d8b0b1ce285924e03a4dbadd702fe70e1cc4d36d20c53e0c3b51b39fc53f658faaba31d89431955a2ff0ee70e8c7bdd8bdf65dae32de00f9c244a413603908cbbc6dda4758552a1972d47128c33f2d6d12163546d6155d44745f336f5964cb8566d7842d75700ca9db3d70d651ea7e42fa539c000000").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 16).unwrap();
    assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("0125c18d400c344936c3dcc12d6405b00a1c39e0610681ea96754a1d0d6d38ee3b5962767c3f255274a9d426c873d78adca65ee9c31b28fb7374591893e0bb90eb39baaa7c20f4f97481b4f9a667fd48af63c099fefb7a656eaf1b8377d25185b73f4eeaec8e7ae5a68a3ce7c9ea7ef6ff167180cbba9a2f21650f2c424bd3193c6b05933d191e3f6eaab125b529c389db4dd597170301450935306786e544113f5f8299cf6c793ad92d26591f2310f51fbbb2026ed10d43e8cd2506967d9b0babcd61e04bab338098cd3d430ed751ad9147529224f5720f8d8a4e8762fe8c53425bbde53af768fad54ae21f968da3fe9d501ca3d82b09b07d3a9bbb0eca7f64b6e5fd7cd669ebc60cab1257d32a4a3b039975f7a72bb38cfb830ce09edee2ec5e22b0d2daf78cdf2d98afd596ae47f259c211de7cdbf877ad8a3945f267fe4b23d017d2b2533a81bde3f1e886df70688664283c6ad4f9ba392017e4f08e81b0b937c8ba2a404efeccabbf521bd226e99b096c490cd67cb137604c1ee784e3ce1af187d4a53eb2a4d87715cd4facedf1d9a48cb69bae0a7c00b4120e45d054445541b79ac56fe0b517bd852d01654acfd26cbf341675229abee19dbe38ceefcc7ee494bcc1407cf786f2d58fe4383780b83c37fbcfbb9c37b3a88cd2afb971778898f675a6bd3653d71d267ff2edc62716b056dd1232318de254a6450044839f56a05d5a83954abf9d78c40e7fac51f4bc1abbb89992e592c4fe19b9b5c7887ee2993f7095a3a79306d29e4285b1ab5dbf1c1b150d10275d876b751683a75ad6e056a6f72ecc944c15f21c10401530732aeefef2e6c193cfea46c2124e6d55db96b60eee73b8d8c6a59ace5da9ece05a1f42a004781b00f7cb275ed08e25cbda9f2a864216fd11f87ddea95c28435943c3e04f4d5fd952820a96ca83b29c330a1c62765039bbd11f24874fe0e7ec38da6a8fb87673e903e29f06670090b81d29793e30261e294a4400f8f10ce4e81f668f29f11c535fb380fb025c7101be60afad564f92c9b1956a81b4caad1185402ea354bd3087af6749e5e01a4712d6e972aa2342495c8c930bd2de3996b958425a3fa077a7edc971613ca1f275c80d7911be8abdc061a5609863eb404216251856274d66dec4bb2ced31aab266e07b503c8ba7").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 8).unwrap();
    assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("0126ef1a96dd5941f8b0f5bb1d5e41155cb346ff2be8106b482c7222f4b3d84375d356294ec071682b224572227c65dbb696f13b9a9b1e07527f3d17b13fbaf567528f989ced8952658197dcb3ce7ee4783f132472164ac32c7a8ffc37eea8086a18e265302724d4e14dc6ce591ceaec88440dada7a2d1f6f47cb6c0a56695cca9220008fa89aeb4ca2afc89a7b6b98879d50a1dbfd266000000ff42d35ccbc5b576607de2f003d8362145794785ad525bc4ce54bc7cd328ea0b7dbed343cd0e9c64b32c5da252aa321d314d69399821c4bb27268f2b835c96ebfe5864d56ab4fd493db5a70672f9a83c86cde5d45bac7382d21de88e18bd6b150798c616128a7ef9a6dbcc768a0c537796249ecc2cd4cd4506ee4609773cb43aece6e1b0d9110bc9e302ebccdc55c2c85d41c1b56478d7060d72131c70afe8867be5992b3dc68d8f7c4d79e0469d7c7a79e5ea125bab74ca6a427373f90d0051297885d8d85d15251fa2f6ba34ef313644df67a0b8573ec1a5c2f9615e90b2f6f64e0eb0b46bdb87f3f5423c47c8758089fad8580da4c70fb7797256a71cf4c8fe9b3917682901000000015d504b4775769eb26b633ebcbdbe47b7431c56c6801f8b6076d0dcf625d25fec7c8db8881b821f446abbd4490a1e9b65e70eab959cab29369ddd8730aad2f5c131ee5e953f31de93e66c9488704d2d55c8e47a9c7383d24c7a58b9052ad9e5dc5570273492b948e3a23dc089b7483a71240b44cbac6381150055c360e7f08c7736ae12b57af812223394ba4457669a3c359d6c75cb5fda8c683fa881c232bf72e16245a1900cdaa1a48a66cdee3afff3ec561243f4c3c6d46b6047debe92f8bfd84edc1c0d828af82069e95ad9be8af9d74c15d89c93281fca96ad378076eb51c5e6a27ab0176e448aaf07e7b3ae44c9eeca777a102c03e6878dfe5a7fa5e449a0564e113330902760c1c119e81bd0cae2cf9f2085e2e56d69275ac2f0d38fcc587478d137141854457717f4668301361be75e1439feec14bd0b0b33cb18c84c0d1de948c1f816472b14e30604156313ec3c2c16c6f397b92b8ea7b40f8e580d52eeef23f4366acc3f6c9e107bfa428ce9220ed700").unwrap());

    let qf = QuadraticForm::hash_to_group(b"seed", &discriminant, 4).unwrap();
    assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("012699de43d36910043706d14ef6f1f1ae85b90b18ec687a7d1a3a1957f5726ecdd059a710ae9545a756778ff57c8c5133a54005b59abdd6a500ee490d2c8c7cc9df01136d6778ce1c617fae4de15ed0bcfe024fc19a2c996265d7db70c4fc05e58f2eccf88eda3a7bd31da1fba6152e5d9497ffd6588fac835e00ce280b6911da861e8072d225a6a42c97b23a9f5de202d0c099212ad1020000ff38c5e59f5f19d7153b35c4c80ad6f9b7eb5efdce97385b1c2e3f4faa176c7839b3b3180d83f3b6cbb1e9fc257348d2995cb1467b5e8574a06c1406458e9aafc8120b69e5a1e24ceca03e56f029a3bab13703e0bdde967b82a3df7da6a72207511fe0db887fbf6417a841040cc55720562659be7f1178cc92342c621892b6d8dd77e4dee8487848cdc80b6a97e75d6f33e04210cabf66c4c29e26583f0e1cd9a8170bf503b20f87ab6a82be2697033a9391bce7395121a941fbd582c03166223e9845ce73067ab2ce312e2039897e47e5682bd2f973c34023ed7f5a86b383401a06014bfc6e5a205767372383e4180dcc99ada08d6ce1704937291bf5a4c86fa3737c09beccdd4fc77e4cc8d902a06c65fba1d8b4cf59d7568169b2850c3bd6a387972f1222d1338d6c8b8d8ab609213af2ece0ff7e498e65a06632978d5db5c4705839a6076b8371bf3cab9fc7ad652f5b411875f26ce3a6052a5119ab75cc9cecc80d26c78380d93bbb17487bb240982d1f017d67dd27d1408af3b274932ed3a81b6932d87ea66d001de82b236526837a04a84916133ace46a74506fe6ecd47737a5cd08377b42ac8a1437cfc87d44dc61cee745858c4ab7bf26cbce56535e08c5f31c488c76eb84562293dcbcfa3d3bddedb2c55bf0811d4a81c4d7fb03acd9586c0bb42cac916e5547b84a2d3eb4ff941cf04c9b55a6eaae1f6bf3f130833691c44f5ac02302478ac124e030000").unwrap());
}

#[test]
fn qf_default_hash_test() {
    let discriminant = Discriminant::try_from(-BigInt::from_str_radix("c3811f4ad2f4a7bdf2ed89385866ad526c6dd3aa942e04c141d0562a8e7b014f08804f47b3c2ecbba0a5a0ad8f4d8e869a10cff13dbc522aea141f6d1c42913f2d3bff8d3e7656c72523a2e9d47f838234bd65f05ef3ca86c2f640bca6630ed8d1da21e30a67f83e25b89c32c2d0dc0bacb81bd971b0932a82d131b4a74bff36b60b66543105da2c3ecb1a4e8c2cb6d47c1e85942cce8f3fc50c27856e6dfbd15c0bd5017fea15ae0eb43dfb32b2d947c3131d1951f00bcc40352eeb65e364551e40d13768f443406760ee6b37a5b5819d3f630c034c7f42212ad49c803772aaafd4cd1f87697c68d5a6b0855f475b370b20058558993e76759caa38edbc82407b4e3559bade5f7479a860ebef62fed82d657765ebb8f7f375c2b78f73669760e4bd4932177087a49a0b68d7", 16).unwrap()).unwrap();

    let qf = QuadraticForm::hash_to_group_with_default_parameters(b"seed", &discriminant).unwrap();
    assert_eq!(bcs::to_bytes(&qf).unwrap(), hex::decode("0125c190cbe0d37017102b39a32fdd1e94a8662c1382bcedc104563ffeab1b15e5ddff66e9ff2e4cb1258d1a13fc7e313905a9cb767db4b539a03e6db8a8f8cacea74e9cd8b6e7e164599d3f3bf992cdd86aa9348241b30dcd3e9d393a5793c4aa89db154203ecf8afcf6da13bd610d394fdd4a31d3ab071d2fa6f4b635500f8e22ba394a456375c9a0993a62dd40a1ae83101000000ff4621f334beac57a7c584008e71fd37b0dbff0df5e553897b459fb734207fbf6fc843647255c4e21f69fdef013a3cd8d87e69bcb1025234b0326542de865aca1be01b508ead8e5ebfa2a7e1ef79dac8bd817ca762c1c170c1b6d42e757463fffed0890bd79812fff39985452f4f6916c47a1a4c5f37134293c5c60eac6fca65dd34d0c903aca613a90f946700119560c4ea3f5070803c2e9b09003f5d965e8fa04b23d32799b019f4139c909d195a90dc4f29cf2fcd77f36adf4d3c7b3d05671c522cbe5ffe708e22463e61af7b296e800d15216df1b6ba266dbf63c7b2dacf9ec499117a11afa512fadf7834eaea71e36cd5a2c8a63dc0583a90d6d3b5c85f37aac0d46df660c111a941204b727bf5003be38a895bd2551b0001684630095786e55b92386337b6fe0572e6f1841c8f5b767c4e4699b01063f598c79ee8595ebec38d42af00b010518a71ef2e00e3a47d3f1d61787746ed3d4edd7e27a47ac65b4591d2f84c012590e19b831b4ff47f8264242cce5b6027c0133131c746d354c6b4fcb814ac7fec295f0bd6b4a4f3bd62d271d9390ec371c5dfbe71b3d51e652484886c0a5798c508e21390c4b96953250d0a5735de009839be00a8ee09357c73db892e101798933c8492d09329f768c8d98e2d31923304b148af79a5385e3460e43785f12aa54c228d01356c7a51e08f55adf1ff6978a0cd69a495b09a60599c7954d7f6a8e83c4ba9885d42e1f64a86c6dbd239b22d47b448e34052b2d15a2dee510ccbdabf802d4c954fae19ba61b1a0a05fd0b2aa7367cf524609877164f7d033519ff5d8b0b1ce285924e03a4dbadd702fe70e1cc4d36d20c53e0c3b51b39fc53f658faaba31d89431955a2ff0ee70e8c7bdd8bdf65dae32de00f9c244a413603908cbbc6dda4758552a1972d47128c33f2d6d12163546d6155d44745f336f5964cb8566d7842d75700ca9db3d70d651ea7e42fa539c000000").unwrap());
}
