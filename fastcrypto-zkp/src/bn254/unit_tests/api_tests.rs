// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::api::{
    get_public_inputs_num, prepare_pvk_bytes, verify_groth16_in_bytes, G1_SIZE, G2_SIZE,
    SCALAR_SIZE,
};
use crate::bn254::verifier::PreparedVerifyingKey;
use crate::dummy_circuits::Fibonacci;
use ark_bn254::{Bn254, Fq, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use fastcrypto::error::FastCryptoError;
use itertools::repeat_n;
use num_bigint::BigUint;
use proptest::collection::vec;
use proptest::prelude::*;

#[path = "./utils.rs"]
mod utils;

#[path = "../../groth16/test_utils.rs"]
mod test_utils;

use test_utils::{
    arb_byte_mutation, arb_mutation, compressed, decode, le_bytes, modulus, Inputs, PROOF_PART,
    PUBLIC_INPUTS_PART,
};

//
// Helper functions
//

/// A verifying key in arkworks' compressed format, for a circuit with one public input, and the
/// four parts of its prepared verifying key.
const VK: &str = "3c747dd28b1d21b2be3dae04a8c88152d2a5cec5efc800f7a4feea5f938e248298b4d9f57babfa38799f78172df2c303a754945bba9235b39be37826e4c15b273a0f051b814c50a489f6845bfe80521a1e99fbce0c6fda1ba521d4c29ea8d29e3cb543973711905d0cda7dee3c71e7b9460c34e9e7285e03d5fa519e2986a428754b79e5ddb20de39d9afb7b901b4a60c2366c20e658b476206a1710f99146914633127ccae0e459b3d2a8aa39db9a6d5aa91b5f7038bc2bbd7e9e713e6a9b2fb254de7356d1b449f95168ed30e5570715367c99b0e07fd8595517cdb042432b0200000000000000ada96147db3a3bef28beecff2d9bf2814bf07a62722e69486b6e2c3cd26844ac0779d941feabcdc6ae03c87f33fc46877f0261428e29bbf1087e8f858e1dfa88";
const PVK_OF_VK: [&str; 4] = [
    "ada96147db3a3bef28beecff2d9bf2814bf07a62722e69486b6e2c3cd26844ac0779d941feabcdc6ae03c87f33fc46877f0261428e29bbf1087e8f858e1dfa88",
    "4d6005b84ae8c96c5ecce7218b59b20a8a6b0ae7b0b4f3d3aa42407f161ddf140b4b211677e840d34950a4a780f91a434304870569e2ab9ee2fe4e3b4b712e2a2e2977ee78da6db29c0c012a13442df99620b008e38a9ea65dbb19a00e10412fc8558f6687fc2f8420ba8546e86dd91779897998a4bbd6d38c3cfd1af46f4d28f5bf00faf918a2c1079b216d03036920a89427bf00d01d17da30adbb9710952785b2dbd6a5e4ae828a970a5862c1c04fc082cf2ff694cbeefb92317dfabc3b21f1e3f17e25aaecbeaabfcd76b72fc9ba6494330ce687ed522bb22468e289dd103212f554cefc72ca9f49717f8aeefe807b4c44260391db2088be32142061921adf9efc013ce13a83aaa856a39480356581c8d2369a8c2b80c418607ec5778804703da5bbff5faf2aab898edd35b694ec5cbd6c8924d5ee5dded531875bcd462636133f8dcb4b858f34c02da0a6a4a12283fbe6def67b54f29f515533da05860430048966aeaa077a536cdc20972c2243de0c15febedcd3241d32c50df205f82a",
    "3cb543973711905d0cda7dee3c71e7b9460c34e9e7285e03d5fa519e2986a428754b79e5ddb20de39d9afb7b901b4a60c2366c20e658b476206a1710f9914611",
    "4633127ccae0e459b3d2a8aa39db9a6d5aa91b5f7038bc2bbd7e9e713e6a9b2fb254de7356d1b449f95168ed30e5570715367c99b0e07fd8595517cdb04243ab",
];
/// The four parts of a prepared verifying key of the [Fibonacci] circuit, the public inputs
/// a = 123 and b = 456 as little-endian scalars, and a proof for them.
const PVK: [&str; 4] = [
    "df35140d037b211901de04f62a417c53c304328304d738bcc4ff623b1e65698765c6fa5f804bac35ce67f2c26e37bd0cba6f8a944a6c8c17a2417c7b88254f000f87f4f3b509521fbd63e8460ef9082880ada8f342803fd2188e5ce75bbb0d06",
    "b51f110c1840d39a3185436f5307ad47b375ff892acd78cfa2939556eb46d22112f76ffdd8f3be5fabcc44df3a6750edaaf65af3218f58988afedf6b4202b41066a18f1a8e6b06194838ab7331524da9389802cfd1cc87ef800cbf927fe65e1009fd4d603bf4790371ea2272d17f9a1d98f790b04af2fef1f35889b7e54cc210ce1e47a6ecece6f9d20e8c4514db8f74b96db01cd3528e49faf67d40b7e18f12cd4aadf7698d3fbca9d5a660f677a8c9bba800d3a125c9431e151fa9120c9d07c80d5f662fd6630f1c7441ce7c2f65cad89898222976d519fcadcd9a9beb7120625ee32258e4436e31b4661521c68dbd78027a0935423f2f3b74087c3dcc4b15f8c23a499e1b2e0e456d24274eb7e5c2a0ca3338c5e4ec4d31fd3392c32c790e05142edd5fe2e671260f33318826f2ce0e0cbadb2d347a1644d14824a1f2f402c2740188daef879da5139d06160b1bd44788a272e92d33553631cbc9db991f18606ba945064aff9ec7c0d6d0fde961d834783008718783f67c778dd952b1270f",
    "04d7dbe72328896134ed56890042202827ce6805cd384ab00afa0997b26a8d0905b8d48c57bcbc7e9d8a2ff6771a50f90d96970636a9e7d89aaf7369ce7e4d9f",
    "06639a71c443532e6c7797e0b18926ea09962bd2fdad9a7130df397463afd315b4bfda26cbef66c4f62f6e65a90d70f058df1f57216846e93890f9b2be68ce85",
];
const PUBLIC_INPUTS: &str = "7b00000000000000000000000000000000000000000000000000000000000000c801000000000000000000000000000000000000000000000000000000000000";
const PROOF: &str = "537a1b8ba0fc0f2b456c59769a58f22fbf9228311f5cc9070e7358e28c51d2033984c58d47b747c7e07bc87520f14e19029042259a21a910040b87533bf3c32613261dbeffd2913f3627895532b49e9cf623fdfa94e4ef9c040086b397ad640c54c165811c46fa50a880a7b8616d2165848b8f631db25b1b1ebf7fe021f4a11a";
/// Another prepared verifying key with two public inputs, both zero, and a proof for them.
const ZERO_INPUTS_PVK: [&str; 4] = [
    "7329e3fb0f59e62c7a88ec42ca108a94f525298de1fa7640123daa7469fd1102dacd7b18f373a7ecf75fba98b812367196ff4e62ad4653f0feba143a6ec268a9442f7562a719360f83480bf4624adfdb80faaf2302b0a6022caf32de5a120d8d",
    "b45caf631bc5d75cf3f00a7520380275d826a41b5641e1acba32b29aea45661480ed201e35888a845744ee5565688aedcc4a25f50fedfc169479285476fc7100a1f525423181d8a1088ee24a9b7e8f91d0bc3465493b591172f3a1a8330f911a2681fee88569d6eac0be6e741f2edd22a244f937db29524a3ed9ddd79112202d194bdc21fe7b374fee3cd4b6395ecb14986054a2b3e2348c496ed12f5db1c806dd1df76a9faa0f62118ea4eb217735206196cf16284f7b5d1bb7fdabc323f02022550841d98b365c22d5d962f4c544bab40059dc5cf576a3c31a1e00cd107c2549df1e99e8837b2e8fe9e846a0f8fdbdf0d47f1051bc280d6cf41fa205d1b72a5be7f6dacca14fc38f83adfa72a38c870cb1e2d638bba767677f087ab65bdd12c9f857334cbcb8d4cdffb901c9ce6123d2525bd93765db4214900ba26a26ce06fa5c661f0a38affe716a95876b394cc20b6862dd112e01be3dec14d7f76b441049cbd5ca74358fd4f4c4027f28b7028a4f49f20129eb28b0f0e861e34bf80805",
    "f43620ffdf673339d95fbd4b40fbce43b7d4487b58b13f8c9ab146de9c992910ee2953bbad19f7374146404f9fb9a4d4c4668d999e1a125357dcfe8d8d6aaa19",
    "fbb7656bf9f28ccfbeb13b78811bd4fb8cc4dcc301bccf8b7f604c60a13caf1996a518acb5ee768617e54dfab6aa3743881a62b2dfd4222fa13d4f85de913216",
];
const ZERO_INPUTS: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const ZERO_INPUTS_PROOF: &str = "52ce4e209a74e81322849ec341378c332cdb08ba74cd8804e763d4d1af73778cce951ab584d2100a1fd9edd2eec8e8f929029bdd9cf8f9fdaccb683368e797092f5d1415f6e26a8604dd87a85b66faa68fcb00627952d21dbeb8392e52692c83f0fc821e2bb35e09cfb3316d9266a2de90d79d67344b6d727b6eac573a0a6d8a";

/// A proof for the elusiv send-quadra circuit, used for private on-chain transfers, and its 14
/// public inputs. The circuit has about 22.5k constraints, see
/// https://github.com/elusiv-privacy/circuits. Its verifying key is [elusiv_vk].
const ELUSIV_PROOF: &str = "14f568dd82eb7bccb1720a6e2eb7307809aa33559e1abd3eed102ecbaf7af52f8057697cb398ae4216ae3755012f8093ca24b7ac1a8955276027d41f7c04a80d012148dac873b42c9258b6f1416f24f88a535c93ae32ce8b38b50f7b00ee140b7b3ae27d3cbd7b4ad6de204b80cdc80644cf69d6db4c06cd14c6d577cdec0d15";
const ELUSIV_PUBLIC_INPUTS: &str = "bb69acdb04b25218cfd5a8c3355f35abd5c09f4efbae9ea82c1578a7a1555714249f07575f1e928456e39764b0a79d8e0dfbdca58de19177cfee71c7fd954e0577fba01a0a5cdc0bd494383bf5641cea53a353533083f6dcb07448084f44690b00000000000000000000000000000000000000000000000000000000000000007b7d28c685f6e00567f4bcf59bb4bb638b3df0a2472c73a20623b57f2a282a250000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008813000000000000000000000000000000000000000000000000000000000000af0b6e2fab5c273f24b73d9069fac116b44165c72f970c939e423e3393565922040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f9fb4023f2d0bc336a7bec7b5d481a3d6ee0f7f5721dfdd4ae82732cb7311f17";

/// The compressed encoding of x = 0 with a positive y. It is not a point: y^2 = 0^3 + 3 has no
/// solution, since 3 is not a square modulo p.
const G1_NOT_ON_CURVE: [u8; G1_SIZE] = [0; G1_SIZE];

/// The compressed encoding of a point on the curve of G2, with x = 1, that is not in G2: the curve
/// has a cofactor, so not all of its points are in the subgroup of order r.
const G2_NOT_IN_SUBGROUP: &str = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080";

/// Arkworks puts two flags in the top bits of the last byte of a compressed point.
const INFINITY_FLAG: u8 = 0x40;
const NEGATIVE_Y_FLAG: u8 = 0x80;

/// The offset of the length of gamma_abc in a verifying key: it follows alpha in G1 and beta, gamma
/// and delta in G2.
const GAMMA_ABC_LENGTH_OFFSET: usize = G1_SIZE + 3 * G2_SIZE;

/// The inputs of [PVK], [PUBLIC_INPUTS] and [PROOF], which verify.
fn valid() -> Inputs {
    Inputs::new(PVK, PUBLIC_INPUTS, PROOF)
}

fn verify(inputs: &Inputs) -> Result<bool, FastCryptoError> {
    inputs.verify_with(verify_groth16_in_bytes)
}

/// The prepared verifying key and the public inputs, decoded the way [verify_groth16_in_bytes]
/// decodes them, or `None` if they don't decode.
fn statement(inputs: &Inputs) -> Option<(PreparedVerifyingKey, Vec<Fr>)> {
    let pvk = PreparedVerifyingKey::deserialize(&inputs.0[..4]).ok()?;
    let public_inputs = &inputs.0[PUBLIC_INPUTS_PART];
    if public_inputs.len() % SCALAR_SIZE != 0 {
        return None;
    }
    let public_inputs = public_inputs
        .chunks(SCALAR_SIZE)
        .map(|chunk| Fr::deserialize_compressed(chunk).ok())
        .collect::<Option<_>>()?;
    Some((pvk, public_inputs))
}

/// The proof (-A, -B, C) for a proof (A, B, C), or `None` if the proof doesn't decode. It verifies
/// iff (A, B, C) does since e(-A, -B) = e(A, B).
fn negate_proof(proof: &[u8]) -> Option<Vec<u8>> {
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof).ok()?;
    Some(compressed(&ark_groth16::Proof::<Bn254> {
        a: -proof.a,
        b: -proof.b,
        c: proof.c,
    }))
}

/// The verifying key of the elusiv send-quadra circuit, see [ELUSIV_PROOF].
fn elusiv_vk() -> ark_groth16::VerifyingKey<Bn254> {
    ark_groth16::VerifyingKey {
        alpha_g1: utils::G1Affine_from_str_projective((
            "8057073471822347335074195152835286348058235024870127707965681971765888348219",
            "14493022634743109860560137600871299171677470588934003383462482807829968516757",
            "1",
        )),
        beta_g2: utils::G2Affine_from_str_projective((
            (
                "3572582736973115805854009786889644784414020463323864932822856731322980736092",
                "20796599916820806690555061040933219683613855446136615092456120794141344002056",
            ),
            (
                "6655819316204680004365614375508079580461146204424752037766280753854543388537",
                "21051385956744942198035008062816432434887289184811055343085396392904977398400",
            ),
            ("1", "0"),
        )),
        gamma_g2: utils::G2Affine_from_str_projective((
            (
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ),
            (
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ),
            ("1", "0"),
        )),
        delta_g2: utils::G2Affine_from_str_projective((
            (
                "11998653647826530912022227389593270429577129765091819606672414955204726946137",
                "12850197969502293778482300034606665950383830355768697463743623195959747528569",
            ),
            (
                "3371177482557063281015231215914240035716553874474070718078727302911297506634",
                "12667795686197095991004340383609552078675969789404912385920584439828198138754",
            ),
            ("1", "0"),
        )),
        gamma_abc_g1: [
            [
                "11423936163622682661315257948859256751456935745483672301927753823261895199269",
                "8106299131826030264309317289206035584499915702251874486285904804204850744645",
                "1",
            ],
            [
                "3101734373871983241904605625023311773791709350380811153571118050344636150719",
                "5892752048111020912174143187873113013528793690570548925602265811558514488885",
                "1",
            ],
            [
                "10476231653569587456624794227763775706638536733174066539315272867287760110504",
                "10966166298405300401399180388536732567182096690752823243070979263725671251842",
                "1",
            ],
            [
                "3616644883823724294840639617628786582022507076201411671428851342676842026051",
                "20036054300972762576589546578455562677975529109923089992859054028247449793275",
                "1",
            ],
            [
                "8922146185459718802170954039785431585338226940878465749467742893964332142463",
                "6543899100030899685821688665010402257161600764202006060926513825176262562594",
                "1",
            ],
            [
                "8838880056209295823278313283853562429175894016112442003934942661774390156254",
                "12827213619164270378479427160832201667918020494718807523503415302940668517033",
                "1",
            ],
            [
                "2830281053896850092944028355764636104294475011402565423874976766597400897579",
                "13415270586926186600118105749667385774136247571413308961986554361125375974552",
                "1",
            ],
            [
                "18596510315364411631453906928618372802526744665579937948378160099177646939132",
                "13639164510921866583928930414183864880892036368934098358398305969672652727368",
                "1",
            ],
            [
                "5166155439194150342865876104665292251058885686253625593517703833929767249773",
                "15776325379616919283841092402757993241658241305931554423955510623840777140969",
                "1",
            ],
            [
                "244871576834190719988785477479956000478101720979685216270364011881385785410",
                "5006539956367064800739393540924950096169041851058318954717373683020872268739",
                "1",
            ],
            [
                "3379906259197166810955208903373839920133048860227880343760386881009843909062",
                "20232197429675204807642408172750830052412585778140676948557231371164499652906",
                "1",
            ],
            [
                "5520775405859402378836749033719619657978092778322140710653552702896452870563",
                "2840091105079872357493316251142119838752629278546220113584117974897982339624",
                "1",
            ],
            [
                "520211872811929422003078090188660039184112525356441893145895540025777918752",
                "18510673159743652418577623905535570073301952222198134524503321213201497608215",
                "1",
            ],
            [
                "6431234738107765889030689757699276709534858281277744012577221575246765244517",
                "4178355859219522686761165914894952086513502987193412248095296044093289572534",
                "1",
            ],
            [
                "4759337634951432350348093011115687353434771991388975508607474262950775320629",
                "3583982358135750838996058092244844686884741536705305315993181569552518297411",
                "1",
            ],
        ]
        .into_iter()
        .map(|s| utils::G1Affine_from_str_projective((s[0], s[1], s[2])))
        .collect(),
    }
}

/// The prepared verifying key, as four parts, of a verifying key whose points are all the identity.
/// The infinity flag is set in the last byte of each point, with the given first byte, which is 0 in
/// the canonical encoding.
fn identity_pvk(num_public_inputs: usize, first_byte: u8) -> [Vec<u8>; 4] {
    let [g1, g2, _] = identity_proof(first_byte);
    [
        g1.repeat(num_public_inputs + 1),
        compressed(&Fq12::one()),
        g2.clone(),
        g2,
    ]
}

/// The proof (A, B, C) whose points are all the identity, encoded as in [identity_pvk].
fn identity_proof(first_byte: u8) -> [Vec<u8>; 3] {
    let mut g1 = vec![0; G1_SIZE];
    g1[0] = first_byte;
    g1[G1_SIZE - 1] = INFINITY_FLAG;
    let mut g2 = vec![0; G2_SIZE];
    g2[0] = first_byte;
    g2[G2_SIZE - 1] = INFINITY_FLAG;
    [g1.clone(), g2, g1]
}

//
// Groth16 verification tests
//

#[test]
fn test_verify_groth16_in_bytes_round_trip() {
    // A proof from arkworks verifies with the prepared verifying key, and only for its public inputs.
    let mut rng = StdRng::seed_from_u64(0);
    let (a, b) = (Fr::from(123), Fr::from(456));
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        Fibonacci::<Fr>::new(42, a, b),
        &mut rng,
    )
    .unwrap();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
        Fibonacci::<Fr>::new(42, a, b),
        &params,
        &mut rng,
    )
    .unwrap();

    let vk = compressed(&params.vk);
    assert_eq!(get_public_inputs_num(vk.len()), Ok(2));
    let pvk = prepare_pvk_bytes(&vk).unwrap();
    assert_eq!(
        pvk,
        PreparedVerifyingKey::from(&params.vk).serialize().unwrap()
    );

    let inputs = Inputs::from_parts(
        pvk.try_into().unwrap(),
        [compressed(&a), compressed(&b)].concat(),
        compressed(&proof),
    );
    assert_eq!(verify(&inputs), Ok(true));
    let swapped = [compressed(&b), compressed(&a)].concat();
    assert_eq!(verify(&inputs.with(PUBLIC_INPUTS_PART, swapped)), Ok(false));
}

#[test]
fn test_verify_groth16_in_bytes_vectors() {
    let elusiv_pvk: [Vec<u8>; 4] = PreparedVerifyingKey::from(&elusiv_vk())
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let elusiv = Inputs::from_parts(
        elusiv_pvk,
        decode(ELUSIV_PUBLIC_INPUTS),
        decode(ELUSIV_PROOF),
    );
    let mut elusiv_other_input = decode(ELUSIV_PUBLIC_INPUTS);
    elusiv_other_input[0] ^= 1;

    // (inputs, expected result)
    for (inputs, expected) in [
        (valid(), true),
        (
            Inputs::new(ZERO_INPUTS_PVK, ZERO_INPUTS, ZERO_INPUTS_PROOF),
            true,
        ),
        (elusiv.clone(), true),
        // Other public inputs, another proof or another verifying key.
        (valid().with(PUBLIC_INPUTS_PART, decode(ZERO_INPUTS)), false),
        (valid().with(PROOF_PART, decode(ZERO_INPUTS_PROOF)), false),
        (Inputs::new(ZERO_INPUTS_PVK, PUBLIC_INPUTS, PROOF), false),
        (elusiv.with(PUBLIC_INPUTS_PART, elusiv_other_input), false),
    ] {
        assert_eq!(verify(&inputs), Ok(expected));
    }
}

/// A verifying key whose points are all the identity accepts the proof whose points are all the
/// identity, for any public inputs: both sides of the verification equation are 1. Only the author
/// of a verifying key chooses its points.
#[test]
fn test_identity_verifying_key() {
    for public_inputs in [PUBLIC_INPUTS, ZERO_INPUTS] {
        let inputs = Inputs::from_parts(
            identity_pvk(2, 0),
            decode(public_inputs),
            identity_proof(0).concat(),
        );
        assert_eq!(verify(&inputs), Ok(true));
    }
}

/// Groth16 proofs are malleable: anyone can turn a proof into other proofs of the same statement,
/// so the bytes of a proof don't identify it.
#[test]
fn test_malleable_proofs() {
    // The re-randomization of ark-groth16 only uses delta from the verifying key.
    let delta_neg = G2Affine::deserialize_compressed(&decode(PVK[3])[..]).unwrap();
    let vk = ark_groth16::VerifyingKey::<Bn254> {
        delta_g2: -delta_neg,
        ..Default::default()
    };
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(&decode(PROOF)[..]).unwrap();
    let rerandomized =
        Groth16::<Bn254>::rerandomize_proof(&vk, &proof, &mut StdRng::seed_from_u64(0));

    for other_proof in [
        negate_proof(&decode(PROOF)).unwrap(),
        compressed(&rerandomized),
    ] {
        assert_ne!(other_proof, decode(PROOF));
        let inputs = valid().with(PROOF_PART, other_proof);
        assert_eq!(verify(&inputs), Ok(true));
    }
}

//
// Verifying key tests
//

#[test]
fn test_prepare_pvk_bytes() {
    let vk = decode(VK);
    assert_eq!(get_public_inputs_num(vk.len()), Ok(1));
    assert_eq!(prepare_pvk_bytes(&vk).unwrap(), PVK_OF_VK.map(decode));

    // Too short.
    for len in [0, GAMMA_ABC_LENGTH_OFFSET, vk.len() - 1] {
        assert!(prepare_pvk_bytes(&vk[..len]).is_err());
    }

    // More points in gamma_abc than there are.
    for gamma_abc_length in [3, u64::MAX] {
        let mut vk = vk.clone();
        vk[GAMMA_ABC_LENGTH_OFFSET..GAMMA_ABC_LENGTH_OFFSET + 8]
            .copy_from_slice(&gamma_abc_length.to_le_bytes());
        assert!(prepare_pvk_bytes(&vk).is_err());
    }
}

/// Non-standard, pinned: arkworks decodes a verifying key from the start of the input and ignores
/// what follows it, while [get_public_inputs_num] only looks at the length of the input. So
/// [get_public_inputs_num] may fail, or report more public inputs than the prepared verifying key
/// has, but never fewer.
#[test]
fn test_prepare_pvk_bytes_ignores_trailing_bytes() {
    let vk = decode(VK);
    let pvk = PVK_OF_VK.map(decode);

    let longer = [vk.clone(), vec![0; 3 * G1_SIZE]].concat();
    assert_eq!(get_public_inputs_num(longer.len()), Ok(4));
    assert_eq!(prepare_pvk_bytes(&longer).unwrap(), pvk);

    // Not a whole number of points longer.
    let longer = [vk.clone(), vec![0; 5]].concat();
    assert!(get_public_inputs_num(longer.len()).is_err());
    assert_eq!(prepare_pvk_bytes(&longer).unwrap(), pvk);

    // gamma_abc with fewer points than follow: one, so no public inputs, or none.
    for gamma_abc_length in [1, 0] {
        let mut shorter = vk.clone();
        shorter[GAMMA_ABC_LENGTH_OFFSET] = gamma_abc_length;
        let mut expected = pvk.clone();
        expected[0].truncate(gamma_abc_length as usize * G1_SIZE);
        assert_eq!(get_public_inputs_num(shorter.len()), Ok(1));
        assert_eq!(prepare_pvk_bytes(&shorter).unwrap(), expected);
    }
}

#[test]
fn test_public_inputs_num() {
    for i in 0..100 {
        let vk = ark_groth16::VerifyingKey::<Bn254> {
            alpha_g1: G1Affine::identity(),
            beta_g2: G2Affine::identity(),
            gamma_g2: G2Affine::identity(),
            delta_g2: G2Affine::identity(),
            gamma_abc_g1: repeat_n(G1Affine::identity(), i + 1).collect(),
        };
        assert_eq!(get_public_inputs_num(compressed(&vk).len()), Ok(i));
    }

    // Shorter than a verifying key without public inputs, or not a whole number of points longer.
    let without_public_inputs = GAMMA_ABC_LENGTH_OFFSET + 8 + G1_SIZE;
    for len in [0, without_public_inputs - 1, without_public_inputs + 1] {
        assert!(get_public_inputs_num(len).is_err());
    }
}

//
// Encoding tests
//

/// Public inputs are 32-byte little-endian scalars. They must be canonical, that is, smaller than
/// the order r of the scalar field, and as many as the verifying key expects.
#[test]
fn test_public_inputs_encoding() {
    let r = modulus::<Fr>();
    let public_inputs = decode(PUBLIC_INPUTS);
    let (a, b) = public_inputs.split_at(SCALAR_SIZE);
    let wrong_count = Err(FastCryptoError::GeneralError(
        "malformed verifying key".to_string(),
    ));

    // (public inputs, expected result)
    for (public_inputs, expected) in [
        (public_inputs.clone(), Ok(true)),
        // a + r is the same scalar as a, but not canonical.
        (
            [le_bytes(&(BigUint::from_bytes_le(a) + &r)), b.to_vec()].concat(),
            Err(FastCryptoError::InvalidInput),
        ),
        ([le_bytes(&(&r - 1u8)), b.to_vec()].concat(), Ok(false)),
        (
            [vec![0xff; SCALAR_SIZE], b.to_vec()].concat(),
            Err(FastCryptoError::InvalidInput),
        ),
        // Not a whole number of scalars.
        (
            public_inputs[1..].to_vec(),
            Err(FastCryptoError::InputLengthWrong(SCALAR_SIZE)),
        ),
        // Fewer or more scalars than the verifying key expects.
        (vec![], wrong_count.clone()),
        (a.to_vec(), wrong_count.clone()),
        (
            [public_inputs.clone(), vec![0; SCALAR_SIZE]].concat(),
            wrong_count,
        ),
    ] {
        let inputs = valid().with(PUBLIC_INPUTS_PART, public_inputs);
        assert_eq!(verify(&inputs), expected);
    }
}

/// Points are compressed as in arkworks: the x-coordinate in little-endian, with two flags in the
/// top bits of the last byte. The x-coordinate must be canonical, the point on the curve and, in
/// G2, in the subgroup of order r. Each part must also be long enough.
#[test]
fn test_invalid_points() {
    let proof = decode(PROOF);
    let a = &proof[..G1_SIZE];
    let with_a = |new_a: &[u8]| valid().with(PROOF_PART, [new_a, &proof[G1_SIZE..]].concat());

    // x = 1 is on the curve, and 1 + p is the same x-coordinate, but not canonical.
    assert!(G1Affine::get_point_from_x_unchecked(Fq::one(), false).is_some());
    let x_plus_p = le_bytes(&(modulus::<Fq>() + 1u8));
    let mut both_flags = a.to_vec();
    both_flags[G1_SIZE - 1] |= INFINITY_FLAG | NEGATIVE_Y_FLAG;
    let b_not_in_subgroup = [a, &decode(G2_NOT_IN_SUBGROUP), &proof[G1_SIZE + G2_SIZE..]].concat();
    let mut alpha_beta_not_canonical = decode(PVK[1]);
    alpha_beta_not_canonical[..32].copy_from_slice(&le_bytes(&modulus::<Fq>()));
    let mut vk_gamma_abc_not_on_curve = decode(PVK[0]);
    vk_gamma_abc_not_on_curve[..G1_SIZE].copy_from_slice(&G1_NOT_ON_CURVE);

    for inputs in [
        with_a(&G1_NOT_ON_CURVE),
        with_a(&x_plus_p),
        with_a(&both_flags),
        valid().with(PROOF_PART, b_not_in_subgroup),
        valid().with(0, vk_gamma_abc_not_on_curve),
        valid().with(1, alpha_beta_not_canonical),
        valid().with(2, decode(G2_NOT_IN_SUBGROUP)),
        valid().with(3, decode(G2_NOT_IN_SUBGROUP)),
    ] {
        assert_eq!(verify(&inputs), Err(FastCryptoError::InvalidInput));
    }

    // Three parts instead of four.
    assert_eq!(
        PreparedVerifyingKey::deserialize(&valid().0[..3]),
        Err(FastCryptoError::InputLengthWrong(3))
    );

    // Each part one byte too short.
    for part in [0, 1, 2, 3, PROOF_PART] {
        let mut inputs = valid();
        inputs.0[part].pop();
        assert_eq!(verify(&inputs), Err(FastCryptoError::InvalidInput));
    }
}

/// Non-standard, pinned: arkworks ignores bytes after the proof and after the last three parts of
/// the prepared verifying key, and decodes a compressed point with the infinity flag as the
/// identity, whatever its x-coordinate. So there are many encodings of a statement and a proof.
#[test]
fn test_lenient_encodings() {
    for part in [1, 2, 3, PROOF_PART] {
        let mut inputs = valid();
        inputs.0[part].extend([0xab; 3]);
        assert_eq!(verify(&inputs), Ok(true));
    }

    // The identity with x = 1, in G1 and in G2.
    let [g1, g2, _] = identity_proof(1);
    assert!(G1Affine::deserialize_compressed(&g1[..]).unwrap().is_zero());
    assert!(G2Affine::deserialize_compressed(&g2[..]).unwrap().is_zero());
    let inputs = Inputs::from_parts(
        identity_pvk(2, 1),
        decode(PUBLIC_INPUTS),
        identity_proof(1).concat(),
    );
    assert_eq!(verify(&inputs), Ok(true));
}

/// alpha_beta may be any canonical element of Fq12: it isn't checked to be in GT, the subgroup of
/// order r. Verification compares it with a product of pairings, which is in GT, so it fails.
#[test]
fn test_alpha_beta_outside_gt() {
    for alpha_beta in [Fq12::zero(), Fq12::from(2u64)] {
        let inputs = valid().with(1, compressed(&alpha_beta));
        assert_eq!(verify(&inputs), Ok(false));
    }
}

//
// Proptests
//

proptest! {
    // Each case runs a pairing, which is slow in debug builds.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Changes to valid inputs never make verification panic, and the result only verifies if the
    /// prepared verifying key and the public inputs still decode to the same values: the proof may
    /// change, see [test_malleable_proofs], but not the statement.
    #[test]
    fn test_verify_mutated_inputs(mutations in vec(arb_mutation(), 1..4)) {
        let mut inputs = valid();
        for mutation in &mutations {
            inputs.apply(mutation, negate_proof);
        }
        if verify(&inputs) == Ok(true) {
            prop_assert_eq!(statement(&inputs), statement(&valid()));
        }
    }

    /// [prepare_pvk_bytes] never panics. Sui checks [get_public_inputs_num] against its limit
    /// before it prepares a key, so when both succeed, [get_public_inputs_num] must report at least
    /// as many public inputs as the prepared verifying key has. Since trailing bytes are ignored, see
    /// [test_prepare_pvk_bytes_ignores_trailing_bytes], [prepare_pvk_bytes] may succeed when
    /// [get_public_inputs_num] fails.
    #[test]
    fn test_prepare_mutated_vk(mutations in vec(arb_byte_mutation(), 1..4)) {
        let mut vk = decode(VK);
        for mutation in &mutations {
            mutation.apply(&mut vk);
        }
        if let (Ok(pvk), Ok(num_public_inputs)) =
            (prepare_pvk_bytes(&vk), get_public_inputs_num(vk.len()))
        {
            prop_assert!(pvk[0].len() / G1_SIZE <= num_public_inputs + 1);
        }
    }
}
