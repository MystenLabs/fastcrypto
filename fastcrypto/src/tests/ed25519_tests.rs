// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::Encoding;
use crate::test_helpers::verify_serialization;
use crate::traits::{InsecureDefault, Signer};
use crate::{
    ed25519::{
        Ed25519AggregateSignature, Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey,
        Ed25519PublicKeyAsBytes, Ed25519Signature, Ed25519SignatureAsBytes,
        ED25519_PRIVATE_KEY_LENGTH, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
    },
    encoding::Base64,
    hash::{HashFunction, Sha256, Sha3_256, Sha512},
    hmac::hkdf_generate_from_ikm,
    signature_service::SignatureService,
    test_helpers,
    traits::{AggregateAuthenticator, EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hex_literal::hex;
use proptest::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use proptest::{collection, sample};
use rand::{rngs::StdRng, SeedableRng as _};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use wycheproof::{eddsa::TestSet, TestResult};

//
// Helper functions
//

const MSG: &[u8] = b"Hello, world!";

/// The message of the ZIP215 test cases in ed25519-consensus.
const ZIP215_MSG: &[u8] = b"Zcash";

const PK_LENGTH: usize = ED25519_PUBLIC_KEY_LENGTH;
const SIG_LENGTH: usize = ED25519_SIGNATURE_LENGTH;
const SK_LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH;

/// The order ℓ = 2^252 + 27742317777372353535851937790883648493 of the prime-order subgroup,
/// little-endian.
const GROUP_ORDER: [u8; 32] =
    hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

/// The field modulus p = 2^255 - 19, little-endian.
const FIELD_MODULUS: [u8; 32] =
    hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

/// A point is encoded as its y-coordinate (little-endian) with the sign of x in the top bit.
const SIGN_BIT: u8 = 0x80;

/// The values y < 19 that are y-coordinates of points. They are the only points with an encoding
/// y + p below 2^255, which ZIP215 accepts and RFC 8032 rejects.
const SMALL_Y_ON_CURVE: [u8; 12] = [0, 1, 3, 4, 5, 6, 9, 10, 14, 15, 16, 18];

/// The canonical encodings of the eight points of small order (the 8-torsion subgroup). The first
/// one is the identity.
const SMALL_ORDER_CANONICAL: [[u8; PK_LENGTH]; 8] = [
    // (0, 1), the identity.
    hex!("0100000000000000000000000000000000000000000000000000000000000000"),
    // (0, -1), of order 2.
    hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    // (±sqrt(-1), 0), of order 4. The first one is `Ed25519PublicKey::insecure_default()`.
    hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    hex!("0000000000000000000000000000000000000000000000000000000000000080"),
    // The four points of order 8.
    hex!("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hex!("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
];

/// The seed of the honest key in the proptests. The proptest strategies never sign with it.
const HONEST_SEED: [u8; SK_LENGTH] = [7; SK_LENGTH];

/// y = 2 is not the y-coordinate of a point.
const OFF_CURVE_ENCODING: [u8; PK_LENGTH] =
    hex!("0200000000000000000000000000000000000000000000000000000000000000");

/// The Wycheproof test case that ZIP215 accepts although Wycheproof marks it invalid: R is (0, 1)
/// encoded with the sign bit set, which RFC 8032 rejects.
const WYCHEPROOF_NON_CANONICAL_R_TC_ID: usize = 151;

/// The 1023-byte message of TEST 1024 in RFC 8032, section 7.1, in hex.
const RFC8032_TEST_1024_MSG: &str = concat!(
    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98",
    "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8",
    "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
    "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc",
    "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
    "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e",
    "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef",
    "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7",
    "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1",
    "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
    "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24",
    "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270",
    "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc",
    "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07",
    "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
    "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a",
    "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e",
    "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7",
    "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c",
    "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
    "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df",
    "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08",
    "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649",
    "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4",
    "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
    "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e",
    "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f",
    "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5",
    "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1",
    "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
    "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
    "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
);

/// The test vectors of RFC 8032, section 7.1: (secret key, public key, message, signature).
const RFC8032_TEST_VECTORS: [(&str, &str, &str, &str); 5] = [
    // TEST 1
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    // TEST 2
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    // TEST 3
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    // TEST 1024
    (
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        RFC8032_TEST_1024_MSG,
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    ),
    // TEST SHA(abc): the message is SHA-512("abc").
    (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
];

/// A (public key, signature, message) triple, as bytes.
type VerificationInput = ([u8; PK_LENGTH], [u8; SIG_LENGTH], Vec<u8>);

pub fn keys() -> Vec<Ed25519KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| Ed25519KeyPair::generate(&mut rng)).collect()
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let (pubkeys, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    (digest.to_vec(), pubkeys, signatures)
}

fn verify_batch_aggregate_signature_inputs() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<Ed25519PublicKey>,
    Vec<Ed25519PublicKey>,
    Ed25519AggregateSignature,
    Ed25519AggregateSignature,
) {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let digest1 = Sha256::digest(message1);
    let (pubkeys1, signatures1): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest1.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();
    let aggregated_signature1 = Ed25519AggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, world?";
    let digest2 = Sha256::digest(message2);
    let (pubkeys2, signatures2): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(2)
        .map(|kp| {
            let sig = kp.sign(digest2.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature2 = Ed25519AggregateSignature::aggregate(&signatures2).unwrap();
    (
        digest1.to_vec(),
        digest2.to_vec(),
        pubkeys1,
        pubkeys2,
        aggregated_signature1,
        aggregated_signature2,
    )
}

fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn signature(bytes: &[u8]) -> Ed25519Signature {
    <Ed25519Signature as ToFromBytes>::from_bytes(bytes).unwrap()
}

fn signature_bytes(r: &[u8; 32], s: &[u8; 32]) -> [u8; SIG_LENGTH] {
    let mut bytes = [0u8; SIG_LENGTH];
    bytes[..32].copy_from_slice(r);
    bytes[32..].copy_from_slice(s);
    bytes
}

fn with_sign_bit(mut encoding: [u8; PK_LENGTH]) -> [u8; PK_LENGTH] {
    encoding[31] |= SIGN_BIT;
    encoding
}

/// The integer s + ℓ for a 32-byte little-endian s < ℓ (it fits in 32 bytes since ℓ < 2^253).
fn add_group_order(s: &[u8]) -> [u8; 32] {
    let mut sum = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let digit = s[i] as u16 + GROUP_ORDER[i] as u16 + carry;
        sum[i] = digit as u8;
        carry = digit >> 8;
    }
    assert_eq!(carry, 0);
    sum
}

/// Verification from bytes, the way Sui's `ed25519_verify` Move native does it.
fn verify_bytes(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    match (
        Ed25519PublicKey::from_bytes(pk),
        <Ed25519Signature as ToFromBytes>::from_bytes(sig),
    ) {
        (Ok(pk), Ok(sig)) => pk.verify(msg, &sig).is_ok(),
        _ => false,
    }
}

/// Point decompression of curve25519-dalek 4, which ed25519-consensus does not use (it uses the
/// curve25519-dalek-ng fork). Like ZIP215, it accepts y ≥ p and x = 0 with the sign bit set.
fn decompress(encoding: &[u8; PK_LENGTH]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*encoding).decompress()
}

/// The encoding y + p of a field element y < 19, without the sign bit. These 19 field elements are
/// the only ones with two encodings below 2^255.
fn non_canonical_field_encoding(y: u8) -> [u8; PK_LENGTH] {
    assert!(y < 19);
    let mut encoding = FIELD_MODULUS;
    encoding[0] += y;
    encoding
}

/// All non-canonical encodings of points, generated as in the ZIP215 tests of ed25519-consensus:
/// the two points with x = 0 encoded with the sign bit set, then y + p with and without the sign
/// bit for each y < 19 that is the y-coordinate of a point. The first six have small order.
fn non_canonical_point_encodings() -> Vec<[u8; PK_LENGTH]> {
    let mut encodings = vec![
        with_sign_bit(SMALL_ORDER_CANONICAL[0]),
        with_sign_bit(SMALL_ORDER_CANONICAL[1]),
    ];
    for y in SMALL_Y_ON_CURVE {
        let encoding = non_canonical_field_encoding(y);
        encodings.extend([encoding, with_sign_bit(encoding)]);
    }
    encodings
}

/// The 14 encodings of points of small order: the 8 canonical ones and 6 non-canonical ones.
fn small_order_encodings() -> Vec<[u8; PK_LENGTH]> {
    SMALL_ORDER_CANONICAL
        .into_iter()
        .chain(non_canonical_point_encodings().into_iter().take(6))
        .collect()
}

/// The challenge k = SHA-512(R || A || M) mod ℓ, computed over the encodings of R and A as given.
fn challenge(r: &[u8], pk: &[u8], msg: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(pk);
    hasher.update(msg);
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().digest)
}

/// The secret scalar a and the nonce prefix of a seed (RFC 8032, section 5.1.5).
fn expand_seed(seed: &[u8; SK_LENGTH]) -> (Scalar, [u8; 32]) {
    let hash = Sha512::digest(seed).digest;
    let mut a = [0u8; 32];
    a.copy_from_slice(&hash[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    (
        Scalar::from_bytes_mod_order(a),
        hash[32..].try_into().unwrap(),
    )
}

fn reference_public_key(seed: &[u8; SK_LENGTH]) -> [u8; PK_LENGTH] {
    EdwardsPoint::mul_base(&expand_seed(seed).0)
        .compress()
        .to_bytes()
}

/// Signing as in RFC 8032, section 5.1.6, except that the small-order points
/// `SMALL_ORDER_CANONICAL[torsion_r]` and `SMALL_ORDER_CANONICAL[torsion_a]` are added to R and to
/// the public key. Only the owner of the seed can do this. Index 0 (the identity) gives RFC 8032.
fn reference_sign(
    seed: &[u8; SK_LENGTH],
    msg: &[u8],
    torsion_r: usize,
    torsion_a: usize,
) -> ([u8; PK_LENGTH], [u8; SIG_LENGTH]) {
    let (a, prefix) = expand_seed(seed);
    let torsion = |i: usize| decompress(&SMALL_ORDER_CANONICAL[i]).unwrap();
    let pk = (EdwardsPoint::mul_base(&a) + torsion(torsion_a))
        .compress()
        .to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(msg);
    let r = Scalar::from_bytes_mod_order_wide(&hasher.finalize().digest);
    let big_r = (EdwardsPoint::mul_base(&r) + torsion(torsion_r))
        .compress()
        .to_bytes();
    let s = r + challenge(&big_r, &pk, msg) * a;
    (pk, signature_bytes(&big_r, s.as_bytes()))
}

/// ZIP215 verification, written from the specification on top of curve25519-dalek 4: A and R
/// must decode (non-canonical encodings allowed), s < ℓ, and [8]([s]B - R - [k]A) = 0.
fn reference_verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <[u8; PK_LENGTH]>::try_from(pk),
        <[u8; SIG_LENGTH]>::try_from(sig),
    ) else {
        return false;
    };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: Option<Scalar> = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into();
    match (decompress(&pk), decompress(&r), s) {
        (Some(a), Some(big_r), Some(s)) => {
            (EdwardsPoint::mul_base(&s) - big_r - challenge(&r, &pk, msg) * a)
                .mul_by_cofactor()
                .is_identity()
        }
        _ => false,
    }
}

/// Checks that every batch verification API accepts the items iff each of them verifies on its
/// own, and returns that result. Items must be non-empty.
fn check_batch_agrees_with_individual(items: &[VerificationInput]) -> bool {
    assert!(!items.is_empty());
    let individual = items
        .iter()
        .all(|(pk, sig, msg)| verify_bytes(pk, sig, msg));

    // A public key that does not decode can't be put in a batch.
    let Ok(pks) = items
        .iter()
        .map(|(pk, _, _)| Ed25519PublicKey::from_bytes(pk))
        .collect::<Result<Vec<_>, _>>()
    else {
        assert!(!individual);
        return individual;
    };
    let sigs: Vec<Ed25519Signature> = items.iter().map(|(_, sig, _)| signature(sig)).collect();
    let msgs: Vec<&[u8]> = items.iter().map(|(_, _, msg)| msg.as_slice()).collect();
    let aggregate = Ed25519AggregateSignature::aggregate(&sigs).unwrap();
    let singles: Vec<Ed25519AggregateSignature> = sigs
        .iter()
        .map(|sig| Ed25519AggregateSignature::aggregate(std::slice::from_ref(sig)).unwrap())
        .collect();

    assert_eq!(
        Ed25519PublicKey::verify_batch_empty_fail_different_msg(&msgs, &pks, &sigs).is_ok(),
        individual
    );
    assert_eq!(
        aggregate.verify_different_msg(&pks, &msgs).is_ok(),
        individual
    );
    assert_eq!(
        Ed25519AggregateSignature::batch_verify(
            &singles.iter().collect::<Vec<_>>(),
            pks.iter()
                .map(|pk| std::slice::from_ref(pk).iter())
                .collect(),
            &msgs
        )
        .is_ok(),
        individual
    );
    if msgs.iter().all(|msg| *msg == msgs[0]) {
        assert_eq!(
            Ed25519PublicKey::verify_batch_empty_fail(msgs[0], &pks, &sigs).is_ok(),
            individual
        );
        assert_eq!(aggregate.verify(&pks, msgs[0]).is_ok(), individual);
        assert_eq!(
            Ed25519AggregateSignature::batch_verify(&[&aggregate], vec![pks.iter()], &[msgs[0]])
                .is_ok(),
            individual
        );
    }
    individual
}

//
// Serialization tests
//

#[test]
fn serialize_deserialize() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let default_pk = Ed25519PublicKey::insecure_default();
    let sk = kp.private();
    let message = b"hello, narwhal";
    let sig = keys().pop().unwrap().sign(message);
    let default_sig = Ed25519Signature::default();

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&default_pk, Some(default_pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));
    verify_serialization(&default_sig, Some(default_sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));
}

#[test]
fn test_serialize_deserialize_aggregate_signatures() {
    // Test empty aggregate signature
    let sig = Ed25519AggregateSignature::default();
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: Ed25519AggregateSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: Ed25519AggregateSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.sigs, sig.sigs);

    // Note that we do not check if the serialized variant equals as_ref() since the serialized
    // variant begins with a length prefix (of the vector of signatures).
}

#[test]
fn test_serde_signatures_human_readable() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);

    let serialized = serde_json::to_string(&signature).unwrap();
    assert_eq!(
        format!(r#""{}""#, Base64::encode(signature.sig.to_bytes())),
        serialized
    );
    let deserialized: Ed25519Signature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), signature.as_ref());
}

#[test]
fn key_pair_from_string_roundtrip() {
    let kp = keys().pop().unwrap();
    let kp_str = Base64::encode(kp.as_ref());
    let recovered = Ed25519KeyPair::from_str(&kp_str).unwrap();
    assert_eq!(kp, recovered);
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = Ed25519PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Ed25519PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <Ed25519Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

#[test]
fn test_to_from_bytes_aggregate_signatures() {
    // Test empty aggregate signature
    let sig = Ed25519AggregateSignature::default();
    let serialized = sig.as_bytes();
    let deserialized = Ed25519AggregateSignature::from_bytes(serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    let serialized = sig.as_bytes();
    let deserialized = Ed25519AggregateSignature::from_bytes(serialized).unwrap();
    assert_eq!(deserialized, sig);

    // Inputs whose length is not a multiple of the signature length must be rejected instead of
    // silently dropping the trailing bytes.
    let mut with_trailing_byte = serialized.to_vec();
    with_trailing_byte.push(0);
    assert!(Ed25519AggregateSignature::from_bytes(&with_trailing_byte).is_err());
    assert!(Ed25519AggregateSignature::from_bytes(&[0u8; 1]).is_err());
}

#[test]
fn test_from_bytes_accepted_lengths() {
    // Each type accepts exactly its own length (any multiple of the signature length for
    // aggregates, including zero). The bytes repeat a valid public key, so a 32-byte input decodes
    // as a public key, and any 32 or 64 bytes are a valid seed or signature encoding.
    let pk = keys().pop().unwrap().public().clone();
    for len in 0..=2 * SIG_LENGTH + 1 {
        let bytes: Vec<u8> = pk.as_bytes().iter().copied().cycle().take(len).collect();
        let json = format!("\"{}\"", Base64::encode(&bytes));

        let decoded = Ed25519PublicKey::from_bytes(&bytes);
        assert_eq!(decoded.is_ok(), len == PK_LENGTH);
        assert_eq!(
            serde_json::from_str::<Ed25519PublicKey>(&json).is_ok(),
            decoded.is_ok()
        );

        let decoded = <Ed25519Signature as ToFromBytes>::from_bytes(&bytes);
        assert_eq!(decoded.is_ok(), len == SIG_LENGTH);
        assert_eq!(
            serde_json::from_str::<Ed25519Signature>(&json).is_ok(),
            decoded.is_ok()
        );

        let decoded = Ed25519PrivateKey::from_bytes(&bytes);
        assert_eq!(decoded.is_ok(), len == SK_LENGTH);
        assert_eq!(Ed25519KeyPair::from_bytes(&bytes).is_ok(), decoded.is_ok());
        assert_eq!(
            serde_json::from_str::<Ed25519KeyPair>(&json).is_ok(),
            decoded.is_ok()
        );

        assert_eq!(
            Ed25519AggregateSignature::from_bytes(&bytes).is_ok(),
            len.is_multiple_of(SIG_LENGTH)
        );
    }
}

#[test]
fn test_public_key_serde_formats() {
    let pk = keys().pop().unwrap().public().clone();

    // Binary serde writes the 32 bytes with no length prefix, and BCS rejects any other length.
    assert_eq!(bcs::to_bytes(&pk).unwrap(), pk.as_bytes());
    assert_eq!(bincode::serialize(&pk).unwrap(), pk.as_bytes());
    let mut with_trailing_byte = pk.as_bytes().to_vec();
    with_trailing_byte.push(0);
    assert!(bcs::from_bytes::<Ed25519PublicKey>(&with_trailing_byte).is_err());
    assert!(bcs::from_bytes::<Ed25519PublicKey>(&pk.as_bytes()[..PK_LENGTH - 1]).is_err());

    // Human-readable serde is padded standard base64 of the bytes, decoded strictly: without the
    // padding, with non-zero padding bits, as hex or as a byte array it is rejected.
    let base64 = pk.encode_base64();
    assert_eq!(serde_json::to_string(&pk).unwrap(), format!("\"{base64}\""));
    let unpadded = base64.trim_end_matches('=');
    assert_ne!(unpadded, base64);
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // 32 bytes are 43 base64 digits and one '='. The last digit carries 4 bits of data and 2 bits
    // of padding.
    let mut digits: Vec<char> = base64.chars().collect();
    let last = alphabet.find(digits[42]).unwrap();
    digits[42] = alphabet.chars().nth(last ^ 1).unwrap();
    let non_zero_padding_bits: String = digits.into_iter().collect();
    for rejected in [
        format!("\"{unpadded}\""),
        format!("\"{non_zero_padding_bits}\""),
        format!("\"{}\"", hex::encode(pk.as_bytes())),
        serde_json::to_string(pk.as_bytes()).unwrap(),
    ] {
        assert!(serde_json::from_str::<Ed25519PublicKey>(&rejected).is_err());
    }

    // A bytes representation holds the same bytes, and converts back to the same key.
    let as_bytes = Ed25519PublicKeyAsBytes::from(&pk);
    assert_eq!(as_bytes.0, pk.as_bytes());
    assert_eq!(Ed25519PublicKey::try_from(&as_bytes).unwrap(), pk);
    assert_eq!(bcs::to_bytes(&as_bytes).unwrap(), pk.as_bytes());
}

// ZIP215 accepts two kinds of non-canonical point encodings that RFC 8032 rejects: y + p instead
// of y (possible for the 19 values y < 19), and x = 0 with the sign bit set. `as_bytes` returns
// the encoding that was decoded, so equality, hashing and ordering of public keys, and every
// serialization, follow the bytes and not the point.

#[test]
fn test_public_key_non_canonical_encodings() {
    let encodings = non_canonical_point_encodings();
    // 12 of the 19 values y < 19 are y-coordinates of points, which gives 24 encodings y + p. The
    // other two are (0, 1) and (0, -1) with the sign bit set.
    assert_eq!(encodings.len(), 26);
    // Six have small order. The other 20 have order 8ℓ, so they have a component of small order
    // and nobody knows their discrete logarithm.
    let points: Vec<EdwardsPoint> = encodings.iter().map(|e| decompress(e).unwrap()).collect();
    assert!(points[..6].iter().all(|p| p.is_small_order()));
    assert!(points[6..]
        .iter()
        .all(|p| !p.is_small_order() && !p.is_torsion_free()));

    for (encoding, point) in encodings.iter().zip(points) {
        let canonical = point.compress().to_bytes();
        assert_ne!(&canonical, encoding);
        let pk = Ed25519PublicKey::from_bytes(encoding).unwrap();
        let canonical_pk = Ed25519PublicKey::from_bytes(&canonical).unwrap();

        assert_eq!(pk.as_bytes(), encoding);
        assert_ne!(pk, canonical_pk);
        assert_eq!(hash_of(&pk), hash_of(encoding));
        assert_ne!(hash_of(&pk), hash_of(&canonical_pk));
        assert_eq!(pk.cmp(&canonical_pk), encoding.cmp(&canonical));

        assert_eq!(bcs::to_bytes(&pk).unwrap(), encoding);
        assert_eq!(bcs::from_bytes::<Ed25519PublicKey>(encoding).unwrap(), pk);
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(json, format!("\"{}\"", Base64::encode(encoding)));
        assert_eq!(serde_json::from_str::<Ed25519PublicKey>(&json).unwrap(), pk);
        let as_bytes = Ed25519PublicKeyAsBytes::from(&pk);
        assert_eq!(&as_bytes.0, encoding);
        assert_eq!(Ed25519PublicKey::try_from(&as_bytes).unwrap(), pk);
    }
}

#[test]
fn test_public_key_small_y_encodings() {
    // For y < 19, the encodings y and y + p, with either sign, decode iff y is in SMALL_Y_ON_CURVE,
    // both in fastcrypto and in the reference implementation. y = 2 is not.
    for y in 0..19u8 {
        let mut canonical = [0u8; PK_LENGTH];
        canonical[0] = y;
        let y_plus_p = non_canonical_field_encoding(y);
        let on_curve = SMALL_Y_ON_CURVE.contains(&y);
        for encoding in [
            canonical,
            with_sign_bit(canonical),
            y_plus_p,
            with_sign_bit(y_plus_p),
        ] {
            assert_eq!(decompress(&encoding).is_some(), on_curve);
            assert_eq!(Ed25519PublicKey::from_bytes(&encoding).is_ok(), on_curve);
            assert_eq!(
                bcs::from_bytes::<Ed25519PublicKey>(&encoding).is_ok(),
                on_curve
            );
        }
    }
    assert_eq!(OFF_CURVE_ENCODING[0], 2);

    // Off-curve encodings are rejected by every decoder. A bytes representation holds them, but
    // does not convert to a public key.
    assert!(Ed25519PublicKey::from_bytes(&OFF_CURVE_ENCODING).is_err());
    assert!(Ed25519PublicKey::decode_base64(&Base64::encode(OFF_CURVE_ENCODING)).is_err());
    assert!(bincode::deserialize::<Ed25519PublicKey>(&OFF_CURVE_ENCODING).is_err());
    let as_bytes = bcs::from_bytes::<Ed25519PublicKeyAsBytes>(&OFF_CURVE_ENCODING).unwrap();
    assert!(Ed25519PublicKey::try_from(&as_bytes).is_err());
}

#[test]
fn test_public_key_small_order_encodings() {
    // The constants are the eight distinct points of small order, encoded canonically.
    let points: Vec<EdwardsPoint> = SMALL_ORDER_CANONICAL
        .iter()
        .map(|e| decompress(e).unwrap())
        .collect();
    for (i, point) in points.iter().enumerate() {
        assert!(point.mul_by_cofactor().is_identity());
        assert_eq!(point.compress().to_bytes(), SMALL_ORDER_CANONICAL[i]);
        assert!(points[..i].iter().all(|other| other != point));
    }
    assert!(points[0].is_identity());

    // With the six non-canonical ones, all 14 encodings decode as public keys and keep their bytes.
    let encodings = small_order_encodings();
    assert_eq!(encodings.len(), 14);
    for encoding in &encodings {
        let pk = Ed25519PublicKey::from_bytes(encoding).unwrap();
        assert_eq!(pk.as_bytes(), encoding);
        assert!(decompress(encoding).unwrap().is_small_order());
    }

    // `insecure_default()` is the all-zero encoding, a point of order 4.
    assert_eq!(
        Ed25519PublicKey::insecure_default().as_bytes(),
        SMALL_ORDER_CANONICAL[2]
    );
}

#[test]
fn test_signature_from_bytes_does_not_validate() {
    // Any 64 bytes decode as a signature, and keep their bytes: whether R is a point and s < ℓ is
    // only checked by verify. Binary and human-readable serde, and bytes representations, agree.
    let sig = keys().pop().unwrap().sign(MSG);
    let r: [u8; 32] = sig.as_bytes()[..32].try_into().unwrap();
    let s: [u8; 32] = sig.as_bytes()[32..].try_into().unwrap();
    for bytes in [
        // s + ℓ.
        signature_bytes(&r, &add_group_order(&s)),
        // s with the top bit set.
        signature_bytes(&r, &with_sign_bit(s)),
        // R not on the curve.
        signature_bytes(&OFF_CURVE_ENCODING, &s),
        [0xff; SIG_LENGTH],
    ] {
        let decoded = signature(&bytes);
        assert_eq!(decoded.as_bytes(), bytes);
        assert_eq!(
            bcs::from_bytes::<Ed25519Signature>(&bytes).unwrap(),
            decoded
        );
        assert_eq!(bcs::to_bytes(&decoded).unwrap(), bytes);
        let json = format!("\"{}\"", Base64::encode(bytes));
        assert_eq!(
            serde_json::from_str::<Ed25519Signature>(&json).unwrap(),
            decoded
        );
        let as_bytes = bcs::from_bytes::<Ed25519SignatureAsBytes>(&bytes).unwrap();
        assert_eq!(Ed25519Signature::try_from(&as_bytes).unwrap(), decoded);
        assert!(Ed25519AggregateSignature::from_bytes(&bytes).is_ok());
    }
}

#[test]
fn test_private_keys_and_key_pairs() {
    // Any 32 bytes are a seed, including all zeros. The key pair derives its public key from the
    // seed as in RFC 8032.
    for seed in [[0u8; SK_LENGTH], [0xff; SK_LENGTH], GROUP_ORDER] {
        let kp = Ed25519KeyPair::from_bytes(&seed).unwrap();
        let (pk, sig) = reference_sign(&seed, MSG, 0, 0);
        assert_eq!(kp.as_bytes(), seed);
        assert_eq!(kp.public().as_bytes(), pk);
        assert_eq!(kp.sign(MSG).as_bytes(), sig);
        assert_eq!(
            Ed25519PrivateKey::from_bytes(&seed).unwrap().as_bytes(),
            seed
        );
    }

    // A key pair is serialized as its seed only, and deserialization derives the public key, so a
    // key pair whose public key does not match its seed can't be deserialized.
    let kp = keys().pop().unwrap();
    assert_eq!(bcs::to_bytes(&kp).unwrap(), kp.as_bytes());
    assert_eq!(
        serde_json::to_string(&kp).unwrap(),
        format!("\"{}\"", Base64::encode(kp.as_bytes()))
    );
    let mut seed_and_public_key = kp.as_bytes().to_vec();
    seed_and_public_key.extend_from_slice(keys()[0].public().as_bytes());
    assert!(Ed25519KeyPair::from_bytes(&seed_and_public_key).is_err());
    assert!(bcs::from_bytes::<Ed25519KeyPair>(&seed_and_public_key).is_err());
    assert!(Ed25519KeyPair::decode_base64(&Base64::encode(&seed_and_public_key)).is_err());
}

//
// Signature verification tests
//

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    let signature = kp.sign(digest.as_ref());

    // Verify the signature.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Sha256::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

#[test]
fn test_default_values() {
    let valid_kp = keys().pop().unwrap();
    let valid_sig = valid_kp.sign(b"message");
    let default_sig = Ed25519Signature::default();
    let valid_pk = valid_kp.public().clone();
    let default_pk = Ed25519PublicKey::insecure_default();
    let valid_agg_sig =
        Ed25519AggregateSignature::aggregate(std::slice::from_ref(&valid_sig)).unwrap();
    let default_agg_sig = Ed25519AggregateSignature::default();

    // Default sig should fail (for both types of keys)
    assert!(valid_pk.verify(b"message", &default_sig).is_err());
    assert!(default_pk.verify(b"message", &default_sig).is_err());

    // Verification with default pk should fail.
    assert!(default_pk.verify(b"message", &valid_sig).is_err());

    // Verifications with one of the default values should fail.
    assert!(valid_agg_sig
        .verify(std::slice::from_ref(&valid_pk), b"message")
        .is_ok());
    assert!(valid_agg_sig
        .verify(std::slice::from_ref(&default_pk), b"message")
        .is_err());
    assert!(default_agg_sig.verify(&[valid_pk], b"message").is_err());
    assert!(default_agg_sig.verify(&[default_pk], b"message").is_err());
}

#[test]
fn test_rfc8032_test_vectors() {
    for (sk, pk, msg, sig) in RFC8032_TEST_VECTORS {
        let (sk, pk, msg, sig) = (
            hex::decode(sk).unwrap(),
            hex::decode(pk).unwrap(),
            hex::decode(msg).unwrap(),
            hex::decode(sig).unwrap(),
        );
        // Binary serde is the raw bytes.
        let private_key: Ed25519PrivateKey = bincode::deserialize(&sk).unwrap();
        let public_key: Ed25519PublicKey = bincode::deserialize(&pk).unwrap();
        let expected: Ed25519Signature = bincode::deserialize(&sig).unwrap();
        let kp = Ed25519KeyPair::from(private_key);
        assert_eq!(kp.public(), &public_key);
        let signature = kp.sign(&msg);
        assert_eq!(bincode::serialize(&signature).unwrap(), sig);
        assert!(public_key.verify(&msg, &expected).is_ok());
        assert!(reference_verify(&pk, &sig, &msg));
        let (reference_pk, reference_sig) = reference_sign(&sk.try_into().unwrap(), &msg, 0, 0);
        assert_eq!(reference_pk.as_slice(), pk);
        assert_eq!(reference_sig.as_slice(), sig);
    }
    assert_eq!(hex::decode(RFC8032_TEST_VECTORS[3].2).unwrap().len(), 1023);
    assert_eq!(
        hex::decode(RFC8032_TEST_VECTORS[4].2).unwrap(),
        Sha512::digest(b"abc").digest
    );
}

#[test]
fn test_s_must_be_reduced() {
    // s + ℓ is the same scalar as s, but verify requires s < ℓ, so it is not a second signature.
    let kp = keys().pop().unwrap();
    let sig = kp.sign(MSG);
    let r: [u8; 32] = sig.as_bytes()[..32].try_into().unwrap();
    let s = add_group_order(&sig.as_bytes()[32..]);
    assert!(kp
        .public()
        .verify(MSG, &signature(&signature_bytes(&r, &s)))
        .is_err());

    // The bound is exact. Under the identity as public key, (R, s) with R = [s]B verifies iff
    // s < ℓ: s = ℓ - 1 verifies, while s = ℓ, which is 0 mod ℓ, does not verify with R = [0]B.
    let pk = Ed25519PublicKey::from_bytes(&SMALL_ORDER_CANONICAL[0]).unwrap();
    let minus_one = -Scalar::ONE;
    let r = EdwardsPoint::mul_base(&minus_one).compress().to_bytes();
    assert!(pk
        .verify(MSG, &signature(&signature_bytes(&r, minus_one.as_bytes())))
        .is_ok());
    let zero = signature_bytes(&SMALL_ORDER_CANONICAL[0], &[0; 32]);
    assert!(pk.verify(MSG, &signature(&zero)).is_ok());
    let order = signature_bytes(&SMALL_ORDER_CANONICAL[0], &GROUP_ORDER);
    assert!(pk.verify(MSG, &signature(&order)).is_err());
    assert!(!reference_verify(&SMALL_ORDER_CANONICAL[0], &order, MSG));
}

#[test]
fn test_cofactored_verification() {
    // ZIP215 checks [8][s]B = [8]R + [8][k]A, so components of small order in R and in A do not
    // matter. The owner of a seed can sign with R + T, and can sign for A + T, for each of the 8
    // points T of small order. These are 8 different public keys for the same seed. Cofactorless
    // verification ([s]B = R + [k]A) rejects all of them when only R has a small-order component.
    let seed = [1u8; SK_LENGTH];
    let mut public_keys = vec![];
    for torsion_a in 0..SMALL_ORDER_CANONICAL.len() {
        for torsion_r in 0..SMALL_ORDER_CANONICAL.len() {
            let (pk, sig) = reference_sign(&seed, MSG, torsion_r, torsion_a);
            assert!(verify_bytes(&pk, &sig, MSG));
            assert!(reference_verify(&pk, &sig, MSG));

            let r: [u8; 32] = sig[..32].try_into().unwrap();
            let s = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).unwrap();
            let cofactorless = EdwardsPoint::mul_base(&s)
                == decompress(&r).unwrap() + challenge(&r, &pk, MSG) * decompress(&pk).unwrap();
            if torsion_a == 0 {
                assert_eq!(cofactorless, torsion_r == 0);
            }
            if torsion_r == 0 {
                public_keys.push(pk);
            }
        }
    }
    public_keys.sort();
    public_keys.dedup();
    assert_eq!(public_keys.len(), SMALL_ORDER_CANONICAL.len());
}

#[test]
fn test_challenge_hashes_encodings_as_given() {
    // k = SHA-512(R || A || M) is computed over the bytes of R and A as given, not over their
    // canonical encodings. With R a non-canonical encoding of a small-order point, [8]R = 0, so the
    // owner of a key can sign with s = [k]a. That verifies when k is computed over the given bytes
    // of R, and fails when it is computed over the canonical encoding of R.
    let seed = [2u8; SK_LENGTH];
    let (a, _) = expand_seed(&seed);
    let pk = reference_public_key(&seed);
    for r in &non_canonical_point_encodings()[..6] {
        let canonical = decompress(r).unwrap().compress().to_bytes();
        let s = challenge(r, &pk, MSG) * a;
        assert!(verify_bytes(&pk, &signature_bytes(r, s.as_bytes()), MSG));
        let s = challenge(&canonical, &pk, MSG) * a;
        assert!(!verify_bytes(&pk, &signature_bytes(r, s.as_bytes()), MSG));
    }
}

#[test]
fn test_small_order_public_keys() {
    // ZIP215 accepts public keys of small order, `insecure_default()` included. For such a key A,
    // [8][k]A = 0, so the verification equation [8][s]B = [8]R does not depend on the key or on the
    // message: (R, s) with R = [s]B verifies for every s < ℓ. A signature by an honest key does
    // not verify under them.
    let honest = keys().pop().unwrap();
    for pk in small_order_encodings() {
        let pk = Ed25519PublicKey::from_bytes(&pk).unwrap();
        for msg in [MSG, ZIP215_MSG, b""] {
            for s in [Scalar::ZERO, Scalar::ONE, -Scalar::ONE] {
                let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
                let sig = signature(&signature_bytes(&r, s.as_bytes()));
                assert!(pk.verify(msg, &sig).is_ok());
            }
            assert!(pk.verify(msg, &honest.sign(msg)).is_err());
        }
    }
}

#[test]
fn wycheproof_test() {
    use wycheproof::eddsa::TestFlag;

    let test_set = TestSet::load(wycheproof::eddsa::TestName::Ed25519).unwrap();
    let mut accepted_invalid = vec![];
    for test_group in test_set.test_groups {
        let pk = Ed25519PublicKey::from_bytes(&test_group.key.pk).unwrap();
        for test in test_group.tests {
            let verified = <Ed25519Signature as ToFromBytes>::from_bytes(&test.sig)
                .is_ok_and(|sig| pk.verify(&test.msg, &sig).is_ok());
            assert_eq!(
                verified,
                reference_verify(&test_group.key.pk, &test.sig, &test.msg),
                "tc {}",
                test.tc_id
            );
            match test.result {
                TestResult::Valid => assert!(verified, "tc {}", test.tc_id),
                TestResult::Invalid if verified => {
                    assert_eq!(test.flags, [TestFlag::InvalidEncoding]);
                    accepted_invalid.push(test.tc_id);
                }
                _ => {}
            }
        }
    }
    // ZIP215 accepts non-canonical encodings of R, which RFC 8032 rejects. That is the only
    // difference with Wycheproof's expectations.
    assert_eq!(accepted_invalid, [WYCHEPROOF_NON_CANONICAL_R_TC_ID]);
}

#[test]
fn ed25519_speccheck() {
    // The test vectors of "Taming the many EdDSAs" (Chalkias, Garillot, Nikolaenko, 2020).
    let msgs = [
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
    ];

    let pks = [
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];

    let sigs = [
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
    ];

    // 0-3: A and R of small or mixed order, verifying with the cofactored and the cofactorless
    //      equations.
    // 4, 5: A (and R in case 4) of mixed order, verifying only with the cofactored equation.
    // 6, 7: s ≥ ℓ.
    // 8, 9: R is a non-canonical encoding of a small-order point. Case 8 verifies only if k is
    //       computed over the canonical encoding of R, case 9 only over the given bytes, as here.
    // 10, 11: A is a non-canonical encoding of (0, -1). Case 10 verifies only with the cofactored
    //         equation, case 11 with both.
    let expected = [
        true, true, true, true, true, true, false, false, false, true, true, true,
    ];

    for i in 0..12 {
        let msg = hex::decode(msgs[i]).unwrap();
        let pk = hex::decode(pks[i]).unwrap();
        let sig = hex::decode(sigs[i]).unwrap();
        assert_eq!(expected[i], verify_bytes(&pk, &sig, &msg), "case {i}");
        assert_eq!(expected[i], reference_verify(&pk, &sig, &msg), "case {i}");
    }
}

//
// Aggregated signatures and batch verification tests
//

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = <Ed25519Signature as ToFromBytes>::from_bytes(&[0u8; 64]).unwrap();

    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Ed25519PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Ed25519PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_aggregate_signaature() {
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = Ed25519AggregateSignature::aggregate(&signatures).unwrap();

    let res = aggregated_signature.verify(&pubkeys[..], &digest);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_aggregate_signature_length_mismatch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = Ed25519AggregateSignature::aggregate(&signatures).unwrap();

    let res = aggregated_signature.verify(&pubkeys[..2], &digest);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_aggregate_signature_is_rejected() {
    // An empty Ed25519 aggregate signature must NOT verify trivially against any message; previously
    // `verify(empty_agg, &[], msg)` returned `Ok(())` because the batch verifier accepts an empty
    // batch as valid.
    let empty_agg: Ed25519AggregateSignature =
        Ed25519AggregateSignature::aggregate(std::iter::empty::<&Ed25519Signature>()).unwrap();
    assert!(empty_agg.verify(&[], b"attacker-chosen message").is_err());
    assert!(empty_agg
        .verify_different_msg(&[], &[b"attacker-chosen message"])
        .is_err());

    // batch_verify on an empty outer slice, or a batch that contains an empty aggregate, must
    // also be rejected.
    assert!(Ed25519AggregateSignature::batch_verify(
        &[],
        Vec::<std::slice::Iter<'_, Ed25519PublicKey>>::new(),
        &[]
    )
    .is_err());
    let (digest, pubkeys, signatures) = signature_test_inputs();
    let real_agg = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    let pk_lists = vec![pubkeys.iter(), [].iter()];
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&real_agg, &empty_agg],
        pk_lists,
        &[&digest[..], b"anything"]
    )
    .is_err());
}

#[test]
fn verify_invalid_aggregate_signature_public_key_switch() {
    let (digest, mut pubkeys, signatures) = signature_test_inputs();
    let aggregated_signature = Ed25519AggregateSignature::aggregate(&signatures).unwrap();

    pubkeys[0] = keys()[3].public().clone();

    let res = aggregated_signature.verify(&pubkeys[..], &digest);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_aggregate_signature() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_ok());
}

#[test]
fn verify_batch_missing_parameters_length_mismatch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Fewer pubkeys than signatures
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());

    // Fewer messages than signatures
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..]]
    )
    .is_err());
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());
}

#[test]
fn verify_batch_missing_keys_in_batch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Pubkeys missing at the end
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[1..].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // Pubkeys missing at the start
    assert!(Ed25519AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[..pubkeys2.len() - 1].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // add an extra signature to both aggregated_signature that batch_verify takes in
    let mut signatures1_with_extra = aggregated_signature1;
    let kp = &keys()[0];
    let sig = kp.sign(&digest1);
    let res = signatures1_with_extra.add_signature(sig);
    assert!(res.is_ok());

    let mut signatures2_with_extra = aggregated_signature2;
    let kp = &keys()[0];
    let sig2 = kp.sign(&digest1);
    let res = signatures2_with_extra.add_signature(sig2);
    assert!(res.is_ok());

    assert!(Ed25519AggregateSignature::batch_verify(
        &[&signatures1_with_extra, &signatures2_with_extra],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
}

#[test]
fn test_add_signatures_to_aggregate() {
    let pks: Vec<Ed25519PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = Ed25519AggregateSignature::default();
    // Test populated aggregate signature
    keys().into_iter().take(3).enumerate().for_each(|(i, kp)| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();

        // Verify that the binary representation is updated for each added signature
        let reconstructed = Ed25519AggregateSignature::from_bytes(sig1.as_ref()).unwrap();
        assert!(reconstructed.verify(&pks[..i], message).is_err());
        assert!(reconstructed.verify(&pks[..i + 1], message).is_ok());
    });

    assert!(sig1.verify(&pks, message).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = Ed25519AggregateSignature::default();

    let kp = &keys()[0];
    let sig = Ed25519AggregateSignature::aggregate(&[kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    let aggregated_signature = Ed25519AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<Ed25519Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_add_signatures_to_aggregate_different_messages() {
    let pks: Vec<Ed25519PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let messages: Vec<&[u8]> = vec![b"hello", b"world", b"!!!!!"];

    // Test 'add signature'
    let mut sig1 = Ed25519AggregateSignature::default();
    // Test populated aggregate signature
    for (i, kp) in keys().into_iter().take(3).enumerate() {
        let sig = kp.sign(messages[i]);
        sig1.add_signature(sig).unwrap();
    }

    assert!(sig1.verify_different_msg(&pks, &messages).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = Ed25519AggregateSignature::default();

    let kp = &keys()[0];
    let sig = Ed25519AggregateSignature::aggregate(&[kp.sign(messages[0])]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2
        .verify_different_msg(&pks[0..1], &messages[0..1])
        .is_ok());

    let aggregated_signature = Ed25519AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .zip(&messages)
            .take(3)
            .skip(1)
            .map(|(kp, message)| kp.sign(message))
            .collect::<Vec<Ed25519Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify_different_msg(&pks, &messages).is_ok());

    // Mismatch in number of pks and messages
    assert!(sig2.verify_different_msg(&pks, &messages[0..1]).is_err());
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = test_helpers::signature_test_inputs_different_msg::<Ed25519KeyPair>();
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = test_helpers::signature_test_inputs_different_msg::<Ed25519KeyPair>();

    // Mismatch between number of messages, signatures and public keys provided
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures[0..1],
    );
    assert!(res.is_err(), "{:?}", res);

    // One signature invalid
    inputs.signatures[0] = Ed25519Signature::default();
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);

    // No signatures provided
    let res = Ed25519PublicKey::verify_batch_empty_fail_different_msg::<&[u8]>(&[], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn test_batch_verification_zip215_matrix() {
    // The ZIP215 test cases of ed25519-consensus: every small-order encoding as public key and as
    // R, with s = 0. All 196 verify, in fastcrypto and in the reference implementation, one by one
    // and with every batch API, alone or all in one batch.
    let encodings = small_order_encodings();
    let items: Vec<VerificationInput> = encodings
        .iter()
        .flat_map(|pk| {
            encodings
                .iter()
                .map(|r| (*pk, signature_bytes(r, &[0; 32]), ZIP215_MSG.to_vec()))
        })
        .collect();
    assert_eq!(items.len(), 196);
    for item in &items {
        assert!(reference_verify(&item.0, &item.1, &item.2));
        assert!(check_batch_agrees_with_individual(std::slice::from_ref(
            item
        )));
    }
    assert!(check_batch_agrees_with_individual(&items));
}

#[test]
fn test_batch_verification_cofactored() {
    // Signatures with small-order components in R and in the public key verify in a batch, mixed
    // with honest signatures and with signatures under small-order keys, as they do individually.
    let mut items: Vec<VerificationInput> = (0..SMALL_ORDER_CANONICAL.len())
        .map(|i| {
            let (pk, sig) = reference_sign(&[i as u8; SK_LENGTH], MSG, i, (i + 3) % 8);
            (pk, sig, MSG.to_vec())
        })
        .collect();
    items.extend(keys().iter().map(|kp| {
        (
            kp.public().as_bytes().try_into().unwrap(),
            kp.sign(MSG).as_bytes().try_into().unwrap(),
            MSG.to_vec(),
        )
    }));
    for (i, pk) in non_canonical_point_encodings()[..6].iter().enumerate() {
        let s = Scalar::from(i as u64);
        let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
        items.push((*pk, signature_bytes(&r, s.as_bytes()), MSG.to_vec()));
    }
    assert!(check_batch_agrees_with_individual(&items));

    // And with a different message for each item.
    for (i, item) in items.iter_mut().enumerate() {
        let seed = [i as u8; SK_LENGTH];
        let msg = vec![i as u8; i];
        let (pk, sig) = reference_sign(&seed, &msg, i % 8, (i * 5) % 8);
        *item = (pk, sig, msg);
    }
    assert!(check_batch_agrees_with_individual(&items));
}

#[test]
fn test_batch_verification_rejects_any_invalid_item() {
    // A batch of valid signatures with one invalid item is rejected by every batch API, wherever
    // the item is.
    let honest: Vec<VerificationInput> = keys()
        .iter()
        .map(|kp| {
            (
                kp.public().as_bytes().try_into().unwrap(),
                kp.sign(MSG).as_bytes().try_into().unwrap(),
                MSG.to_vec(),
            )
        })
        .collect();
    let (pk, sig, _) = honest[0].clone();
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    let invalid: Vec<VerificationInput> = vec![
        // Another message.
        (pk, sig, b"Hello, world?".to_vec()),
        // s + ℓ.
        (pk, signature_bytes(&r, &add_group_order(&s)), MSG.to_vec()),
        // R not on the curve.
        (pk, signature_bytes(&OFF_CURVE_ENCODING, &s), MSG.to_vec()),
        // R of small order.
        (
            pk,
            signature_bytes(&SMALL_ORDER_CANONICAL[4], &s),
            MSG.to_vec(),
        ),
        // A small-order key with an honest signature.
        (SMALL_ORDER_CANONICAL[2], sig, MSG.to_vec()),
        // A small-order key with R of small order but s ≠ 0.
        (
            SMALL_ORDER_CANONICAL[2],
            signature_bytes(&SMALL_ORDER_CANONICAL[0], Scalar::ONE.as_bytes()),
            MSG.to_vec(),
        ),
    ];
    for item in invalid {
        assert!(!check_batch_agrees_with_individual(std::slice::from_ref(
            &item
        )));
        for position in 0..=honest.len() {
            let mut items = honest.clone();
            items.insert(position, item.clone());
            assert!(!check_batch_agrees_with_individual(&items));
        }
    }
}

//
// Other tests
//

#[test]
fn test_hkdf_generate_from_ikm() {
    let seed = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];
    let salt = &[3, 2, 1];
    let kp = hkdf_generate_from_ikm::<Sha3_256, Ed25519KeyPair>(seed, salt, &[]).unwrap();
    let kp2 = hkdf_generate_from_ikm::<Sha3_256, Ed25519KeyPair>(seed, salt, &[]).unwrap();
    assert_eq!(kp.private().as_bytes(), kp2.private().as_bytes());
}

#[test]
#[cfg(feature = "copy_key")]
fn test_copy_key_pair() {
    let kp = keys().pop().unwrap();
    let kp_copied = kp.copy();

    assert_eq!(kp.public().0.as_bytes(), kp_copied.public().0.as_bytes());
    assert_eq!(kp.private().0.as_bytes(), kp_copied.private().0.as_bytes());
}

#[test]
fn keypair_from_signing_key() {
    // Create two equal keypairs.
    let kp1 = keys().pop().unwrap();
    let kp2 = keys().pop().unwrap();
    assert_eq!(kp1, kp2);

    let signing_key = kp1.private().0.clone();
    let restored_kp = Ed25519KeyPair::from(signing_key);
    assert_eq!(kp2, restored_kp);
}

#[test]
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign(b"Hello, world!");
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

#[test]
fn fmt_aggregate_signature() {
    // Test empty aggregate signature
    let sig = Ed25519AggregateSignature::default();
    assert_eq!(sig.to_string(), "[]");

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<Ed25519PublicKey>, Vec<Ed25519Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = Ed25519AggregateSignature::aggregate(&signatures).unwrap();
    assert_eq!(
        sig.to_string(),
        format!(
            "[\"{}\", \"{}\", \"{}\"]",
            Base64::encode(signatures[0].as_bytes()),
            Base64::encode(signatures[1].as_bytes()),
            Base64::encode(signatures[2].as_bytes())
        )
    );
}

#[test]
fn hash_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();

    let mut hasher = DefaultHasher::new();
    public_key.hash(&mut hasher);
    let digest = hasher.finish();

    let mut other_hasher = DefaultHasher::new();
    public_key.as_bytes().hash(&mut other_hasher);
    let expected = other_hasher.finish();
    assert_eq!(expected, digest);
}

#[test]
fn fmt_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    assert_eq!(
        public_key.to_string(),
        Base64::encode(public_key.as_bytes())
    );
}

#[test]
fn debug_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    assert_eq!(
        format!("{:?}", public_key),
        Base64::encode(public_key.as_bytes())
    );
}

#[test]
fn public_key_ordering() {
    // Public keys are ordered by their bytes.
    let pks: Vec<Ed25519PublicKey> = keys().iter().map(|kp| kp.public().clone()).collect();
    for pk1 in &pks {
        for pk2 in &pks {
            assert_eq!(pk1.as_bytes().cmp(pk2.as_bytes()), pk1.cmp(pk2));
            assert_eq!(
                pk1.as_bytes().cmp(pk2.as_bytes()),
                pk1.partial_cmp(pk2).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();

    // Spawn the signature service.
    let service = SignatureService::new(kp);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let signature = service.request_signature(digest).await;

    // Verify the signature we received.
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
}

// Checks if the private keys zeroed out
#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.0) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        // SigningKey.zeroize() zeroizes seed and s value in the struct,
        // (the rest does not contain private key material), hence shifting the bytes by 192.
        // pub struct SigningKey {
        //     seed: [u8; 32],
        //     s: Scalar,
        //     prefix: [u8; 32],
        //     vk: VerificationKey,
        // }
        // Starting at index 192 is precisely the 32 bytes of the private key.
        unsafe {
            for (i, &byte) in sk_bytes.iter().enumerate().take(ED25519_PRIVATE_KEY_LENGTH) {
                assert_eq!(*ptr.add(i + 192), byte);
            }
        }

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, ED25519_PRIVATE_KEY_LENGTH) };
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Starting at index 192 where the 32 bytes of the private key lives, is zeroized.
    unsafe {
        for i in 0..ED25519_PRIVATE_KEY_LENGTH {
            assert_eq!(*ptr.add(i + 192), 0);
        }
    }

    // Check that self.bytes is taken by the OnceCell default value.
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, ED25519_PRIVATE_KEY_LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Ed25519PrivateKey>");
        assert_eq!(format!("{:?}", sk), "<elided secret for Ed25519PrivateKey>");
    });
}

#[test]
#[cfg(feature = "copy_key")]
fn serialize_private_key_only_for_keypair() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|kp| {
        let sk = kp.copy().private();
        let serialized_kp = bincode::serialize(&kp).unwrap();
        let serialized_sk = bincode::serialize(&sk).unwrap();
        assert_eq!(serialized_sk, serialized_kp);
    });
}

//
// Proptests
//

fn arb_keypair() -> impl Strategy<Value = Ed25519KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Ed25519KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

/// 32 bytes that are likely to be interesting public keys: random bytes, honest keys with or
/// without a flipped bit, the encodings y and y + p of small values of y with either sign, and the
/// small-order encodings. About three quarters decode.
fn arb_public_key_bytes() -> impl Strategy<Value = [u8; PK_LENGTH]> {
    prop_oneof![
        any::<[u8; PK_LENGTH]>(),
        (
            any::<[u8; SK_LENGTH]>(),
            proptest::option::of(0..PK_LENGTH * 8)
        )
            .prop_map(|(seed, bit)| {
                let mut pk = reference_public_key(&seed);
                if let Some(bit) = bit {
                    pk[bit / 8] ^= 1 << (bit % 8);
                }
                pk
            }),
        (0..19u8, any::<bool>(), any::<bool>()).prop_map(|(y, plus_p, sign)| {
            let mut encoding = if plus_p {
                FIELD_MODULUS
            } else {
                [0u8; PK_LENGTH]
            };
            encoding[0] += y;
            if sign {
                encoding[31] |= SIGN_BIT;
            }
            encoding
        }),
        sample::select(small_order_encodings()),
    ]
}

/// Valid (public key, signature, message) triples for `msg`: honest signatures, signatures with
/// small-order components in R and in the public key (which only the owner of the seed can make),
/// and signatures under small-order public keys.
fn arb_valid_verification_input(msg: Vec<u8>) -> BoxedStrategy<VerificationInput> {
    let torsion = || prop_oneof![Just(0), 0..SMALL_ORDER_CANONICAL.len()];
    let msg1 = msg.clone();
    let msg2 = msg.clone();
    prop_oneof![
        2 => (any::<[u8; SK_LENGTH]>(), torsion(), torsion()).prop_map(
            move |(seed, torsion_r, torsion_a)| {
                let (pk, sig) = reference_sign(&seed, &msg, torsion_r, torsion_a);
                (pk, sig, msg.clone())
            }
        ),
        1 => (sample::select(small_order_encodings()), any::<[u8; 32]>()).prop_map(
            move |(pk, s)| {
                let s = Scalar::from_bytes_mod_order(s);
                let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
                (pk, signature_bytes(&r, s.as_bytes()), msg1.clone())
            }
        ),
        1 => (sample::select(small_order_encodings()), sample::select(small_order_encodings()))
            .prop_map(move |(pk, r)| (pk, signature_bytes(&r, &[0; 32]), msg2.clone())),
    ]
    .boxed()
}

/// Adversarial (public key, signature, message) triples for `msg`: valid ones, valid ones with a
/// bit of the key or the signature flipped or with s replaced by s + ℓ, the same tampering of the
/// signature of the key of `HONEST_SEED`, non-canonical and small-order encodings of the key and
/// of R, and random bytes. About half verify.
fn arb_verification_input(msg: Vec<u8>) -> BoxedStrategy<VerificationInput> {
    let encodings: Vec<[u8; PK_LENGTH]> = non_canonical_point_encodings()
        .into_iter()
        .chain(SMALL_ORDER_CANONICAL)
        .collect();
    let msg1 = msg.clone();
    let msg2 = msg.clone();
    let msg3 = msg.clone();
    prop_oneof![
        5 => arb_valid_verification_input(msg.clone()),
        // The honest key's signature with one bit flipped, or with s replaced by s + ℓ.
        1 => (0..=SIG_LENGTH * 8).prop_map(move |bit| {
            let (pk, mut sig) = reference_sign(&HONEST_SEED, &msg3, 0, 0);
            if bit < SIG_LENGTH * 8 {
                sig[bit / 8] ^= 1 << (bit % 8);
            } else {
                let s = add_group_order(&sig[32..]);
                sig[32..].copy_from_slice(&s);
            }
            (pk, sig, msg3.clone())
        }),
        2 => (arb_valid_verification_input(msg.clone()), 0..(PK_LENGTH + SIG_LENGTH) * 8)
            .prop_map(|((mut pk, mut sig, msg), bit)| {
                if bit < PK_LENGTH * 8 {
                    pk[bit / 8] ^= 1 << (bit % 8);
                } else {
                    let bit = bit - PK_LENGTH * 8;
                    sig[bit / 8] ^= 1 << (bit % 8);
                }
                (pk, sig, msg)
            }),
        1 => arb_valid_verification_input(msg.clone()).prop_map(|(pk, sig, msg)| {
            let r: [u8; 32] = sig[..32].try_into().unwrap();
            (pk, signature_bytes(&r, &add_group_order(&sig[32..])), msg)
        }),
        1 => (
            sample::select(encodings.clone()),
            sample::select(encodings),
            prop_oneof![Just([0u8; 32]), any::<[u8; 32]>()],
        )
            .prop_map(move |(pk, r, s)| (pk, signature_bytes(&r, &s), msg1.clone())),
        1 => (any::<[u8; PK_LENGTH]>(), any::<[u8; SIG_LENGTH]>())
            .prop_map(move |(pk, sig)| (pk, sig, msg2.clone())),
    ]
    .boxed()
}

fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    collection::vec(any::<u8>(), 0..64)
}

/// Batches of 1 to 5 items, mostly valid, with one message for all items or one message each.
fn arb_batch() -> impl Strategy<Value = Vec<VerificationInput>> {
    let item = |msg: Vec<u8>| {
        prop_oneof![
            3 => arb_valid_verification_input(msg.clone()),
            1 => arb_verification_input(msg),
        ]
    };
    prop_oneof![
        arb_message().prop_flat_map(move |msg| collection::vec(item(msg), 1..6)),
        collection::vec(arb_message().prop_flat_map(item), 1..6),
    ]
}

/// Bytes of any length up to two signatures, mostly 64 bytes.
fn arb_signature_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        any::<[u8; SIG_LENGTH]>().prop_map(|bytes| bytes.to_vec()),
        collection::vec(any::<u8>(), 0..=2 * SIG_LENGTH + 1),
    ]
}

/// Bytes of any length up to two seeds, mostly 32 bytes.
fn arb_seed_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        any::<[u8; SK_LENGTH]>().prop_map(|bytes| bytes.to_vec()),
        collection::vec(any::<u8>(), 0..=2 * SK_LENGTH + 1),
    ]
}

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Ed25519KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }

    // Public keys decode iff they are 32 bytes that the reference implementation decodes, keep
    // their bytes, compare and hash by their bytes, and every decoder agrees with from_bytes.
    #[test]
    fn test_decode_adversarial_public_keys(
        bytes in prop_oneof![
            3 => arb_public_key_bytes().prop_map(|pk| pk.to_vec()),
            1 => collection::vec(any::<u8>(), 0..=2 * PK_LENGTH + 1),
        ],
    ) {
        let decoded = Ed25519PublicKey::from_bytes(&bytes);
        let point = <[u8; PK_LENGTH]>::try_from(bytes.as_slice())
            .ok()
            .and_then(|pk| decompress(&pk));
        prop_assert_eq!(decoded.is_ok(), point.is_some());
        if let (Ok(pk), Some(point)) = (&decoded, point) {
            let canonical = point.compress().to_bytes();
            let canonical_pk = Ed25519PublicKey::from_bytes(&canonical).unwrap();
            prop_assert_eq!(pk.as_bytes(), &bytes[..]);
            prop_assert_eq!(pk == &canonical_pk, bytes == canonical);
            prop_assert_eq!(hash_of(pk), hash_of(&bytes[..]));
            prop_assert_eq!(pk.cmp(&canonical_pk), bytes[..].cmp(&canonical[..]));
        }
        prop_assert_eq!(
            bcs::from_bytes::<Ed25519PublicKey>(&bytes).ok(),
            decoded.as_ref().ok().cloned()
        );
        let json = format!("\"{}\"", Base64::encode(&bytes));
        prop_assert_eq!(
            serde_json::from_str::<Ed25519PublicKey>(&json).ok(),
            decoded.as_ref().ok().cloned()
        );
        let as_bytes = bcs::from_bytes::<Ed25519PublicKeyAsBytes>(&bytes);
        prop_assert_eq!(as_bytes.is_ok(), bytes.len() == PK_LENGTH);
        if let Ok(as_bytes) = as_bytes {
            prop_assert_eq!(Ed25519PublicKey::try_from(&as_bytes).ok(), decoded.ok());
        }
    }

    // Verification agrees with the reference implementation, and with a batch of one item.
    #[test]
    fn test_verify_adversarial_inputs(
        (pk, sig, msg) in arb_message().prop_flat_map(arb_verification_input),
    ) {
        let verified = verify_bytes(&pk, &sig, &msg);
        prop_assert_eq!(verified, reference_verify(&pk, &sig, &msg));
        // Under the honest key, the only signature that verifies is its owner's.
        let (honest_pk, honest_sig) = reference_sign(&HONEST_SEED, &msg, 0, 0);
        prop_assert_eq!(verify_bytes(&honest_pk, &sig, &msg), sig == honest_sig);
        prop_assert_eq!(check_batch_agrees_with_individual(&[(pk, sig, msg)]), verified);
    }

    // Every batch verification API accepts a batch iff each item verifies on its own.
    #[test]
    fn test_batch_agrees_with_individual_verification(items in arb_batch()) {
        check_batch_agrees_with_individual(&items);
    }

    // Signatures decode from exactly 64 bytes and aggregates from any multiple of 64, whatever the
    // bytes, and keep them. Binary and human-readable serde agree.
    #[test]
    fn test_decode_adversarial_signatures(bytes in arb_signature_bytes()) {
        let decoded = <Ed25519Signature as ToFromBytes>::from_bytes(&bytes);
        prop_assert_eq!(decoded.is_ok(), bytes.len() == SIG_LENGTH);
        if let Ok(sig) = &decoded {
            prop_assert_eq!(sig.as_bytes(), &bytes[..]);
        }
        prop_assert_eq!(
            bcs::from_bytes::<Ed25519Signature>(&bytes).ok(),
            decoded.as_ref().ok().cloned()
        );
        let json = format!("\"{}\"", Base64::encode(&bytes));
        prop_assert_eq!(serde_json::from_str::<Ed25519Signature>(&json).ok(), decoded.ok());

        let aggregate = Ed25519AggregateSignature::from_bytes(&bytes);
        prop_assert_eq!(aggregate.is_ok(), bytes.len().is_multiple_of(SIG_LENGTH));
        if let Ok(aggregate) = aggregate {
            prop_assert_eq!(aggregate.as_bytes(), &bytes[..]);
        }
    }

    // Key pairs decode from any 32 bytes, and derive the public key and sign as RFC 8032 does.
    #[test]
    fn test_private_keys_match_reference(bytes in arb_seed_bytes(), msg in arb_message()) {
        let decoded = Ed25519KeyPair::from_bytes(&bytes);
        prop_assert_eq!(decoded.is_ok(), bytes.len() == SK_LENGTH);
        prop_assert_eq!(Ed25519PrivateKey::from_bytes(&bytes).is_ok(), decoded.is_ok());
        if let Ok(kp) = decoded {
            let seed: [u8; SK_LENGTH] = bytes.try_into().unwrap();
            let (pk, sig) = reference_sign(&seed, &msg, 0, 0);
            prop_assert_eq!(kp.as_bytes(), seed);
            prop_assert_eq!(kp.public().as_bytes(), pk);
            let signature = kp.sign(&msg);
            prop_assert_eq!(signature.as_bytes(), sig);
            prop_assert_eq!(bcs::from_bytes::<Ed25519KeyPair>(&seed).unwrap(), kp);
        }
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // The adversarial strategies above must produce enough inputs that decode and verify, and
    // enough that do not, for the proptests to check something.
    const SAMPLES: usize = 500;
    let mut runner = TestRunner::deterministic();
    let mut rate = |strategy: BoxedStrategy<bool>| {
        (0..SAMPLES)
            .filter(|_| strategy.new_tree(&mut runner).unwrap().current())
            .count() as f64
            / SAMPLES as f64
    };

    let decoded = rate(
        arb_public_key_bytes()
            .prop_map(|pk| Ed25519PublicKey::from_bytes(&pk).is_ok())
            .boxed(),
    );
    assert!((0.6..0.85).contains(&decoded), "{decoded}");

    let verified = rate(
        arb_message()
            .prop_flat_map(arb_verification_input)
            .prop_map(|(pk, sig, msg)| verify_bytes(&pk, &sig, &msg))
            .boxed(),
    );
    assert!((0.4..0.6).contains(&verified), "{verified}");

    let batch_verified = rate(
        arb_batch()
            .prop_map(|items| {
                items
                    .iter()
                    .all(|(pk, sig, msg)| verify_bytes(pk, sig, msg))
            })
            .boxed(),
    );
    assert!((0.55..0.85).contains(&batch_verified), "{batch_verified}");
}
