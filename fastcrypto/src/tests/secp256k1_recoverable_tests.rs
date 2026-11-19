// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::{Blake2b256, Sha3_256};
use crate::secp256k1::{
    Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
};
use crate::secp256k1_tests::{
    arb_scalar_bytes, flip_bit, hash_of, is_high_s, keys, negate_s, rate, wycheproof_tests,
    GROUP_ORDER, MSG, SIG_LENGTH,
};
use crate::test_helpers::verify_serialization;
use crate::traits::{RecoverableSignature, RecoverableSigner, Signer, VerifyRecoverable};
use crate::{
    hash::{HashFunction, Keccak256, Sha256},
    secp256k1::recoverable::{Secp256k1RecoverableSignature, SECP256K1_RECOVERABLE_SIGNATURE_SIZE},
    traits::{KeyPair, ToFromBytes, VerifyingKey},
};

use crate::encoding::{Base64, Encoding, Hex};
use k256::ecdsa::signature::Signer as _;
use proptest::{collection, prelude::*};
use rand::{rngs::StdRng, SeedableRng as _};
use rust_secp256k1::ecdsa::Signature;
use wycheproof::ecdsa::TestName;
use wycheproof::TestResult;

//
// Helper functions
//

/// The largest valid recovery id. Ids 2 and 3 mean that the x-coordinate of R is r + n.
const MAX_RECOVERY_ID: u8 = 3;

/// p - n, big-endian. If r >= p - n, then r + n >= p is not an x-coordinate, so the recovery ids 2
/// and 3 cannot be used.
const FIELD_MODULUS_MINUS_GROUP_ORDER: [u8; 32] =
    hex_literal::hex!("000000000000000000000000000000014551231950b75fc4402da1722fc9baee");

/// The largest r for which the recovery ids 2 and 3 can be used: r + n = p - 3 is an x-coordinate
/// (and p - 2 and p - 1 are not).
const LARGEST_OVERFLOWING_R: [u8; 32] =
    hex_literal::hex!("000000000000000000000000000000014551231950b75fc4402da1722fc9baeb");

/// There is no point with x = 5, so r = 5 cannot be used with the recovery ids 0 and 1.
const X_NOT_ON_CURVE: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000005");

/// The example transaction of EIP-155 (https://eips.ethereum.org/EIPS/eip-155): the signing data
/// (RLP of nonce 9, gas price 20 gwei, gas limit 21000, to 0x3535...35, value 1 ether, no data,
/// chain id 1), the private key, the signature (r, s, and v = 37, so the recovery id is
/// v - 35 - 2 * chain id = 0), and the sender address.
const EIP155_SIGNING_DATA: [u8; 45] = hex_literal::hex!(
    "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
);
const EIP155_SIGNING_HASH: [u8; 32] =
    hex_literal::hex!("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");
const EIP155_PRIVATE_KEY: [u8; 32] = [0x46; 32];
const EIP155_SIGNATURE: [u8; SECP256K1_RECOVERABLE_SIGNATURE_SIZE] = hex_literal::hex!(
    "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa63627667cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d8300"
);
const EIP155_SENDER: &str = "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f";

fn decode(bytes: &[u8]) -> Result<Secp256k1RecoverableSignature, crate::error::FastCryptoError> {
    <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(bytes)
}

/// The 65-byte recoverable signature r || s || recovery id.
fn with_recovery_id(signature: &[u8], recovery_id: u8) -> Vec<u8> {
    let mut bytes = signature[..SIG_LENGTH].to_vec();
    bytes.push(recovery_id);
    bytes
}

/// A recoverable signature with s replaced by n - s and the other recovery id, which recovers the
/// same key.
fn high_s(signature: &[u8]) -> Vec<u8> {
    with_recovery_id(&negate_s(signature), signature[SIG_LENGTH] ^ 1)
}

/// The Ethereum address of a public key: the last 20 bytes of keccak256 of the uncompressed
/// encoding without its prefix.
fn ethereum_address(pk: &Secp256k1PublicKey) -> [u8; 20] {
    let uncompressed = pk.pubkey.serialize_uncompressed();
    Keccak256::digest(&uncompressed[1..]).digest[12..]
        .try_into()
        .unwrap()
}

/// Recovery with k256 0.11, an independent implementation, given the digest of the message. It
/// only supports the recovery ids 0 and 1.
fn k256_recover(digest: &[u8; 32], signature: &[u8]) -> Option<Secp256k1PublicKey> {
    let signature = k256::ecdsa::recoverable::Signature::try_from(signature).ok()?;
    let pk = signature
        .recover_verifying_key_from_digest_bytes(k256::FieldBytes::from_slice(digest))
        .ok()?;
    Some(Secp256k1PublicKey::from_bytes(&pk.to_bytes()).unwrap())
}

//
// Serialization tests
//

#[test]
fn serialize_deserialize() {
    // The other types (pk, sk, keypair) are tested in the nonrecoverable tests.
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    verify_serialization(&sig, Some(sig.as_bytes()));

    // Human-readable serde uses base64 of the same bytes.
    let json = serde_json::to_string(&sig).unwrap();
    assert_eq!(json, format!("\"{}\"", Base64::encode(sig.as_bytes())));
    assert_eq!(
        serde_json::from_str::<Secp256k1RecoverableSignature>(&json).unwrap(),
        sig
    );
}

#[test]
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

#[test]
fn hash_signature() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    assert_eq!(hash_of(&sig), hash_of(&sig.as_bytes()));
}

// A recoverable signature is r || s || recovery id. The recovery id must be 0, 1, 2 or 3 (as in
// Sui's secp256k1_ecrecover Move native): Ethereum's v values (27 and 28, or 35 + 2 * chain id and
// 36 + 2 * chain id) are not accepted and must be converted by the caller. Like non-recoverable
// signatures, r and s must be in [0, n), and s is not normalized.
#[test]
fn to_from_bytes_signature() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    assert_eq!(decode(sig.as_bytes()).unwrap(), sig);

    // Only 65 bytes are accepted.
    for len in (0..=3 * SECP256K1_RECOVERABLE_SIGNATURE_SIZE)
        .filter(|&len| len != SECP256K1_RECOVERABLE_SIGNATURE_SIZE)
    {
        let bytes: Vec<u8> = sig.as_bytes().iter().cycle().take(len).copied().collect();
        assert!(decode(&bytes).is_err(), "{}", len);
    }

    let accepted: Vec<u8> = (0..=255u8)
        .filter(|&v| decode(&with_recovery_id(sig.as_bytes(), v)).is_ok())
        .collect();
    assert_eq!(accepted, (0..=MAX_RECOVERY_ID).collect::<Vec<_>>());

    for v in 0..=MAX_RECOVERY_ID {
        // Decoding keeps the recovery id and s.
        for bytes in [
            with_recovery_id(sig.as_bytes(), v),
            with_recovery_id(&negate_s(sig.as_bytes()), v),
        ] {
            assert_eq!(decode(&bytes).unwrap().as_bytes(), bytes);
        }

        let mut bytes = with_recovery_id(sig.as_bytes(), v);
        bytes[..32].copy_from_slice(&GROUP_ORDER);
        assert!(decode(&bytes).is_err());
        let mut bytes = with_recovery_id(sig.as_bytes(), v);
        bytes[32..64].copy_from_slice(&GROUP_ORDER);
        assert!(decode(&bytes).is_err());
    }
}

//
// Recovery tests
//

#[test]
fn test_public_key_recovery() {
    let kp = keys().pop().unwrap();
    let pk = kp.public();

    // A signature only recovers the signer's key, and only verifies, with the hash function it was
    // made with. Keccak-256 and SHA-256 are the hash functions of Sui's secp256k1_ecrecover Move
    // native. The default is SHA-256.
    let signatures = [
        kp.sign_recoverable_with_hash::<Sha256>(MSG),
        kp.sign_recoverable_with_hash::<Keccak256>(MSG),
        kp.sign_recoverable_with_hash::<Sha3_256>(MSG),
        kp.sign_recoverable_with_hash::<Blake2b256>(MSG),
    ];
    assert_eq!(kp.sign_recoverable(MSG), signatures[0]);
    for (i, sig) in signatures.iter().enumerate() {
        let recovered = [
            sig.recover_with_hash::<Sha256>(MSG).ok(),
            sig.recover_with_hash::<Keccak256>(MSG).ok(),
            sig.recover_with_hash::<Sha3_256>(MSG).ok(),
            sig.recover_with_hash::<Blake2b256>(MSG).ok(),
        ];
        let verified = [
            pk.verify_recoverable_with_hash::<Sha256>(MSG, sig).is_ok(),
            pk.verify_recoverable_with_hash::<Keccak256>(MSG, sig)
                .is_ok(),
            pk.verify_recoverable_with_hash::<Sha3_256>(MSG, sig)
                .is_ok(),
            pk.verify_recoverable_with_hash::<Blake2b256>(MSG, sig)
                .is_ok(),
        ];
        for j in 0..signatures.len() {
            assert_eq!(recovered[j].as_ref() == Some(pk), i == j);
            assert_eq!(verified[j], i == j);
        }
        assert_eq!(sig.recover(MSG).ok(), recovered[0]);
        assert_eq!(pk.verify_recoverable(MSG, sig).is_ok(), verified[0]);

        // The non-recoverable part is a low-s signature.
        let standard = Secp256k1Signature::from(sig);
        assert_eq!(standard.as_bytes(), &sig.as_bytes()[..SIG_LENGTH]);
        assert!(!is_high_s(standard.as_bytes()));
    }
    assert!(pk
        .verify(MSG, &Secp256k1Signature::from(&signatures[0]))
        .is_ok());
    assert!(pk
        .verify_with_hash::<Keccak256>(MSG, &Secp256k1Signature::from(&signatures[1]))
        .is_ok());

    // The recovered key is always encoded compressed, so it can be compared as bytes (as Sui's bridge
    // committee does with the output of the Move native).
    let recovered = signatures[1].recover_with_hash::<Keccak256>(MSG).unwrap();
    assert_eq!(recovered.as_bytes(), pk.as_bytes());
    let from_uncompressed =
        Secp256k1PublicKey::from_bytes(&pk.pubkey.serialize_uncompressed()).unwrap();
    assert!(from_uncompressed
        .verify_recoverable_with_hash::<Keccak256>(MSG, &signatures[1])
        .is_ok());
}

#[test]
fn test_public_key_recovery_error() {
    let kp = keys().pop().unwrap();
    let sig = kp.sign_recoverable(MSG);
    let with_r = |r: &[u8; 32], v: u8| {
        let mut bytes = with_recovery_id(sig.as_bytes(), v);
        bytes[..32].copy_from_slice(r);
        decode(&bytes).unwrap()
    };

    for v in 0..=MAX_RECOVERY_ID {
        // r = 0 and s = 0 decode, but nothing is recovered.
        assert!(with_r(&[0; 32], v).recover(MSG).is_err());
        let mut bytes = with_recovery_id(sig.as_bytes(), v);
        bytes[32..64].fill(0);
        assert!(decode(&bytes).unwrap().recover(MSG).is_err());
    }

    // The recovery ids 0 and 1 need a point with x = r.
    assert!(with_r(&X_NOT_ON_CURVE, 0).recover(MSG).is_err());
    assert!(with_r(&X_NOT_ON_CURVE, 1).recover(MSG).is_err());

    // The recovery ids 2 and 3 need r + n < p. That is not the case for an honest signature (except
    // with negligible probability), nor for r = p - n.
    for v in 2..=MAX_RECOVERY_ID {
        assert!(decode(&with_recovery_id(sig.as_bytes(), v))
            .unwrap()
            .recover(MSG)
            .is_err());
        assert!(with_r(&FIELD_MODULUS_MINUS_GROUP_ORDER, v)
            .recover(MSG)
            .is_err());
    }
    // A smaller r can work with the recovery ids 2 and 3 (see also test_recoverable_id_gt_1).
    let pk2 = with_r(&LARGEST_OVERFLOWING_R, 2).recover(MSG).unwrap();
    let pk3 = with_r(&LARGEST_OVERFLOWING_R, 3).recover(MSG).unwrap();
    assert_ne!(pk2, pk3);
}

// Recovery does not require low-s, like Ethereum's ecrecover precompile and k256: negating s
// negates R, so (r, n - s) with the other recovery id (v ^ 1) recovers the same key. The
// non-recoverable verification of (r, n - s) fails.
#[test]
fn fail_to_verify_if_upper_s() {
    // Test case from https://github.com/fjl/go-ethereum/blob/41c854a60fad2ad9bb732857445624c7214541db/crypto/signature_test.go#L79
    // Note that keccak256(msg) = d301ce462d3e639518f482c7f03821fec1e602018630ce621e1e7851c12343a6.
    let msg =
        hex::decode("f854018664697363763582765f82696490736563703235366b312d6b656363616b83697034847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();
    let pk = Secp256k1PublicKey::from_bytes(
        &hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap(),
    )
    .unwrap();
    let mut sig = Signature::from_compact(&hex::decode("638a54215d80a6713c8d523a6adc4e6e73652d859103a36b700851cb0e61b66b8ebfc1a610c57d732ec6e0a8f06a9a7a28df5051ece514702ff9cdff0b11f454").unwrap()).unwrap();

    // Append 0 to the end of the signature to make it a recoverable signature.
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.serialize_compact());
    sig_bytes[64] = 0;
    let rec_sig = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&sig_bytes).unwrap();

    // Failed to verify with upper S.
    assert!(pk
        .verify_recoverable_with_hash::<Keccak256>(&msg, &rec_sig)
        .is_err());

    // Normalize S to be less than N/2.
    sig.normalize_s();
    let mut sig_bytes1 = [0u8; 65];
    sig_bytes1[..64].copy_from_slice(&sig.serialize_compact());
    sig_bytes1[64] = 0;
    let normalized_rec_sig =
        <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&sig_bytes1).unwrap();

    // Verify with normalized lower S.
    assert!(pk
        .verify_recoverable_with_hash::<Keccak256>(&msg, &normalized_rec_sig)
        .is_ok());

    // The upper S verifies with the other recovery id.
    let rec_sig = decode(&with_recovery_id(&sig_bytes, 1)).unwrap();
    assert!(pk
        .verify_recoverable_with_hash::<Keccak256>(&msg, &rec_sig)
        .is_ok());

    let kp = keys().pop().unwrap();
    for msg in [&b"a"[..], b"b", b"c", b"d"] {
        let sig = kp.sign_recoverable_with_hash::<Keccak256>(msg);
        let high_s = decode(&high_s(sig.as_bytes())).unwrap();
        assert_ne!(high_s, sig);
        assert!(is_high_s(high_s.as_bytes()));
        assert_eq!(
            high_s.recover_with_hash::<Keccak256>(msg).unwrap(),
            *kp.public()
        );
        assert!(kp
            .public()
            .verify_recoverable_with_hash::<Keccak256>(msg, &high_s)
            .is_ok());
        let digest = Keccak256::digest(msg).digest;
        assert_eq!(
            k256_recover(&digest, high_s.as_bytes()).as_ref(),
            Some(kp.public())
        );

        // With the same recovery id, another key is recovered.
        let same_v = decode(&with_recovery_id(
            high_s.as_bytes(),
            sig.as_bytes()[SIG_LENGTH],
        ))
        .unwrap();
        assert_ne!(
            same_v.recover_with_hash::<Keccak256>(msg).ok().as_ref(),
            Some(kp.public())
        );

        // The non-recoverable signature does not verify.
        assert!(kp
            .public()
            .verify_with_hash::<Keccak256>(msg, &Secp256k1Signature::from(&high_s))
            .is_err());
    }
}

#[test]
fn test_recoverable_id_gt_1() {
    // Recoverable signatures with id 2 or 3 only occur when the value of r is small enough which
    // is negligible; therefore, the below test specifically tests such signatures.
    // The TESTCASES below were generated by manually modifying recoverable signature's
    // r value to be between 0 - 100 and recovering the corresponding public key with id 2 or 3.
    const TESTCASES: [(&str, &str); 5] = [
        ("AkqS1785aGbz8POF/nEP+Y9mS7ERe5U+OoiObVsPXuU2", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGqa9Jtwd/wx59g+AKzBNH0Iw+GtUKTutqsETyXIYd3HvluPnwI="),
        ("A/iqkiaYR+MaHVFwsLSLlFu3jgf7Aap8YfzTwgapTkOp", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGqa9Jtwd/wx59g+AKzBNH0Iw+GtUKTutqsETyXIYd3HvluPnwM="),
        ("AxgPOtl8W79VgZ/M5oxcfCHdJ8IAqIsQgsXD6ncx+q4m", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALvDKQRwd/wx59g+AKzBNH0Iw+GtUKTutqsETyXIYd3HvluPnwI="),
        ("A3jQ342n9qFqG6rRvcpodIqxaSHqahQfwWoELEwygMlm", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALvDKQRwd/wx59g+AKzBNH0Iw+GtUKTutqsETyXIYd3HvluPnwM="),
        ("Awv/Vfdf/dDUXpPm90M2sY6SCvdVV9ZsSZ081wjI4cL6", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABR04Elwd/wx59g+AKzBNH0Iw+GtUKTutqsETyXIYd3HvluPnwI="),
    ];
    const MESSAGE: &[u8] = b"Hello, world!";

    for (pk_str, sig_str) in TESTCASES {
        let signature_bytes = Base64::decode(sig_str).unwrap();
        let pk_bytes = Base64::decode(pk_str).unwrap();
        let recoverable_signature =
            Secp256k1RecoverableSignature::from_bytes(signature_bytes.as_slice()).unwrap();
        let pk = Secp256k1PublicKey::from_bytes(pk_bytes.as_slice()).unwrap();
        let signature = Secp256k1Signature::from_bytes(&signature_bytes.as_slice()[..64]).unwrap();
        let generated_pk = recoverable_signature.recover(MESSAGE).unwrap();

        pk.verify_recoverable(MESSAGE, &recoverable_signature)
            .unwrap();
        pk.verify(MESSAGE, &signature).unwrap();
        assert_eq!(pk, generated_pk);
    }
}

#[test]
fn test_ethereum_eip155_example() {
    // Ethereum signs keccak256 of the signing data with RFC 6979 nonces and low-s, like this
    // module, so the signature is reproduced exactly.
    assert_eq!(
        Keccak256::digest(EIP155_SIGNING_DATA).digest,
        EIP155_SIGNING_HASH
    );
    let kp = Secp256k1KeyPair::from(Secp256k1PrivateKey::from_bytes(&EIP155_PRIVATE_KEY).unwrap());
    let sig = kp.sign_recoverable_with_hash::<Keccak256>(&EIP155_SIGNING_DATA);
    assert_eq!(sig.as_bytes(), EIP155_SIGNATURE);

    // ecrecover gives the sender.
    let sig = decode(&EIP155_SIGNATURE).unwrap();
    let pk = sig
        .recover_with_hash::<Keccak256>(&EIP155_SIGNING_DATA)
        .unwrap();
    assert_eq!(pk, *kp.public());
    assert_eq!(Hex::encode(ethereum_address(&pk)), EIP155_SENDER);
    assert_eq!(
        k256_recover(&EIP155_SIGNING_HASH, &EIP155_SIGNATURE),
        Some(pk.clone())
    );

    // The other recovery id gives another address.
    let other = decode(&with_recovery_id(&EIP155_SIGNATURE, 1))
        .unwrap()
        .recover_with_hash::<Keccak256>(&EIP155_SIGNING_DATA)
        .unwrap();
    assert_ne!(other, pk);
}

#[test]
fn test_recoverable_nonrecoverable_conversion() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message.
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign_recoverable(message);
    assert!(kp.public().verify_recoverable(message, &signature).is_ok());

    let nonrecoverable_signature = Secp256k1Signature::from(&signature);
    assert!(kp
        .public()
        .verify(message, &nonrecoverable_signature)
        .is_ok());
}

#[test]
fn wycheproof_test() {
    // Wycheproof tests do not have a recovery id, so a test passes if one of the recovery ids
    // verifies. Recovery accepts high-s signatures, so valid tests are accepted whatever their s.
    for (name, p1363) in [
        (TestName::EcdsaSecp256k1Sha256, false),
        (TestName::EcdsaSecp256k1Sha256P1363, true),
        (TestName::EcdsaSecp256k1Sha3_256, false),
    ] {
        let mut accepted_high_s = 0;
        for (pk, msg, signature, result) in wycheproof_tests(name, p1363) {
            let verified = signature.as_ref().is_some_and(|signature| {
                signature.len() == SIG_LENGTH
                    && (0..=MAX_RECOVERY_ID).any(|v| {
                        decode(&with_recovery_id(signature, v)).is_ok_and(|sig| match name {
                            TestName::EcdsaSecp256k1Sha3_256 => pk
                                .verify_recoverable_with_hash::<Sha3_256>(&msg, &sig)
                                .is_ok(),
                            _ => pk
                                .verify_recoverable_with_hash::<Sha256>(&msg, &sig)
                                .is_ok(),
                        })
                    })
            });
            match result {
                TestResult::Valid => {
                    assert!(verified, "{:?}", name);
                    if is_high_s(signature.as_ref().unwrap()) {
                        accepted_high_s += 1;
                    }
                }
                TestResult::Invalid => assert!(!verified, "{:?}", name),
                TestResult::Acceptable => unreachable!("these test sets have no acceptable tests"),
            }
        }
        assert!(accepted_high_s > 0);
    }
}

//
// Proptests
//

/// Either r || s || v with adversarial values, or the Keccak-256 recoverable signature by
/// `keys()[0]` on `MSG`: as is, with one bit flipped, or in its high-s form.
fn arb_recoverable_signature_bytes() -> impl Strategy<Value = Vec<u8>> {
    let honest = keys()[0]
        .sign_recoverable_with_hash::<Keccak256>(MSG)
        .as_bytes()
        .to_vec();
    prop_oneof![
        3 => (
            arb_scalar_bytes(),
            arb_scalar_bytes(),
            prop_oneof![3 => 0..=MAX_RECOVERY_ID, 1 => any::<u8>()],
        )
            .prop_map(|(r, s, v)| with_recovery_id(&[r, s].concat(), v)),
        1 => Just(honest.clone()),
        3 => flip_bit(honest.clone()),
        1 => Just(high_s(&honest)),
    ]
}

proptest! {
    // fastcrypto and k256 produce the same recoverable signatures with Keccak-256 (as in Ethereum)
    // and recover the signer's key from them, but not with the other recovery id. With the default
    // hash function, a recoverable signature without its recovery id is the non-recoverable
    // signature.
    #[test]
    fn test_k256_against_secp256k1_lib_with_recovery(
        seed in any::<[u8; 32]>(),
        msg in collection::vec(any::<u8>(), 0..100),
    ) {
        let kp = Secp256k1KeyPair::generate(&mut StdRng::from_seed(seed));
        let sig = kp.sign_recoverable_with_hash::<Keccak256>(&msg);
        let k256_kp = k256::ecdsa::SigningKey::from_bytes(kp.as_bytes()).unwrap();
        let k256_sig: k256::ecdsa::recoverable::Signature = k256_kp.sign(&msg);
        prop_assert_eq!(sig.as_bytes(), k256_sig.as_ref());

        let digest = Keccak256::digest(&msg).digest;
        prop_assert_eq!(&sig.recover_with_hash::<Keccak256>(&msg).unwrap(), kp.public());
        prop_assert_eq!(&k256_recover(&digest, sig.as_bytes()).unwrap(), kp.public());
        let other_v = decode(&with_recovery_id(sig.as_bytes(), sig.as_bytes()[SIG_LENGTH] ^ 1)).unwrap();
        prop_assert!(kp.public().verify_recoverable_with_hash::<Keccak256>(&msg, &other_v).is_err());

        let sig = kp.sign_recoverable(&msg);
        prop_assert!(sig.as_bytes()[SIG_LENGTH] <= 1);
        prop_assert_eq!(&Secp256k1Signature::from(&sig), &kp.sign(&msg));
    }

    // Decoding and recovery (as in Sui's secp256k1_ecrecover Move native, with Keccak-256 as in
    // Sui's bridge) never panic on adversarial bytes. Signatures decode iff r < n, s < n and the
    // recovery id is at most 3. A recovered key is encoded compressed, verifies the signature (also
    // as a non-recoverable signature once s is normalized), agrees with k256, and is the signer's
    // key only for the signer's signature and its high-s form.
    #[test]
    fn test_recover_adversarial_signatures(bytes in arb_recoverable_signature_bytes()) {
        let kp = &keys()[0];
        let honest = kp.sign_recoverable_with_hash::<Keccak256>(MSG).as_bytes().to_vec();
        let digest = Keccak256::digest(MSG).digest;

        let decoded = decode(&bytes);
        prop_assert_eq!(
            decoded.is_ok(),
            bytes[..32] < GROUP_ORDER[..]
                && bytes[32..64] < GROUP_ORDER[..]
                && bytes[SIG_LENGTH] <= MAX_RECOVERY_ID
        );
        let recovered = decoded.as_ref().ok().and_then(|sig| {
            sig.recover_with_hash::<Keccak256>(MSG).ok()
        });
        if let Ok(sig) = &decoded {
            prop_assert_eq!(sig.as_bytes(), &bytes[..]);
        }
        if let (Ok(sig), Some(pk)) = (&decoded, &recovered) {
            prop_assert_eq!(&Secp256k1PublicKey::from_bytes(pk.as_bytes()).unwrap(), pk);
            prop_assert!(pk.verify_recoverable_with_hash::<Keccak256>(MSG, sig).is_ok());
            let mut standard = Secp256k1Signature::from(sig).sig;
            standard.normalize_s();
            let standard =
                <Secp256k1Signature as ToFromBytes>::from_bytes(&standard.serialize_compact()).unwrap();
            prop_assert!(pk.verify_with_hash::<Keccak256>(MSG, &standard).is_ok());
        }
        prop_assert_eq!(
            recovered.as_ref() == Some(kp.public()),
            bytes == honest || bytes == high_s(&honest)
        );
        if bytes[SIG_LENGTH] <= 1 {
            prop_assert_eq!(&recovered, &k256_recover(&digest, &bytes));
        }

        // Binary and human-readable serde agree with from_bytes.
        prop_assert_eq!(
            bcs::from_bytes::<Secp256k1RecoverableSignature>(&bytes).ok(),
            decoded.as_ref().ok().cloned()
        );
        let json = format!("\"{}\"", Base64::encode(&bytes));
        prop_assert_eq!(
            serde_json::from_str::<Secp256k1RecoverableSignature>(&json).ok(),
            decoded.ok()
        );
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // The adversarial strategy above must produce enough signatures that decode and recover the
    // signer's key, and enough that do not, for the proptest to check something.
    let decoded = rate(arb_recoverable_signature_bytes(), |bytes| {
        decode(bytes).is_ok()
    });
    assert!((0.7..0.95).contains(&decoded), "{decoded}");
    let pk = keys()[0].public().clone();
    let recovered = rate(arb_recoverable_signature_bytes(), |bytes| {
        decode(bytes)
            .is_ok_and(|sig| sig.recover_with_hash::<Keccak256>(MSG).ok() == Some(pk.clone()))
    });
    assert!((0.15..0.35).contains(&recovered), "{recovered}");
}
