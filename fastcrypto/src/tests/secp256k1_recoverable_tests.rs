// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hash::{Blake2b256, Sha3_256};
use crate::secp256k1::{
    Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
};
use crate::secp256k1_tests::{
    arb_scalar_bytes, hash_of, is_high_s, keys, negate_s, wycheproof_tests, GROUP_ORDER, MSG,
    SIG_LENGTH,
};
use crate::test_helpers::verify_serialization;
use crate::traits::{RecoverableSignature, RecoverableSigner, Signer, VerifyRecoverable};
use crate::{
    hash::{HashFunction, Keccak256, Sha256},
    secp256k1::recoverable::{Secp256k1RecoverableSignature, SECP256K1_RECOVERABLE_SIGNATURE_SIZE},
    traits::{KeyPair, ToFromBytes, VerifyingKey},
};

use crate::encoding::{Base64, Encoding, Hex};
#[cfg(feature = "copy_key")]
use k256::ecdsa::signature::Signature as ExternalSignature;
#[cfg(feature = "copy_key")]
use k256::ecdsa::signature::Signer as ExternalSigner;
#[cfg(feature = "copy_key")]
use k256::ecdsa::signature::Verifier as ExternalVerifier;
#[cfg(feature = "copy_key")]
use proptest::arbitrary::Arbitrary;
use proptest::{collection, prelude::*, strategy::Strategy};
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

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign_recoverable(b"Hello, world!");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig =
        <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig.as_ref(), signature.as_ref());
    // check for failure
    let mut sig_bytes = signature.as_ref().to_vec();
    sig_bytes.pop();
    assert!(<Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&sig_bytes).is_err());
}

// The recovery id is the last byte and must be 0, 1, 2 or 3 (as in Sui's secp256k1_ecrecover Move
// native). Ethereum's v values (27 and 28, or 35 + 2 * chain id and 36 + 2 * chain id) are not
// accepted and must be converted by the caller.
#[test]
fn test_recovery_id_range() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    let accepted: Vec<u8> = (0..=255u8)
        .filter(|&v| decode(&with_recovery_id(sig.as_bytes(), v)).is_ok())
        .collect();
    assert_eq!(accepted, (0..=MAX_RECOVERY_ID).collect::<Vec<_>>());
    for v in [27, 28, 37, 38] {
        assert!(decode(&with_recovery_id(sig.as_bytes(), v)).is_err());
    }

    // Decoding keeps the recovery id.
    for v in 0..=MAX_RECOVERY_ID {
        let bytes = with_recovery_id(sig.as_bytes(), v);
        assert_eq!(decode(&bytes).unwrap().as_bytes(), bytes);
    }

    // Only 65 bytes are accepted.
    for len in (0..=3 * SECP256K1_RECOVERABLE_SIGNATURE_SIZE)
        .filter(|&len| len != SECP256K1_RECOVERABLE_SIGNATURE_SIZE)
    {
        let bytes: Vec<u8> = sig.as_bytes().iter().cycle().take(len).copied().collect();
        assert!(decode(&bytes).is_err(), "{}", len);
    }
}

// Like non-recoverable signatures, r and s must be in [0, n), and s is not normalized.
#[test]
fn test_recoverable_signature_encodings() {
    let sig = keys().pop().unwrap().sign_recoverable(MSG);
    let bytes = sig.as_bytes();
    for v in 0..=MAX_RECOVERY_ID {
        let high_s = with_recovery_id(&negate_s(bytes), v);
        assert_eq!(decode(&high_s).unwrap().as_bytes(), high_s);

        let mut bytes = with_recovery_id(bytes, v);
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
    let message: &[u8] = b"Hello, world!";
    let signature: Secp256k1RecoverableSignature = kp.sign_recoverable(message);
    let recovered_key = signature.recover(message).unwrap();
    assert_eq!(*kp.public(), recovered_key);
}

#[test]
fn test_public_key_recovery_error() {
    // incorrect length
    assert!(<Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&[0u8; 1]).is_err());

    // invalid recovery id at index 65
    assert!(<Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&[4u8; 65]).is_err());

    let signature = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&[0u8; 65]).unwrap();
    let message: &[u8] = b"Hello, world!";
    assert!(signature.recover(message).is_err());

    // Verify signature using different hash function
    let kp = keys().pop().unwrap();
    let signature_2: Secp256k1RecoverableSignature = kp.sign_recoverable(message);
    assert_ne!(
        signature_2
            .recover_with_hash::<Blake2b256>(message)
            .unwrap(),
        kp.public
    );
}

#[test]
fn verify_valid_signature_with_default_hash() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message.
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign_recoverable(message);

    // Verify the signature against hashed message.
    assert!(kp.public().verify_recoverable(message, &signature).is_ok());
}

#[test]
fn verify_hashed_failed_if_different_hash_function() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message.
    let message: &[u8] = &[0u8; 1];
    let signature = kp.sign_recoverable(message);

    // Verify the signature using other hash function fails.
    assert!(kp
        .public()
        .verify_recoverable_with_hash::<Blake2b256>(message, &signature)
        .is_err());
}

#[test]
fn test_recover_with_hash_functions() {
    let kp = keys().pop().unwrap();
    let pk = kp.public();

    // Keccak-256 and SHA-256 are the hash functions of Sui's secp256k1_ecrecover Move native. The
    // default is SHA-256.
    let signatures = [
        kp.sign_recoverable_with_hash::<Sha256>(MSG),
        kp.sign_recoverable_with_hash::<Keccak256>(MSG),
        kp.sign_recoverable_with_hash::<Sha3_256>(MSG),
    ];
    assert_eq!(kp.sign_recoverable(MSG), signatures[0]);
    for (i, sig) in signatures.iter().enumerate() {
        // Recovery with another hash function gives another key, or fails.
        let recovered = [
            sig.recover_with_hash::<Sha256>(MSG).ok(),
            sig.recover_with_hash::<Keccak256>(MSG).ok(),
            sig.recover_with_hash::<Sha3_256>(MSG).ok(),
        ];
        for (j, key) in recovered.iter().enumerate() {
            assert_eq!(key.as_ref() == Some(pk), i == j);
        }
        assert_eq!(sig.recover(MSG).ok(), recovered[0]);

        // The non-recoverable part is a valid signature with the same hash function.
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
}

// Recovery does not require low-s, like Ethereum's ecrecover precompile and k256: negating s
// negates R, so (r, n - s) with the opposite parity of R (recovery id v ^ 1) recovers the same key.
// Non-recoverable verification of the same (r, n - s) fails.
#[test]
fn test_recover_high_s() {
    let kp = keys().pop().unwrap();
    for msg in [&b"a"[..], b"b", b"c", b"d"] {
        let sig = kp.sign_recoverable_with_hash::<Keccak256>(msg);
        let bytes = sig.as_bytes();
        let v = bytes[SIG_LENGTH];
        let high_s = decode(&with_recovery_id(&negate_s(bytes), v ^ 1)).unwrap();
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
        let same_v = decode(&with_recovery_id(&negate_s(bytes), v)).unwrap();
        assert_ne!(
            same_v.recover_with_hash::<Keccak256>(msg).ok().as_ref(),
            Some(kp.public())
        );

        // The non-recoverable signature does not verify...
        let standard = Secp256k1Signature::from(&high_s);
        assert!(kp
            .public()
            .verify_with_hash::<Keccak256>(msg, &standard)
            .is_err());

        // ... but try_from_nonrecoverable (which uses recovery) converts it to the high-s
        // recoverable signature.
        let sha256_sig = kp.sign_recoverable(msg);
        let sha256_high_s = <Secp256k1Signature as ToFromBytes>::from_bytes(&negate_s(
            &sha256_sig.as_bytes()[..SIG_LENGTH],
        ))
        .unwrap();
        assert!(kp.public().verify(msg, &sha256_high_s).is_err());
        let converted = Secp256k1RecoverableSignature::try_from_nonrecoverable(
            &sha256_high_s,
            kp.public(),
            msg,
        )
        .unwrap();
        assert_eq!(
            converted.as_bytes(),
            with_recovery_id(
                &negate_s(sha256_sig.as_bytes()),
                sha256_sig.as_bytes()[SIG_LENGTH] ^ 1
            )
        );
    }
}

#[test]
fn test_recovery_failures() {
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
        let generated_recoverable_signature =
            Secp256k1RecoverableSignature::try_from_nonrecoverable(&signature, &pk, MESSAGE)
                .unwrap();
        let generated_pk = recoverable_signature.recover(MESSAGE).unwrap();

        pk.verify_recoverable(MESSAGE, &recoverable_signature)
            .unwrap();
        pk.verify(MESSAGE, &signature).unwrap();
        pk.verify_recoverable(MESSAGE, &generated_recoverable_signature)
            .unwrap();
        assert_eq!(recoverable_signature, generated_recoverable_signature);
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

    let recovered_signature = Secp256k1RecoverableSignature::try_from_nonrecoverable(
        &nonrecoverable_signature,
        kp.public(),
        message,
    )
    .unwrap();
    assert!(kp
        .public()
        .verify_recoverable(message, &recovered_signature)
        .is_ok());
}

#[test]
fn test_invalid_nonrecoverable_conversion() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Sign over raw message.
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign_recoverable(message);
    let nonrecoverable_signature = Secp256k1Signature::from(&signature);

    // Try to convert a nonrecoverable signature to a recoverable one with a different message.
    let other_message: &[u8] = b"Hello, other world!";
    assert!(Secp256k1RecoverableSignature::try_from_nonrecoverable(
        &nonrecoverable_signature,
        kp.public(),
        other_message,
    )
    .is_err());
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
/// `keys()[0]` on `MSG`: as is, with one bit flipped, or with s negated and the recovery id flipped.
fn arb_recoverable_signature_bytes() -> impl Strategy<Value = Vec<u8>> {
    let honest = || {
        keys()[0]
            .sign_recoverable_with_hash::<Keccak256>(MSG)
            .as_bytes()
            .to_vec()
    };
    prop_oneof![
        3 => (
            arb_scalar_bytes(),
            arb_scalar_bytes(),
            prop_oneof![3 => 0..=MAX_RECOVERY_ID, 1 => any::<u8>()],
        )
            .prop_map(|(r, s, v)| with_recovery_id(&[r, s].concat(), v)),
        1 => Just(()).prop_map(move |_| honest()),
        3 => (0..SECP256K1_RECOVERABLE_SIGNATURE_SIZE * 8).prop_map(move |bit| {
            let mut bytes = honest();
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        }),
        1 => Just(()).prop_map(move |_| {
            let bytes = honest();
            with_recovery_id(&negate_s(&bytes), bytes[SIG_LENGTH] ^ 1)
        }),
    ]
}

proptest! {
    #[test]
    #[cfg(feature = "copy_key")]
    fn test_k256_against_secp256k1_lib_with_recovery(
        r in <[u8; 32]>::arbitrary()
) {
        let message: &[u8] = b"hello world!";
        let hashed_msg = rust_secp256k1::Message::from_slice(Keccak256::digest(message).as_ref()).unwrap();

        // construct private key with arbitrary seed and sign
        let mut rng = StdRng::from_seed(r);
        let key_pair = Secp256k1KeyPair::generate(&mut rng);
        let key_pair_copied = key_pair.copy();
        let key_pair_copied_2 = key_pair.copy();
        let key_pair_copied_3 = key_pair.copy();

        let signature: Secp256k1RecoverableSignature = key_pair.sign_recoverable_with_hash::<Keccak256>(message);
        assert!(key_pair.public().verify_recoverable_with_hash::<Keccak256>(message, &signature).is_ok());

        // construct a signature with r, s, v where v is flipped from the original signature.
        let bytes = ToFromBytes::as_bytes(&signature);
        let mut flipped_bytes = [0u8; 65];
        flipped_bytes[..64].copy_from_slice(&bytes[..64]);
        if bytes[64] == 0 {
            flipped_bytes[64] = 1;
        } else {
            flipped_bytes[64] = 0;
        }
        let malleated_signature: Secp256k1RecoverableSignature = Secp256k1RecoverableSignature::from_bytes(&flipped_bytes).unwrap();

        // malleable(altered) signature with opposite sign fails to verify
        assert!(key_pair.public().verify_recoverable_with_hash::<Keccak256>(message, &malleated_signature).is_err());

        // use k256 to construct private key with the same bytes and signs the same message
        let priv_key_1 = k256::ecdsa::SigningKey::from_bytes(key_pair_copied_3.private().as_bytes()).unwrap();
        let pub_key_1 = priv_key_1.verifying_key();
        let signature_1: k256::ecdsa::recoverable::Signature = priv_key_1.sign(message);
        assert!(pub_key_1.verify(message, &signature_1).is_ok());

        // two private keys are serialized the same
        assert_eq!(key_pair_copied.private().as_bytes(), priv_key_1.to_bytes().as_slice());

        // two pubkeys are the same
        assert_eq!(
            key_pair.public().as_bytes(),
            pub_key_1.to_bytes().as_slice()
        );

        // same recovered pubkey are recovered
        let recovered_key = signature.sig.recover(&hashed_msg).unwrap();
        let recovered_key_1 = signature_1.recover_verifying_key(message).expect("couldn't recover pubkey");
        assert_eq!(recovered_key.serialize(),recovered_key_1.to_bytes().as_slice());

        // same signatures produced from both implementations
        assert_eq!(signature.as_ref(), signature_1.as_bytes());

        // use ffi-implemented keypair to verify sig constructed by k256
        let secp_sig1 = bincode::deserialize::<Secp256k1RecoverableSignature>(signature_1.as_ref()).unwrap();
        assert!(key_pair_copied_2.public().verify_recoverable_with_hash::<Keccak256>(message, &secp_sig1).is_ok());

        // use k256 keypair to verify sig constructed by ffi-implementation
        let typed_sig = k256::ecdsa::recoverable::Signature::try_from(signature.as_ref()).unwrap();
        assert!(pub_key_1.verify(message, &typed_sig).is_ok());
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
        let high_s = with_recovery_id(&negate_s(&honest), honest[SIG_LENGTH] ^ 1);
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
            bytes == honest || bytes == high_s
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

    // Signing, conversion to a non-recoverable signature and back, and recovery agree.
    #[test]
    fn test_recoverable_conversions(
        seed in any::<[u8; 32]>(),
        msg in collection::vec(any::<u8>(), 0..100),
    ) {
        let kp = Secp256k1KeyPair::generate(&mut StdRng::from_seed(seed));
        let sig = kp.sign_recoverable(&msg);
        prop_assert!(sig.as_bytes()[SIG_LENGTH] <= 1);
        prop_assert_eq!(&sig.recover(&msg).unwrap(), kp.public());
        let standard = Secp256k1Signature::from(&sig);
        prop_assert_eq!(&standard, &kp.sign(&msg));
        prop_assert_eq!(
            Secp256k1RecoverableSignature::try_from_nonrecoverable(&standard, kp.public(), &msg)
                .unwrap(),
            sig
        );
    }
}
