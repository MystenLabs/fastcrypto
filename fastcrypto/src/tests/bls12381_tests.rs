// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::encoding::Encoding;
use crate::{
    bls12381::{BLS_G1_LENGTH, BLS_G2_LENGTH, BLS_PRIVATE_KEY_LENGTH},
    encoding::Base64,
    hash::{HashFunction, Sha256, Sha3_256},
    hmac::hkdf_generate_from_ikm,
    traits::{
        AggregateAuthenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes, VerifyingKey,
    },
};
use proptest::{collection, prelude::*};
use rand::{rngs::StdRng, SeedableRng as _};
use signature::{Signature, Signer, Verifier};


// We use the following macro in order to run all tests for both min_sig and min_pk.
macro_rules! define_tests { () => {
pub fn keys() -> Vec<BLS12381KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| BLS12381KeyPair::generate(&mut rng))
        .collect()
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = BLS12381PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = BLS12381PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <BLS12381Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

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

fn signature_test_inputs() -> (Vec<u8>, Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let (pubkeys, signatures): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    (digest.to_vec(), pubkeys, signatures)
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = BLS12381Signature::default();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = BLS12381PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

fn verify_batch_aggregate_signature_inputs() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<BLS12381PublicKey>,
    Vec<BLS12381PublicKey>,
    BLS12381AggregateSignature,
    BLS12381AggregateSignature,
) {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let digest1 = Sha256::digest(message1);
    let (pubkeys1, signatures1): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest1.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();
    let aggregated_signature1 = BLS12381AggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, worl!";
    let digest2 = Sha256::digest(message2);
    let (pubkeys2, signatures2): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(2)
        .map(|kp| {
            let sig = kp.sign(digest2.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature2 = BLS12381AggregateSignature::aggregate(&signatures2).unwrap();
    (
        digest1.to_vec(),
        digest2.to_vec(),
        pubkeys1,
        pubkeys2,
        aggregated_signature1,
        aggregated_signature2,
    )
}

#[test]
fn verify_batch_aggregate_signature() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    assert!(BLS12381AggregateSignature::batch_verify(
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

    // Fewer PubKeys than signatures
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());

    // Fewer messages than signatures
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..]]
    )
    .is_err());
    assert!(BLS12381AggregateSignature::batch_verify(
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

    // PubKeys missing at the end
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[1..].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // PubKeys missing at the start
    assert!(BLS12381AggregateSignature::batch_verify(
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

    assert!(BLS12381AggregateSignature::batch_verify(
        &[&signatures1_with_extra, &signatures2_with_extra],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
}

#[test]
fn test_serialize_deserialize_aggregate_signatures() {
    // Test empty aggregate signature
    let sig = BLS12381AggregateSignature::default();
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: BLS12381AggregateSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());

    let message = b"hello, narwhal";
    // Test populated aggregate signature
    let (_, signatures): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    let sig = BLS12381AggregateSignature::aggregate(&signatures).unwrap();
    let serialized = bincode::serialize(&sig).unwrap();
    let deserialized: BLS12381AggregateSignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());
}

#[test]
fn test_add_signatures_to_aggregate() {
    let pks: Vec<BLS12381PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = BLS12381AggregateSignature::default();
    // Test populated aggregate signature
    keys().into_iter().take(3).for_each(|kp| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();
    });

    assert!(sig1.verify(&pks, message).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12381AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12381AggregateSignature::aggregate(&[kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    let aggregated_signature = BLS12381AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<BLS12381Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_add_signatures_to_aggregate_different_messages() {
    let pks: Vec<BLS12381PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let messages: Vec<&[u8]> = vec![b"hello", b"world", b"!!!!!"];

    // Test 'add signature'
    let mut sig1 = BLS12381AggregateSignature::default();
    // Test populated aggregate signature
    for (i, kp) in keys().into_iter().take(3).enumerate() {
        let sig = kp.sign(messages[i]);
        sig1.add_signature(sig).unwrap();
    }

    assert!(sig1.verify_different_msg(&pks, &messages).is_ok());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12381AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12381AggregateSignature::aggregate(&[kp.sign(messages[0])]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2
        .verify_different_msg(&pks[0..1], &messages[0..1])
        .is_ok());

    let aggregated_signature = BLS12381AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .zip(&messages)
            .take(3)
            .skip(1)
            .map(|(kp, message)| kp.sign(message))
            .collect::<Vec<BLS12381Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();

    assert!(sig2.verify_different_msg(&pks, &messages).is_ok());
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = signature_tests::signature_test_inputs_different_msg::<BLS12381KeyPair>();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = signature_tests::signature_test_inputs_different_msg::<BLS12381KeyPair>();
    inputs.signatures[0] = BLS12381Signature::default();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn test_human_readable_signatures() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);

    let serialized = serde_json::to_string(&signature).unwrap();
    assert_eq!(
        format!(
            "{{\"sig\":\"{}\"}}",
            Base64::encode(&signature.sig.to_bytes())
        ),
        serialized
    );
    let deserialized: BLS12381Signature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, signature);
}

#[test]
fn test_hkdf_generate_from_ikm() {
    let seed = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];
    let salt = &[3, 2, 1];
    let kp = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(seed, salt, &[]).unwrap();
    let kp2 = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(seed, salt, &[]).unwrap();

    assert_eq!(kp.private().as_bytes(), kp2.private().as_bytes());
}

#[test]
fn test_public_key_bytes_conversion() {
    let kp = keys().pop().unwrap();
    let pk_bytes: BLS12381PublicKeyBytes = kp.public().into();
    let rebuilt_pk: BLS12381PublicKey = pk_bytes.try_into().unwrap();
    assert_eq!(kp.public().as_bytes(), rebuilt_pk.as_bytes());
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();

    // Spawn the signature service.
    let mut service = SignatureService::new(kp);

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
        let kp = BLS12381KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, BLS12381PrivateKey::LENGTH) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is zeroized
    unsafe {
        for i in 0..BLS12381PrivateKey::LENGTH {
            assert_eq!(*ptr.add(i), 0);
        }
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, BLS12381PrivateKey::LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for BLS12381PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for BLS12381PrivateKey>"
        );
    });
}

#[test]
fn test_signature_aggregation() {
    let mut rng = StdRng::from_seed([0; 32]);
    let msg = b"message";

    // Valid number of signatures
    for size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192] {
        let blst_keypairs: Vec<_> = (0..size)
            .map(|_| BLS12381KeyPair::generate(&mut rng))
            .collect();
        let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(msg)).collect();
        assert!(BLS12381AggregateSignature::aggregate(&blst_signatures).is_ok());
    }

    // Invalid number of signatures
    let blst_keypairs: Vec<_> = (0..0)
        .map(|_| BLS12381KeyPair::generate(&mut rng))
        .collect();
    let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(msg)).collect();
    assert!(BLS12381AggregateSignature::aggregate(&blst_signatures).is_err());
}

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = BLS12381KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            BLS12381KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

prop_compose! {
    fn valid_signature(pk: BLS12381PrivateKey)
                      (msg in any::<[u8; 32]>()) -> ([u8; 32], BLS12381Signature) {
            (msg, pk.sign(&msg))
    }
}

prop_compose! {
  fn maybe_valid_sig(pk: BLS12381PrivateKey)
                    (disc in bool::arbitrary(),
                    (msg, sig) in valid_signature(pk))
                       -> ([u8; 32], BLS12381Signature) {
    if disc {
      (msg, sig)
    } else {
      let mut rng = StdRng::from_seed([0; 32]);
      let mut msg = msg;
      rng.fill_bytes(&mut msg);
      (msg, sig)
    }
  }
}

fn arb_sig_triplet() -> impl Strategy<Value = (BLS12381PublicKey, [u8; 32], BLS12381Signature)> {
    arb_keypair()
        .prop_flat_map(|kp| {
            let pk: BLS12381PublicKey = kp.public().clone();
            (Just(pk), maybe_valid_sig(kp.private()))
        })
        .prop_flat_map(|(pk, (msg, sig))| (Just(pk), Just(msg), Just(sig)))
        .no_shrink()
}

const BLS_MAX_SIGNATURES: usize = 100;

fn aggregate_treewise(sigs: &[BLS12381Signature]) -> BLS12381AggregateSignature {
    if sigs.len() <= 1 {
        return sigs
            .first()
            .map(|s| {
                let mut res = BLS12381AggregateSignature::default();
                res.add_signature(s.clone()).unwrap();
                res
            })
            .unwrap_or_default();
    } else {
        let mid = sigs.len() / 2;
        let (left, right) = sigs.split_at(mid);
        let left = aggregate_treewise(left);
        let right = aggregate_treewise(right);
        let mut res = BLS12381AggregateSignature::default();
        res.add_aggregate(left).unwrap();
        res.add_aggregate(right).unwrap();
        res
    }
}

proptest! {
    // Tests that serde does not panic
    #[test]
    fn test_basic_deser_publickey(bits in collection::vec(any::<u8>(), BLS_G2_LENGTH..=BLS_G2_LENGTH)) {
        let _ = BLS12381PublicKey::from_bytes(&bits);
    }

    #[test]
    fn test_basic_deser_privatekey(bits in collection::vec(any::<u8>(), BLS_PRIVATE_KEY_LENGTH..=BLS_PRIVATE_KEY_LENGTH)) {
        let _ = BLS12381PrivateKey::from_bytes(&bits);
    }

    #[test]
    fn test_basic_deser_signature(bits in collection::vec(any::<u8>(), BLS_G1_LENGTH..=BLS_G1_LENGTH)) {
        let _ = <BLS12381Signature as Signature>::from_bytes(&bits);
        let _ = <BLS12381Signature as ToFromBytes>::from_bytes(&bits);
    }

    // Tests that signature verif does not panic
    #[test]
    fn test_basic_verify_signature(
        (pk, msg, sig) in arb_sig_triplet()
    ) {
        let _ = pk.verify(&msg, &sig);
    }


    // Test compatibility between aggregate and iterated verification
    #[test]
    fn test_aggregate_verify_distinct_messages(
        triplets in collection::vec(arb_sig_triplet(), 1..=BLS_MAX_SIGNATURES)
    ){
        let mut aggr = BLS12381AggregateSignature::default();
        let (pks_n_msgs, sigs): (Vec<_>, Vec<_>) = triplets.into_iter().map(|(pk, msg, sig)| ((pk, msg), sig)).unzip();
        for sig in sigs.clone() {
            aggr.add_signature(sig).unwrap();
        }
        let (pks, msgs): (Vec<_>, Vec<_>) = pks_n_msgs.into_iter().unzip();

        let res_aggregated = aggr.verify_different_msg(&pks, &msgs.iter().map(|m| m.as_ref()).collect::<Vec<_>>());
        let iterated_bits = sigs.iter().zip(pks.iter().zip(msgs.iter())).map(|(sig, (pk, msg))| pk.verify(msg, sig)).collect::<Vec<_>>();
        let res_iterated = iterated_bits.iter().all(|b| b.is_ok());


        assert_eq!(res_aggregated.is_ok(), res_iterated, "Aggregated: {:?}, iterated: {:?}", res_aggregated, iterated_bits);
    }

    #[test]
    fn test_aggregate_verify_distinct_messages_treewise(
        triplets in collection::vec(arb_sig_triplet(), 1..=BLS_MAX_SIGNATURES)
    ){
        let (pks_n_msgs, sigs): (Vec<_>, Vec<_>) = triplets.into_iter().map(|(pk, msg, sig)| ((pk, msg), sig)).unzip();
        let aggr = aggregate_treewise(&sigs);
        let (pks, msgs): (Vec<_>, Vec<_>) = pks_n_msgs.into_iter().unzip();

        let res_aggregated = aggr.verify_different_msg(&pks, &msgs.iter().map(|m| m.as_ref()).collect::<Vec<_>>());
        let iterated_bits = sigs.iter().zip(pks.iter().zip(msgs.iter())).map(|(sig, (pk, msg))| pk.verify(msg, sig)).collect::<Vec<_>>();
        let res_iterated = iterated_bits.iter().all(|b| b.is_ok());

        assert_eq!(res_aggregated.is_ok(), res_iterated, "Aggregated: {:?}, iterated: {:?}", res_aggregated, iterated_bits);
    }

}
}} // macro_rules! define_tests

pub mod min_sig {
    use super::*;
    use crate::bls12381::min_sig::{
            BLS12381AggregateSignature, BLS12381KeyPair, BLS12381PrivateKey, BLS12381PublicKey,
            BLS12381PublicKeyBytes, BLS12381Signature,
        };
    define_tests!();
}

pub mod min_pk {
    use super::*;
    use crate::bls12381::min_pk::{
        BLS12381AggregateSignature, BLS12381KeyPair, BLS12381PrivateKey, BLS12381PublicKey,
        BLS12381PublicKeyBytes, BLS12381Signature,
    };
    define_tests!();
}