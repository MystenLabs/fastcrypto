// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::{
    blst_bendian_from_scalar, blst_fr, blst_fr_from_scalar, blst_fr_mul, blst_p1, blst_p1_affine,
    blst_p1_deserialize, blst_p1_from_affine, blst_p1_mult, blst_p1_serialize, blst_p2,
    blst_p2_affine, blst_p2_deserialize, blst_p2_from_affine, blst_p2_mult, blst_p2_serialize,
    blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
};
use once_cell::sync::OnceCell;
//
// Implement MSKR for BLS12381
//
use crate::bls12381::min_pk::{
    BLS12381KeyPair, BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
};
use crate::bls12381::mskr::{HashToScalar, Randomize};
use crate::hash::{HashFunction, Sha256};
use crate::traits::VerifyingKey;

pub struct BLS12381Hash {}

impl HashToScalar<blst_fr> for BLS12381Hash {
    fn hash_to_scalar(bytes: &[u8]) -> blst_fr {
        let digest = Sha256::digest(bytes);
        let mut field_value = blst_fr::default();
        unsafe {
            let mut scalar: blst_scalar = blst_scalar::default();
            blst_scalar_from_bendian(&mut scalar, digest.digest.as_ptr());
            blst_fr_from_scalar(&mut field_value, &scalar);
        }
        field_value
    }
}

impl Randomize<BLS12381PublicKey, blst_fr, BLS12381Hash, { BLS12381PublicKey::LENGTH }>
    for BLS12381PublicKey
{
    fn randomize_internal(&self, r: &blst_fr) -> Self {
        // It's not possible to extract the underlying point from a pk directly, so we serialize
        // it and deserialize it as a point.
        let pubkey_bytes = &self.pubkey.serialize();
        let mut serialized: [u8; 96] = [0; 96];

        unsafe {
            // Public key as affine point.
            let mut pubkey_affine_pt = blst_p1_affine::default();
            blst_p1_deserialize(&mut pubkey_affine_pt, pubkey_bytes.as_ptr());

            // Public key as point.
            let mut pubkey_pt = blst_p1::default();
            blst_p1_from_affine(&mut pubkey_pt, &pubkey_affine_pt);

            // Randomization factor as scalar.
            let mut scalar = blst_scalar::default();
            blst_scalar_from_fr(&mut scalar, r);

            // Randomized public key as point.
            let mut randomized_pt = blst_p1::default();
            blst_p1_mult(&mut randomized_pt, &pubkey_pt, &(scalar.b[0]), 256);

            // Serialize randomized public key.
            blst_p1_serialize(serialized.as_mut_ptr(), &randomized_pt);
        }
        BLS12381PublicKey {
            pubkey: PublicKey::deserialize(&serialized).unwrap(),
            bytes: OnceCell::new(),
        }
    }
}

impl Randomize<BLS12381PublicKey, blst_fr, BLS12381Hash, { BLS12381PublicKey::LENGTH }>
    for BLS12381Signature
{
    fn randomize_internal(&self, r: &blst_fr) -> Self {
        // It's not possible to extract the underlying point from a pk directly, so we serialize
        // it and deserialize it as a point.
        let pubkey_bytes = &self.sig.serialize();
        let mut serialized: [u8; 192] = [0; 192];

        unsafe {
            // Signature as affine point.
            let mut pubkey_affine_pt = blst_p2_affine::default();
            blst_p2_deserialize(&mut pubkey_affine_pt, pubkey_bytes.as_ptr());

            // Signature as point.
            let mut pubkey_pt = blst_p2::default();
            blst_p2_from_affine(&mut pubkey_pt, &pubkey_affine_pt);

            // Randomization factor as scalar.
            let mut scalar = blst_scalar::default();
            blst_scalar_from_fr(&mut scalar, r);

            // Randomized signature as point.
            let mut randomized_pt = blst_p2::default();
            blst_p2_mult(&mut randomized_pt, &pubkey_pt, &(scalar.b[0]), 256);

            // Serialize randomized signature.
            blst_p2_serialize(serialized.as_mut_ptr(), &randomized_pt);
        }

        BLS12381Signature {
            sig: Signature::deserialize(&serialized).unwrap(),
            bytes: OnceCell::new(),
        }
    }
}

impl Randomize<BLS12381PublicKey, blst_fr, BLS12381Hash, { BLS12381PublicKey::LENGTH }>
    for BLS12381PrivateKey
{
    fn randomize_internal(&self, r: &blst_fr) -> Self {
        let privkey_bytes = self.privkey.to_bytes();
        let mut randomized_bytes: [u8; 32] = [0; 32];

        unsafe {
            // Parse private key as scalar.
            let mut as_scalar = blst_scalar::default();
            blst_scalar_from_bendian(&mut as_scalar, privkey_bytes.as_ptr());

            // Convert scalar to field element.
            let mut as_field_element = blst_fr::default();
            blst_fr_from_scalar(&mut as_field_element, &as_scalar);

            // Randomize field element.
            let mut randomized_as_field_element = blst_fr::default();
            blst_fr_mul(&mut randomized_as_field_element, &as_field_element, r);

            // Convert to scalar.
            let mut randomized = blst_scalar::default();
            blst_scalar_from_fr(&mut randomized, &randomized_as_field_element);

            // Serialize scalar.
            blst_bendian_from_scalar(randomized_bytes.as_mut_ptr(), &randomized);
        }

        BLS12381PrivateKey {
            privkey: SecretKey::from_bytes(&randomized_bytes).unwrap(),
            bytes: OnceCell::new(),
        }
    }
}
impl Randomize<BLS12381PublicKey, blst_fr, BLS12381Hash, { BLS12381PublicKey::LENGTH }>
    for BLS12381KeyPair
{
    fn randomize_internal(&self, r: &blst_fr) -> Self {
        BLS12381KeyPair {
            private: self.private.randomize_internal(r),
            public: self.public.randomize_internal(r),
        }
    }
}
