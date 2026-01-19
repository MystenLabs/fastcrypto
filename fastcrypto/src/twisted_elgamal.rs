use crate::error::FastCryptoError::InvalidInput;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar, RISTRETTO_POINT_BYTE_LENGTH};
use crate::groups::{Doubling, GroupElement, Scalar};
use crate::pedersen::PedersenCommitment;
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use bulletproofs::PedersenGens;
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref G: RistrettoPoint = RistrettoPoint(PedersenGens::default().B);
    static ref H: RistrettoPoint = RistrettoPoint(PedersenGens::default().B_blinding);
}

pub fn generate_keypair(rng: &mut impl AllowedRng) -> (RistrettoPoint, RistrettoScalar) {
    let private_key = RistrettoScalar::rand(rng);
    let public_key = *H * private_key.inverse().unwrap();
    (public_key, private_key)
}

pub struct Ciphertext {
    commitment: PedersenCommitment,
    decryption_handle: RistrettoPoint,
}

impl Ciphertext {
    pub fn encrypt(public_key: &RistrettoPoint, message: u32, rng: &mut impl AllowedRng) -> Self {
        let r = RistrettoScalar::rand(rng);
        Self {
            commitment: PedersenCommitment::from_blinding_factor(
                &RistrettoScalar::from(message as u64),
                &r,
            ),
            decryption_handle: public_key * r,
        }
    }

    pub fn decrypt(
        &self,
        private_key: &RistrettoScalar,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u32>,
    ) -> FastCryptoResult<u32> {
        let mut c = self.commitment.0 - self.decryption_handle * private_key;
        for x_low in 0..1u32 << 16 {
            if let Some(x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + (x_high << 16));
            }
            c -= *G;
        }
        Err(InvalidInput)
    }
}

/// Precompute discrete log table for use in decryption. This only needs to be computed once.
pub fn precompute_table() -> HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u32> {
    let step = G.repeated_doubling(16);
    let mut point = RistrettoPoint::zero();
    let mut table = HashMap::with_capacity(1 << 16);
    for x_high in 0..1 << 16 {
        table.insert(point.to_byte_array(), x_high);
        point += step;
    }
    table
}

#[test]
fn test_round_trip() {
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let message = 1234567890u32;
    let ciphertext = Ciphertext::encrypt(&pk, message, &mut rand::thread_rng());

    // This table can be reused, so it only has to be computed once
    let table = precompute_table();
    assert_eq!(ciphertext.decrypt(&sk, &table).unwrap(), message);
}
