// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of Pedersen Commitments and [Bulletproofs](https://crypto.stanford.edu/bulletproofs/), which are short non-interactive zero-knowledge proofs that require no trusted setup.
//!
//! # Example
//! ```rust
//! # use fastcrypto::bulletproofs::*;
//! # use fastcrypto::bulletproofs::Range::Bits16;
//! # use fastcrypto::groups::ristretto255::RistrettoScalar;
//! # use fastcrypto::groups::Scalar;
//! use fastcrypto::pedersen::{Blinding, PedersenCommitment};
//! let mut rng = rand::thread_rng();
//! let value = 300;
//! let (commitment, blinding) = PedersenCommitment::commit_u64(value, &mut rng);
//! let range = Bits16;
//! let proof =
//!    RangeProof::prove(value, &blinding, &range, b"dst", &mut rng).unwrap();
//! assert!(proof.verify(&commitment, &range, b"dst", &mut rng).is_ok());
//! ```

use crate::error::FastCryptoError::{GeneralOpaqueError, InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::pedersen::{Blinding, PedersenCommitment, GENERATORS};
use crate::traits::AllowedRng;
use bulletproofs::{BulletproofGens, RangeProof as ExternalRangeProof};
use itertools::Itertools;
use merlin::Transcript;

/// Bulletproof Range Proofs
#[derive(Debug)]
pub struct RangeProof(ExternalRangeProof);

pub enum Range {
    /// The range [0,...,2^8).
    Bits8,

    /// The range [0,...,2^16).
    Bits16,

    /// The range [0,...,2^32).
    Bits32,

    /// The range [0,...,2^64).
    Bits64,
}

impl Range {
    pub fn is_in_range(&self, value: u64) -> bool {
        if value == 0 {
            return true;
        }
        value.ilog2() < self.upper_bound_in_bits()
    }

    fn upper_bound_in_bits(&self) -> u32 {
        match self {
            Range::Bits8 => 8,
            Range::Bits16 => 16,
            Range::Bits32 => 32,
            Range::Bits64 => 64,
        }
    }
}

impl RangeProof {
    /// Prove that the `value` is in the given range using the given commitment blinding.
    /// This enables creating proofs for an existing commitment.
    /// Returns an `InvalidInput` error if the value is not in range.
    pub fn prove(
        value: u64,
        blinding: &Blinding,
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        Self::prove_batch(&[value], std::slice::from_ref(blinding), range, dst, rng)
    }

    /// Verifies a range proof: That the commitment is to a value in the given range.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        self.verify_batch(std::slice::from_ref(commitment), range, dst, rng)
    }

    /// Create a proof that all the given `values` are in the range using the given commitment blindings.
    /// This enables creating proofs for existing commitments.
    ///
    /// Fails if
    /// * any of the `values` are <i>not</i> in the range.
    /// * `values.len() != blindings.len()`,
    /// * `values.len()` is not a power of 2,
    pub fn prove_batch(
        values: &[u64],
        blindings: &[Blinding],
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        if values.iter().any(|&v| !range.is_in_range(v))
            || blindings.len() != values.len()
            || !values.len().is_power_of_two()
        {
            return Err(InvalidInput);
        }

        let bits = range.upper_bound_in_bits() as usize;
        ExternalRangeProof::prove_multiple_with_rng(
            &BulletproofGens::new(bits, values.len()),
            &GENERATORS,
            &mut transcript(dst),
            values,
            &blindings.iter().map(Blinding::to_dalek).collect_vec(),
            bits,
            rng,
        )
        .map(|(proof, _)| RangeProof(proof))
        .map_err(|_| GeneralOpaqueError)
    }

    /// Verifies that a range proof that all commitments are to values in the given `range`.
    pub fn verify_batch(
        &self,
        commitments: &[PedersenCommitment],
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        let bits = range.upper_bound_in_bits() as usize;
        self.0
            .verify_multiple_with_rng(
                &BulletproofGens::new(bits, commitments.len()),
                &GENERATORS,
                &mut transcript(dst),
                &commitments
                    .iter()
                    .map(PedersenCommitment::to_dalek)
                    .collect_vec(),
                bits,
                rng,
            )
            .map_err(|_| InvalidProof)
    }

    /// Serialize a range proof. The output will be serialized Risretto255 group elements and scalars.
    /// It follows the format used in https://github.com/dalek-cryptography/bulletproofs/blob/be67b6d5f5ad1c1f54d5511b52e6d645a1313d07/src/range_proof/mod.rs#L59-L76.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Deserialize a range proof. See also [Self::to_bytes].
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        ExternalRangeProof::from_bytes(bytes)
            .map(RangeProof)
            .map_err(|_| InvalidInput)
    }
}

/// Create a transcript bound to the given domain separation tag.
fn transcript(dst: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(&[]);
    transcript.append_message(b"DST", dst);
    transcript
}

#[test]
fn test_is_in_range() {
    assert!(Range::Bits8.is_in_range(0));
    assert!(Range::Bits8.is_in_range(u8::MAX as u64));
    assert!(!Range::Bits8.is_in_range(1 << 8));
    assert!(Range::Bits16.is_in_range(0));
    assert!(Range::Bits16.is_in_range(u16::MAX as u64));
    assert!(!Range::Bits16.is_in_range(1 << 16));
    assert!(Range::Bits32.is_in_range(0));
    assert!(Range::Bits32.is_in_range(u32::MAX as u64));
    assert!(!Range::Bits32.is_in_range(1 << 32));
    assert!(Range::Bits64.is_in_range(0));
    assert!(Range::Bits64.is_in_range(u64::MAX));
}

#[test]
fn test_range_proof() {
    let range = Range::Bits16;
    let mut rng = rand::thread_rng();
    let value = 1234u64;
    let (commitment, blinding) = PedersenCommitment::commit_u64(value, &mut rng);

    let proof = RangeProof::prove(value, &blinding, &range, b"test", &mut rng).unwrap();
    assert!(RangeProof::prove(value, &blinding, &Range::Bits8, b"test", &mut rng).is_err());

    assert!(proof.verify(&commitment, &range, b"test", &mut rng).is_ok());
    assert!(proof
        .verify(&commitment, &range, b"other", &mut rng)
        .is_err());
}

#[test]
fn test_batch_range_proof_valid() {
    let range = Range::Bits32;
    let mut rng = rand::thread_rng();
    let values = (1u64..=8).collect::<Vec<_>>();
    let (commitments, blindings) = values
        .iter()
        .map(|&v| PedersenCommitment::commit_u64(v, &mut rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let proof =
        RangeProof::prove_batch(&values, &blindings, &range, b"test_dst", &mut rng).unwrap();
    assert!(proof
        .verify_batch(&commitments, &range, b"test_dst", &mut rng)
        .is_ok());
}

#[test]
fn test_to_from_bytes() {
    let range = Range::Bits32;
    let mut rng = rand::thread_rng();
    let values = (1u64..=8).collect::<Vec<_>>();
    let (commitments, blindings) = values
        .iter()
        .map(|&v| PedersenCommitment::commit_u64(v, &mut rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let proof = RangeProof::prove_batch(&values, &blindings, &range, b"test", &mut rng).unwrap();
    let proof_bytes = proof.to_bytes();
    let reconstructed_proof = RangeProof::from_bytes(&proof_bytes).unwrap();
    assert!(reconstructed_proof
        .verify_batch(&commitments, &range, b"test", &mut rng)
        .is_ok());
}

#[test]
fn regression_test() {
    use crate::encoding::{Encoding, Hex};
    use crate::groups::ristretto255::RistrettoPoint;
    use crate::pedersen::PedersenCommitment;
    use crate::serde_helpers::ToFromByteArray;

    let proof = RangeProof::from_bytes(&Hex::decode("e27e1f3db57f05833973ec4b3e9def2b660ef256e42be0ca2747d47ff1ccdb30e65730ffed8175c640a8bfaa6d8840baa74130b439e9270dcbb0ce041801040a00d0d7dcdcd088f6bb63320ec2c1c2db4b5634ec7b477c2685a390a76658a679809d44e5a62481597a843a0d93953ebc9dc0b4640a02408111e7ad82da6c7460334eb71999b7758f27ea76f76b5335b21398574525e04b1d609eca69080f250cd573edf050ca9cb0d152d493037b2f46b0d2a8db005ec2bb13cfc67829fd220c989e3e3b4ba93bd798ff45892f69b279bc3311ed19ab396c8ce7a81d314ef10ef6b7ce7d0d323ae8e03c69e38bc3dfc88f4930d69adc8661e577f7bcd10c7b3d0c2dd337a9149a90ef961b0ac7f39b43a9658698036bb94ec2fa30de9058c16e20a6a88b60adf0af37e01f90a51bf3353256f4ec10d862b1870b58dd4f0cea255891878a36e54ebbfc126d271e54459abcd74b1b05512e43ae8cd8df88d96159ae6e0b0dda3e0da88c8aad392d264e34c9cc40464d3cb24f39a25373104ff03cb45050dc9d65d5909a07bbbee45e875d48aa3e1355d7356a97d7d8a37fa88355b0115b8eeda7e2dbae17c4259b9a75d93830e9934781275e771263313824bb4f8439f882fba97f4bb8f5159a22640181d155f8ca342055654325a6d6ae25460d4075e595f8eb1cde6afd95a0c1eec6edcfc60c666501bfbb38098faec118672f622a484e848e1fc523bf6b09f4f03324ae2bc66f9eeffa4d9fd86392c1602b4d1e3fafd9db0f5d263cfdc98f7d65ad4cd6d765e7c151d7cd528839f4d6b8bd481203e7e5c3fcfa114f86bd71240b8a4e7efa760f6691d2d23120957d258915379a2bf98c4bb3c011e704ebdeb463dd53bbd3e6ca01a1dc070e4064b73e4d690a76ced51e0b0562783409c8c8cdff0864f7636641481562aaeb1c2c962ecd2a5e3e2b376ee5f0b1bcad29f0e3cd292144455c63b708154bca4f80d337f06bfe5f520750afaf6d2fa78e400a6bbf1625e8b262ea24539237fd365b4dd1fdc9644b2752bf6e6c0aa3bdd8332ebf9f34c32176e4fea97a5a185dd267e11f6283e20dce2a83e4fc1e1e848d6e1b3174564aa3b5eb9c523f35f1274b54da5a2a6d7905").unwrap()).unwrap();
    let commitments = [
        "3864fd028e266349c38e76d2b3361e1a197084247dd9c7413c061bcbd2026634",
        "0e95477497ebd8390b70fde21813ad0f060d2b5fe8ee300f045d5dc4941fd431",
        "74a2b02427dd95fbe2e0fdc7c1fb046ad1bfec0cb7777581ccc2bc3fcb81462f",
        "d65e1514458c92150f02ef24d9524490f26bdbba9302e7e06056007576bf8e44",
        "a27f94f3d348cb67237a0e86beba42a20d6cd36b63ce7421e5a8fd2043f7727e",
        "00f28f68b3dad813674a578644391e4faa272a6d29522eb38e1773c72cfed145",
        "6afc2e4d5d9924b8359a25cefe49a04ea8b1cab5b03c17d535a69b4603350e52",
        "d0983791c005d212e98659c181e72f187680f2675b163dc817d8dc41d03b3c7c",
    ]
    .iter()
    .map(|s| Hex::decode(s).unwrap())
    .map(|b| RistrettoPoint::from_byte_array(&b.try_into().unwrap()).unwrap())
    .map(PedersenCommitment)
    .collect::<Vec<_>>();
    assert!(proof
        .verify_batch(
            &commitments,
            &Range::Bits32,
            b"test",
            &mut rand::thread_rng()
        )
        .is_ok());
}
