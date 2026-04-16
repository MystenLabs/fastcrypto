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
//! let value = 300;
//! let range = Bits16;
//! let mut rng = rand::rng();
//! let blinding = Blinding::rand(&mut rng);
//! let proof =
//!    RangeProof::prove(value, &blinding, &range, &mut rng).unwrap();
//! let commitment = PedersenCommitment::new(&RistrettoScalar::from(value), &blinding);
//! assert!(proof.verify(&commitment, &range, &mut rng).is_ok());
//! ```

use crate::error::FastCryptoError::{GeneralOpaqueError, InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::pedersen::{Blinding, PedersenCommitment, GENERATORS};
use crate::traits::AllowedRng;
use bulletproofs::{BulletproofGens, RangeProof as ExternalRangeProof};
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
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        Self::prove_batch(&[value], std::slice::from_ref(blinding), range, rng)
    }

    /// Verifies a range proof: That the commitment is to a value in the given range.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        range: &Range,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        self.verify_batch(std::slice::from_ref(commitment), range, rng)
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
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        if values.iter().any(|&v| !range.is_in_range(v))
            || blindings.len() != values.len()
            || !values.len().is_power_of_two()
        {
            return Err(InvalidInput);
        }

        let bits = range.upper_bound_in_bits() as usize;
        let bp_gens = BulletproofGens::new(bits, values.len());
        let mut prover_transcript = Transcript::new(&[]);

        // TODO: Can we avoid calculating the Pedersen commitments here?
        ExternalRangeProof::prove_multiple_with_rng(
            &bp_gens,
            &GENERATORS,
            &mut prover_transcript,
            values,
            &blindings.iter().map(|b| b.0 .0).collect::<Vec<_>>(),
            bits,
            &mut crate::traits::old_rng(rng),
        )
        .map(|(proof, _)| RangeProof(proof))
        .map_err(|_| GeneralOpaqueError)
    }

    /// Verifies that a range proof that all commitments are to values in the given `range`.
    pub fn verify_batch(
        &self,
        commitments: &[PedersenCommitment],
        range: &Range,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        let bits = range.upper_bound_in_bits() as usize;
        let bp_gens = BulletproofGens::new(bits, commitments.len());
        let mut verifier_transcript = Transcript::new(&[]);

        self.0
            .verify_multiple_with_rng(
                &bp_gens,
                &GENERATORS,
                &mut verifier_transcript,
                &commitments
                    .iter()
                    .map(|c| c.0 .0.compress())
                    .collect::<Vec<_>>(),
                bits,
                &mut crate::traits::old_rng(rng),
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
fn test_range_proof_valid() {
    use crate::groups::ristretto255::RistrettoScalar;

    let range = Range::Bits32;
    let mut rng = rand::rng();
    let blinding = Blinding::rand(&mut rng);

    let value = 1u64;
    let proof = RangeProof::prove(value, &blinding, &range, &mut rng).unwrap();
    let commitment = PedersenCommitment::new(&RistrettoScalar::from(value), &blinding);
    assert!(proof.verify(&commitment, &range, &mut rng).is_ok());
}

#[test]
fn test_batch_range_proof_valid() {
    use crate::groups::ristretto255::RistrettoScalar;
    let range = Range::Bits32;
    let mut rng = rand::rng();
    let values = (1u64..=8).collect::<Vec<_>>();
    let (commitments, blindings) = values
        .iter()
        .map(|&v| PedersenCommitment::commit(&RistrettoScalar::from(v), &mut rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let proof = RangeProof::prove_batch(&values, &blindings, &range, &mut rng).unwrap();
    assert!(proof.verify_batch(&commitments, &range, &mut rng).is_ok());
}

#[test]
fn test_to_from_bytes() {
    use crate::encoding::{Encoding, Hex};
    use crate::groups::ristretto255::RistrettoScalar;
    use crate::serde_helpers::ToFromByteArray;

    let range = Range::Bits32;
    let mut rng = rand::rng();
    let values = (1u64..=8).collect::<Vec<_>>();
    let (commitments, blindings) = values
        .iter()
        .map(|&v| PedersenCommitment::commit(&RistrettoScalar::from(v), &mut rng))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    commitments
        .iter()
        .for_each(|c| println!("{}", Hex::encode(c.0.to_byte_array())));
    let proof = RangeProof::prove_batch(&values, &blindings, &range, &mut rng).unwrap();
    let proof_bytes = proof.to_bytes();
    println!("{}", Hex::encode(&proof_bytes));
    let reconstructed_proof = RangeProof::from_bytes(&proof_bytes).unwrap();
    assert!(reconstructed_proof
        .verify_batch(&commitments, &range, &mut rng)
        .is_ok());
}

#[test]
fn regression_test() {
    use crate::encoding::{Encoding, Hex};
    use crate::groups::ristretto255::RistrettoPoint;
    use crate::pedersen::PedersenCommitment;
    use crate::serde_helpers::ToFromByteArray;

    let proof = RangeProof::from_bytes(&Hex::decode("483752e4e9be898bb7098adbe1cd4ec71614c7cf897de2d9e6b5d7615bb96b7b9ca3621b3fd885045903b82a4bc979094639f216c479362b0ab497dcbbe5600580c3a9e90d1fab586d7f3e8c9fcae71da9474c106610b5d473824a33e3472e20e04390d7052480b3500a96167e405a9b27f59a6b74f47457454014307a97e108ab6681983e5556fb19d2a33f753b364695cb7188948ff7f997a5fe3d55fcc902fcd5afcbd45a41ef298d6e16560fb407d29c81dac20705cd18d52f4925700003bf7b175cdf6d5d8c6eeef35f7357a88edac323eef8dda1f90ff4ebafab91650182d44889691ed4e1789891d7111c2adc97feb2e48e5bde1d3407f98e2a85b66c086bc4d03cbdd9237023bd601bbad70377345bafe027d2e794d702585a7ce72008cb2efec10638555841eb17917c1b6d41533e5a93496fbb2c8cf1e98830732290dd8d6b6a10c2622d866c6e0dbac2aee6c94409f5a50affbc47081cd24414414e080474c144f2b2e38d8c02a56c9dc8bc5ca6b342cfbec04c40b9e8225a7f1fb62b3ddc4ad00f7606ce2942f123503da272e2a6e25a6f0d0038030b489c8675d614bc0073056ffa2ec10231c50b7fcae9d961f66dd299da4b1985a2eb6c215aee1e41de609e70ffcf73bd2b1c677e7afe31c0d16c202dbc006f187266f94f2be44668778c18f0b76f9cb4608594350371c2e0391b6be322fbb78fa03400f272ecae55d95c3ddccfc76353753fa596ef076ac02084a9bcc525df5e5ab086850868c17b907c484553e19fd693702884c4745eb833bd27598a23ef0e68828c934b7a0a8f66e811bede8bf8a4e141a8f12f964e92e76d5af2b3e9f76792b935fc0d8cd906e7ab4f9e6a3bd9b826c0503a929634e7cdf8fdf5173772e372bb19862072ed0fb3afb44cae8b79caad81370ce67e4a1b44b8a56150219ca6982cf21c2fd80b4f8a675e585456223f60a96574c0972aa5f1ae68e04d9cf5b6e635f0903c3efe47d4c0c0d8d656d14928397d4e20806b50fb945d8c5b3af7b9c3b06dab726a41897ba3e94531eba51f7c16e390709a5efe407255dcfc40d86a1eb0fa4f01adee93fa6ed44a9ad03ba83b7d09f88bb4dbb51d8ef4b73b36b75dcaae04890a").unwrap()).unwrap();
    let commitments = [
        "7c7ea4aadabb7162ed05f265527c50fb1a441b0ca655231bf6d7c45d6cf67e1d",
        "702b85154cd2dd7d0505af8cc6484f0aa854549e64b87f07277af70d995a2d21",
        "6693d794456c40fbcaaf0692c376aca4ba168782a6b76df49100b8d766a73b5c",
        "1a7ff5f0f877da164da5630b280278e03e75cb19ed1469b1853df3fb8050a662",
        "e25bae601d7113cd0db0603fe7072e88f5aeae6177e423bf2e22abf5f997ef6b",
        "b6d98f2eae41a89e49fa2381a7b88517bfbe0fdebb656712e2e9d6f50df1720c",
        "e2b788992088af1a3f9810a4c85fc4bfa4fc48e2cfcc3e546deb030e47e6cc7a",
        "60d05a6cdd77f71b15356fb830eb3a5a26b79b2870df6a39dd704490e0e6162d",
    ]
    .iter()
    .map(|s| Hex::decode(s).unwrap())
    .map(|b| RistrettoPoint::from_byte_array(&b.try_into().unwrap()).unwrap())
    .map(PedersenCommitment)
    .collect::<Vec<_>>();
    assert!(proof
        .verify_batch(&commitments, &Range::Bits32, &mut rand::rng())
        .is_ok());
}
