// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! High-level BP++ range proof API.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::pedersen::{Blinding, PedersenCommitment};
use crate::traits::AllowedRng;
use typenum::{Unsigned, U1024, U128, U16, U2048, U256, U32, U4096, U512, U64, U8192};

use crate::bulletproofspp::circuit::{self, CircuitParams, CircuitProof};
use crate::bulletproofspp::crs::{dims, Generators};
use crate::bulletproofspp::norm_linear::NormLength;
use crate::bulletproofspp::transcript::BpppTranscript;

pub use crate::pedersen::Range;

/// A BP++ range proof that one or more Pedersen commitments (as in
/// [`crate::pedersen`]) open to values in a given [`Range`].
///
/// Unlike `fastcrypto::bulletproofs`, batches of any size `>= 1` are
/// supported; amortization per value is best when the total digit count
/// `m * bits/4` fills a power of two.
#[derive(Clone, Debug)]
pub struct RangeProof {
    proof: Proof,
}

/// Serialized size of a proof at norm length `N`: the four circuit
/// commitments, one `(X, R)` pair per fold round, and the final scalars, 32
/// bytes each with no framing.
fn serialized_len<N: NormLength>() -> usize {
    32 * (4 + 2 * N::Rounds::USIZE + 1 + N::NFinal::USIZE)
}

/// The proof at each norm length a statement can have, and the dispatch on
/// it. Proving takes the norm length from the statement, and decoding takes
/// it from the byte length, which is distinct for every variant.
macro_rules! norm_lengths {
    ($($variant:ident => $n:ty),* $(,)?) => {
        /// Boxed: a decompressed proof is a few kilobytes at the largest
        /// norm length, and the enum is otherwise that size at every length.
        #[derive(Clone, Debug)]
        enum Proof {
            $($variant(Box<CircuitProof<$n>>),)*
        }

        impl Proof {
            /// Whether a proof can be made at norm length `nm`.
            fn supports(nm: usize) -> bool {
                [$(<$n>::USIZE),*].contains(&nm)
            }

            fn prove(
                nm: usize,
                transcript: &mut BpppTranscript,
                gens: &Generators,
                range: Range,
                rng: &mut impl AllowedRng,
                values: &[u64],
                blindings: &[RistrettoScalar],
            ) -> FastCryptoResult<Self> {
                $(if nm == <$n>::USIZE {
                    let params = CircuitParams::new::<$n>(range, values.len())?;
                    let (proof, _) =
                        circuit::prove(transcript, gens, &params, rng, values, blindings)?;
                    return Ok(Proof::$variant(Box::new(proof)));
                })*
                Err(FastCryptoError::InvalidInput)
            }

            /// Verify against `commitments`. The norm length is this proof's
            /// own, so [CircuitParams::new] rejects one the statement does
            /// not imply.
            fn verify(
                &self,
                transcript: &mut BpppTranscript,
                gens: &Generators,
                range: Range,
                commitments: &[RistrettoPoint],
            ) -> FastCryptoResult<()> {
                match self {
                    $(Proof::$variant(proof) => {
                        let params = CircuitParams::new::<$n>(range, commitments.len())?;
                        circuit::verify(transcript, gens, &params, proof, commitments)
                    })*
                }
            }

            fn to_bytes(&self) -> Vec<u8> {
                match self {
                    $(Proof::$variant(proof) => bcs::to_bytes(proof),)*
                }
                .expect("a proof is always serializable")
            }

            fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
                let invalid = |_| FastCryptoError::InvalidInput;
                $(if bytes.len() == serialized_len::<$n>() {
                    return Ok(Proof::$variant(Box::new(
                        bcs::from_bytes(bytes).map_err(invalid)?,
                    )));
                })*
                Err(FastCryptoError::InvalidInput)
            }
        }
    };
}

norm_lengths! {
    Nm16 => U16,
    Nm32 => U32,
    Nm64 => U64,
    Nm128 => U128,
    Nm256 => U256,
    Nm512 => U512,
    Nm1024 => U1024,
    Nm2048 => U2048,
    Nm4096 => U4096,
    Nm8192 => U8192,
}

/// The Fiat-Shamir transcript, binding the caller's domain separation tag
/// and the statement dimensions before any commitment is absorbed.
fn transcript(dst: &[u8], n_bits: usize, m: usize) -> BpppTranscript {
    let mut t = BpppTranscript::new(b"fastcrypto-bppp-range-proof-01");
    t.append_message(b"dst", dst);
    t.append_u64(b"n_bits", n_bits as u64);
    t.append_u64(b"m", m as u64);
    t
}

impl RangeProof {
    /// Prove that `value` is in `range` under the commitment
    /// `PedersenCommitment::new(&value.into(), blinding)`. This enables
    /// creating proofs for an existing commitment. Returns an `InvalidInput`
    /// error if the value is not in range.
    pub fn prove(
        value: u64,
        blinding: &Blinding,
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Self> {
        Self::prove_batch(&[value], std::slice::from_ref(blinding), range, dst, rng)
    }

    /// Verify that `commitment` opens to a value in `range`.
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        range: &Range,
        dst: &[u8],
    ) -> FastCryptoResult<()> {
        self.verify_batch(std::slice::from_ref(commitment), range, dst)
    }

    /// Prove that all `values` are in `range` under the commitments given by
    /// `values` and `blindings`, as one aggregated proof. Fails with
    /// `InvalidInput` if any value is out of range, the lengths differ,
    /// `values` is empty, or `N` is not the norm length `(range, m)` implies,
    /// and with `GeneralOpaqueError` if proving itself fails.
    pub fn prove_batch(
        values: &[u64],
        blindings: &[Blinding],
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Self> {
        if values.is_empty()
            || values.len() != blindings.len()
            || values.iter().any(|&v| !range.is_in_range(v))
        {
            return Err(FastCryptoError::InvalidInput);
        }
        let (n_bits, m) = (range.bits(), values.len());
        let (_, _, nm) = dims(*range, m);

        // Checked before Generators::new, which populates the process-wide
        // CRS cache.
        if !Proof::supports(nm) {
            return Err(FastCryptoError::InvalidInput);
        }

        // Past the input checks, proving can only fail on a challenge that
        // degenerates a scalar inversion. That has negligible probability but
        // depends on the witness, so report it opaquely.
        let opaque = |_| FastCryptoError::GeneralOpaqueError;
        let gens = Generators::new(*range, m).map_err(opaque)?;
        let blinding_scalars: Vec<RistrettoScalar> = blindings.iter().map(|b| b.0).collect();
        let proof = Proof::prove(
            nm,
            &mut transcript(dst, n_bits, m),
            &gens,
            *range,
            rng,
            values,
            &blinding_scalars,
        )
        .map_err(opaque)?;
        Ok(RangeProof { proof })
    }

    /// Verify that all `commitments` open to values in `range`.
    pub fn verify_batch(
        &self,
        commitments: &[PedersenCommitment],
        range: &Range,
        dst: &[u8],
    ) -> FastCryptoResult<()> {
        if commitments.is_empty() {
            return Err(FastCryptoError::InvalidInput);
        }
        let (n_bits, m) = (range.bits(), commitments.len());
        let (_, _, nm) = dims(*range, m);

        // Checked before Generators::new, which populates the process-wide
        // CRS cache.
        if !Proof::supports(nm) {
            return Err(FastCryptoError::InvalidInput);
        }
        let gens = Generators::new(*range, m)?;
        let points: Vec<RistrettoPoint> = commitments.iter().map(|c| c.0).collect();
        self.proof
            .verify(&mut transcript(dst, n_bits, m), &gens, *range, &points)
            .map_err(|_| FastCryptoError::InvalidProof)
    }

    /// Serialize: the four circuit commitments, the per-round `(X, R)` pairs
    /// and the final scalars, 32 bytes each with no framing.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }

    /// Deserialize. The byte length selects the norm length, and so the proof
    /// shape; consistency with the statement is checked at verification.
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        Ok(RangeProof {
            proof: Proof::from_bytes(bytes)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::GroupElement;
    use crate::serde_helpers::ToFromByteArray;

    /// Frozen proof for values [0, u32::MAX, 12345, 1 << 31] in Bits32 with
    /// dst "test", 480 bytes: 15 group elements and scalars, no framing.
    /// Breaks if the transcript layout, challenge derivation, generator
    /// derivation, or serialization change.
    // TODO: regenerate when the DST strings and transcript labels are frozen.
    #[test]
    fn regression_test() {
        let proof = RangeProof::from_bytes(&hex::decode("00d5d5d1529f01cf6420ec103dace15476ca510f5b92ae6762bc25f4bd1249021219fad1752e829b54c9726bdb9253128ba6e82ca16fd8ea2595e26a536b4406621a5bbe5a65f5d917da8906719361ad8dcb5c9618861e1ccaee288bd7db8d5e9e5b0e4cb21110d789b367d90e778ec30faeda08c405e7b40a64c9f55e355105dad137e8eb12facf2017dd0887338d6d1416718a9ab599e36a5fc26844b2ce5f44c9c0a0e79d43c07257498c7d755a0fb1e36d620fb312db78f230c11795af452ec6fd20bdddcd078dd121fd667b1226e14f79027b1502b770e804c776ce2e617c2e34ae010e418b31f72222ae7e76d5107747b507355aaa17b89d113ff8ee16963d2647afb472778c27d1983e8e0741be8e3252ce46faa2973ce1f6e352f670484baa1173bae5e99c5f3f0ff65ee368d191f8519986017a8faf1e08d6310d0f0bdf52df2d0b75fdbbdd56eacce0a932270b24b242ec9efb49a062b1d8dd4a0032d10c7962108d26a9239e1103806279e12396a064585f6b878050a84bbe41058a3416edfe76b21e7ec4945454970e53fe7cfb47d49e87373ae22f5ae499b50238eb4f534c997a1e88772fdc181885e7089147978798c99c43867803f5d554015048dbb1bbaa9976da6a08d9457c049a4521e733a28994bb3060f17119940509").unwrap()).unwrap();
        let commitments: Vec<PedersenCommitment> = [
            "442e20bdd70d96394130625763bb90729481036a4c0643972d0febc382919279",
            "464bbfe7ad1f58a942a57736d2627fe6d514609f0caeeb855eb6cacfe665c773",
            "24161bc7218ec384347e95140a2bdbaf44040cdb3b92ae1dd5083ec55d8ccc4c",
            "f821e18063a4f31afd5cffe02426f8a8dfb3db79d2982297b44e4160ed04a770",
        ]
        .iter()
        .map(|s| {
            let bytes: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
            PedersenCommitment(RistrettoPoint::from_byte_array(&bytes).unwrap())
        })
        .collect();
        assert!(proof
            .verify_batch(&commitments, &Range::Bits32, b"test")
            .is_ok());
    }

    const ALL_RANGES: [Range; 4] = [Range::Bits8, Range::Bits16, Range::Bits32, Range::Bits64];

    fn commit_all(values: &[u64]) -> (Vec<PedersenCommitment>, Vec<Blinding>) {
        let mut rng = rand::thread_rng();
        values
            .iter()
            .map(|&v| PedersenCommitment::commit_u64(v, &mut rng))
            .unzip()
    }

    /// Completeness across every range, batch sizes spanning the padding and
    /// fold boundaries, and the extremes of each range.
    #[test]
    fn test_completeness_all_ranges_and_batch_sizes() {
        fn check(range: Range, batch_sizes: &[usize]) {
            let mut rng = rand::thread_rng();
            let max = range.max_value();
            for &m in batch_sizes {
                let values: Vec<u64> = (0..m)
                    .map(|i| match i {
                        0 => 0,
                        1 => max,
                        2 => 1,
                        _ => rand::Rng::gen::<u64>(&mut rng) & max,
                    })
                    .collect();
                let (commitments, blindings) = commit_all(&values);
                let proof = RangeProof::prove_batch(&values, &blindings, &range, b"test", &mut rng)
                    .unwrap();
                assert!(
                    proof.verify_batch(&commitments, &range, b"test").is_ok(),
                    "completeness failed for {}x{m}",
                    range.bits()
                );
                // Serialization round-trips at every shape.
                assert!(RangeProof::from_bytes(&proof.to_bytes())
                    .unwrap()
                    .verify_batch(&commitments, &range, b"test")
                    .is_ok());
            }
        }

        for range in ALL_RANGES {
            check(range, &[1, 2, 3, 5, 8, 9, 16]);
        }
    }

    /// A proof is valid only for the exact `(bits, batch size)` it was made
    /// for. `Bits16 x 8` and `Bits32 x 4` have identical proof shapes and
    /// identical CRS sizes (32 digit slots), so nothing but the transcript
    /// binding of the dimensions separates them.
    #[test]
    fn test_cross_configuration_confusion() {
        let mut rng = rand::thread_rng();
        let values = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let (commitments16, blindings16) = commit_all(&values);
        let proof16 =
            RangeProof::prove_batch(&values, &blindings16, &Range::Bits16, b"test", &mut rng)
                .unwrap();
        assert!(proof16
            .verify_batch(&commitments16, &Range::Bits16, b"test")
            .is_ok());

        let (commitments32, blindings32) = commit_all(&values[..4]);
        let proof32 = RangeProof::prove_batch(
            &values[..4],
            &blindings32,
            &Range::Bits32,
            b"test",
            &mut rng,
        )
        .unwrap();
        // Same byte length: the two shapes are indistinguishable on the wire.
        assert_eq!(proof16.to_bytes().len(), proof32.to_bytes().len());

        // Neither proof verifies as the other configuration.
        assert!(proof16
            .verify_batch(&commitments32, &Range::Bits32, b"test")
            .is_err());
        assert!(proof32
            .verify_batch(&commitments16, &Range::Bits16, b"test")
            .is_err());

        // Nor does a proof widen or narrow its range for the same batch.
        for range in ALL_RANGES {
            if range != Range::Bits16 {
                assert!(
                    proof16
                        .verify_batch(&commitments16, &range, b"test")
                        .is_err(),
                    "Bits16 proof accepted as {} bits",
                    range.bits()
                );
            }
        }
    }

    /// Every input to `verify` participates in the transcript: the domain
    /// separation tag must bind exactly, including at the empty and
    /// prefix-collision boundaries.
    #[test]
    fn test_dst_binding() {
        let mut rng = rand::thread_rng();
        let (commitment, blinding) = PedersenCommitment::commit_u64(7, &mut rng);
        let proof = RangeProof::prove(7, &blinding, &Range::Bits8, b"dst", &mut rng).unwrap();
        for other in [b"".as_slice(), b"ds", b"dstx", b"DST", b"dst\0"] {
            assert!(
                proof.verify(&commitment, &Range::Bits8, other).is_err(),
                "dst {other:?} accepted"
            );
        }
        assert!(proof.verify(&commitment, &Range::Bits8, b"dst").is_ok());

        // The empty dst is itself usable, and binds.
        let empty = RangeProof::prove(7, &blinding, &Range::Bits8, b"", &mut rng).unwrap();
        assert!(empty.verify(&commitment, &Range::Bits8, b"").is_ok());
        assert!(empty.verify(&commitment, &Range::Bits8, b"dst").is_err());
    }

    /// Proving is randomized: two proofs of the same statement differ, so the
    /// proof carries no deterministic fingerprint of the witness.
    #[test]
    fn test_proofs_are_randomized() {
        let mut rng = rand::thread_rng();
        let (commitment, blinding) = PedersenCommitment::commit_u64(42, &mut rng);
        let a = RangeProof::prove(42, &blinding, &Range::Bits32, b"test", &mut rng).unwrap();
        let b = RangeProof::prove(42, &blinding, &Range::Bits32, b"test", &mut rng).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert!(a.verify(&commitment, &Range::Bits32, b"test").is_ok());
        assert!(b.verify(&commitment, &Range::Bits32, b"test").is_ok());
    }

    /// Deserialization must reject or safely fail on arbitrary input, never
    /// panic, and a decoded proof must never verify against an unrelated
    /// statement.
    #[test]
    fn test_from_bytes_robustness() {
        let mut rng = rand::thread_rng();
        let (commitment, blinding) = PedersenCommitment::commit_u64(9, &mut rng);
        let proof = RangeProof::prove(9, &blinding, &Range::Bits16, b"test", &mut rng).unwrap();
        let bytes = proof.to_bytes();

        // Only the lengths a shape produces are accepted.
        assert_eq!(bytes.len(), 416);
        for len in [0usize, 1, 415, 417, 448, 1024] {
            assert!(
                RangeProof::from_bytes(&vec![0u8; len]).is_err(),
                "length {len} accepted"
            );
        }

        // Random bytes at accepted lengths: never panic, never verify.
        for len in [416usize, 480, 544] {
            for _ in 0..64 {
                let mut buf = vec![0u8; len];
                rand::RngCore::fill_bytes(&mut rng, &mut buf);
                if let Ok(p) = RangeProof::from_bytes(&buf) {
                    assert!(p.verify(&commitment, &Range::Bits16, b"test").is_err());
                }
            }
        }

        // Every single-byte corruption of a valid proof is rejected.
        for i in (0..bytes.len()).step_by(7) {
            let mut corrupted = bytes.clone();
            corrupted[i] ^= 0x80;
            let accepted = RangeProof::from_bytes(&corrupted)
                .is_ok_and(|p| p.verify(&commitment, &Range::Bits16, b"test").is_ok());
            assert!(!accepted, "corruption at byte {i} accepted");
        }
    }

    /// Argument validation at the public API.
    #[test]
    fn test_input_validation() {
        let mut rng = rand::thread_rng();
        let (commitments, blindings) = commit_all(&[1, 2]);

        // Empty batches, on both sides.
        assert!(RangeProof::prove_batch(&[], &[], &Range::Bits8, b"t", &mut rng).is_err());
        let proof =
            RangeProof::prove_batch(&[1, 2], &blindings, &Range::Bits8, b"t", &mut rng).unwrap();
        assert!(proof.verify_batch(&[], &Range::Bits8, b"t").is_err());

        // Mismatched values/blindings lengths.
        assert!(RangeProof::prove_batch(&[1], &blindings, &Range::Bits8, b"t", &mut rng).is_err());
        assert!(
            RangeProof::prove_batch(&[1, 2, 3], &blindings, &Range::Bits8, b"t", &mut rng).is_err()
        );

        // A longer batch than the proof was made for.
        let extended = [
            commitments[0].clone(),
            commitments[1].clone(),
            commitments[0].clone(),
        ];
        assert!(proof.verify_batch(&extended, &Range::Bits8, b"t").is_err());
    }

    /// A zero blinding is a degenerate but legal opening; it must not break
    /// proving or verification.
    #[test]
    fn test_zero_blinding() {
        let mut rng = rand::thread_rng();
        let blinding = Blinding(RistrettoScalar::zero());
        let commitment = PedersenCommitment::new(&RistrettoScalar::from(1000u64), &blinding);
        let proof = RangeProof::prove(1000, &blinding, &Range::Bits16, b"test", &mut rng).unwrap();
        assert!(proof.verify(&commitment, &Range::Bits16, b"test").is_ok());

        // Zero value with zero blinding: the commitment is the identity.
        let zero = PedersenCommitment::new(&RistrettoScalar::zero(), &blinding);
        let proof = RangeProof::prove(0, &blinding, &Range::Bits8, b"test", &mut rng).unwrap();
        assert!(proof.verify(&zero, &Range::Bits8, b"test").is_ok());
    }

    /// Two commitments to the same value with different blindings, and the
    /// same blinding reused across a batch: neither must confuse the
    /// per-value binding.
    #[test]
    fn test_repeated_values_and_blindings() {
        let mut rng = rand::thread_rng();
        let blinding = Blinding::rand(&mut rng);
        let values = [77u64, 77, 77];
        let blindings = vec![blinding.clone(), blinding.clone(), blinding.clone()];
        let commitments: Vec<PedersenCommitment> = values
            .iter()
            .map(|&v| PedersenCommitment::new(&RistrettoScalar::from(v), &blinding))
            .collect();
        let proof =
            RangeProof::prove_batch(&values, &blindings, &Range::Bits8, b"test", &mut rng).unwrap();
        assert!(proof
            .verify_batch(&commitments, &Range::Bits8, b"test")
            .is_ok());
    }

    #[test]
    fn test_is_in_range() {
        assert!(Range::Bits8.is_in_range(0));
        assert!(Range::Bits8.is_in_range(u8::MAX as u64));
        assert!(!Range::Bits8.is_in_range(1 << 8));
        assert!(Range::Bits16.is_in_range(u16::MAX as u64));
        assert!(!Range::Bits16.is_in_range(1 << 16));
        assert!(Range::Bits32.is_in_range(u32::MAX as u64));
        assert!(!Range::Bits32.is_in_range(1 << 32));
        assert!(Range::Bits64.is_in_range(u64::MAX));
    }

    #[test]
    fn test_range_proof() {
        let mut rng = rand::thread_rng();
        let value = 1234u64;
        // Interop: an existing commitment from fastcrypto::pedersen.
        let (commitment, blinding) = PedersenCommitment::commit_u64(value, &mut rng);

        let range = Range::Bits16;
        let proof = RangeProof::prove(value, &blinding, &range, b"test", &mut rng).unwrap();
        assert!(RangeProof::prove(value, &blinding, &Range::Bits8, b"test", &mut rng).is_err());

        assert!(proof.verify(&commitment, &range, b"test").is_ok());
        assert!(proof.verify(&commitment, &range, b"other").is_err());
        let (other_commitment, _) = PedersenCommitment::commit_u64(value, &mut rng);
        assert!(proof.verify(&other_commitment, &range, b"test").is_err());
    }

    #[test]
    fn test_batch_range_proof() {
        let mut rng = rand::thread_rng();
        // Batch of 5: not a power of two, exercises norm-side padding.
        let values = [0u64, u32::MAX as u64, 1, 42, 1 << 20];
        let (commitments, blindings): (Vec<_>, Vec<_>) = values
            .iter()
            .map(|&v| PedersenCommitment::commit_u64(v, &mut rng))
            .unzip();
        let range = Range::Bits32;
        let proof =
            RangeProof::prove_batch(&values, &blindings, &range, b"test", &mut rng).unwrap();
        assert!(proof.verify_batch(&commitments, &range, b"test").is_ok());

        // Swapped commitments must fail; so must a shorter batch.
        let mut swapped = commitments.clone();
        swapped.swap(0, 1);
        assert!(proof.verify_batch(&swapped, &range, b"test").is_err());
        assert!(proof
            .verify_batch(&commitments[..4], &range, b"test")
            .is_err());

        // An out-of-range value anywhere in the batch fails at proving.
        assert!(RangeProof::prove_batch(
            &[1, 1 << 32, 2, 3, 4],
            &blindings,
            &range,
            b"test",
            &mut rng
        )
        .is_err());
    }

    #[test]
    fn test_to_from_bytes() {
        let mut rng = rand::thread_rng();
        let values = [7u64, 1 << 15];
        let (commitments, blindings): (Vec<_>, Vec<_>) = values
            .iter()
            .map(|&v| PedersenCommitment::commit_u64(v, &mut rng))
            .unzip();
        let range = Range::Bits16;
        let proof =
            RangeProof::prove_batch(&values, &blindings, &range, b"test", &mut rng).unwrap();

        let bytes = proof.to_bytes();
        // 16x2 has the 64-bit shape: 10 group elements + 3 scalars.
        assert_eq!(bytes.len(), 13 * 32);
        let recovered = RangeProof::from_bytes(&bytes).unwrap();
        assert!(recovered
            .verify_batch(&commitments, &range, b"test")
            .is_ok());

        // A valid-shaped proof for the wrong statement dimensions fails at
        // verification (shape gate).
        let (c64, b64) = PedersenCommitment::commit_u64(5, &mut rng);
        let proof64 = RangeProof::prove(5, &b64, &Range::Bits64, b"test", &mut rng).unwrap();
        let recovered64 = RangeProof::from_bytes(&proof64.to_bytes()).unwrap();
        assert!(recovered64.verify(&c64, &Range::Bits64, b"test").is_ok());
        assert!(recovered64
            .verify_batch(&[c64.clone(), c64], &Range::Bits64, b"test")
            .is_err());
    }
}
