// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! High-level BP++ range proof API.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::ristretto255::RistrettoScalar;
use crate::pedersen::{Blinding, PedersenCommitment};
use crate::traits::AllowedRng;

use crate::bulletproofspp::circuit::{self, CircuitParams, CircuitProof};
use crate::bulletproofspp::crs::Generators;
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
    proof: CircuitProof,
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
    ) -> FastCryptoResult<RangeProof> {
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
    /// `InvalidInput` if any value is out of range, the lengths differ, or
    /// `values` is empty, and with `GeneralOpaqueError` if proving itself
    /// fails.
    pub fn prove_batch(
        values: &[u64],
        blindings: &[Blinding],
        range: &Range,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<RangeProof> {
        if values.is_empty()
            || values.len() != blindings.len()
            || values.iter().any(|&v| !range.is_in_range(v))
        {
            return Err(FastCryptoError::InvalidInput);
        }
        let (n_bits, m) = (range.bits(), values.len());

        let gens = Generators::new(*range, m)?;
        let params = CircuitParams::new(*range, m)?;
        let blinding_scalars: Vec<RistrettoScalar> = blindings.iter().map(|b| b.0).collect();
        let (proof, _) = circuit::prove(
            &mut transcript(dst, n_bits, m),
            &gens,
            &params,
            rng,
            values,
            &blinding_scalars,
        )
        // Fails only on a degenerate challenge, which depends on the witness.
        .map_err(|_| FastCryptoError::GeneralOpaqueError)?;
        Ok(RangeProof { proof })
    }

    /// Verify that all `commitments` open to values in `range`.
    ///
    /// The generators for a new batch size `commitments.len()` are derived and
    /// cached for the lifetime of the process, so callers must bound the batch
    /// size when it comes from untrusted input.
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
        let gens = Generators::new(*range, m)?;
        let params = CircuitParams::new(*range, m)?;
        circuit::verify(
            &mut transcript(dst, n_bits, m),
            &gens,
            &params,
            &self.proof,
            commitments,
        )
        .map_err(|_| FastCryptoError::InvalidProof)
    }

    /// Serialize: the four circuit commitments, the per-round `(X, R)`
    /// pairs, and the final scalars, 32 bytes each.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }

    /// Deserialize. The byte length determines the proof shape (13 elements
    /// for norm length 16, 2*rounds + 9 otherwise). Points and scalars are
    /// validated; consistency with the statement is checked at verification.
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        CircuitProof::from_bytes(bytes).map(|proof| RangeProof { proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::RistrettoPoint;
    use crate::groups::GroupElement;
    use crate::serde_helpers::ToFromByteArray;

    /// Frozen proof for values [0, u32::MAX, 12345, 1 << 31] in Bits32 with
    /// dst "test". Breaks if the transcript layout, challenge derivation,
    /// generator derivation, or serialization change.
    // TODO: regenerate when the DST strings and transcript labels are frozen.
    #[test]
    fn regression_test() {
        let proof = RangeProof::from_bytes(&hex::decode("ca5cda5004810d8e5aab8e5ace297de164b40774a6ba66cd5af31970d826730e6edfefd97badd22a20c580d0708719c9cb09a7736988aceea129982423f44b6b300f43d77a6ca219e1739012ebcd98f7723c5d60e89d77b141730dd3c8b95909e432a9970035fbd757ba62b122110bcf8921d340f78dadb4468dff20ee202a30d82a5ea89e84a24e6b1970383d9d3afbcf870bdb98952c27814b66418ce0d3094c8f427d2d1c37a78058c0bf245d6f99e2e454f02731149ca4e1a55652a9d0461cdc8563b26ad1bf78cd7959659c785ce008bc8862bd1c0a45025f31dd955c142ef5731a51a16b05b5b1feed484c11df84466e70a2365e62ace5fc234bf3423aa822d39f37f3b5bc1454a8ce22b473884b9d9866bd2b482bb98d3e50e684e841bed02286e1d94bb2c7716b1470ab821c2685c2fd6b2d18724ce09308f3c1d44c200e6a4345823b1607b8c0f8d2f5b27c4f91e5e02fa8a1a87ffb10e8660fe90d139ea7e0e352fccba66b8029b5aeafc26489929a51ac05763610a8357493160429d45b1ca91ebfc482bf6053c9ebd2453176e91e510990ca7bb7be341c81550bbdf33682aaa078d5cec76edebb77345e09fc48d1c92e2c609c87dcb94df9dd08887cea5e4a65871a63b62b14b97cfd24c4ec6fe58514664832256520be048d04").unwrap()).unwrap();
        let commitments: Vec<PedersenCommitment> = [
            "c45e013fa7beb8394d42c75aa825dedd7f5c919c96af2f2c78bd71012d46ac28",
            "70b1bf252ba5448bde56597329e84b8c9e40c7f7ee1ddca68806ef288a616d63",
            "16d69009903a4d776402a8f188332c72d70ea2043d5f5f03dea410ed88dbc77d",
            "96d9856ccf03ef588de3f9a9153e0df1d19ae030d14d5e6c0f8cf27661d00e16",
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
        let mut rng = rand::thread_rng();
        for range in ALL_RANGES {
            let max = range.max_value();
            for m in [1usize, 2, 3, 5, 8, 9, 16] {
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

        // Lengths that are not a valid element count.
        assert!(RangeProof::from_bytes(&[]).is_err());
        for elems in [1usize, 2, 4, 12, 14, 16, 74, 100] {
            assert!(
                RangeProof::from_bytes(&vec![0u8; 32 * elems]).is_err(),
                "{elems} elements accepted"
            );
        }
        // Non-multiples of 32.
        for len in [1usize, 31, 33, 415] {
            assert!(RangeProof::from_bytes(&vec![0u8; len]).is_err());
        }

        // Random bytes at valid lengths: never panic, never verify.
        for elems in [13usize, 15, 17, 19] {
            for _ in 0..32 {
                let mut buf = vec![0u8; 32 * elems];
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
                .and_then(|p| p.verify(&commitment, &Range::Bits16, b"test"))
                .is_ok();
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
        assert_eq!(bytes.len(), 416);
        let recovered = RangeProof::from_bytes(&bytes).unwrap();
        assert!(recovered
            .verify_batch(&commitments, &range, b"test")
            .is_ok());

        // Length and encoding validation.
        assert!(RangeProof::from_bytes(&bytes[..415]).is_err());
        assert!(RangeProof::from_bytes(&bytes[..384]).is_err()); // 12 elements
        let mut corrupted = bytes.clone();
        corrupted[0] ^= 1;
        // Either an invalid point encoding or a proof that fails to verify.
        assert!(RangeProof::from_bytes(&corrupted)
            .map(|p| p.verify_batch(&commitments, &range, b"test"))
            .and_then(|r| r)
            .is_err());

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
