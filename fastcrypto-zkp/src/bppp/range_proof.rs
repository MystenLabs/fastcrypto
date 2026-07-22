// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! High-level BP++ range proof API.

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::AllowedRng;

use crate::bppp::circuit::{self, CircuitParams, CircuitProof};
use crate::bppp::crs::Generators;
use crate::bppp::norm_linear::NormLinearProof;
use crate::bppp::transcript::BpppTranscript;

/// The provable ranges.
#[derive(Clone, Copy, Debug)]
pub enum Range {
    /// The range [0, 2^8).
    Bits8,
    /// The range [0, 2^16).
    Bits16,
    /// The range [0, 2^32).
    Bits32,
    /// The range [0, 2^64).
    Bits64,
}

impl Range {
    pub fn is_in_range(&self, value: u64) -> bool {
        if value == 0 {
            return true;
        }
        value.ilog2() < self.bits() as u32
    }

    fn bits(&self) -> usize {
        match self {
            Range::Bits8 => 8,
            Range::Bits16 => 16,
            Range::Bits32 => 32,
            Range::Bits64 => 64,
        }
    }
}

/// A BP++ range proof that one or more Pedersen commitments (as in
/// [`fastcrypto::pedersen`]) open to values in a given [`Range`].
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
    /// `values` is empty.
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
        let gens = Generators::new(n_bits, m)?;
        let params = CircuitParams::new(n_bits, m)?;
        let blinding_scalars: Vec<RistrettoScalar> = blindings.iter().map(|b| b.0).collect();
        let (proof, _) = circuit::prove(
            &mut transcript(dst, n_bits, m),
            &gens,
            &params,
            rng,
            values,
            &blinding_scalars,
        )?;
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
        let gens = Generators::new(n_bits, m)?;
        let params = CircuitParams::new(n_bits, m)?;
        let points: Vec<RistrettoPoint> = commitments.iter().map(|c| c.0).collect();
        circuit::verify(
            &mut transcript(dst, n_bits, m),
            &gens,
            &params,
            &self.proof,
            &points,
        )
        .map_err(|_| FastCryptoError::InvalidProof)
    }

    /// Serialize: the four circuit commitments, the per-round `(X, R)`
    /// pairs, and the final scalars, 32 bytes each.
    pub fn to_bytes(&self) -> Vec<u8> {
        let p = &self.proof;
        let nl = &p.nl_proof;
        let elems = 4 + 2 * nl.rounds.len() + nl.l_final.len() + nl.n_final.len();
        let mut bytes = Vec::with_capacity(32 * elems);
        for point in [&p.c_l, &p.c_o, &p.c_r, &p.c_s] {
            bytes.extend(point.to_byte_array());
        }
        for (x, r) in &nl.rounds {
            bytes.extend(x.to_byte_array());
            bytes.extend(r.to_byte_array());
        }
        for scalar in nl.l_final.iter().chain(&nl.n_final) {
            bytes.extend(scalar.to_byte_array());
        }
        bytes
    }

    /// Deserialize. The element count determines the proof shape: 13
    /// elements for norm length 16 (3 rounds, 3 final scalars), 2*rounds + 9
    /// otherwise (final scalars 1 + 4). Points and scalars are validated;
    /// consistency with the statement is checked at verification.
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        if !bytes.len().is_multiple_of(32) {
            return Err(FastCryptoError::InvalidInput);
        }
        let elems = bytes.len() / 32;
        // Sanity bound: `rounds` grows with log2 of the norm length, so even
        // absurdly large statements stay far below 32 rounds.
        const MAX_ROUNDS: usize = 32;
        let (rounds, l_len, n_len) = match elems {
            13 => (3, 1, 2),
            e if e >= 15 && !e.is_multiple_of(2) && (e - 9) / 2 <= MAX_ROUNDS => ((e - 9) / 2, 1, 4),
            _ => return Err(FastCryptoError::InvalidInput),
        };
        // 4 + 2*rounds + l_len + n_len equals `elems` in every match arm, so
        // the chunk iterator yields exactly as many chunks as taken below.
        let mut chunks = bytes.chunks_exact(32);
        let mut next_point = || -> FastCryptoResult<RistrettoPoint> {
            let chunk: &[u8; 32] = chunks.next().unwrap().try_into().unwrap();
            RistrettoPoint::from_byte_array(chunk).map_err(|_| FastCryptoError::InvalidInput)
        };
        let c_l = next_point()?;
        let c_o = next_point()?;
        let c_r = next_point()?;
        let c_s = next_point()?;
        let round_points = (0..rounds)
            .map(|_| Ok((next_point()?, next_point()?)))
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let mut next_scalar = || -> FastCryptoResult<RistrettoScalar> {
            let chunk: &[u8; 32] = chunks.next().unwrap().try_into().unwrap();
            RistrettoScalar::from_byte_array(chunk).map_err(|_| FastCryptoError::InvalidInput)
        };
        let l_final = (0..l_len)
            .map(|_| next_scalar())
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let n_final = (0..n_len)
            .map(|_| next_scalar())
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(RangeProof {
            proof: CircuitProof {
                c_l,
                c_o,
                c_r,
                c_s,
                nl_proof: NormLinearProof {
                    rounds: round_points,
                    l_final,
                    n_final,
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen proof for values [0, u32::MAX, 12345, 1 << 31] in Bits32 with
    /// dst "test". Breaks if the transcript layout, challenge derivation,
    /// generator derivation, or serialization change.
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
        assert!(recovered.verify_batch(&commitments, &range, b"test").is_ok());

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
