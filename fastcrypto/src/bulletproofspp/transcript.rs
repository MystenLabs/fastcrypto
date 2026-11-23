// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Merlin-based Fiat-Shamir transcript for BP++.

use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::pedersen::PedersenCommitment;
use crate::serde_helpers::ToFromByteArray;
use merlin::Transcript;

/// The labels of the BP++ transcript. Callers name a label, and only this
/// module sees its bytes, which Merlin requires to be `'static`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Label {
    RangeProof,
    Dst,
    NBits,
    M,
    Circuit,
    V,
    CL,
    CO,
    CR,
    CS,
    Alpha,
    Rho,
    Lambda,
    Beta,
    Tau,
    NormLinear,
    X,
    R,
    Gamma,
    LFinal,
    NFinal,
    #[cfg(test)]
    Test(&'static [u8]),
}

impl Label {
    /// The bytes Merlin absorbs for this label.
    pub(crate) fn bytes(self) -> &'static [u8] {
        match self {
            Label::RangeProof => b"fastcrypto-bppp-range-proof-01",
            Label::Dst => b"dst",
            Label::NBits => b"n_bits",
            Label::M => b"m",
            Label::Circuit => b"bppp_circuit",
            Label::V => b"V",
            Label::CL => b"C_L",
            Label::CO => b"C_O",
            Label::CR => b"C_R",
            Label::CS => b"C_S",
            Label::Alpha => b"alpha",
            Label::Rho => b"rho",
            Label::Lambda => b"lambda",
            Label::Beta => b"beta",
            Label::Tau => b"tau",
            Label::NormLinear => b"norm_linear",
            Label::X => b"X",
            Label::R => b"R",
            Label::Gamma => b"gamma",
            Label::LFinal => b"l_final",
            Label::NFinal => b"n_final",
            #[cfg(test)]
            Label::Test(bytes) => bytes,
        }
    }
}

pub(crate) struct BpppTranscript {
    inner: Transcript,
}

impl BpppTranscript {
    pub(crate) fn new(label: Label) -> Self {
        BpppTranscript {
            inner: Transcript::new(label.bytes()),
        }
    }

    /// Mark a protocol-stage boundary with a fixed tag (e.g. `norm_linear`),
    /// so identically-labeled absorptions in different sub-protocols cannot
    /// be confused. For caller-supplied data use [`Self::append_message`].
    pub(crate) fn domain_sep(&mut self, label: Label) {
        self.inner.append_message(b"dom-sep", label.bytes());
    }

    /// Append variable-length data (e.g. the caller's domain separation tag).
    pub(crate) fn append_message(&mut self, label: Label, data: &[u8]) {
        self.inner.append_message(label.bytes(), data);
    }

    /// Append a point in its canonical 32-byte encoding.
    pub(crate) fn append_point(&mut self, label: Label, point: &RistrettoPoint) {
        self.inner
            .append_message(label.bytes(), &point.to_byte_array());
    }

    /// Append each commitment's point under the same label, in order.
    pub(crate) fn append_commits(&mut self, label: Label, commits: &[PedersenCommitment]) {
        for commit in commits {
            self.append_point(label, &commit.0);
        }
    }

    /// Append a scalar in its canonical 32-byte little-endian encoding.
    pub(crate) fn append_scalar(&mut self, label: Label, scalar: &RistrettoScalar) {
        self.inner
            .append_message(label.bytes(), &scalar.to_byte_array());
    }

    /// Append each scalar under the same label, in order.
    pub(crate) fn append_scalars(&mut self, label: Label, scalars: &[RistrettoScalar]) {
        for scalar in scalars {
            self.append_scalar(label, scalar);
        }
    }

    /// Append a u64 in little-endian encoding.
    pub(crate) fn append_u64(&mut self, label: Label, value: u64) {
        self.inner
            .append_message(label.bytes(), &value.to_le_bytes());
    }

    /// Squeeze a scalar challenge: 64 uniform bytes reduced mod the group
    /// order, so the challenge bias is negligible.
    pub(crate) fn challenge_scalar(&mut self, label: Label) -> RistrettoScalar {
        let mut buf = [0u8; 64];
        self.inner.challenge_bytes(label.bytes(), &mut buf);
        RistrettoScalar::from_bytes_mod_order_wide(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::GroupElement;

    #[test]
    fn test_deterministic_and_binding() {
        let transcript = |data: &[u8], value: u64| {
            let mut t = BpppTranscript::new(Label::Test(b"test"));
            t.append_message(Label::Dst, data);
            t.append_u64(Label::Test(b"n"), value);
            t.append_point(Label::Test(b"P"), &RistrettoPoint::generator());
            t.challenge_scalar(Label::Test(b"c"))
        };

        // Same input, same challenge; any change to the input changes it.
        assert_eq!(transcript(b"a", 1), transcript(b"a", 1));
        assert_ne!(transcript(b"a", 1), transcript(b"b", 1));
        assert_ne!(transcript(b"a", 1), transcript(b"a", 2));
    }

    #[test]
    fn test_challenge_advances_transcript() {
        let mut t = BpppTranscript::new(Label::Test(b"test"));
        let c1 = t.challenge_scalar(Label::Test(b"c"));
        let c2 = t.challenge_scalar(Label::Test(b"c"));
        assert_ne!(c1, c2);
    }
}
