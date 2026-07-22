// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Merlin-based Fiat-Shamir transcript for BP++.

use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use merlin::Transcript;

pub(crate) struct BpppTranscript {
    inner: Transcript,
}

impl BpppTranscript {
    pub(crate) fn new(label: &'static [u8]) -> Self {
        BpppTranscript {
            inner: Transcript::new(label),
        }
    }

    /// Mark a protocol-stage boundary with a fixed tag (e.g. `norm_linear`),
    /// so identically-labeled absorptions in different sub-protocols cannot
    /// be confused. For caller-supplied data use [`Self::append_message`].
    pub(crate) fn domain_sep(&mut self, label: &'static [u8]) {
        self.inner.append_message(b"dom-sep", label);
    }

    /// Append variable-length data (e.g. the caller's domain separation tag).
    pub(crate) fn append_message(&mut self, label: &'static [u8], data: &[u8]) {
        self.inner.append_message(label, data);
    }

    /// Append a point in its canonical 32-byte encoding.
    pub(crate) fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.inner.append_message(label, &point.to_byte_array());
    }

    /// Append a scalar in its canonical 32-byte little-endian encoding.
    pub(crate) fn append_scalar(&mut self, label: &'static [u8], scalar: &RistrettoScalar) {
        self.inner.append_message(label, &scalar.to_byte_array());
    }

    /// Append a u64 in little-endian encoding.
    pub(crate) fn append_u64(&mut self, label: &'static [u8], value: u64) {
        self.inner.append_message(label, &value.to_le_bytes());
    }

    /// Squeeze a scalar challenge: 64 uniform bytes reduced mod the group
    /// order, so the challenge bias is negligible.
    pub(crate) fn challenge_scalar(&mut self, label: &'static [u8]) -> RistrettoScalar {
        let mut buf = [0u8; 64];
        self.inner.challenge_bytes(label, &mut buf);
        RistrettoScalar::from_bytes_mod_order_wide(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::GroupElement;

    #[test]
    fn test_deterministic_and_binding() {
        let transcript = |data: &[u8], value: u64| {
            let mut t = BpppTranscript::new(b"test");
            t.append_message(b"dst", data);
            t.append_u64(b"n", value);
            t.append_point(b"P", &RistrettoPoint::generator());
            t.challenge_scalar(b"c")
        };

        // Same input, same challenge; any change to the input changes it.
        assert_eq!(transcript(b"a", 1), transcript(b"a", 1));
        assert_ne!(transcript(b"a", 1), transcript(b"b", 1));
        assert_ne!(transcript(b"a", 1), transcript(b"a", 2));
    }

    #[test]
    fn test_challenge_advances_transcript() {
        let mut t = BpppTranscript::new(b"test");
        let c1 = t.challenge_scalar(b"c");
        let c2 = t.challenge_scalar(b"c");
        assert_ne!(c1, c2);
    }
}
