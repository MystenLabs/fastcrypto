// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.

use crate::polynomial::Poly;
use crate::types::IndexedValue;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{GroupElement, HashToGroupElement, Scalar};

pub type Share<S> = IndexedValue<S>;
pub type PartialSignature<S> = IndexedValue<S>;

/// Trait [ThresholdBls] provides sign & verify functions for standard and partial BLS signatures.
pub trait ThresholdBls {
    type Private: Scalar;
    /// `Public` represents the group over which the public keys are represented.
    type Public: GroupElement<ScalarType = Self::Private>;
    /// `Signature` represents the group over which the signatures are represented.
    type Signature: GroupElement<ScalarType = Self::Private> + HashToGroupElement;

    /// Curve dependent implementation of computing and comparing the pairings as part of the
    /// signature verification.
    fn verify_pairings(
        pk: &Self::Public,
        sig: &Self::Signature,
        msg: &[u8],
    ) -> Result<(), FastCryptoError>;

    /// Sign a message using the private key.
    fn sign(private: &Self::Private, msg: &[u8]) -> Self::Signature {
        let h = Self::Signature::hash_to_group_element(msg);
        h * private
    }

    /// Verify a signature on a given message.
    fn verify(
        public: &Self::Public,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), FastCryptoError> {
        Self::verify_pairings(public, sig, msg).map_err(|_| FastCryptoError::InvalidSignature)
    }

    /// Sign a message using the private share/partial key.
    fn partial_sign(share: &Share<Self::Private>, msg: &[u8]) -> PartialSignature<Self::Signature> {
        PartialSignature {
            index: share.index,
            value: Self::sign(&share.value, msg),
        }
    }

    /// Verify a signature done by a partial key holder.
    fn partial_verify(
        vss_pk: &Poly<Self::Public>,
        msg: &[u8],
        partial_sig: &PartialSignature<Self::Signature>,
    ) -> Result<(), FastCryptoError> {
        let pk_i = vss_pk.eval(partial_sig.index);
        Self::verify(&pk_i.value, msg, &partial_sig.value)
    }

    /// Interpolate partial signatures to recover the full signature.
    fn aggregate(
        threshold: u32,
        partials: &[PartialSignature<Self::Signature>],
    ) -> Result<Self::Signature, FastCryptoError> {
        // No conversion is required since PartialSignature<S> and Eval<S> are different aliases to
        // IndexedValue<S>.
        Poly::<Self::Signature>::recover_c0(threshold, partials)
    }
}
