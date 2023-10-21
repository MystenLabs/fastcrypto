// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.

use crate::dl_verification::{batch_coefficients, get_random_scalars};
use crate::polynomial::Poly;
use crate::types::IndexedValue;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, HashToGroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;

pub type Share<S> = IndexedValue<S>;
pub type PartialSignature<S> = IndexedValue<S>;

/// Trait [ThresholdBls] provides sign & verify functions for standard and partial BLS signatures.
pub trait ThresholdBls {
    type Private: Scalar;
    /// `Public` represents the group over which the public keys are represented.
    type Public: GroupElement<ScalarType = Self::Private> + MultiScalarMul;
    /// `Signature` represents the group over which the signatures are represented.
    type Signature: GroupElement<ScalarType = Self::Private> + HashToGroupElement + MultiScalarMul;

    /// Curve dependent implementation of computing and comparing the pairings as part of the
    /// signature verification.
    fn verify_pairings(
        pk: &Self::Public,
        sig: &Self::Signature,
        msg: &[u8],
    ) -> Result<(), FastCryptoError>;

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
        Self::partial_sign_batch(&[share.clone()], msg)[0].clone()
    }

    /// Sign a message using one of more private share/partial keys.
    fn partial_sign_batch(
        shares: &[Share<Self::Private>],
        msg: &[u8],
    ) -> Vec<PartialSignature<Self::Signature>> {
        let h = Self::Signature::hash_to_group_element(msg);
        shares
            .iter()
            .map(|share| PartialSignature {
                index: share.index,
                value: h * share.value,
            })
            .collect()
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

    /// Verify a set of signatures done by a partial key holder.
    /// Randomly check if \sum r_i sig_i is a valid signature with public key \sum r_i p(i) G
    /// where r_i are random scalars.
    fn partial_verify_batch<R: AllowedRng>(
        vss_pk: &Poly<Self::Public>,
        msg: &[u8],
        partial_sigs: &[PartialSignature<Self::Signature>],
        rng: &mut R,
    ) -> Result<(), FastCryptoError> {
        let rs = get_random_scalars::<Self::Private, R>(partial_sigs.len() as u32, rng);
        let evals_as_scalars = partial_sigs
            .iter()
            .map(|e| Self::Private::from(e.index.get().into()))
            .collect::<Vec<_>>();
        // TODO: should we cache it instead?
        let coeffs = batch_coefficients(&rs, &evals_as_scalars, vss_pk.degree());
        let pk = Self::Public::multi_scalar_mul(&coeffs, vss_pk.as_vec()).expect("sizes match");
        let aggregated_sig = Self::Signature::multi_scalar_mul(
            &rs,
            &partial_sigs.iter().map(|s| s.value).collect::<Vec<_>>(),
        )
        .expect("sizes match");

        Self::verify(&pk, msg, &aggregated_sig)
    }

    /// Interpolate partial signatures to recover the full signature.
    fn aggregate(
        threshold: u32,
        partials: &[PartialSignature<Self::Signature>],
    ) -> FastCryptoResult<Self::Signature> {
        let unique_partials = partials
            .iter()
            .unique_by(|p| p.index)
            .take(threshold as usize)
            .cloned()
            .collect::<Vec<_>>();
        // No conversion is required since PartialSignature<S> and Eval<S> are different aliases to
        // IndexedValue<S>.
        Poly::<Self::Signature>::recover_c0_msm(threshold, &unique_partials)
    }
}
