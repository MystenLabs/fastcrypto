// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::batch_avss::ReceiverOutput;
use crate::threshold_schnorr::pascal_matrix::LazyPascalMatrixMultiplier;
use crate::threshold_schnorr::{Parameters, G, S};
use crate::types::get_uniform_value;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;

/// An iterator that yields presigning tuples (t_i, p_i).
pub struct Presignatures {
    secret: Vec<LazyPascalMatrixMultiplier<S>>,
    public: LazyPascalMatrixMultiplier<G>,
}

impl Iterator for Presignatures {
    type Item = (Vec<S>, G);

    fn next(&mut self) -> Option<Self::Item> {
        // `public` drives the length; `secret` is empty for a zero-weight party.
        let public = self.public.next()?;
        let secret = self
            .secret
            .iter_mut()
            .map(Iterator::next)
            .collect::<Option<Vec<_>>>()
            .expect("secret and public multipliers have equal length");
        Some((secret, public))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.public.len();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Presignatures {}

impl Presignatures {
    /// Based on the output of a batched AVSS from multiple dealers, create a presignature
    /// generator.
    ///
    /// All parties must use the same outputs in the same order, and the output from a dealer with
    /// weight `w` should be equal to `batch_size_per_weight * w`.
    ///
    /// More parties contributing outputs gives more presignatures, so include as many as possible
    /// but at least `params.t` (by weight).
    /// Caller should wait for at least `params.t` outputs, plus some \delta time to collect more.
    ///
    /// `params.t` is the reconstruction threshold. The nonce polynomials are shared at degree
    /// `params.t - 1`, so this produces `total_weight - (params.t - 1)` presignatures per nonce
    /// position: the privacy threshold of the sharings is `t - 1`, meaning a sub-`t` coalition can
    /// know or bias up to `t - 1` of the input nonces, so only `total_weight - (t - 1)` combined
    /// nonces per position remain uniformly random and safe to output.
    ///
    /// An InvalidInput error will be returned if:
    /// * `params.t` is zero,
    /// * The total weight of the dealers for the outputs is not at least `params.t`,
    /// * The batch size of one of the outputs is not divisible by `batch_size_per_weight`,
    /// * or if batch_size_per_weight is zero.
    pub fn new(
        outputs: Vec<ReceiverOutput>,
        batch_size_per_weight: u16,
        params: Parameters,
        use_legacy: bool,
    ) -> FastCryptoResult<Self> {
        if batch_size_per_weight == 0 {
            return Err(InvalidInput);
        }
        let batch_size_per_weight = batch_size_per_weight as usize;

        // Recover each dealer's weight from its public key count, which works even for a
        // zero-weight party.
        let weights = outputs
            .iter()
            .map(|o| {
                let batch_size = o.public_keys.len();
                (batch_size % batch_size_per_weight == 0)
                    .then_some(batch_size / batch_size_per_weight)
                    .ok_or(InvalidInput)
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let total_weight_of_outputs: usize = weights.iter().sum();
        if params.t == 0 || total_weight_of_outputs < params.t as usize {
            return Err(InvalidInput);
        }

        // TODO: remove legacy mode once the old protocol is deprecated.
        let height = if use_legacy {
            total_weight_of_outputs - params.f as usize
        } else {
            total_weight_of_outputs - (params.t as usize - 1)
        };

        // This party's weight, aka it's number of shares
        let my_weight =
            get_uniform_value(outputs.iter().map(|o| o.my_shares.weight())).ok_or(InvalidInput)?;

        // Each share's batch must cover exactly the nonces dealt by that dealer.
        // The zero-weight party holds no shares, so there is nothing to check.
        if outputs.iter().zip(weights.iter()).any(|(o, w)| {
            !o.my_shares.shares.is_empty()
                && o.my_shares
                    .try_uniform_batch_size()
                    .ok()
                    .is_none_or(|bs| bs != *w * batch_size_per_weight)
        }) {
            return Err(InvalidInput);
        }

        // There is one secret presigning output per shares for this party
        let secret = (0..my_weight as usize)
            .map(|i| {
                LazyPascalMatrixMultiplier::new(
                    height,
                    (0..batch_size_per_weight)
                        .map(|j| {
                            outputs
                                .iter()
                                .zip(weights.iter())
                                .flat_map(|(o, w)| {
                                    o.my_shares.shares[i].batch[j * w..(j + 1) * w].to_vec()
                                })
                                .collect()
                        })
                        .collect(),
                )
            })
            .collect_vec();

        let public = LazyPascalMatrixMultiplier::new(
            height,
            (0..batch_size_per_weight)
                .map(|j| {
                    outputs
                        .iter()
                        .zip(weights.iter())
                        .flat_map(|(o, w)| o.public_keys[j * w..(j + 1) * w].to_vec())
                        .collect()
                })
                .collect_vec(),
        );

        // Sanity check that the multiplier sizes match the expected nonce count.
        let expected_len = height * batch_size_per_weight;
        assert!(secret.iter().all(|s| s.len() == expected_len));
        assert_eq!(public.len(), expected_len);

        Ok(Self { secret, public })
    }
}

#[cfg(test)]
mod tests {
    use super::Presignatures;
    use crate::threshold_schnorr::batch_avss::{ReceiverOutput, ShareBatch, SharesForNode};
    use crate::threshold_schnorr::{Parameters, G, S};
    use crate::types::ShareIndex;
    use fastcrypto::groups::GroupElement;

    #[test]
    fn test_new_with_zero_weight_party() {
        // A zero-weight party gets ReceiverOutputs with empty shares; this must not panic.
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 2, f: 1 }; // total weight is 2; requires t > f

        // Two weight-1 dealers: each output has batch_size_per_weight public keys, no shares.
        let outputs = (0..2)
            .map(|_| ReceiverOutput {
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![G::generator(); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        let presignatures =
            Presignatures::new(outputs, batch_size_per_weight, params, false).unwrap();

        let total_weight_of_outputs = 2;
        let expected_len =
            (total_weight_of_outputs - (params.t as usize - 1)) * batch_size_per_weight as usize;
        assert_eq!(presignatures.len(), expected_len);

        let tuples = presignatures.collect::<Vec<_>>();
        assert_eq!(tuples.len(), expected_len);
        assert!(tuples.iter().all(|(secret, _public)| secret.is_empty()));
    }

    #[test]
    fn test_presig_count_uses_privacy_threshold_not_f() {
        // Regression test for the SI-matrix height: in the default (non-legacy) mode it must be
        // `total_weight - (t - 1)`, the privacy threshold of the degree-`(t-1)` nonce sharings,
        // NOT `total_weight - f`. The two differ exactly when `t > f + 1`, so pick such a case:
        // t = 3, f = 1 (t - 1 = 2 != f = 1). The legacy mode still uses `total_weight - f`.
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 3, f: 1 };

        // Four weight-1 dealers -> total weight 4. Zero-weight receiver perspective (empty shares).
        let outputs = (0..4)
            .map(|_| ReceiverOutput {
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![G::generator(); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        // Default mode (privacy threshold t-1): (4 - (3 - 1)) * 2 = 4.
        let new =
            Presignatures::new(outputs.clone(), batch_size_per_weight, params, false).unwrap();
        assert_eq!(
            new.len(),
            (4 - (params.t as usize - 1)) * batch_size_per_weight as usize
        );
        assert_eq!(new.len(), 4);

        // Legacy mode (total_weight - f): (4 - 1) * 2 = 6.
        let legacy = Presignatures::new(outputs, batch_size_per_weight, params, true).unwrap();
        assert_eq!(
            legacy.len(),
            (4 - params.f as usize) * batch_size_per_weight as usize
        );
        assert_eq!(legacy.len(), 6);
    }

    #[test]
    fn test_new_rejects_too_short_batch() {
        // Each dealer deals batch_size_per_weight nonces per weight, so a weight-1 dealer's share
        // batch must have batch_size_per_weight entries. A shorter batch must be rejected, not
        // panic.
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 2, f: 1 }; // total weight is 2; requires t > f

        let outputs = (0..2)
            .map(|_| ReceiverOutput {
                my_shares: SharesForNode {
                    shares: vec![ShareBatch {
                        index: ShareIndex::new(1).unwrap(),
                        batch: vec![S::generator()], // length 1 < expected 2
                        blinding_share: S::generator(),
                    }],
                },
                public_keys: vec![G::generator(); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        assert!(Presignatures::new(outputs, batch_size_per_weight, params, false).is_err());
    }
}
