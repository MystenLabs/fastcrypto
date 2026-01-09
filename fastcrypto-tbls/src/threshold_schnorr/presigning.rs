// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::batch_avss::ReceiverOutput;
use crate::threshold_schnorr::pascal_matrix::LazyPascalMatrixMultiplier;
use crate::threshold_schnorr::{G, S};
use crate::types::get_uniform_value;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;

/// An iterator that yields presigning tuples (i, t_i, p_i).
pub struct Presignatures {
    secret: Vec<LazyPascalMatrixMultiplier<S>>,
    public: LazyPascalMatrixMultiplier<G>,
    index: usize,
}

impl Iterator for Presignatures {
    type Item = (usize, Vec<S>, G);

    fn next(&mut self) -> Option<Self::Item> {
        let secret = self
            .secret
            .iter_mut()
            .map(Iterator::next)
            .collect::<Option<Vec<_>>>();
        let public = self.public.next();

        match (secret, public) {
            (Some(s), Some(p)) => {
                self.index += 1;
                Some((self.index, s, p))
            }
            (None, None) => None,
            _ => unreachable!(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.public.len();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Presignatures {}

impl Presignatures {
    /// Based on the output of a batched AVSS from multiple dealers, create a presignature generator.
    ///
    /// All parties must use the same outputs in the same order, and the output from a dealer with weight `w` should be equal to `batch_size_per_weight * w`.
    ///
    /// An InvalidInput error will be returned if:
    /// * The total weight of the dealers for the outputs is not at least 2f+1,
    /// * The batch size of one of the outputs is not divisible by `batch_size_per_weight`,
    /// * or if batch_size_per_weight is zero.
    pub fn new(
        outputs: Vec<ReceiverOutput>,
        batch_size_per_weight: usize,
        f: usize,
    ) -> FastCryptoResult<Self> {
        if batch_size_per_weight == 0 {
            return Err(InvalidInput);
        }

        // Each node should deal a batch sized proportional to their weight, and the total weight of the outputs should be at least 2*f + 1
        let weights = outputs
            .iter()
            .map(|o| {
                (o.batch_size % batch_size_per_weight == 0)
                    .then_some(o.batch_size / batch_size_per_weight)
                    .ok_or(InvalidInput)
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let total_weight_of_outputs: usize = weights.iter().sum();
        if total_weight_of_outputs < 2 * f + 1 {
            return Err(InvalidInput);
        }

        // This party's weight, aka it's number of shares
        let my_weight = get_uniform_value(outputs.iter().map(|o| o.my_shares.weight()))
            .expect("Checked in batch_avss");

        // There is one secret presigning output per shares for this party
        let secret = (0..my_weight)
            .map(|i| {
                LazyPascalMatrixMultiplier::new(
                    total_weight_of_outputs - f,
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
            total_weight_of_outputs - f,
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

        // Sanity checks that the size of the multipliers matches the expected number of nonces that this presigning will give
        let expected_len = (total_weight_of_outputs - f) * batch_size_per_weight;
        assert_eq!(
            get_uniform_value(secret.iter().map(|s| s.len())).unwrap(),
            expected_len
        );
        assert_eq!(public.len(), expected_len);

        Ok(Self {
            secret,
            public,
            index: 0,
        })
    }
}
