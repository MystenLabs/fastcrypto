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
    /// This iterator can yield `(outputs.len() - f) * BATCH_SIZE` presignatures.
    ///
    /// BATCH_SIZE must be larger than or equal to the `outputs.len() - f`.
    pub fn new(outputs: Vec<ReceiverOutput>, f: usize) -> FastCryptoResult<Self> {
        if outputs.len() < 2 * f + 1 {
            return Err(InvalidInput);
        }
        let height = outputs.len() - f; // >= f + 1
        let batch_size = outputs[0].my_shares.try_uniform_batch_size()?;
        if batch_size + f < outputs.len() {
            return Err(InvalidInput);
        }

        let my_weight =
            get_uniform_value(outputs.iter().map(|o| o.my_shares.weight())).ok_or(InvalidInput)?;

        // There is one secret presigning output per weight for this party.
        let secret = (0..my_weight)
            .map(|i| {
                LazyPascalMatrixMultiplier::new(
                    height,
                    (0..batch_size)
                        .map(|j| {
                            outputs
                                .iter()
                                .map(|o| o.my_shares.shares[i].batch[j])
                                .collect()
                        })
                        .collect(),
                )
            })
            .collect_vec();

        let public = LazyPascalMatrixMultiplier::new(
            height,
            (0..batch_size)
                .map(|i| outputs.iter().map(|o| o.public_keys[i]).collect())
                .collect(),
        );

        assert_eq!(
            get_uniform_value(secret.iter().map(LazyPascalMatrixMultiplier::len)).unwrap(),
            public.len()
        );

        Ok(Self {
            secret,
            public,
            index: 0,
        })
    }
}
