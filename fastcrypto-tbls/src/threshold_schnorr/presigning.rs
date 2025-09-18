// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::batch_avss::ReceiverOutput;
use crate::threshold_schnorr::si_matrix::LazyPascalMatrixMultiplier;
use crate::threshold_schnorr::{G, S};
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InputTooShort;
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;

/// An iterator that yields presigning tuples (i, t_i, p_i).
pub struct Presignatures<const BATCH_SIZE: usize> {
    secret: Vec<LazyPascalMatrixMultiplier<S>>,
    public: LazyPascalMatrixMultiplier<G>,
    index: usize,
}

impl<const BATCH_SIZE: usize> Iterator for Presignatures<BATCH_SIZE> {
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
            _ => None,
        }
    }
}

impl<const BATCH_SIZE: usize> Presignatures<BATCH_SIZE> {
    /// Based on the output if a batched AVSS from multiple dealers, complete the presigning.
    ///
    /// The resulting iterator can give
    pub fn new(
        my_indices: &[ShareIndex],
        avss_outputs: &[ReceiverOutput<BATCH_SIZE>],
        f: usize,
    ) -> FastCryptoResult<Self> {
        if avss_outputs.len() < 2 * f + 1 {
            return Err(InputTooShort(2 * f + 1));
        }
        let m = avss_outputs.len() - f;

        // There is one secret presigning output per weight for this party.
        let secret = my_indices
            .iter()
            .enumerate()
            .map(|(i, _index)| {
                let rho = avss_outputs
                    .iter()
                    .map(|output| output.my_shares.batches[i].shares.to_vec())
                    .collect();
                LazyPascalMatrixMultiplier::new(m, rho)
            })
            .collect_vec();

        let public = LazyPascalMatrixMultiplier::new(
            m,
            avss_outputs
                .iter()
                .map(|output| output.public_keys.to_vec())
                .collect(),
        );

        assert_eq!(secret[0].remaining(), public.remaining());

        Ok(Self {
            secret,
            public,
            index: 0,
        })
    }

    pub fn remaining(&self) -> usize {
        // The public and secret iterators has the same number of elements
        self.public.remaining()
    }
}
