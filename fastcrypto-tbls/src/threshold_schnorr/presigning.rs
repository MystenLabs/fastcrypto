// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nodes::PartyId;
use crate::threshold_schnorr::batch_avss_avid::ReceiverOutput;
use crate::threshold_schnorr::pascal_matrix::LazyPascalMatrixMultiplier;
use crate::threshold_schnorr::{BatchId, Parameters, G, S};
use crate::types::get_uniform_value;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::{Blake2b256, HashFunction};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Domain separation prefix for the hash identifying a presigning instance.
const SESSION_ID_DOMAIN: &[u8] = b"fastcrypto_threshold_schnorr_presigning_session";

/// An iterator that yields presigning tuples (t_i, p_i).
///
/// The tuples are tied to the committee and weights they were created for, since share indices
/// follow the cumulative weights. They must be discarded and regenerated when the committee
/// changes.
pub struct Presignatures {
    secret: Vec<LazyPascalMatrixMultiplier<S>>,
    public: LazyPascalMatrixMultiplier<G>,
    batch_id: BatchId,
    dealers: Vec<PartyId>,
    /// Hash of the two above, which identifies this presigning instance.
    session_id: [u8; 32],
}

impl std::fmt::Debug for Presignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presignatures")
            .field("batch_id", &Hex::encode(self.batch_id.as_bytes()))
            .field("dealers", &self.dealers)
            .field("session_id", &Hex::encode(self.session_id))
            .field("remaining", &self.public.len())
            .finish()
    }
}

/// The public part of a [PresignaturePair]: the presigning instance it came from, the index of
/// the pair within that instance and the two public presignatures. This is what the parties must
/// agree on, and what aggregation needs.
///
/// The fields are private so that pairs can only come from [Presignatures::pairs], which hands
/// out disjoint pairs. Overlapping pairs such as `(0, 1)`, `(1, 2)`, `(2, 3)` would use every
/// tuple in the middle twice and still produce valid signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPresignaturePair {
    session_id: [u8; 32],
    index: u32,
    first: G,
    second: G,
}

impl PublicPresignaturePair {
    /// The presigning instance this pair came from, as hashed by [Presignatures::new].
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The index of this pair within its presigning instance.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The public part of the first presigning tuple, `D` in the protocol description.
    pub fn first(&self) -> &G {
        &self.first
    }

    /// The public part of the second presigning tuple, `D'` in the protocol description.
    pub fn second(&self) -> &G {
        &self.second
    }

    #[cfg(test)]
    pub(crate) fn new_for_testing(session_id: [u8; 32], index: u32, first: G, second: G) -> Self {
        Self {
            session_id,
            index,
            first,
            second,
        }
    }
}

/// Two presigning tuples to be used for a single signature, along with the index of the pair
/// within its presigning instance. Yielded by [Presignatures::pairs], see
/// [PublicPresignaturePair] for why it cannot be built directly.
#[derive(Clone, Debug)]
pub struct PresignaturePair {
    public: PublicPresignaturePair,
    first_shares: Vec<S>,
    second_shares: Vec<S>,
}

impl PresignaturePair {
    /// What the other parties must agree on to sign with this pair.
    pub fn public(&self) -> &PublicPresignaturePair {
        &self.public
    }

    pub(crate) fn into_parts(self) -> (PublicPresignaturePair, Vec<S>, Vec<S>) {
        (self.public, self.first_shares, self.second_shares)
    }

    #[cfg(test)]
    pub(crate) fn new_for_testing(
        public: PublicPresignaturePair,
        first_shares: Vec<S>,
        second_shares: Vec<S>,
    ) -> Self {
        Self {
            public,
            first_shares,
            second_shares,
        }
    }
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
    /// The generator always starts at the first tuple and stores no position, so the caller must
    /// keep track of which tuples have been used in state that survives restarts, and resume with
    /// e.g. `nth`.
    ///
    /// All parties must use the same outputs, and the output from a dealer with weight `w` should
    /// be equal to `batch_size_per_weight * w`. The outputs must come from distinct dealers, with
    /// at most one output per dealer.
    ///
    /// More parties contributing outputs gives more presignatures, so include as many as possible
    /// but at least `params.t` (by weight). The set of outputs must be agreed on before calling
    /// this, e.g., by the dealers' certificates on the TOB channel.
    ///
    /// `params.t` is the reconstruction threshold. The nonce polynomials are shared at degree
    /// `params.t - 1`, so this produces `total_weight - (params.t - 1)` presignatures per nonce
    /// position: the privacy threshold of the sharings is `t - 1`, meaning a sub-`t` coalition can
    /// know or bias up to `t - 1` of the input nonces, so only `total_weight - (t - 1)` combined
    /// nonces per position remain uniformly random and safe to output.
    ///
    /// The outputs must all come from the same nonce batch, and are used in ascending dealer order
    /// whatever order they are given in. That batch and those dealers identify this presigning
    /// instance, `pid = (bid, J)` in the protocol description, and are hashed into the binding
    /// factor of every pair from this generator, so pairs from different batches, or from
    /// different dealer sets of the same batch, can never be bound the same way.
    ///
    /// An InvalidInput error will be returned if:
    /// * the outputs are empty, come from more than one batch, or two come from the same dealer,
    /// * `params.t` is zero,
    /// * The total weight of the dealers for the outputs is not at least `params.t`,
    /// * The batch size of one of the outputs is not divisible by `batch_size_per_weight`,
    /// * or if batch_size_per_weight is zero.
    pub fn new(
        outputs: Vec<ReceiverOutput>,
        batch_size_per_weight: u16,
        params: Parameters,
    ) -> FastCryptoResult<Self> {
        if batch_size_per_weight == 0 || outputs.is_empty() {
            return Err(InvalidInput);
        }

        // The dealer order fixes the layout of the presigning matrix, so it is canonicalised here
        // rather than left to the caller: every party combines the same dealings the same way.
        let mut outputs = outputs;
        outputs.sort_by_key(|output| output.dealer);
        let dealers = outputs.iter().map(|output| output.dealer).collect_vec();
        let batch_id = outputs[0].batch_id.clone();
        if !dealers.windows(2).all(|pair| pair[0] < pair[1])
            || outputs.iter().any(|output| output.batch_id != batch_id)
        {
            return Err(InvalidInput);
        }
        let batch_size_per_weight = batch_size_per_weight as usize;

        // Outputs from different dealings have different public keys with overwhelming
        // probability, so equal ones mean either the same output twice or two dealers dealing the
        // same nonces. Neither is unsafe, but the first means the caller counted one contribution
        // twice, which extracts more presignatures than the honest entropy justifies. Outputs
        // without public keys add no weight and are ignored.
        if outputs
            .iter()
            .filter(|o| !o.public_keys.is_empty())
            .tuple_combinations()
            .any(|(a, b)| a.public_keys == b.public_keys)
        {
            warn!("presigning: two outputs share their public keys");
        }

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

        let height = total_weight_of_outputs - (params.t as usize - 1);

        // This party's weight, aka its number of shares
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

        Ok(Self {
            secret,
            public,
            // bcs length-prefixes the byte strings and the dealer list, so a long batch id
            // cannot encode as a short one followed by another dealer.
            session_id: Blake2b256::digest(
                bcs::to_bytes(&(SESSION_ID_DOMAIN, batch_id.as_bytes(), &dealers))
                    .expect("serializing bytes and ids never fails"),
            )
            .digest,
            batch_id,
            dealers,
        })
    }

    /// Pair up the tuples, two per signature, dropping a trailing tuple with nothing to pair it
    /// with. Pairs are indexed from the start of the returned iterator, so it must be created
    /// from a fresh generator and resumed with e.g. `nth`, not by advancing the tuples first.
    pub fn pairs(self) -> impl Iterator<Item = PresignaturePair> {
        let session_id = self.session_id;
        self.tuples().enumerate().map(
            move |(index, ((first_shares, first), (second_shares, second)))| PresignaturePair {
                public: PublicPresignaturePair {
                    session_id,
                    index: index as u32,
                    first,
                    second,
                },
                first_shares,
                second_shares,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchId, PartyId, Presignatures};
    use crate::threshold_schnorr::batch_avss_avid::{ReceiverOutput, ShareBatch, SharesForNode};
    use crate::threshold_schnorr::{Parameters, G, S};
    use fastcrypto::groups::GroupElement;

    #[test]
    fn test_new_with_zero_weight_party() {
        // A zero-weight party gets ReceiverOutputs with empty shares; this must not panic.
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 2, f: 1 }; // total weight is 2; requires t >= f

        // Two weight-1 dealers: each output has batch_size_per_weight public keys, no shares.
        let outputs = (0..2)
            .map(|i| ReceiverOutput {
                batch_id: BatchId::new(b"batch".to_vec()),
                dealer: i as PartyId,
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![G::generator() * S::from(i + 1); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        let presignatures = Presignatures::new(outputs, batch_size_per_weight, params).unwrap();

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
        // Regression test for the SI-matrix height: it must be `total_weight - (t - 1)`, the
        // privacy threshold of the degree-`(t-1)` nonce sharings, NOT `total_weight - f`. The two
        // agree only when `t - 1 == f`, so this covers both sides: t = 3, f = 1 gives fewer
        // positions than `total_weight - f` would, and t = f gives one more.
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 3, f: 1 };

        // Four weight-1 dealers -> total weight 4. Zero-weight receiver perspective (empty shares).
        let outputs = (0..4)
            .map(|i| ReceiverOutput {
                batch_id: BatchId::new(b"batch".to_vec()),
                dealer: i as PartyId,
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![G::generator() * S::from(i + 1); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        // Privacy threshold t-1: (4 - (3 - 1)) * 2 = 4.
        let presignatures = Presignatures::new(outputs, batch_size_per_weight, params).unwrap();
        assert_eq!(
            presignatures.len(),
            (4 - (params.t as usize - 1)) * batch_size_per_weight as usize
        );
        assert_eq!(presignatures.len(), 4);

        // `t == f` is allowed (`validate` rejects only `t < f`), and is the direction where
        // `total_weight - f` under-produces instead of over-producing.
        let params = Parameters { t: 2, f: 2 };
        let outputs = (0..4)
            .map(|i| ReceiverOutput {
                batch_id: BatchId::new(b"batch".to_vec()),
                dealer: i as PartyId,
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![G::generator() * S::from(i + 1); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        // Total weight 4 and `t - 1 = 1` give a height of 3, and each row yields one presignature
        // per nonce position, so (4 - (2 - 1)) * 2 = 6. Using `f = 2` as the threshold would leave
        // a height of 2 and so (4 - 2) * 2 = 4.
        let presignatures = Presignatures::new(outputs, batch_size_per_weight, params).unwrap();
        assert_eq!(
            presignatures.len(),
            (4 - (params.t as usize - 1)) * batch_size_per_weight as usize
        );
        assert_eq!(presignatures.len(), 6);
    }

    #[test]
    fn test_new_rejects_too_short_batch() {
        // Each dealer deals batch_size_per_weight nonces per weight, so a weight-1 dealer's share
        // batch must have batch_size_per_weight entries. A shorter batch must be rejected, not
        // panic.
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 2, f: 1 }; // total weight is 2; requires t >= f

        let outputs = (0..2)
            .map(|i| ReceiverOutput {
                batch_id: BatchId::new(b"batch".to_vec()),
                dealer: i as PartyId,
                my_shares: SharesForNode {
                    shares: vec![ShareBatch {
                        batch: vec![S::generator()], // length 1 < expected 2
                        blinding_share: S::generator(),
                    }],
                },
                public_keys: vec![G::generator() * S::from(i + 1); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        assert!(Presignatures::new(outputs, batch_size_per_weight, params).is_err());
    }

    #[test]
    fn test_pair_indices() {
        // Four weight-1 dealers with three nonces each: nine tuples, which pair up into four
        // pairs, leaving the last tuple unpaired.
        let batch_size_per_weight: u16 = 3;
        let params = Parameters { t: 2, f: 1 };
        let outputs = (0..4)
            .map(|i| ReceiverOutput {
                batch_id: BatchId::new(b"batch".to_vec()),
                dealer: i as PartyId,
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![G::generator() * S::from(i + 1); batch_size_per_weight as usize],
            })
            .collect::<Vec<_>>();

        let presignatures = Presignatures::new(outputs, batch_size_per_weight, params).unwrap();
        assert_eq!(presignatures.len(), 9);
        assert_eq!(
            presignatures
                .pairs()
                .map(|pair| pair.public().index())
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    fn mock_outputs(
        dealers: &[PartyId],
        batch_id: &BatchId,
        batch_size_per_weight: u16,
    ) -> Vec<ReceiverOutput> {
        dealers
            .iter()
            .map(|&dealer| ReceiverOutput {
                batch_id: batch_id.clone(),
                dealer,
                my_shares: SharesForNode { shares: vec![] },
                public_keys: vec![
                    G::generator() * S::from(dealer as u128 + 1);
                    batch_size_per_weight as usize
                ],
            })
            .collect()
    }

    #[test]
    fn test_new_rejects_inconsistent_outputs() {
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 2, f: 1 };
        let batch_id = BatchId::new(b"batch".to_vec());
        let new = |outputs: Vec<ReceiverOutput>| {
            Presignatures::new(outputs, batch_size_per_weight, params)
        };

        assert!(new(mock_outputs(&[0, 1], &batch_id, batch_size_per_weight)).is_ok());
        // The dealer order is canonicalised rather than rejected
        assert!(new(mock_outputs(&[1, 0], &batch_id, batch_size_per_weight)).is_ok());
        // No outputs at all, and two outputs from one dealer
        assert!(new(vec![]).is_err());
        assert!(new(mock_outputs(&[0, 0], &batch_id, batch_size_per_weight)).is_err());
        // Outputs from two different batches
        let mut mixed = mock_outputs(&[0, 1], &batch_id, batch_size_per_weight);
        mixed[1].batch_id = BatchId::new(b"other batch".to_vec());
        assert!(new(mixed).is_err());
    }

    #[test]
    fn test_session_id_covers_batch_and_dealers() {
        let batch_size_per_weight: u16 = 2;
        let params = Parameters { t: 2, f: 1 };
        let session_id = |dealers: &[PartyId], batch_id: &[u8]| {
            let batch_id = BatchId::new(batch_id.to_vec());
            *Presignatures::new(
                mock_outputs(dealers, &batch_id, batch_size_per_weight),
                batch_size_per_weight,
                params,
            )
            .unwrap()
            .pairs()
            .next()
            .unwrap()
            .public()
            .session_id()
        };

        let id = session_id(&[0, 1], b"batch");
        assert_ne!(id, session_id(&[0, 1], b"other batch"));
        assert_ne!(id, session_id(&[0, 2], b"batch"));
        // The dealer order is canonicalised, so it does not change the instance
        assert_eq!(id, session_id(&[1, 0], b"batch"));
    }
}
