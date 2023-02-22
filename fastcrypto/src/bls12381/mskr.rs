// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::ToFromBytes;

/// Trait impl'd by keys and signatures for signature schemes supporting the MSKR (Multi-Signature with Key Randomization) scheme.
pub trait Randomize<
    PubKey: ToFromBytes,
    Scalar,
    H: HashToScalar<Scalar>,
    const PUBLIC_KEY_LENGTH: usize,
>: Sized
{
    /// Randomize this with the given scalar.
    fn randomize_internal(&self, r: &Scalar) -> Self;

    /// Randomize this deterministically based on the given public keys.
    fn randomize(&self, pk: &PubKey, pks: &[PubKey]) -> Self {
        self.randomize_internal(
            &randomization_scalar::<PubKey, Scalar, H, PUBLIC_KEY_LENGTH>(pk, pks),
        )
    }
}

pub trait HashToScalar<Scalar> {
    fn hash_to_scalar(bytes: &[u8]) -> Scalar;
}

/// Compute as hash of (pk, pks) into a scalar type.
pub(crate) fn randomization_scalar<
    PubKey: ToFromBytes,
    Scalar,
    H: HashToScalar<Scalar>,
    const PUBLIC_KEY_LENGTH: usize,
>(
    pk: &PubKey,
    pks: &[PubKey],
) -> Scalar {
    let mut seed: Vec<u8> = Vec::with_capacity(PUBLIC_KEY_LENGTH * (pks.len() + 1));
    seed.extend_from_slice(pk.as_bytes());
    for pki in pks {
        seed.extend_from_slice(pki.as_bytes());
    }
    H::hash_to_scalar(seed.as_slice())
}
