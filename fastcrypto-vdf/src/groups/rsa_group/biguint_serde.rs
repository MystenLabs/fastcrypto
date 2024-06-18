// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigUint;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(BigUint::from_bytes_be(&<Vec<u8>>::deserialize(
        deserializer,
    )?))
}

pub(crate) fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.to_bytes_be().serialize(serializer)
}
