// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigInt;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(BigInt::from_signed_bytes_be(&<Vec<u8>>::deserialize(
        deserializer,
    )?))
}

pub(crate) fn serialize<S>(value: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.to_signed_bytes_be().serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(transparent)]
    struct TestStruct(#[serde(with = "super")] BigInt);

    #[test]
    fn test_serde() {
        let test_values = vec![
            TestStruct(BigInt::from(-1234567890)),
            TestStruct(BigInt::from(1234567890)),
            TestStruct(BigInt::from(0)),
        ];
        for value in test_values {
            let serialized = bcs::to_bytes(&value).unwrap();
            let deserialized: TestStruct = bcs::from_bytes(&serialized).unwrap();
            assert_eq!(value, deserialized);
        }
    }
}
