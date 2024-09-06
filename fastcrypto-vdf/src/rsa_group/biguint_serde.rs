// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BigUint, D::Error> {
    <Vec<u8>>::deserialize(deserializer).map(|b| BigUint::from_bytes_be(&b))
}

pub(super) fn serialize<S: Serializer>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error> {
    value.to_bytes_be().serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use serde::Serialize;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(transparent)]
    struct TestStruct(#[serde(with = "super")] BigUint);

    #[test]
    fn test_serde() {
        let test_values = vec![
            TestStruct(BigUint::from(0u8)),
            TestStruct(BigUint::from(1234567890u128)),
            TestStruct(BigUint::from(1234567890123456789u128)),
        ];
        for value in test_values {
            let serialized = bcs::to_bytes(&value).unwrap();
            let deserialized: TestStruct = bcs::from_bytes(&serialized).unwrap();
            assert_eq!(value, deserialized);
        }
    }
}
