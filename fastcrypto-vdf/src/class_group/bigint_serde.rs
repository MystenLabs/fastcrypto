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
