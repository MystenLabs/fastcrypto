use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::groups::bls12381::Base64G1Element;
use crate::groups::bls12381::G1Element;
use crate::groups::GroupElement;
use serde::de::DeserializeOwned;
use serde::ser::SerializeTuple;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use std::{fmt::Display, marker::PhantomData};

/// Basic wrapper that stores a bincode serialized version of object T.
/// To be used in external interfaces instead of the internal object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base64Representation<T, const N: usize> {
    pub bytes: [u8; N],
    phantom: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned, const N: usize> Base64Representation<T, N> {
    pub fn from_type(value: &T) -> Result<Self, FastCryptoError> {
        let buffer = bincode::serialize(value).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Self {
            bytes: buffer
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
            phantom: Default::default(),
        })
    }

    pub fn to_type(&self) -> Result<T, FastCryptoError> {
        let res: T =
            bincode::deserialize(&self.bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(res)
    }
}

impl<T, const N: usize> AsRef<[u8]> for Base64Representation<T, N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_ref()
    }
}

impl<T, const N: usize> Serialize for Base64Representation<T, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Base64::encode(&self.bytes).serialize(serializer)
    }
}

impl<'de, T, const N: usize> Deserialize<'de> for Base64Representation<T, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded =
            Base64::decode(&s).map_err(|_| de::Error::custom("Base64 decoding failed"))?;
        let bytes: [u8; N] = decoded
            .try_into()
            .map_err(|_| de::Error::custom("Base64 decoding failed"))?;
        Ok(Self {
            bytes,
            phantom: Default::default(),
        })
    }
}

// remove ...

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Dummy {
    e: Base64G1Element,
}

#[test]
fn test_g1() {
    type T = Base64G1Element;
    let g = G1Element::generator();
    let g_as_bytes = T::from_type(&g).unwrap();
    let ser = bincode::serialize(&g_as_bytes).unwrap();
    println!("1 {}", serde_json::to_string(&g_as_bytes).unwrap());
    println!("2 {}", serde_json::to_string(&ser).unwrap());

    let g_as_bytes2: T = bincode::deserialize(&ser).unwrap();
    assert_eq!(g_as_bytes, g_as_bytes2);
    let g2 = g_as_bytes2.to_type().unwrap();
    assert_eq!(g, g2);
    let d = Dummy {
        e: T::from_type(&g).unwrap(),
    };
    println!("3 {}", serde_json::to_string(&d).unwrap());
}
