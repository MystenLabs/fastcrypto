use base64ct::{Base64, Encoding};
use digest::OutputSizeUser;
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use std::fmt;
use typenum::U32;

/// Represents a hash digest of `DigestLength` bytes.
#[derive(Hash, PartialEq, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest<DigestLength: ArrayLength<u8> + 'static>(GenericArray<u8, DigestLength>);

impl<DigestLength: ArrayLength<u8> + 'static> Digest<DigestLength> {
    pub fn from_bytes(val: &[u8]) -> Self {
        let array = GenericArray::from_slice(val);
        Digest(array.to_owned())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        DigestLength::USIZE
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> fmt::Debug for Digest<DigestLength> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(&self.0))
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> fmt::Display for Digest<DigestLength> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            Base64::encode_string(&self.0)
                .get(0..DigestLength::USIZE)
                .unwrap()
        )
    }
}

impl<DigestLength: ArrayLength<u8> + 'static> AsRef<[u8]> for Digest<DigestLength> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hashable<DigestLength: ArrayLength<u8> + 'static> {
    fn digest(&self) -> Digest<DigestLength>;
}

impl Hashable<U32> for &[u8] {
    fn digest(&self) -> Digest<U32> {
        Sha256::default().digest(self)
    }
}

/// Trait implemented by hash functions providing a output of fixed length
pub trait HashFunction<DigestLength: ArrayLength<u8>>: OutputSizeUser + Sized + Default {
    fn update(&mut self, data: &[u8]);

    fn finalize(self) -> Digest<DigestLength>;

    fn digest(mut self, data: &[u8]) -> Digest<DigestLength> {
        self.update(data);
        self.finalize()
    }
}

#[derive(Default)]
pub struct HashFunctionWrapper<Variant: digest::Digest + 'static>(Variant);

impl<Variant: digest::Digest + 'static> OutputSizeUser for HashFunctionWrapper<Variant> {
    type OutputSize = Variant::OutputSize;
}

impl<Variant: digest::Digest + 'static + Default> HashFunction<Variant::OutputSize>
    for HashFunctionWrapper<Variant>
{
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest<Variant::OutputSize> {
        Digest(self.0.finalize())
    }
}

// SHA-2
pub type Sha224 = HashFunctionWrapper<sha2::Sha224>;
pub type Sha256 = HashFunctionWrapper<sha2::Sha256>;
pub type Sha384 = HashFunctionWrapper<sha2::Sha384>;
pub type Sha512 = HashFunctionWrapper<sha2::Sha512>;
pub type Sha512_224 = HashFunctionWrapper<sha2::Sha512_224>;
pub type Sha512_256 = HashFunctionWrapper<sha2::Sha512_256>;

// SHA-3
pub type Sha3_224 = HashFunctionWrapper<sha3::Sha3_224>;
pub type Sha3_256 = HashFunctionWrapper<sha3::Sha3_256>;
pub type Sha3_384 = HashFunctionWrapper<sha3::Sha3_384>;
pub type Sha3_512 = HashFunctionWrapper<sha3::Sha3_512>;
pub type Shake128 = HashFunctionWrapper<sha3::Shake128>;
pub type Shake256 = HashFunctionWrapper<sha3::Shake256>;

// KECCAK
pub type Keccak224 = HashFunctionWrapper<sha3::Keccak224>;
pub type Keccak256 = HashFunctionWrapper<sha3::Keccak256>;
pub type Keccak384 = HashFunctionWrapper<sha3::Keccak384>;
pub type Keccak512 = HashFunctionWrapper<sha3::Keccak512>;

// Blake
pub type Blake2b512 = HashFunctionWrapper<blake2::Blake2b>;
