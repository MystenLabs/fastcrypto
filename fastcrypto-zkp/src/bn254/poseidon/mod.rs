// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::poseidon::constants::*;
use crate::{FrRepr, FIELD_SIZE};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use byte_slice_cast::AsByteSlice;
use fastcrypto::error::FastCryptoError::{InputTooLong, InvalidInput};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use ff::PrimeField as OtherPrimeField;
use neptune::poseidon::HashMode::OptimizedStatic;
use neptune::Poseidon;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use std::cmp::Ordering;

/// The output of the Poseidon hash function is a field element in BN254 which is 254 bits long, so
/// we need 32 bytes to represent it as an integer.
pub const FIELD_ELEMENT_SIZE_IN_BYTES: usize = 32;

/// The degree of the Merkle tree used to hash multiple elements.
pub const MERKLE_TREE_DEGREE: usize = 16;

mod constants;

/// Define a macro to calculate the poseidon hash of a vector of inputs using the neptune library.
macro_rules! define_poseidon_hash {
    ($inputs:expr, $poseidon_constants:expr) => {{
        let mut poseidon = Poseidon::new(&$poseidon_constants);
        poseidon.reset();
        for input in $inputs.iter() {
            poseidon.input(bn254_to_fr(*input)).expect("The number of inputs must be aligned with the constants");
        }
        poseidon.hash_in_mode(OptimizedStatic);

        // Neptune returns the state element with index 1 but we want the first element to be aligned
        // with poseidon-rs and circomlib's implementation which returns the 0'th element.
        //
        // See:
        //  * https://github.com/lurk-lab/neptune/blob/b7a9db1fc6ce096aff52b903f7d228eddea6d4e3/src/poseidon.rs#L698
        //  * https://github.com/arnaucube/poseidon-rs/blob/f4ba1f7c32905cd2ae5a71e7568564bb150a9862/src/lib.rs#L116
        //  * https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/poseidon.circom#L207
        poseidon.elements[0]
    }};
}

/// Poseidon hash function over BN254. The input vector cannot be empty and must contain at most 16
/// elements, otherwise an error is returned.
pub fn hash(inputs: Vec<Fr>) -> Result<Fr, FastCryptoError> {
    if inputs.is_empty() || inputs.len() > 16 {
        return Err(FastCryptoError::InputLengthWrong(inputs.len()));
    }

    // Instances of Poseidon and PoseidonConstants from neptune have different types depending on
    // the number of inputs, so unfortunately we need to use a macro here.
    let result = match inputs.len() {
        1 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U1),
        2 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U2),
        3 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U3),
        4 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U4),
        5 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U5),
        6 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U6),
        7 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U7),
        8 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U8),
        9 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U9),
        10 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U10),
        11 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U11),
        12 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U12),
        13 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U13),
        14 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U14),
        15 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U15),
        16 => define_poseidon_hash!(inputs, POSEIDON_CONSTANTS_U16),
        _ => return Err(InvalidInput),
    };
    Ok(fr_to_bn254fr(result))
}

/// Calculate the poseidon hash of the field element inputs. If the input length is <= 16, calculate
/// H(inputs), otherwise chunk the inputs into groups of 16, hash them and input the results recursively.
pub fn to_poseidon_hash(inputs: Vec<Fr>) -> Result<Fr, FastCryptoError> {
    if inputs.len() <= MERKLE_TREE_DEGREE {
        hash(inputs)
    } else {
        to_poseidon_hash(
            inputs
                .chunks(MERKLE_TREE_DEGREE)
                .map(|chunk| hash(chunk.to_vec()))
                .collect::<FastCryptoResult<Vec<_>>>()?,
        )
    }
}

/// Calculate the poseidon hash of an array of inputs. Each input is interpreted as a BN254 field
/// element assuming a little-endian encoding. The field elements are then hashed using the poseidon
/// hash function ([to_poseidon_hash]) and the result is serialized as a little-endian integer (32
/// bytes).
///
/// If one of the inputs is in non-canonical form, e.g. it represents an integer greater than the
/// field size or is longer than 32 bytes, an error is returned.
pub fn hash_to_bytes(
    inputs: &Vec<Vec<u8>>,
) -> Result<[u8; FIELD_ELEMENT_SIZE_IN_BYTES], FastCryptoError> {
    let field_element = hash_to_field_element(inputs)?;
    Ok(field_element_to_canonical_le_bytes(&field_element))
}

/// Calculate the poseidon hash of a byte array:
///  1) Interpret all the `bytes` as a little-endian integer.
///  2) Set the `8*bytes.len()`'th bit of the integer.
///  3) Write the base-expansion of the integer where the base it the BN254 field size.
///  4) Interpret the digits as field elements and hash them with the Poseidon hash function.
///  5) Return the hash as a little-endian integer (32 bytes).
pub fn hash_bytes_to_bytes(
    bytes: &[u8],
) -> Result<[u8; FIELD_ELEMENT_SIZE_IN_BYTES], FastCryptoError> {
    let field_elements = map_bytes_injectively_to_field_elements(bytes);
    let result = to_poseidon_hash(field_elements)?;
    Ok(field_element_to_canonical_le_bytes(&result))
}

/// Map a byte array to a vector of field elements. The mapping works as follows:
///  1) Interpret all the `bytes` as a little-endian integer.
///  2) Set the `8*bytes.len()`'th bit of the integer.
///  3) Write the base-expansion of the integer where the base it the BN254 field size.
///  4) Interpret the digits as field elements and return.
fn map_bytes_injectively_to_field_elements(bytes: &[u8]) -> Vec<Fr> {
    let mut n = BigUint::from_bytes_le(bytes);

    // To ensure that the bits to field elements mapping is injective in case the leading bit is
    // zero, we need to set the highest bit.
    n.set_bit((8 * bytes.len()) as u64, true);

    let mut digits = Vec::new();
    while !n.is_zero() {
        let (q, r) = n.div_rem(&FIELD_SIZE);
        digits.push(from_canonical_le_bytes_to_field_element(&r.to_bytes_le())
            .expect("The Euclidean division ensures that the representation is canonical because the remainder is smaller than the field size"));
        n = q
    }
    digits
}

/// Given a binary representation of a BN254 field element as an integer in little-endian encoding,
/// this function returns the corresponding field element. If the field element is not canonical (is
/// larger than the field size as an integer), an `FastCryptoError::InvalidInput` is returned.
///
/// If more than 32 bytes is given, an `FastCryptoError::InputTooLong` is returned.
fn from_canonical_le_bytes_to_field_element(bytes: &[u8]) -> Result<Fr, FastCryptoError> {
    match bytes.len().cmp(&FIELD_ELEMENT_SIZE_IN_BYTES) {
        Ordering::Less => Ok(Fr::from_le_bytes_mod_order(bytes)),
        Ordering::Equal => {
            let field_element = Fr::from_le_bytes_mod_order(bytes);
            // Unfortunately, there doesn't seem to be a nice way to check if a modular reduction
            // happened without doing the extra work of serializing the field element again.
            let reduced_bytes = field_element.into_bigint().to_bytes_le();
            if reduced_bytes != bytes {
                return Err(InvalidInput);
            }
            Ok(field_element)
        }
        Ordering::Greater => Err(InputTooLong(bytes.len())),
    }
}

/// Convert a BN254 field element to a byte array as the little-endian representation of the
/// underlying canonical integer representation of the element.
fn field_element_to_canonical_le_bytes(field_element: &Fr) -> [u8; FIELD_ELEMENT_SIZE_IN_BYTES] {
    let bytes = field_element.into_bigint().to_bytes_le();
    <[u8; FIELD_ELEMENT_SIZE_IN_BYTES]>::try_from(bytes)
        .expect("The result is guaranteed to be 32 bytes")
}

/// Calculate the poseidon hash of an array of inputs. Each input is interpreted as a BN254 field
/// element assuming a little-endian encoding. The field elements are then hashed using the poseidon
/// hash function ([to_poseidon_hash]).
///
/// If one of the inputs is in non-canonical form, e.g. it represents an integer greater than the
/// field size or is longer than 32 bytes, an error is returned.
pub fn hash_to_field_element(inputs: &Vec<Vec<u8>>) -> Result<Fr, FastCryptoError> {
    let mut field_elements = Vec::new();
    for input in inputs {
        field_elements.push(from_canonical_le_bytes_to_field_element(input)?);
    }
    to_poseidon_hash(field_elements)
}

/// Convert an ff field element to an arkworks-ff field element.
fn fr_to_bn254fr(fr: crate::Fr) -> Fr {
    // We use big-endian as in the definition of the BN254 prime field (see fastcrypto-zkp/src/lib.rs).
    Fr::from_be_bytes_mod_order(fr.to_repr().as_byte_slice())
}

/// Convert an arkworks-ff field element to an ff field element.
fn bn254_to_fr(fr: Fr) -> crate::Fr {
    let mut bytes = [0u8; 32];
    // We use big-endian as in the definition of the BN254 prime field (see fastcrypto-zkp/src/lib.rs).
    bytes.clone_from_slice(&fr.into_bigint().to_bytes_be());
    crate::Fr::from_repr_vartime(FrRepr(bytes))
        .expect("The bytes of fr are guaranteed to be canonical here")
}

#[cfg(test)]
mod test {
    use crate::bn254::poseidon::hash_to_bytes;
    use crate::bn254::poseidon::{hash, hash_bytes_to_bytes};
    use crate::bn254::{poseidon::to_poseidon_hash, zk_login::Bn254Fr};
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use lazy_static::lazy_static;
    use proptest::arbitrary::Arbitrary;
    use proptest::collection;
    use std::str::FromStr;

    fn to_bigint_arr(vals: Vec<u8>) -> Vec<Bn254Fr> {
        vals.into_iter().map(Bn254Fr::from).collect()
    }

    #[test]
    fn poseidon_test() {
        let input1 = Fr::from_str("134696963602902907403122104327765350261").unwrap();
        let input2 = Fr::from_str("17932473587154777519561053972421347139").unwrap();
        let input3 = Fr::from_str("10000").unwrap();
        let input4 = Fr::from_str(
            "50683480294434968413708503290439057629605340925620961559740848568164438166",
        )
        .unwrap();
        let hash = hash(vec![input1, input2, input3, input4]).unwrap();
        assert_eq!(
            hash,
            Fr::from_str(
                "2272550810841985018139126931041192927190568084082399473943239080305281957330"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_to_poseidon_hash() {
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![1]))
                .unwrap()
                .to_string(),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![1, 2]))
                .unwrap()
                .to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
            ]))
            .unwrap()
            .to_string(),
            "4203130618016961831408770638653325366880478848856764494148034853759773445968"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
            ]))
            .unwrap()
            .to_string(),
            "9989051620750914585850546081941653841776809718687451684622678807385399211877"
        );
        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29
            ]))
            .unwrap()
            .to_string(),
            "4123755143677678663754455867798672266093104048057302051129414708339780424023"
        );

        assert_eq!(
            to_poseidon_hash(to_bigint_arr(vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32
            ]))
            .unwrap()
            .to_string(),
            "15368023340287843142129781602124963668572853984788169144128906033251913623349"
        );
    }

    #[test]
    fn test_binary_hashing() {
        assert_eq!(
            hash_bytes_to_bytes(&[]).unwrap(),
            hash_to_bytes(&vec![vec![1]]).unwrap()
        );

        assert_eq!(
            hash_bytes_to_bytes(&[0]).unwrap(),
            hash_to_bytes(&vec![vec![0, 1]]).unwrap()
        );

        assert_eq!(
            hash_bytes_to_bytes(&[0, 1, 2, 3]).unwrap(),
            hash_to_bytes(&vec![vec![0, 1, 2, 3, 1]]).unwrap()
        );

        let large_input = hex::decode("bc23bbeaa1ab56ad6b3cc61f413a64e6f0e0fa58a35a039a9442918b1e83e3f1ec6b9db62ca937c43db07eacb4e291ae0a67b88cddef85633b364d8a5fee4f95c1f703cd74a07947e498f1f74aefaab5458c310b5eedfe24d148330e0ae25f01ee92a8808030ce3cabbeff0c4c4892119ae1644b9c0b834ab9f27e4ee02cffdee251568b652565431f1f23511ef9653295ae37b861709ec58e5990809bc184c8d9fc5cde1264e58ebe517cbf653d4a69a6d662d5bb1663c5b580b9d9f3b1159346e2bebc8eaf38fc1552971378e50a1edb6d3ae9d60f1ca4fb2d47167ec23ddf7b2597fd2d461f22cb631a37f22673ad03ed42da73fe0dc7d798713aab6e97ebc902ba70").unwrap();
        assert_eq!(
            hash_bytes_to_bytes(&large_input).unwrap(),
            [
                156, 236, 71, 218, 237, 179, 78, 53, 125, 57, 169, 211, 254, 169, 31, 58, 162, 250,
                30, 64, 115, 137, 243, 78, 246, 174, 106, 219, 114, 39, 180, 33
            ]
        );
    }

    #[test]
    fn test_hash_to_bytes() {
        let inputs: Vec<Vec<u8>> = vec![vec![1u8]];
        let hash = hash_to_bytes(&inputs).unwrap();
        // 18586133768512220936620570745912940619677854269274689475585506675881198879027 in decimal
        let expected =
            hex::decode("33018202c57d898b84338b16d1a4960e133c6a4d656cfec1bd62a9ea00611729")
                .unwrap();
        assert_eq!(hash.as_slice(), &expected);

        // 7853200120776062878684798364095072458815029376092732009249414926327459813530 in decimal
        let inputs: Vec<Vec<u8>> = vec![vec![1u8], vec![2u8]];
        let hash = hash_to_bytes(&inputs).unwrap();
        let expected =
            hex::decode("9a1817447a60199e51453274f217362acfe962966b4cf63d4190d6e7f5c05c11")
                .unwrap();
        assert_eq!(hash.as_slice(), &expected);

        // Input larger than the modulus
        let inputs = vec![vec![255; 32]];
        assert!(hash_to_bytes(&inputs).is_err());

        // Input smaller than the modulus
        let inputs = vec![vec![255; 31]];
        assert!(hash_to_bytes(&inputs).is_ok());
    }

    #[cfg(test)]
    lazy_static! {
        static ref POSEIDON_ARK: poseidon_ark::Poseidon = poseidon_ark::Poseidon::new();
    }

    proptest::proptest! {
        #[test]
        fn test_against_poseidon_ark(r in collection::vec(<[u8; 32]>::arbitrary(), 1..16)) {

            let inputs = r.into_iter().map(|ri| ark_bn254::Fr::from_le_bytes_mod_order(&ri)).collect::<Vec<_>>();
            let expected = POSEIDON_ARK.hash(inputs.clone()).unwrap().into_bigint().to_bytes_le();

            let actual = hash_to_bytes(&inputs.iter().map(|i| i.into_bigint().to_bytes_le().to_vec()).collect::<Vec<_>>()).unwrap();
            assert_eq!(&actual, expected.as_slice());
        }
    }
}
