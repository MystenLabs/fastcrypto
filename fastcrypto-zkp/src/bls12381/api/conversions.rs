// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::{
    GTElement, Scalar, FP_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};
use fastcrypto::serde_helpers::ToFromByteArray;

use crate::groth16::api::{FromLittleEndianByteArray, GTSerialize};

impl FromLittleEndianByteArray<SCALAR_LENGTH> for Scalar {
    fn from_little_endian_byte_array(bytes: &[u8; SCALAR_LENGTH]) -> FastCryptoResult<Self> {
        let mut reversed = *bytes;
        reversed.reverse();
        Scalar::from_byte_array(&reversed)
    }
}

impl GTSerialize<GT_ELEMENT_BYTE_LENGTH> for GTElement {
    fn to_arkworks_bytes(&self) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
        gt_element_to_arkworks(&self.to_byte_array())
    }

    fn from_arkworks_bytes(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        GTElement::from_byte_array(&arkworks_to_gt_element(bytes))
    }
}

/// Split the input into `TOTAL_SIZE / permutation.len()` chunks, and permute the chunks according
/// to the given permutation.
fn permute_elements<const TOTAL_SIZE: usize>(
    bytes: &[u8; TOTAL_SIZE],
    permutation: &[usize],
) -> [u8; TOTAL_SIZE] {
    let elements = permutation.len();
    assert_eq!(TOTAL_SIZE % elements, 0);
    let element_size = TOTAL_SIZE / elements;
    let mut result = [0u8; TOTAL_SIZE];
    for (from, to) in permutation.iter().enumerate() {
        let from = from * element_size;
        let to = to * element_size;
        result[to..to + element_size].copy_from_slice(&bytes[from..from + element_size]);
    }
    result
}

/// Reverse the endianness of each element in the input array, where each element is `N` bytes long.
fn reverse_endianness_for_elements<const TOTAL_SIZE: usize>(
    bytes: &mut [u8; TOTAL_SIZE],
    element_size: usize,
) {
    assert_eq!(TOTAL_SIZE % element_size, 0);
    bytes
        .chunks_exact_mut(element_size)
        .for_each(|chunk| chunk.reverse());
}

/// Given a serialization of a arkworks [`PairingOutput`] element, this function returns a
/// serialization of the corresponding [`GTElement`] element. It is _not_ verified whether the input
/// is a valid serialization.
fn arkworks_to_gt_element(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
    // This permutation flips the order of the i in 0..3 and j in 0..2 loops and may be computed as:
    // for i in 0..3 {
    //   for j in 0..2 {
    //     PERMUTATION[i + j * 3] = i * 2 + j;
    //   }
    // }
    let mut bytes = permute_elements(bytes, &[0, 2, 4, 1, 3, 5]);
    reverse_endianness_for_elements(&mut bytes, FP_BYTE_LENGTH);
    bytes
}

/// Given a serialization of a [`GTElement`], this function returns a serialization of the
/// corresponding element as a arkworks [`PairingOutput`] type. It is _not_ verified whether the
/// input is a valid serialization.
fn gt_element_to_arkworks(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
    // This is the inverse of the permutation in `arkworks_to_gt_element`.
    let mut bytes = permute_elements(bytes, &[0, 3, 1, 4, 2, 5]);
    reverse_endianness_for_elements(&mut bytes, FP_BYTE_LENGTH);
    bytes
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ec::pairing::PairingOutput;
    use ark_ec::Group;
    use ark_ff::Zero;
    use ark_serialize::CanonicalSerialize;
    use fastcrypto::error::FastCryptoError;

    use crate::bls12381::api::conversions::{arkworks_to_gt_element, gt_element_to_arkworks};
    use crate::groth16::api::{FromLittleEndianByteArray, GTSerialize};
    use fastcrypto::groups::bls12381::{
        G1Element, G2Element, GTElement, Scalar, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH,
        GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
    };
    use fastcrypto::groups::GroupElement;
    use fastcrypto::serde_helpers::ToFromByteArray;

    #[test]
    fn test_gt_element_conversion() {
        let generator = PairingOutput::<Bls12_381>::generator();
        let mut arkworks_bytes = Vec::new();
        let mut uncompressed_bytes = Vec::new();

        // GT elements cannot be compressed, so compressed and uncompressed serialization should be the same.
        generator.serialize_compressed(&mut arkworks_bytes).unwrap();
        generator
            .serialize_uncompressed(&mut uncompressed_bytes)
            .unwrap();
        assert_eq!(arkworks_bytes, uncompressed_bytes);

        // The arkworks serialization does not match the GroupElement serialization.
        let fc_bytes = GTElement::generator().to_byte_array();
        assert_eq!(arkworks_bytes.len(), fc_bytes.len());
        assert_ne!(arkworks_bytes, fc_bytes);

        // After conversion, the arkworks serialization should match the GroupElement serialization.
        assert_eq!(arkworks_bytes, gt_element_to_arkworks(&fc_bytes));
        assert_eq!(
            arkworks_to_gt_element(&arkworks_bytes.try_into().unwrap()),
            fc_bytes
        );

        // Compare serializations of the identity element
        let arkworks_id = PairingOutput::<Bls12_381>::zero();
        let mut arkworks_bytes = Vec::new();
        arkworks_id
            .serialize_uncompressed(&mut arkworks_bytes)
            .unwrap();
        let fc_bytes = GTElement::zero().to_byte_array();
        assert_ne!(&fc_bytes.to_vec(), &arkworks_bytes);
        assert_eq!(&gt_element_to_arkworks(&fc_bytes).to_vec(), &arkworks_bytes);
        assert_eq!(
            arkworks_to_gt_element(&arkworks_bytes.try_into().unwrap()),
            fc_bytes
        );
    }

    fn test_arkworks_compatability_for_group_element<
        const SIZE: usize,
        G: GroupElement,
        A: Group + CanonicalSerialize,
    >(
        g: G,
        a: A,
        serializer: fn(G) -> [u8; SIZE],
        deserializer: fn(&[u8; SIZE]) -> Result<G, FastCryptoError>,
    ) {
        let bytes = serializer(g);
        let mut arkworks_bytes = Vec::new();
        a.serialize_compressed(&mut arkworks_bytes).unwrap();
        assert_eq!(bytes.to_vec(), arkworks_bytes);
        assert_eq!(bytes.len(), SIZE);

        let g2 = deserializer(&bytes).unwrap();
        assert_eq!(g, g2);

        let a2 = A::deserialize_compressed(&arkworks_bytes[..]).unwrap();
        assert_eq!(a, a2);
    }

    fn test_arkworks_compatability_for_group<
        const SIZE: usize,
        G: GroupElement + ToFromByteArray<SIZE>,
        A: Group + CanonicalSerialize,
    >(
        serializer: fn(G) -> [u8; SIZE],
        deserializer: fn(&[u8; SIZE]) -> Result<G, FastCryptoError>,
    ) {
        test_arkworks_compatability_for_group_element::<SIZE, _, _>(
            G::zero(),
            A::zero(),
            serializer,
            deserializer,
        );
        test_arkworks_compatability_for_group_element::<SIZE, _, _>(
            G::generator(),
            A::generator(),
            serializer,
            deserializer,
        );
        let scalar = 12345u128;
        test_arkworks_compatability_for_group_element::<SIZE, _, _>(
            G::generator() * G::ScalarType::from(scalar),
            A::generator() * A::ScalarField::from(scalar),
            serializer,
            deserializer,
        );
    }

    #[test]
    fn test_arkworks_compatability() {
        test_arkworks_compatability_for_group::<G1_ELEMENT_BYTE_LENGTH, _, G1Projective>(
            |g| g.to_byte_array(),
            G1Element::from_byte_array,
        );
        test_arkworks_compatability_for_group::<G2_ELEMENT_BYTE_LENGTH, _, G2Projective>(
            |g| g.to_byte_array(),
            G2Element::from_byte_array,
        );
        test_arkworks_compatability_for_group::<GT_ELEMENT_BYTE_LENGTH, _, PairingOutput<Bls12_381>>(
            |g| g.to_arkworks_bytes(),
            GTElement::from_arkworks_bytes,
        );
    }

    #[test]
    fn test_from_le_bytes() {
        let x = 12345678u128;
        let arkworks_scalar = Fr::from(x);
        let mut arkworks_bytes = Vec::new();
        arkworks_scalar
            .serialize_compressed(&mut arkworks_bytes)
            .unwrap();
        assert_eq!(arkworks_bytes.len(), SCALAR_LENGTH);
        assert_eq!(arkworks_bytes[..16], x.to_le_bytes());

        let scalar =
            Scalar::from_little_endian_byte_array(&arkworks_bytes.try_into().unwrap()).unwrap();
        assert_eq!(scalar, Scalar::from(x));
    }
}
