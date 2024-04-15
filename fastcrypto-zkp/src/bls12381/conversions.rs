use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::{FP_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH, GTElement, Scalar, SCALAR_LENGTH};
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

// An element in the quadratic extension of Fp consists of two field elements.
const FP_EXTENSION_BYTE_LENGTH: usize = 2 * FP_BYTE_LENGTH;

/// Reorder the six field extensions in a GT element according to the given permutation.
/// This functions panics if one of the elements in the permutation is larger than 5.
fn permute_elements(
    bytes: &[u8; 6 * FP_EXTENSION_BYTE_LENGTH],
    permutation: &[usize; 6],
) -> [u8; 6 * FP_EXTENSION_BYTE_LENGTH] {
    // TODO: This could be done in-place to avoid allocating a new array.
    let mut result = [0u8; 12 * FP_BYTE_LENGTH];
    for (from, to) in permutation.iter().enumerate() {
        let from = from * FP_EXTENSION_BYTE_LENGTH;
        let to = to * FP_EXTENSION_BYTE_LENGTH;
        result[to..to + FP_EXTENSION_BYTE_LENGTH]
            .copy_from_slice(&bytes[from..from + FP_EXTENSION_BYTE_LENGTH]);
    }
    result
        .chunks_exact_mut(FP_BYTE_LENGTH)
        .for_each(|chunk| chunk.reverse());
    result
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
    const PERMUTATION: [usize; 6] = [0, 2, 4, 1, 3, 5];
    permute_elements(bytes, &PERMUTATION)
}

/// Given a serialization of a [`GTElement`], this function returns a serialization of the
/// corresponding element as a arkworks [`PairingOutput`] type. It is _not_ verified whether the
/// input is a valid serialization.
fn gt_element_to_arkworks(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
    // This is the inverse of the permutation in `arkworks_to_gt_element`.
    const PERMUTATION: [usize; 6] = [0, 3, 1, 4, 2, 5];
    permute_elements(bytes, &PERMUTATION)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_ec::pairing::PairingOutput;
    use ark_ff::Zero;
    use ark_serialize::CanonicalSerialize;
    use fastcrypto::error::FastCryptoError;

    use fastcrypto::groups::bls12381::{G1_ELEMENT_BYTE_LENGTH, G1Element, G2_ELEMENT_BYTE_LENGTH, G2Element, GT_ELEMENT_BYTE_LENGTH, GTElement};
    use fastcrypto::groups::GroupElement;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use crate::bls12381::conversions::{arkworks_to_gt_element, gt_element_to_arkworks};
    use crate::groth16::api::GTSerialize;

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
}
