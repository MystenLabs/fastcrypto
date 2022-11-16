// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::{
    ristretto255::{Ristretto255, RistrettoPoint, RistrettoScalar},
    AdditiveGroup,
};
use crate::traits::ToFromBytes;

#[test]
fn test_arithmetic() {
    // From https://ristretto.group/test_vectors/ristretto255.html
    let five_bp = RistrettoPoint::from_bytes(
        &hex::decode("e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e").unwrap(),
    )
    .unwrap();

    // Test that multiplying the base point by five gives the expected result
    let p = RistrettoScalar::from(5) * Ristretto255::base_point();
    assert_eq!(five_bp, p);

    // Test that adding the base point with it self five times gives the same result
    let q = Ristretto255::base_point()
        + Ristretto255::base_point()
        + Ristretto255::base_point()
        + Ristretto255::base_point()
        + Ristretto255::base_point();
    assert_eq!(five_bp, q);

    // Adding the identity element does not change anything
    assert_eq!(&q + Ristretto255::identity(), q);

    // Test the order of the base point
    assert_ne!(Ristretto255::identity(), Ristretto255::base_point());
    assert_eq!(
        Ristretto255::identity(),
        Ristretto255::base_point_order() * Ristretto255::base_point()
    );
}

#[test]
fn test_serialize_deserialize_element() {
    let p = Ristretto255::base_point() + Ristretto255::base_point();
    let serialized = bincode::serialize(&p).unwrap();
    let deserialized: RistrettoPoint = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);
}

#[test]
fn test_compress_decompress_points() {
    let p = Ristretto255::base_point() + Ristretto255::base_point();
    let p_compressed = p.as_bytes();

    // Test vector from https://ristretto.group/test_vectors/ristretto255.html
    assert_eq!(
        &hex::decode("6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919").unwrap(),
        p_compressed
    );
    // Decompress
    assert_eq!(p, RistrettoPoint::from_bytes(p_compressed).unwrap());

    // Decompress non-square. Should fail.
    let non_square: [u8; 32] =
        hex::decode("26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(RistrettoScalar::from_canonical_bytes(non_square).is_err());
}
