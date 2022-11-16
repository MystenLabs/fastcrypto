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

    // Multiplying the base point by five gives the expected result
    let p = RistrettoScalar::from(5) * Ristretto255::base_point();
    assert_eq!(five_bp, p);

    // Adding the base point with it self five times gives the expected result
    let q = Ristretto255::base_point()
        + Ristretto255::base_point()
        + Ristretto255::base_point()
        + Ristretto255::base_point()
        + Ristretto255::base_point();
    assert_eq!(five_bp, q);

    // Adding the identity element does not change anything
    assert_eq!(
        Ristretto255::base_point() + Ristretto255::identity(),
        Ristretto255::base_point()
    );
}

#[test]
fn test_serialize_deserialize_element() {
    let p = Ristretto255::base_point() + Ristretto255::base_point();
    let serialized = bincode::serialize(&p).unwrap();
    let deserialized: RistrettoPoint = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);
}
