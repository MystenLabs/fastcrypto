// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ristretto255::{self, RistrettoScalar};

#[test]
fn test_arithmetic() {
    // From https://ristretto.group/test_vectors/ristretto255.html
    let five_bp = "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e";

    // Multiplying the base point by five gives the expected result
    let p = RistrettoScalar::from(5) * ristretto255::base_point();
    let p_compressed = hex::encode(p.as_ref());
    assert_eq!(five_bp, p_compressed);

    // Adding the base point with it self five times gives the expected result
    let q = ristretto255::base_point()
        + ristretto255::base_point()
        + ristretto255::base_point()
        + ristretto255::base_point()
        + ristretto255::base_point();
    let q_compressed = hex::encode(q.as_ref());
    assert_eq!(five_bp, q_compressed);

    // Adding the identity element does not change anything
    assert_eq!(
        ristretto255::base_point() + ristretto255::identity(),
        ristretto255::base_point()
    );
}
