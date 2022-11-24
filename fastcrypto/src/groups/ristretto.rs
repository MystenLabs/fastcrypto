// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek_ng::scalar::Scalar as ExternalRistrettoScalar;
use curve25519_dalek_ng::{ristretto::RistrettoPoint as ExternalRistrettoPoint, traits::Identity};
use fastcrypto_derive::{
    AddAssignSelfRef, AddSelfRef, MulAssignSelfRef, MulSelfRef, NegSelf, SubAssignSelfRef,
    SubSelfRef, SumSelfRef,
};

use super::Group;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    AddSelfRef,
    AddAssignSelfRef,
    SubSelfRef,
    SubAssignSelfRef,
    NegSelf,
    MulSelfRef,
    MulAssignSelfRef,
    SumSelfRef,
)]
#[ScalarType = "RistrettoScalar"]
struct RistrettoPoint(ExternalRistrettoPoint);

struct RistrettoScalar(ExternalRistrettoScalar);

impl Group for RistrettoPoint {
    type Scalar = RistrettoScalar;

    fn identity() -> Self {
        RistrettoPoint(ExternalRistrettoPoint::identity())
    }

    fn is_identity(&self) -> bool {
        self == &Self::identity()
    }
}
