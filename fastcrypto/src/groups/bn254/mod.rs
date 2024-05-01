// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::{GroupElement, Pairing};
use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::pairing::{Pairing as ArkworksPairing, PairingOutput};
use derive_more::{Add, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;

mod g1;
mod g2;
mod gt;
mod scalar;

#[cfg(test)]
mod tests;

/// The byte length of a compressed element of G1.
pub const G1_ELEMENT_BYTE_LENGTH: usize = 32;

/// The byte length of a compressed element of G2.
pub const G2_ELEMENT_BYTE_LENGTH: usize = 64;

/// The byte length of a compressed element of GT.
pub const GT_ELEMENT_BYTE_LENGTH: usize = 384;

/// The byte length of a scalar.
pub const SCALAR_LENGTH: usize = 32;

/// Elements of the group G1 in BN254.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend, From)]
#[repr(transparent)]
pub struct G1Element(G1Projective);

/// Elements of the group G2 in BN254.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend, From)]
#[repr(transparent)]
pub struct G2Element(G2Projective);

/// Elements of the subgroup GT of F_q^{12} in BN254. Note that it is written in additive notation here.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend, From)]
pub struct GTElement(PairingOutput<Bn254>);

/// This represents a scalar modulo r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// which is the order of the groups G1, G2 and GT. Note that r is a 254 bit prime.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend, From)]
pub struct Scalar(Fr);

impl Pairing for G1Element {
    type Other = G2Element;
    type Output = GTElement;

    fn pairing(&self, other: &Self::Other) -> <Self as Pairing>::Output {
        GTElement(Bn254::pairing(self.0, other.0))
    }
}
