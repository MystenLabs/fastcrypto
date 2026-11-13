// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Crate-wide Verus declarations for fastcrypto-threshold, compiled only when Verus runs (see
//! `lib.rs`): what Verus may assume about types and traits from other crates, and the spec
//! functions and lemmas for the AVID sender check.

use crate::nodes::{Nodes, PartyId};
use crate::threshold_schnorr::G;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError;
use vstd::prelude::*;
use vstd::set_lib::*;

verus! {

// Types and traits from other crates that the specs mention, trusted with no spec.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExFastCryptoError(FastCryptoError);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExRistrettoPoint(fastcrypto::groups::ristretto255::RistrettoPoint);

#[verifier::external_trait_specification]
pub trait ExSerialize {
    type ExternalTraitSpecificationFor: serde::Serialize;
}

#[verifier::external_trait_specification]
pub trait ExDeserialize<'de>: Sized {
    type ExternalTraitSpecificationFor: serde::Deserialize<'de>;
}

#[verifier::external_trait_specification]
pub trait ExDeserializeOwned: for<'de> serde::Deserialize<'de> {
    type ExternalTraitSpecificationFor: serde::de::DeserializeOwned;
}

#[verifier::external_trait_specification]
pub trait ExAdditiveGroup:
    Copy
    + Clone
    + core::fmt::Debug
    + Eq
    + core::ops::Add<Output = Self>
    + core::ops::AddAssign
    + for<'a> core::ops::Add<&'a Self, Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::SubAssign
    + for<'a> core::ops::Sub<&'a Self, Output = Self>
    + core::ops::Neg<Output = Self>
    + Sized
{
    type ExternalTraitSpecificationFor: fastcrypto::groups::AdditiveGroup;
}

#[verifier::external_trait_specification]
pub trait ExModule<S>:
    fastcrypto::groups::AdditiveGroup
    + core::ops::Mul<S, Output = Self>
    + for<'a> core::ops::Mul<&'a S, Output = Self>
{
    type ExternalTraitSpecificationFor: fastcrypto::groups::Module<S>;
}

#[verifier::external_trait_specification]
pub trait ExScalar:
    fastcrypto::groups::Module<Self>
    + core::ops::Div<Self, Output = Result<Self, FastCryptoError>>
    + Copy
    + From<u128>
    + Sized
    + core::fmt::Debug
    + serde::Serialize
    + serde::de::DeserializeOwned
{
    type ExternalTraitSpecificationFor: fastcrypto::groups::Scalar;
}

#[verifier::external_trait_specification]
pub trait ExGroupElement:
    fastcrypto::groups::Module<Self::ScalarType>
    + core::ops::Div<Self::ScalarType, Output = Result<Self, FastCryptoError>>
{
    type ExternalTraitSpecificationFor: fastcrypto::groups::GroupElement;
    type ScalarType: fastcrypto::groups::Scalar;
}

pub assume_specification[ <fastcrypto::groups::ristretto255::RistrettoScalar as From<u128>>::from ](
    x: u128,
) -> fastcrypto::groups::ristretto255::RistrettoScalar;

pub assume_specification[ <fastcrypto::groups::secp256k1::Scalar as From<u128>>::from ](
    x: u128,
) -> fastcrypto::groups::secp256k1::Scalar;

#[verifier::external_trait_specification]
pub trait ExZeroize {
    type ExternalTraitSpecificationFor: zeroize::Zeroize;
}

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExRistrettoScalar(fastcrypto::groups::ristretto255::RistrettoScalar);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExProjectivePoint(fastcrypto::groups::secp256k1::ProjectivePoint);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSecp256k1Scalar(fastcrypto::groups::secp256k1::Scalar);

pub assume_specification<C: Clone>[ <crate::polynomial::Poly<C> as Clone>::clone ](
    p: &crate::polynomial::Poly<C>,
) -> crate::polynomial::Poly<C>;

#[verifier::external_trait_specification]
pub trait ExRngCore {
    type ExternalTraitSpecificationFor: rand::RngCore;
}

#[verifier::external_trait_specification]
pub trait ExCryptoRng {
    type ExternalTraitSpecificationFor: rand::CryptoRng;
}

#[verifier::external_trait_specification]
pub trait ExAllowedRng: rand::CryptoRng + rand::RngCore {
    type ExternalTraitSpecificationFor: fastcrypto::traits::AllowedRng;
}

/// `nodes.share_ids_of(id)`, when it is `Ok`.
pub uninterp spec fn spec_share_ids<C: fastcrypto::groups::GroupElement>(
    nodes: Nodes<C>,
    id: PartyId,
) -> Seq<ShareIndex>;

// The AVID sender check, `avid::total_weight_of_distinct`.

/// `ids` is nonempty, and its elements are distinct parties `< n`.
pub open spec fn distinct_ids(ids: Seq<u16>, n: int) -> bool {
    ids.len() > 0 && ids.no_duplicates() && forall|i: int| 0 <= i < ids.len() ==> ids[i] < n
}

/// The sum of `weights[i]` over the elements `i` of `ids`.
pub open spec fn weight_of(ids: Seq<u16>, weights: Seq<u16>) -> int
    decreases ids.len(),
{
    if ids.len() == 0 {
        0
    } else {
        weight_of(ids.drop_last(), weights) + weights[ids.last() as int]
    }
}

/// There are at most 2^16 distinct `u16`s.
pub proof fn lemma_distinct_len(s: Seq<u16>)
    requires
        s.no_duplicates(),
    ensures
        s.len() <= 65536,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let t = s.map_values(|x: u16| x as int);
    assert(t.no_duplicates());
    t.unique_seq_to_set();
    lemma_int_range(0, 65536);
    assert(t.to_set().subset_of(set_int_range(0, 65536)));
    lemma_len_subset(t.to_set(), set_int_range(0, 65536));
}

} // verus!
