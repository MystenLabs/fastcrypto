// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::rsa_group::biguint_serde;
use crate::groups::Parameter;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAModulus {
    #[serde(with = "biguint_serde")]
    pub value: BigUint,
}

impl Parameter for RSAModulus {}

lazy_static! {
    // Modulus from Google Certificate, GTS Root R1 (https://pki.goog/repository/).
    pub static ref GOOGLE_RSA_MODULUS_4096: RSAModulus = RSAModulus {
        value: BigUint::from_str_radix("00b611028b1ee3a1779b3bdcbf943eb795a7403ca1fd82f97d32068271f6f68c7ffbe8dbbc6a2e9797a38c4bf92bf6b1f9ce841db1f9c597deefb9f2a3e9bc12895ea7aa52abf82327cba4b19c63dbd7997ef00a5eeb68a6f4c65a470d4d1033e34eb113a3c8186c4becfc0990df9d6429252307a1b4d23d2e60e0cfd20987bbcd48f04dc2c27a888abbbacf5919d6af8fb007b09e31f182c1c0df2ea66d6c190eb5d87e261a45033db079a49428ad0f7f26e5a808fe96e83c689453ee833a882b159609b2e07a8c2e75d69ceba756648f964f68ae3d97c2848fc0bc40c00b5cbdf687b3356cac18507f84e04ccd92d320e933bc5299af32b529b3252ab448f972e1ca64f7e682108de89dc28a88fa38668afc63f901f978fd7b5c77fa7687faecdfb10e799557b4bd26efd601d1eb160abb8e0bb5c5c58a55abd3acea914b29cc19a432254e2af16544d002ceaace49b4ea9f7c83b0407be743aba76ca38f7d8981fa4ca5ffd58ec3ce4be0b5d8b38e45cf76c0ed402bfd530fb0a7d53b0db18aa203de31adcc77ea6f7b3ed6df912212e6befad832fc1063145172de5dd61693bd296833ef3a66ec078a26df13d757657827de5e491400a2007f9aa821b6a9b195b0a5b90d1611dac76c483c40e07e0d5acd563cd19705b9cb4bed394b9cc43fd255136e24b0d671faf4c1bacced1bf5fe8141d800983d3ac8ae7a9837180595", 16).unwrap(),
    };
}
