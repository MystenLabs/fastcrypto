// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero},
    HashMarker, OutputSizeUser,
};
use hkdf::hmac::Hmac;
use sha3::{Keccak256, Sha3_256};

fn hkdf<H>(salt: Option<&[u8]>) -> Vec<u8>
where
    H: CoreProxy + OutputSizeUser,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let ikm = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];

    let hk = hkdf::Hkdf::<H, Hmac<H>>::new(salt, ikm);
    let mut okm = vec![0u8; 1024];
    hk.expand(&[], &mut okm).unwrap();
    okm
}

#[test]
fn test_regression_of_salt_padding() {
    // When HMAC is called, salt is padded with zeros to the internal block size.
    assert_eq!(hkdf::<Sha3_256>(None), hkdf::<Sha3_256>(Some(&[])));
    assert_eq!(hkdf::<Keccak256>(None), hkdf::<Keccak256>(Some(&[])));
    assert_eq!(hkdf::<Sha3_256>(None), hkdf::<Sha3_256>(Some(&[0])));
    // Sha3_256's internal block size is 136.
    assert_eq!(hkdf::<Sha3_256>(None), hkdf::<Sha3_256>(Some(&[0u8; 136])));
    assert_ne!(hkdf::<Sha3_256>(None), hkdf::<Sha3_256>(Some(&[0u8; 137])));
}
