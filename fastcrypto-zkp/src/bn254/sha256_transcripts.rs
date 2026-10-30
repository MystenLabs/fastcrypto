// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::hash::{HashFunction, Sha256};

pub(super) fn append_fixed_width_be(
    output: &mut Vec<u8>,
    value: &[u8],
    width: usize,
) -> FastCryptoResult<()> {
    let value = value
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first_nonzero| &value[first_nonzero..]);
    let padding_len = width
        .checked_sub(value.len())
        .ok_or(FastCryptoError::InvalidInput)?;
    let padded_len = output
        .len()
        .checked_add(padding_len)
        .ok_or(FastCryptoError::InvalidInput)?;
    output.resize(padded_len, 0);
    output.extend_from_slice(value);
    Ok(())
}

pub(super) fn append_length_prefixed_padded_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
    max_len: usize,
) -> FastCryptoResult<()> {
    let value_len = u16::try_from(value.len()).map_err(|_| FastCryptoError::InvalidInput)?;
    let padding_len = max_len
        .checked_sub(value.len())
        .ok_or(FastCryptoError::InvalidInput)?;
    output.extend_from_slice(&value_len.to_be_bytes());
    output.extend_from_slice(value);
    let padded_len = output
        .len()
        .checked_add(padding_len)
        .ok_or(FastCryptoError::InvalidInput)?;
    output.resize(padded_len, 0);
    Ok(())
}

pub(super) fn sha256_low_253(input: &[u8]) -> [u8; 32] {
    let mut digest: [u8; 32] = Sha256::digest(input).into();
    digest[0] &= 0x1f;
    digest
}

pub(super) fn hash_eph_public_key(eph_pk_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(eph_pk_bytes).into()
}
