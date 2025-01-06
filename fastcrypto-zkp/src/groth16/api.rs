// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use serde::de::DeserializeOwned;

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Pairing};
use fastcrypto::serde_helpers::{deserialize_vector, serialize_vector, ToFromByteArray};

use crate::groth16::{PreparedVerifyingKey, VerifyingKey};

/// Deserialize bytes as an Arkworks representation of a verifying key, and return a vector of the
/// four components of a prepared verified key (see more at [`PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes<
    G1,
    const G1_SIZE: usize,
    const G2_SIZE: usize,
    const GT_SIZE: usize,
    const FR_SIZE: usize,
>(
    vk_bytes: &[u8],
) -> FastCryptoResult<Vec<Vec<u8>>>
where
    G1: Pairing + ToFromByteArray<G1_SIZE>,
    <G1 as Pairing>::Other: ToFromByteArray<G2_SIZE>,
    <G1 as Pairing>::Output: GTSerialize<GT_SIZE>,
{
    let vk = VerifyingKey::<G1>::from_arkworks_format::<G1_SIZE, G2_SIZE>(vk_bytes)?;
    Ok(PreparedVerifyingKey::from(&vk).serialize_into_parts())
}

/// Verify Groth16 proof using the serialized form of the four components in a prepared verifying key
/// (see more at [`PreparedVerifyingKey`]), serialized proof public input, which should
/// be concatenated serialized field elements of the scalar field of [`crate::conversions::SCALAR_SIZE`]
/// bytes each in little-endian format, and serialized proof points.
pub fn verify_groth16_in_bytes<
    G1,
    const G1_SIZE: usize,
    const G2_SIZE: usize,
    const GT_SIZE: usize,
    const FR_SIZE: usize,
>(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError>
where
    G1: ToFromByteArray<G1_SIZE> + DeserializeOwned + MultiScalarMul + Pairing,
    <G1 as Pairing>::Other: ToFromByteArray<G2_SIZE> + DeserializeOwned,
    <G1 as Pairing>::Output: GroupElement + GTSerialize<GT_SIZE>,
    G1::ScalarType: FromLittleEndianByteArray<FR_SIZE>,
{
    let public_inputs = deserialize_vector(
        public_inputs_as_bytes,
        G1::ScalarType::from_little_endian_byte_array,
    )?;
    let proof =
        bcs::from_bytes(proof_points_as_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    let prepared_vk = PreparedVerifyingKey::<G1>::deserialize_from_parts(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    )?;
    Ok(prepared_vk.verify(&public_inputs, &proof).is_ok())
}

impl<G1: Pairing> VerifyingKey<G1> {
    pub fn from_arkworks_format<const G1_SIZE: usize, const G2_SIZE: usize>(
        bytes: &[u8],
    ) -> FastCryptoResult<Self>
    where
        G1: ToFromByteArray<G1_SIZE>,
        <G1 as Pairing>::Other: ToFromByteArray<G2_SIZE>,
    {
        // The verifying key consists of:
        // - alpha: G1
        // - beta: G2
        // - gamma: G2
        // - delta: G2
        // - n: u64 lendian (size of gamma_abc)
        // - gamma_abc: Vec<G1>

        // We can't use bcs because there, the length of the vector is prefixed as a single byte and
        // not a little-endian u64 as it is here.

        if bytes.len() < G1_SIZE + 3 * G2_SIZE + size_of::<u64>()
            || (bytes.len() - (G1_SIZE + 3 * G2_SIZE + size_of::<u64>())) % G1_SIZE != 0
        {
            return Err(FastCryptoError::InvalidInput);
        }

        let (alpha, bytes) = bytes.split_at(G1_SIZE);
        let alpha = G1::from_byte_array(alpha.try_into().expect("Length already checked"))?;

        let (beta, bytes) = bytes.split_at(G2_SIZE);
        let beta = G1::Other::from_byte_array(beta.try_into().expect("Length already checked"))?;

        let (gamma, bytes) = bytes.split_at(G2_SIZE);
        let gamma = G1::Other::from_byte_array(gamma.try_into().expect("Length already checked"))?;

        let (delta, bytes) = bytes.split_at(G2_SIZE);
        let delta = G1::Other::from_byte_array(delta.try_into().expect("Length already checked"))?;

        let (gamma_abc_length, bytes) = bytes.split_at(size_of::<u64>());
        let gamma_abc_length =
            u64::from_le_bytes(gamma_abc_length.try_into().expect("Length already checked"));

        // There must be at least one element in gamma_abc, since this should be equal to the number
        // of public inputs + 1.
        if gamma_abc_length == 0 {
            return Err(FastCryptoError::InvalidInput);
        }

        let gamma_abc = deserialize_vector(bytes, G1::from_byte_array)?;

        if gamma_abc.len() != gamma_abc_length as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(VerifyingKey {
            alpha,
            beta,
            gamma,
            delta,
            gamma_abc,
        })
    }
}

impl<G1: Pairing> PreparedVerifyingKey<G1> {
    pub fn serialize_into_parts<const G1_SIZE: usize, const G2_SIZE: usize, const GT_SIZE: usize>(
        &self,
    ) -> Vec<Vec<u8>>
    where
        G1: ToFromByteArray<G1_SIZE>,
        G1::Other: ToFromByteArray<G2_SIZE>,
        <G1 as Pairing>::Output: GTSerialize<GT_SIZE>,
    {
        vec![
            serialize_vector(&self.vk_gamma_abc, G1::to_byte_array),
            self.alpha_beta.to_arkworks_bytes().to_vec(),
            self.gamma_neg.to_byte_array().to_vec(),
            self.delta_neg.to_byte_array().to_vec(),
        ]
    }

    pub fn deserialize_from_parts<
        const G1_SIZE: usize,
        const G2_SIZE: usize,
        const GT_SIZE: usize,
    >(
        vk_gamma_abc_bytes: &[u8],
        alpha_beta_bytes: &[u8],
        gamma_neg_bytes: &[u8],
        delta_neg_bytes: &[u8],
    ) -> FastCryptoResult<Self>
    where
        G1: ToFromByteArray<G1_SIZE>,
        G1::Other: ToFromByteArray<G2_SIZE>,
        <G1 as Pairing>::Output: GTSerialize<GT_SIZE>,
    {
        let vk_gamma_abc =
            deserialize_vector::<G1_SIZE, G1>(vk_gamma_abc_bytes, G1::from_byte_array)?;

        let alpha_beta = <G1 as Pairing>::Output::from_arkworks_bytes(
            alpha_beta_bytes
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        let gamma_neg = <G1 as Pairing>::Other::from_byte_array(
            gamma_neg_bytes
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        let delta_neg = <G1 as Pairing>::Other::from_byte_array(
            delta_neg_bytes
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        Ok(Self {
            vk_gamma_abc,
            alpha_beta,
            gamma_neg,
            delta_neg,
        })
    }
}

/// Serialization of GT elements is typically not standardized across libraries, so implementations
/// must specify what implementation to use here to be compatible with the arkworks format (see
/// [`ark_ec::pairing::PairingOutput`]).
pub trait GTSerialize<const SIZE_IN_BYTES: usize>: Sized {
    /// Serialize the element into a byte array.
    fn to_arkworks_bytes(&self) -> [u8; SIZE_IN_BYTES];

    /// Deserialize the element from a byte array.
    fn from_arkworks_bytes(bytes: &[u8; SIZE_IN_BYTES]) -> FastCryptoResult<Self>;
}

/// Scalars given to the API are expected to be in little-endian format.
pub trait FromLittleEndianByteArray<const SIZE_IN_BYTES: usize>: Sized {
    fn from_little_endian_byte_array(bytes: &[u8; SIZE_IN_BYTES]) -> FastCryptoResult<Self>;
}
