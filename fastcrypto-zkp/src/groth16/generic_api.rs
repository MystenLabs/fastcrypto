// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, Pairing};
use fastcrypto::serde_helpers::{deserialize_vector, serialize_vector, ToFromByteArray};

use crate::groth16::{PreparedVerifyingKey, VerifyingKey};

/// Deserialize bytes as an Arkworks representation of a verifying key, and return a vector of the
/// four components of a prepared verified key (see more at [`PreparedVerifyingKey`]).
pub(crate) fn prepare_pvk_bytes<
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
    <G1 as Pairing>::Output: ToFromByteArray<GT_SIZE>,
{
    let vk = VerifyingKey::<G1>::from_arkworks_format::<G1_SIZE, G2_SIZE>(vk_bytes)?;
    Ok(PreparedVerifyingKey::from(&vk).serialize_into_parts())
}

/// Verify Groth16 proof using the serialized form of the four components in a prepared verifying key
/// (see more at [`PreparedVerifyingKey`]), serialized proof public input, which should
/// be concatenated serialized field elements of the scalar field of [`crate::conversions::SCALAR_SIZE`]
/// bytes each, and serialized proof points.
pub(crate) fn verify_groth16_in_bytes<
    G1: Pairing,
    const G1_SIZE: usize,
    const G2_SIZE: usize,
    const GT_SIZE: usize,
    const FR_SIZE: usize,
>(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError>
where
    G1: ToFromByteArray<G1_SIZE> + DeserializeOwned,
    <G1 as Pairing>::Other: ToFromByteArray<G2_SIZE> + DeserializeOwned,
    <G1 as Pairing>::Output: GroupElement + ToFromByteArray<GT_SIZE>,
    G1::ScalarType: ToFromByteArray<FR_SIZE>,
{
    let x = deserialize_vector::<FR_SIZE, G1::ScalarType>(proof_public_inputs_as_bytes)?;
    let proof =
        bcs::from_bytes(proof_points_as_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    let prepared_vk = PreparedVerifyingKey::<G1>::deserialize_from_parts(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    )?;
    Ok(prepared_vk.verify(&x, &proof).is_ok())
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

        // We can't use bincode because there, the length of the vector is prefixed as a single byte
        // and not a lendian u64.

        if (bytes.len() - (G1_SIZE + 3 * G2_SIZE + 8)) % G1_SIZE != 0 {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut i = 0;

        let alpha = G1::from_byte_array(
            bytes[i..G1_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;
        i += G1_SIZE;

        let beta = G1::Other::from_byte_array(
            bytes[i..i + G2_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;
        i += G2_SIZE;

        let gamma = G1::Other::from_byte_array(
            bytes[i..i + G2_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;
        i += G2_SIZE;

        let delta = G1::Other::from_byte_array(
            bytes[i..i + G2_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;
        i += G2_SIZE;

        let n = u64::from_le_bytes(
            bytes[i..i + 8]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        );
        // There must be at least one element in gamma_abc, since this should be equal to the number
        // of public inputs + 1.
        if n == 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        i += 8;

        let gamma_abc = deserialize_vector::<G1_SIZE, G1>(&bytes[i..])
            .map_err(|_| FastCryptoError::InvalidInput)?;

        if gamma_abc.len() != n as usize {
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
        <G1 as Pairing>::Output: ToFromByteArray<GT_SIZE>,
    {
        vec![
            serialize_vector(&self.vk_gamma_abc),
            self.alpha_beta.to_byte_array().to_vec(),
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
        <G1 as Pairing>::Output: ToFromByteArray<GT_SIZE>,
    {
        if vk_gamma_abc_bytes.len() % G1_SIZE != 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let vk_gamma_abc = deserialize_vector::<G1_SIZE, G1>(vk_gamma_abc_bytes)?;

        let alpha_beta = <G1 as Pairing>::Output::from_byte_array(
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
