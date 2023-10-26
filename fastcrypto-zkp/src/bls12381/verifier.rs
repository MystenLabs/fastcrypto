// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use std::borrow::Borrow;
use std::{iter, ops::Neg, ptr};

use ark_bls12_381::{Bls12_381, Fq12, Fr as BlsFr, G1Affine, G2Affine};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blst::{
    blst_final_exp, blst_fp, blst_fp12, blst_fr, blst_miller_loop, blst_p1, blst_p1_add_or_double,
    blst_p1_affine, blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine, blst_p1s_mult_pippenger,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_scalar, blst_scalar_from_fr, limb_t, Pairing,
};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::{error::FastCryptoError, utils::log2_byte};

use crate::bls12381::conversions::{
    bls_fq12_to_blst_fp12, bls_fr_to_blst_fr, bls_g1_affine_to_blst_g1_affine,
    bls_g2_affine_to_blst_g2_affine, blst_fp12_to_bls_fq12, G1_COMPRESSED_SIZE,
};
use crate::bls12381::{FieldElement, Proof, VerifyingKey};

#[cfg(test)]
#[path = "unit_tests/verifier_tests.rs"]
mod verifier_tests;

/// This is a helper function to store a pre-processed version of the verifying key.
/// This is roughly homologous to [`ark_groth16::data_structures::PreparedVerifyingKey`].
/// Note that contrary to Arkworks, we don't store a "prepared" version of the gamma_g2_neg_pc,
/// delta_g2_neg_pc fields, because we can't use them with blst's pairing engine and also because
/// they are very large and unpractical to use in the binary api.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedVerifyingKey {
    /// The element vk.gamma_abc_g1,
    /// aka the `[gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * G]`, where i spans the public inputs
    pub vk_gamma_abc_g1: Vec<G1Affine>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: blst_fp12,
    /// The element `- gamma * H` in `E::G2`, for use in pairings.
    pub gamma_g2_neg_pc: G2Affine,
    /// The element `- delta * H` in `E::G2`, for use in pairings.
    pub delta_g2_neg_pc: G2Affine,
}

impl PreparedVerifyingKey {
    /// Returns the validity of the Groth16 proof passed as argument. The format of the inputs is assumed to be in arkworks format.
    /// See [`multipairing_with_processed_vk`] for the actual pairing computation details.
    ///
    /// ## Example
    /// ```
    /// use fastcrypto_zkp::dummy_circuits::Fibonacci;
    /// use ark_bls12_381::{Bls12_381, Fr};
    /// use ark_ff::One;
    /// use ark_groth16::Groth16;
    /// use ark_std::rand::thread_rng;
    /// use blake2::digest::Mac;
    /// use fastcrypto_zkp::bls12381::FieldElement;
    /// use fastcrypto_zkp::bls12381::verifier::PreparedVerifyingKey;
    ///
    /// let mut rng = thread_rng();
    ///
    /// let params = {
    ///     let circuit = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1
    ///     Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap()
    /// };
    ///
    /// let proof = {
    ///     let circuit = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1
    ///     // Create a proof with our parameters, picking a random witness assignment
    ///     Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &params, &mut rng).unwrap()
    /// };
    ///
    /// // Prepare the verification key (for proof verification). Ideally, we would like to do this only
    /// // once per circuit.
    /// let pvk = PreparedVerifyingKey::from(&params.vk.into());
    ///
    /// // We provide the public inputs which we know are used in our circuits
    /// // this must be the same as the inputs used in the proof right above.
    /// let inputs: Vec<FieldElement> = [Fr::one().into(); 2].to_vec();
    ///
    /// // Verify the proof
    /// let r = pvk.verify(&inputs, &proof.into()).unwrap();
    /// ```
    pub fn verify(&self, x: &[FieldElement], proof: &Proof) -> Result<bool, FastCryptoError> {
        // Note the "+1" : this API implies the first scalar coefficient is 1 and not sent
        if (x.len() + 1) != self.vk_gamma_abc_g1.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let x: Vec<BlsFr> = x.iter().map(|x| x.0).collect();

        let res = multipairing_with_processed_vk(self, &x, &proof.0);
        Ok(res == self.alpha_g1_beta_g2)
    }

    /// Deserialize the prepared verifying key from the serialized fields of vk_gamma_abc_g1, alpha_g1_beta_g2, gamma_g2_neg_pc, delta_g2_neg_pc
    pub fn deserialize<V: Borrow<[u8]>>(bytes: &Vec<V>) -> Result<Self, FastCryptoError> {
        if bytes.len() != 4 {
            return Err(FastCryptoError::InputLengthWrong(bytes.len()));
        }

        let vk_gamma_abc_g1_bytes = bytes[0].borrow();
        if vk_gamma_abc_g1_bytes.len() % G1_COMPRESSED_SIZE != 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let mut vk_gamma_abc_g1: Vec<G1Affine> = Vec::new();
        for g1_bytes in vk_gamma_abc_g1_bytes.chunks(G1_COMPRESSED_SIZE) {
            let g1 = G1Affine::deserialize_compressed(g1_bytes)
                .map_err(|_| FastCryptoError::InvalidInput)?;
            vk_gamma_abc_g1.push(g1);
        }

        let alpha_g1_beta_g2 = bls_fq12_to_blst_fp12(
            &Fq12::deserialize_compressed(bytes[1].borrow())
                .map_err(|_| FastCryptoError::InvalidInput)?,
        );

        let gamma_g2_neg_pc = G2Affine::deserialize_compressed(bytes[2].borrow())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        let delta_g2_neg_pc = G2Affine::deserialize_compressed(bytes[3].borrow())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        Ok(PreparedVerifyingKey {
            vk_gamma_abc_g1,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        })
    }

    /// Serialize the prepared verifying key to its vectors form.
    pub fn serialize(&self) -> Result<Vec<Vec<u8>>, FastCryptoError> {
        let mut res = Vec::new();

        let mut vk_gamma = Vec::new();
        for g1 in &self.vk_gamma_abc_g1 {
            let mut g1_bytes = Vec::new();
            g1.serialize_compressed(&mut g1_bytes)
                .map_err(|_| FastCryptoError::InvalidInput)?;
            vk_gamma.append(&mut g1_bytes);
        }
        res.push(vk_gamma);

        let mut fq12 = Vec::new();
        blst_fp12_to_bls_fq12(&self.alpha_g1_beta_g2)
            .serialize_compressed(&mut fq12)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        res.push(fq12);

        let mut gamma_bytes = Vec::new();
        self.gamma_g2_neg_pc
            .serialize_compressed(&mut gamma_bytes)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        res.push(gamma_bytes);

        let mut delta_bytes = Vec::new();
        self.delta_g2_neg_pc
            .serialize_compressed(&mut delta_bytes)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        res.push(delta_bytes);
        Ok(res)
    }
}

impl From<&VerifyingKey> for PreparedVerifyingKey {
    /// Takes an input [`ark_groth16::VerifyingKey`] `vk` and returns a `PreparedVerifyingKey`. This is roughly homologous to
    /// [`ark_groth16::PreparedVerifyingKey::process_vk`], but uses a blst representation of the elements.
    ///
    /// ## Example:
    /// ```
    /// use fastcrypto_zkp::{dummy_circuits::Fibonacci};
    /// use ark_bls12_381::{Bls12_381, Fr};
    /// use ark_ff::One;
    /// use ark_groth16::Groth16;
    /// use ark_std::rand::thread_rng;
    /// use fastcrypto_zkp::bls12381::verifier::PreparedVerifyingKey;
    ///
    /// let mut rng = thread_rng();
    /// let params = {
    ///     let c = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1 (standard Fibonacci)
    ///     Groth16::<Bls12_381>::generate_random_parameters_with_reduction(c, &mut rng).unwrap()
    /// };
    ///
    /// // Prepare the verification key (for proof verification). Ideally, we would like to do this only
    /// // once per circuit.
    /// let pvk = PreparedVerifyingKey::from(&params.vk.into());
    /// ```
    fn from(vk: &VerifyingKey) -> Self {
        let g1_alpha = bls_g1_affine_to_blst_g1_affine(&vk.0.alpha_g1);
        let g2_beta = bls_g2_affine_to_blst_g2_affine(&vk.0.beta_g2);
        let blst_alpha_g1_beta_g2 = {
            let mut tmp = blst_fp12::default();
            unsafe { blst_miller_loop(&mut tmp, &g2_beta, &g1_alpha) };

            let mut out = blst_fp12::default();
            unsafe { blst_final_exp(&mut out, &tmp) };
            out
        };
        PreparedVerifyingKey {
            vk_gamma_abc_g1: vk.0.gamma_abc_g1.clone(),
            alpha_g1_beta_g2: blst_alpha_g1_beta_g2,
            gamma_g2_neg_pc: vk.0.gamma_g2.neg(),
            delta_g2_neg_pc: vk.0.delta_g2.neg(),
        }
    }
}

impl VerifyingKey {
    /// Deserialize a serialized Groth16 verifying key in compressed format using arkworks' canonical serialisation format: https://docs.rs/ark-serialize/latest/ark_serialize/.
    pub fn deserialize(bytes: &[u8]) -> FastCryptoResult<Self> {
        ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map(VerifyingKey)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

/// This helper constant makes it easier to use compute the linear combination involved in the pairing inputs.
const G1_IDENTITY: blst_p1 = blst_p1 {
    x: blst_fp { l: [0; 6] },
    y: blst_fp { l: [0; 6] },
    z: blst_fp { l: [0; 6] },
};

/// Returns a single scalar multiplication of `pt` by `b`.
fn mul(pt: &blst_p1, b: &blst_fr) -> blst_p1 {
    let mut scalar: blst_scalar = blst_scalar::default();
    unsafe {
        blst_scalar_from_fr(&mut scalar, b);
    }

    // Count the number of bytes to be multiplied.
    let mut i = scalar.b.len();
    while i != 0 && scalar.b[i - 1] == 0 {
        i -= 1;
    }

    let mut result = blst_p1::default();
    if i == 0 {
        return G1_IDENTITY;
    } else if i == 1 && scalar.b[0] == 1 {
        return *pt;
    } else {
        // Count the number of bits to be multiplied.
        unsafe {
            blst_p1_mult(
                &mut result,
                pt,
                &(scalar.b[0]),
                8 * i - 7 + log2_byte(scalar.b[i - 1]),
            );
        }
    }
    result
}

/// Facade for the blst_p1_add_or_double function.
fn add_or_dbl(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    let mut ret = blst_p1::default();
    unsafe {
        blst_p1_add_or_double(&mut ret, a, b);
    }
    ret
}

/// Computes the [\sum p_i * b_i, p_i in p_affine, b_i in coeffs] in G1.
fn g1_linear_combination(
    out: &mut blst_p1,
    p_affine: &[blst_p1_affine],
    coeffs: &[blst_fr],
    len: usize,
) {
    if len < 8 {
        // Direct approach
        let mut tmp;
        *out = G1_IDENTITY;
        for i in 0..len {
            let mut p = blst_p1::default();
            unsafe { blst_p1_from_affine(&mut p, &p_affine[i]) };

            tmp = mul(&p, &coeffs[i]);
            *out = add_or_dbl(out, &tmp);
        }
    } else {
        let mut scratch: Vec<u8>;
        unsafe {
            scratch = vec![0u8; blst_p1s_mult_pippenger_scratch_sizeof(len)];
        }

        let mut scalars = vec![blst_scalar::default(); len];

        for i in 0..len {
            let mut scalar: blst_scalar = blst_scalar::default();
            unsafe {
                blst_scalar_from_fr(&mut scalar, &coeffs[i]);
            }
            scalars[i] = scalar
        }

        let scalars_arg: [*const blst_scalar; 2] = [scalars.as_ptr(), ptr::null()];
        let points_arg: [*const blst_p1_affine; 2] = [p_affine.as_ptr(), ptr::null()];
        unsafe {
            blst_p1s_mult_pippenger(
                out,
                points_arg.as_ptr(),
                len,
                scalars_arg.as_ptr() as *const *const u8,
                256,
                scratch.as_mut_ptr() as *mut limb_t,
            );
        }
    }
}

/// This represents the multiplicative unit scalar, see fr_one_test
pub(crate) const BLST_FR_ONE: blst_fr = blst_fr {
    l: [
        8589934590,
        6378425256633387010,
        11064306276430008309,
        1739710354780652911,
    ],
};

/// Returns the result of the multi-pairing involved in the verification equation. This will then be compared to the pre-computed term
/// pvk.alpha_g1_beta_g2 to check the validity of the proof.
///
/// The textbook Groth16 equation is (in additive notation):
/// e(A, B) = e(g * alpha, h * beta) + e(g * f, h * gamma) + e(C, h * delta)
/// where f is the linear combination of the a_i points in the verifying key with the input scalars
///
/// Due to the pre-processing of e(g * alpha, h * beta), and using the pairing inverse, we instead compute:
/// e(A, B) + e(g * f, h * - gamma) + e(C, h * - delta).
///
/// Eventually, we will compare this value to  e(g * alpha, h * beta)
///
fn multipairing_with_processed_vk(
    pvk: &PreparedVerifyingKey,
    x: &[BlsFr],
    proof: &ark_groth16::Proof<Bls12_381>,
) -> blst_fp12 {
    // Linear combination: note that the arkworks interface assumes the 1st scalar is an implicit 1
    let pts: Vec<blst_p1_affine> = pvk
        .vk_gamma_abc_g1
        .iter()
        .map(bls_g1_affine_to_blst_g1_affine)
        .collect();
    let one = BLST_FR_ONE;
    let ss: Vec<blst_fr> = iter::once(one)
        .chain(x.iter().map(bls_fr_to_blst_fr))
        .collect();
    let mut out = blst_p1::default();
    g1_linear_combination(&mut out, &pts, &ss[..], ss.len());

    let blst_proof_a = bls_g1_affine_to_blst_g1_affine(&proof.a);
    let blst_proof_b = bls_g2_affine_to_blst_g2_affine(&proof.b);

    let mut blst_proof_1_g1 = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut blst_proof_1_g1, &out) };
    let blst_proof_1_g2 = bls_g2_affine_to_blst_g2_affine(&pvk.gamma_g2_neg_pc);

    let blst_proof_2_g1 = bls_g1_affine_to_blst_g1_affine(&proof.c);
    let blst_proof_2_g2 = bls_g2_affine_to_blst_g2_affine(&pvk.delta_g2_neg_pc);

    let dst = [0u8; 3];
    let mut pairing_blst = Pairing::new(false, &dst);
    pairing_blst.raw_aggregate(&blst_proof_b, &blst_proof_a);
    pairing_blst.raw_aggregate(&blst_proof_1_g2, &blst_proof_1_g1);
    pairing_blst.raw_aggregate(&blst_proof_2_g2, &blst_proof_2_g1);
    pairing_blst.as_fp12().final_exp()
}

#[cfg(test)]
mod tests {
    use crate::bls12381::verifier::PreparedVerifyingKey;
    use crate::bls12381::VerifyingKey;
    use crate::dummy_circuits::DummyCircuit;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_serialization() {
        const PUBLIC_SIZE: usize = 128;
        let rng = &mut thread_rng();
        let c = DummyCircuit::<Fr> {
            a: Some(<Fr>::rand(rng)),
            b: Some(<Fr>::rand(rng)),
            num_variables: PUBLIC_SIZE,
            num_constraints: 10,
        };
        let (_, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
        let pvk = PreparedVerifyingKey::from(&VerifyingKey(vk));

        let serialized = pvk.serialize().unwrap();
        let deserialized = PreparedVerifyingKey::deserialize(&serialized).unwrap();
        assert_eq!(pvk, deserialized);
    }
}
