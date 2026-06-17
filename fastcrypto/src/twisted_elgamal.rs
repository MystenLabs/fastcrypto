// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bulletproofs::{Range, RangeProof};
use crate::error::FastCryptoError::{InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar, RISTRETTO_POINT_BYTE_LENGTH};
use crate::groups::{Doubling, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use crate::pedersen::{Blinding, PedersenCommitment, G, H};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use derive_more::{Add, Mul, Sub};
use itertools::{iterate, Itertools};
use serde::{Deserialize, Serialize};
use std::array::from_fn;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKey(RistrettoScalar);

#[derive(Debug, Clone, Add, Sub, Mul, Serialize, Deserialize)]
pub struct Ciphertext {
    commitment: PedersenCommitment,
    decryption_handle: RistrettoPoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiRecipientCiphertext {
    commitment: PedersenCommitment,
    decryption_handles: Vec<RistrettoPoint>,
}

/// A verifiable key encapsulation verifiably encrypts a private key to multiple recipients.
/// A batch range proof shows that each 32-bit limb of the private key lies in the range [0, 2^32-1].
/// A key consistency proof shows that the 32-bit key limbs have been encrypted to the correct recipient public keys
/// and that they correspond to the provided sender public key.
pub struct VerifiableKeyEncapsulation<const N: usize> {
    pub ciphertexts: [MultiRecipientCiphertext; N],
    pub range_proof: RangeProof,
    pub consistency_proof: KeyConsistencyProof<N>,
}

/// A sigma protocol proof that `N` Twisted ElGamal ciphertexts encrypt the 32-bit limbs of a
/// private key whose corresponding public key is known. Concretely, for each limb `i` and
/// recipient `j` it proves: (1) the decryption handle `D_ij = r_i * S_j` was formed with the
/// same blinding `r_i` used in the Pedersen commitment `C_i = r_i * G + u_i * H`, and (2) the
/// same limb values `u_i` that open those commitments reconstruct to the private key, i.e.
/// `(\sum_i u_i * 2^{32i}) * G == U` where `U` is the sender's public key. Crucially, the proof
/// binds (1) and (2) together, so the verifier is assured that the values inside the commitments
/// are exactly the limbs of the private key for `U`. The proof is made non-interactive via the
/// Fiat-Shamir transform and supports multiple recipients sharing the same commitment per limb.
pub struct KeyConsistencyProof<const N: usize> {
    a1: Vec<RistrettoPoint>,
    a2: [RistrettoPoint; N],
    a3: RistrettoPoint,
    z1: [RistrettoScalar; N],
    z2: [RistrettoScalar; N],
}

/// Sigma protocol that a Twisted ElGamal ciphertext is a valid encryption of some message (without revealing the message).
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsistencyProof {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    z1: RistrettoScalar,
    z2: RistrettoScalar,
}

pub fn generate_keypair(rng: &mut impl AllowedRng) -> (PublicKey, PrivateKey) {
    let sk = PrivateKey(RistrettoScalar::rand(rng));
    (PublicKey::from(&sk), sk)
}

impl From<&PrivateKey> for PublicKey {
    fn from(sk: &PrivateKey) -> Self {
        PublicKey(*G * sk.0)
    }
}

impl Ciphertext {
    pub fn encrypt(
        encryption_key: &PublicKey,
        message: u32,
        rng: &mut impl AllowedRng,
    ) -> (Self, Blinding) {
        let blinding = Blinding::rand(rng);
        (
            Self {
                decryption_handle: encryption_key.0 * blinding.0,
                commitment: PedersenCommitment::new(
                    &RistrettoScalar::from(message as u64),
                    &blinding,
                ),
            },
            blinding,
        )
    }

    pub fn encrypt_with_consistency_proof(
        encryption_key: &PublicKey,
        message: u32,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, Blinding, ConsistencyProof)> {
        let (ciphertext, blinding) = Self::encrypt(encryption_key, message, rng);
        let proof = ConsistencyProof::prove(
            &RistrettoScalar::from(message as u64),
            &ciphertext,
            &blinding,
            encryption_key,
            dst,
            rng,
        )?;
        Ok((ciphertext, blinding, proof))
    }

    pub fn decrypt(
        &self,
        private_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
    ) -> FastCryptoResult<u32> {
        let mut c = self.commitment.0 - (self.decryption_handle / private_key.0)?;
        for x_low in 0..1 << 16 {
            if let Some(&x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + ((x_high as u32) << 16));
            }
            c -= *H;
        }
        Err(InvalidInput)
    }
}

impl ConsistencyProof {
    pub fn prove(
        message: &RistrettoScalar,
        ciphertext: &Ciphertext,
        blinding: &Blinding,
        encryption_key: &PublicKey,
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Self> {
        let r1 = RistrettoScalar::rand(rng);
        let r2 = RistrettoScalar::rand(rng);
        let a1 = encryption_key.0 * r1;
        let a2 = RistrettoPoint::multi_scalar_mul(&[r1, r2], &[*G, *H]).expect("Constant length");

        let c = Self::challenge(&a1, &a2, ciphertext, encryption_key, dst);
        let z1 = r1 + c * blinding.0;
        let z2 = r2 + c * message;

        Ok(Self { a1, a2, z1, z2 })
    }

    pub fn verify(
        &self,
        ciphertext: &Ciphertext,
        encryption_key: &PublicKey,
        dst: &[u8],
    ) -> FastCryptoResult<()> {
        let c = Self::challenge(&self.a1, &self.a2, ciphertext, encryption_key, dst);
        if self.a1
            != RistrettoPoint::multi_scalar_mul(
                &[-c, self.z1],
                &[ciphertext.decryption_handle, encryption_key.0],
            )
            .expect("Constant lengths")
            || self.a2
                != RistrettoPoint::multi_scalar_mul(
                    &[-c, self.z1, self.z2],
                    &[ciphertext.commitment.0, *G, *H],
                )
                .expect("Constant lengths")
        {
            return Err(InvalidProof);
        }
        Ok(())
    }

    fn challenge(
        a1: &RistrettoPoint,
        a2: &RistrettoPoint,
        ciphertext: &Ciphertext,
        encryption_key: &PublicKey,
        dst: &[u8],
    ) -> RistrettoScalar {
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&vec![
                dst.to_vec(),
                G.to_byte_array().to_vec(),
                H.to_byte_array().to_vec(),
                encryption_key.0.to_byte_array().to_vec(),
                ciphertext.commitment.0.to_byte_array().to_vec(),
                ciphertext.decryption_handle.to_byte_array().to_vec(),
                a1.to_byte_array().to_vec(),
                a2.to_byte_array().to_vec(),
            ])
            .expect("Serialization succeeds"),
        )
    }
}

impl MultiRecipientCiphertext {
    // Encrypt a 32-bit ciphertext to multiple recipients where the decryption handles share the same blinding factor.
    pub fn encrypt(
        encryption_keys: &[PublicKey],
        message: u32,
        rng: &mut impl AllowedRng,
    ) -> (Self, Blinding) {
        let blinding = Blinding::rand(rng);
        (
            Self {
                decryption_handles: encryption_keys.iter().map(|pk| pk.0 * blinding.0).collect(),
                commitment: PedersenCommitment::new(
                    &RistrettoScalar::from(message as u64),
                    &blinding,
                ),
            },
            blinding,
        )
    }

    /// Decrypt the ciphertext of a single recipient identified by the provided index.
    pub fn decrypt(
        &self,
        index: usize,
        decryption_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
    ) -> FastCryptoResult<u32> {
        self.ciphertext(index)?.decrypt(decryption_key, table)
    }

    pub fn ciphertext(&self, index: usize) -> FastCryptoResult<Ciphertext> {
        if index >= self.decryption_handles.len() {
            return Err(InvalidInput);
        }
        Ok(Ciphertext {
            commitment: self.commitment.clone(),
            decryption_handle: self.decryption_handles[index],
        })
    }
}

impl<const N: usize> KeyConsistencyProof<N> {
    pub fn prove(
        sender_private_key_limbs: &[u32; N],
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        ciphertexts: &[MultiRecipientCiphertext; N],
        blindings: &[Blinding; N],
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> Self {
        // Sample N random a_i and b_i
        let a: [_; N] = from_fn(|_| RistrettoScalar::rand(rng));
        let b: [_; N] = from_fn(|_| RistrettoScalar::rand(rng));

        // A_1ij = a_i * pk_j for all (i, j) — N*m elements, ordered by limb then recipient
        let a1 = a
            .iter()
            .flat_map(|ai| recipient_encryption_keys.iter().map(move |pk| pk.0 * ai))
            .collect_vec();

        // A_2i = a_i * G + b_i * H for all i
        let a2 = from_fn(|i| *G * a[i] + *H * b[i]);

        // A_3i = b_i * G for all i
        let a3_per_limb: [RistrettoPoint; N] = from_fn(|i| *G * b[i]);
        // Aggregate `A_3 = \sum_i A_3i * 2^{32i}` (equivalent to `(\sum_i b_i * 2^{32i}) * G`).
        let base = RistrettoScalar::from(1u64 << 32);
        let a3 = RistrettoPoint::multi_scalar_mul(
            &iterate(RistrettoScalar::generator(), |e| e * base)
                .take(N)
                .collect_vec(),
            &a3_per_limb,
        )
        .expect("Consistent lengths");

        // c = Hash(dst, sender_public_key, recipient_encryption_keys, ciphertexts, a1, a2, a3)
        let c = Self::challenge(
            sender_public_key,
            recipient_encryption_keys,
            ciphertexts,
            &a1,
            &a2,
            &a3,
            dst,
        );

        // z_1i = a_i + c * r_i
        let z1 = from_fn(|i| a[i] + c * blindings[i].0);

        // z_2i = b_i + c * u_i
        let z2 = from_fn(|i| b[i] + c * RistrettoScalar::from(sender_private_key_limbs[i] as u64));

        Self { a1, a2, a3, z1, z2 }
    }

    /// Verify checks the provided consistency proof. To do so, it batches all three groups of verification equations
    /// into a single MSM using random scalars. The three groups of equations that must hold for a valid proof are:
    ///
    ///   Check 1 (decryption handle consistency): Verifies that each decryption handle was formed with the same
    ///   blinding r_i as the commitment via
    ///     A1_ij + c * D_ij == z_1i * S_j
    ///   for all limbs i and recipients j where D_ij = r_i * S_j is the decryption handle and S_j is recipient j's public key.
    ///   Combined equations using scalars mu_ij derived from the random batching value r:
    ///     \sum_j (\sum_i mu_ij * z_1i) * S_j - \sum_{i,j} mu_ij * A1_ij - \sum_{i,j} (c * mu_ij) * D_ij == 0
    ///
    ///   Check 2 (commitment consistency): Verifies knowledge of the blinding r_i and message u_i opening the
    ///   commitment via
    ///     A2_i + c * C_i == z_1i * G + z_2i * H
    ///   for all limbs i where C_i = r_i * G + u_i * H is the Pedersen commitment.
    ///   Combined equations using scalars rho_i derived from the random batching value r:
    ///     (\sum_i rho_i * z_1i) * G + (\sum_i rho_i * z_2i) * H - \sum_i rho_i * A2_i - \sum_i (c * rho_i) * C_i == 0
    ///
    ///   Check 3 (public key consistency): Verifies that the encrypted 32-bit key limbs u_i reconstruct to the
    ///   private key corresponding to U via
    ///     (\sum_i z_2i * 2^{32i}) * G == (\sum_i A3_i * 2^{32i}) + c * U
    ///   where U is the sender's public key.
    ///
    ///   We combine the individual checks as
    ///     (check 1) + alpha * (check 2) + beta * (check 3) == 0
    ///   using outer scalars alpha and beta derived from the random batching value r to ensure soundness.
    ///
    /// Here `c` is the Fiat-Shamir challenge binding the proof, while the batching scalars
    /// (mu, rho, alpha, beta) are expanded from a fresh random value `r` sampled from `rng`. Since
    /// `r` is drawn by the verifier after the proof is fixed, the prover cannot predict the batching
    /// scalars, so a malformed proof passes the combined MSM only with negligible probability.
    pub fn verify(
        &self,
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        ciphertexts: &[MultiRecipientCiphertext; N],
        dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        // Fiat-Shamir challenge binding the proof
        let c = Self::challenge(
            sender_public_key,
            recipient_encryption_keys,
            ciphertexts,
            &self.a1,
            &self.a2,
            &self.a3,
            dst,
        );

        // Fresh random value used only to expand the batching scalars below. Sampling it here (after
        // the proof is fixed) keeps the batching coefficients unpredictable to the prover.
        let r = RistrettoScalar::rand(rng);

        // Number of recipients
        let m = recipient_encryption_keys.len();

        // Compute inner scalars mu_ij from the random batching value r for all i and j used in check 1
        let mu: Vec<RistrettoScalar> = (0..N)
            .flat_map(|i| (0..m).map(move |j| batching_coefficient(b"mu", &r, &[i, j])))
            .collect();

        // Compute inner scalars rho_i from the random batching value r for all i used in check 2
        let rho: [RistrettoScalar; N] = from_fn(|i| batching_coefficient(b"rho", &r, &[i]));

        // Compute outer scalars alpha and beta from the random batching value r, combining the three zero-expressions:
        //   (check 1) + alpha * (check 2) + beta * (check 3) == 0
        let alpha = batching_coefficient(b"alpha", &r, &[]);
        let beta = batching_coefficient(b"beta", &r, &[]);

        // Check 2: compute sum_i(rho_i * z_1i) and sum_i(rho_i * z_2i)
        let rho_z1 = RistrettoScalar::inner_product(rho, self.z1);
        let rho_z2 = RistrettoScalar::inner_product(rho, self.z2);

        // Check 3: compute z = \sum_i z_2i * 2^{32i}
        let b = RistrettoScalar::from(1u64 << 32);
        let z = RistrettoScalar::inner_product(
            iterate(RistrettoScalar::generator(), |e| e * b),
            self.z2,
        );

        let mut scalars: Vec<RistrettoScalar> = vec![alpha * rho_z1 + beta * z, alpha * rho_z2];
        let mut points: Vec<RistrettoPoint> = vec![*G, *H];

        // Check 1: Append (\sum_i mu_ij * z_1i, S_j) terms for each recipient j
        for j in 0..m {
            scalars.push(RistrettoScalar::inner_product(
                (0..N).map(|i| mu[i * m + j]),
                self.z1,
            ));
            points.push(recipient_encryption_keys[j].0);
        }

        // Check 1: Append (-mu_ij, A1_ij) and (-c * mu_ij, D_ij) terms
        for (i, (a1_chunk, ci)) in self.a1.chunks(m).zip(ciphertexts).enumerate() {
            for (j, (a1ij, dij)) in a1_chunk.iter().zip(&ci.decryption_handles).enumerate() {
                scalars.push(-mu[i * m + j]);
                points.push(*a1ij);
                scalars.push(-(c * mu[i * m + j]));
                points.push(*dij);
            }
        }

        // Check 2: Append (-alpha * rho_i, A2_i) and (-c * alpha * rho_i, C_i) terms
        for ((rhoi, a2i), ci) in rho.iter().zip(self.a2).zip(ciphertexts) {
            scalars.push(-(alpha * *rhoi));
            points.push(a2i);
            scalars.push(-(c * alpha * *rhoi));
            points.push(ci.commitment.0);
        }

        // Check 3: Append (-beta * c, U) and (-beta, A3) terms (a3 is the aggregate mask).
        scalars.push(-(beta * c));
        points.push(sender_public_key.0);
        scalars.push(-beta);
        points.push(self.a3);

        if RistrettoPoint::multi_scalar_mul(&scalars, &points).expect("Consistent lengths")
            != RistrettoPoint::zero()
        {
            return Err(InvalidProof);
        }

        Ok(())
    }

    /// Fiat-Shamir challenge over the proof's public inputs, matching Contra's Move/TS
    /// `contra::key_consistency_proof::challenge_key_consistency`.
    fn challenge(
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        ciphertexts: &[MultiRecipientCiphertext; N],
        a1: &[RistrettoPoint],
        a2: &[RistrettoPoint],
        a3: &RistrettoPoint,
        dst: &[u8],
    ) -> RistrettoScalar {
        let chunks: Vec<Vec<u8>> = std::iter::once(dst.to_vec())
            .chain(std::iter::once(G.to_byte_array().to_vec()))
            .chain(std::iter::once(H.to_byte_array().to_vec()))
            .chain(std::iter::once(
                sender_public_key.0.to_byte_array().to_vec(),
            ))
            .chain(
                recipient_encryption_keys
                    .iter()
                    .map(|pk| pk.0.to_byte_array().to_vec()),
            )
            .chain(ciphertexts.iter().flat_map(|ct| {
                std::iter::once(ct.commitment.0.to_byte_array().to_vec()).chain(
                    ct.decryption_handles
                        .iter()
                        .map(|dh| dh.to_byte_array().to_vec()),
                )
            }))
            .chain(a1.iter().map(|p| p.to_byte_array().to_vec()))
            .chain(a2.iter().map(|p| p.to_byte_array().to_vec()))
            .chain(std::iter::once(a3.to_byte_array().to_vec()))
            .collect();
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&chunks).expect("Serialization succeeds"),
        )
    }
}

impl<const N: usize> VerifiableKeyEncapsulation<N> {
    /// Verifiably encrypt a private key to multiple recipient public keys.
    pub fn batch_seal(
        sender_private_key: &PrivateKey,
        recipient_encryption_keys: &[PublicKey],
        range_proof_dst: &[u8],
        consistency_proof_dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation<N> {
        // Re-arrange private key into N 32-bit limbs
        let limbs: [u32; N] = sender_private_key
            .0
            .to_byte_array()
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap();

        // Encrypt all N 32-bit key limbs with Twisted ElGamal to the recipient public keys
        let (ciphertexts, blindings): (Vec<_>, Vec<_>) = limbs
            .iter()
            .map(|&li| MultiRecipientCiphertext::encrypt(recipient_encryption_keys, li, rng))
            .unzip();
        let ciphertexts: [MultiRecipientCiphertext; N] = ciphertexts.try_into().unwrap();

        // Create range proof
        let range_proof = RangeProof::prove_batch(
            &limbs.map(|m| m as u64),
            &blindings,
            &Range::Bits32,
            range_proof_dst,
            rng,
        )
        .unwrap();

        // Create consistency proof
        let consistency_proof = KeyConsistencyProof::prove(
            &limbs,
            &PublicKey::from(sender_private_key),
            recipient_encryption_keys,
            &ciphertexts,
            &blindings.try_into().unwrap(),
            consistency_proof_dst,
            rng,
        );

        VerifiableKeyEncapsulation {
            ciphertexts,
            range_proof,
            consistency_proof,
        }
    }

    /// Verifiably encrypt a private key to a single recipient public key.
    pub fn seal(
        sender_private_key: &PrivateKey,
        recipient_encryption_key: &PublicKey,
        range_proof_dst: &[u8],
        consistency_proof_dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation<N> {
        Self::batch_seal(
            sender_private_key,
            std::slice::from_ref(recipient_encryption_key),
            range_proof_dst,
            consistency_proof_dst,
            rng,
        )
    }

    /// Verify the key consistency proofs.
    pub fn verify(
        &self,
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        range_proof_dst: &[u8],
        consistency_proof_dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        // Verify range proof over the Pedersen commitments of all limb ciphertexts
        let commitments = self
            .ciphertexts
            .iter()
            .map(|c| c.commitment.clone())
            .collect::<Vec<_>>();
        self.range_proof
            .verify_batch(&commitments, &Range::Bits32, range_proof_dst, rng)?;
        self.consistency_proof.verify(
            sender_public_key,
            recipient_encryption_keys,
            &self.ciphertexts,
            consistency_proof_dst,
            rng,
        )
    }

    /// Open the key encapsulation for a single recipient decryption key identified by the provided index using the
    /// provided 16-bit discrete log decryption table. All recipient public keys must be provided to verify the
    /// consistency proof, which is bound to the full set of recipients.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        index: usize,
        recipient_decryption_key: &PrivateKey,
        recipient_public_keys: &[PublicKey],
        sender_public_key: &PublicKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        range_proof_dst: &[u8],
        consistency_proof_dst: &[u8],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<PrivateKey> {
        // Verify consistency proofs against all recipient keys
        self.verify(
            sender_public_key,
            recipient_public_keys,
            range_proof_dst,
            consistency_proof_dst,
            rng,
        )?;

        // Decrypt each limb ciphertext using the recipient's decryption key
        let limbs = self
            .ciphertexts
            .iter()
            .map(|c| c.decrypt(index, recipient_decryption_key, table))
            .collect::<FastCryptoResult<Vec<_>>>()?;

        // Reconstruct the private key from its 32-bit limbs
        let private_key_bytes = limbs.iter().flat_map(|l| l.to_le_bytes()).collect_vec();
        let private_key = RistrettoScalar::from_byte_array(&private_key_bytes.try_into().unwrap())?;

        // Verify the recovered key corresponds to the sender's public key
        if PublicKey::from(&PrivateKey(private_key)) != *sender_public_key {
            return Err(InvalidInput);
        }
        Ok(PrivateKey(private_key))
    }
}

/// Precompute discrete log table for use in decryption. This only needs to be computed once.
///
/// The table contains a mapping from Ristretto points <i>(2<sup>16</sup> x) G<i> to <i>x</i> for all <i>x</i> in the range <i>0, .., 2<sup>16</sup>-1</i>.
pub fn precompute_table() -> HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16> {
    let step = H.repeated_doubling(16);
    iterate(RistrettoPoint::zero(), |p| p + step)
        .enumerate()
        .map(|(i, p)| (p.to_byte_array(), i as u16))
        .take(1 << 16)
        .collect()
}

/// Expand the verifier's random value `r` into a batching coefficient for the given `label` and
/// (optional) indices. Verifier-internal; not part of the proof.
fn batching_coefficient(label: &[u8], r: &RistrettoScalar, indices: &[usize]) -> RistrettoScalar {
    RistrettoScalar::fiat_shamir_reduction_to_group_element(
        &bcs::to_bytes(&vec![
            label.to_vec(),
            bcs::to_bytes(&(r, indices)).expect("Serialization succeeds"),
        ])
        .expect("Serialization succeeds"),
    )
}

#[test]
fn test_round_trip() {
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let message = 1234567890u32;
    let (ciphertext, _) = Ciphertext::encrypt(&pk, message, &mut rand::thread_rng());

    // This table can be reused, so it only has to be computed once
    let table = precompute_table();
    assert_eq!(ciphertext.decrypt(&sk, &table).unwrap(), message);
}

#[test]
fn test_round_trip_with_consistency_proof() {
    let dst = b"test";
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let message = 1234567890u32;
    let (ciphertext, _, proof) =
        Ciphertext::encrypt_with_consistency_proof(&pk, message, dst, &mut rand::thread_rng())
            .unwrap();
    assert!(proof.verify(&ciphertext, &pk, dst).is_ok());

    // A different DST must not verify
    assert!(proof.verify(&ciphertext, &pk, b"other").is_err());

    let (other_pk, _) = generate_keypair(&mut rand::thread_rng());
    assert!(proof.verify(&ciphertext, &other_pk, dst).is_err());

    // This table can be reused, so it only has to be computed once
    let table = precompute_table();
    assert_eq!(ciphertext.decrypt(&sk, &table).unwrap(), message);
}

#[test]
fn encrypt_and_range_proof() {
    let value = 1234u32;
    let range = crate::bulletproofs::Range::Bits32;
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, blinding) = Ciphertext::encrypt(&pk, value, &mut rng);
    let range_proof =
        crate::bulletproofs::RangeProof::prove(value as u64, &blinding, &range, b"test", &mut rng)
            .unwrap();

    assert!(range_proof
        .verify(&ciphertext.commitment, &range, b"test", &mut rng)
        .is_ok());

    assert_eq!(ciphertext.decrypt(&sk, &precompute_table()).unwrap(), value);
}

#[test]
fn linear_encryptions() {
    let value_1 = 12u32;
    let value_2 = 34u32;
    let s = 7u32;
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let (ciphertext_1, _) = Ciphertext::encrypt(&pk, value_1, &mut rand::thread_rng());
    let (ciphertext_2, _) = Ciphertext::encrypt(&pk, value_2, &mut rand::thread_rng());
    let ciphertext_3 = ciphertext_1 + ciphertext_2 * RistrettoScalar::from(s as u64);
    assert_eq!(
        ciphertext_3.decrypt(&sk, &precompute_table()).unwrap(),
        value_1 + value_2 * s
    );
}

#[test]
fn test_key_consistency_proof() {
    const N: usize = 8;
    let mut rng = rand::thread_rng();

    // Generate sender and recipient key pairs
    let (pk_snd, sk_snd) = generate_keypair(&mut rng);
    let (pk_rcv, _sk_rcv) = generate_keypair(&mut rng);

    // Split sender private key into 8 x 32-bit limbs
    let sk_bytes = sk_snd.0.to_byte_array();
    let limbs: [u32; N] = std::array::from_fn(|i| {
        u32::from_le_bytes(sk_bytes[4 * i..4 * (i + 1)].try_into().unwrap())
    });

    // Encrypt each limb as a multi-recipient Twisted ElGamal ciphertext towards the recipient
    let (ciphertexts, blindings): (Vec<_>, Vec<_>) = limbs
        .iter()
        .map(|&limb| {
            MultiRecipientCiphertext::encrypt(std::slice::from_ref(&pk_rcv), limb, &mut rng)
        })
        .unzip();
    let ciphertexts: [MultiRecipientCiphertext; N] = ciphertexts.try_into().unwrap();
    let blindings: [Blinding; N] = blindings.try_into().unwrap();

    // Prove
    let dst = b"test";
    let proof = KeyConsistencyProof::<N>::prove(
        &limbs,
        &pk_snd,
        std::slice::from_ref(&pk_rcv),
        &ciphertexts,
        &blindings,
        dst,
        &mut rng,
    );

    // Verification passes with correct sender public key
    assert!(proof
        .verify(
            &pk_snd,
            std::slice::from_ref(&pk_rcv),
            &ciphertexts,
            dst,
            &mut rng
        )
        .is_ok());

    // A different DST must not verify
    assert!(proof
        .verify(
            &pk_snd,
            std::slice::from_ref(&pk_rcv),
            &ciphertexts,
            b"other",
            &mut rng
        )
        .is_err());

    // Verification fails with a different sender public key
    let (other_pk_snd, _) = generate_keypair(&mut rng);
    assert!(proof
        .verify(&other_pk_snd, &[pk_rcv], &ciphertexts, dst, &mut rng)
        .is_err());
}

#[test]
fn test_verifiable_key_encapsulation() {
    const N: usize = 8;
    let range_dst = b"range";
    let consistency_dst = b"consistency";
    let mut rng = rand::thread_rng();
    let table = precompute_table();

    // Sender key pair; the private key will be encapsulated
    let (pk_snd, sk_snd) = generate_keypair(&mut rng);

    // Three recipient key pairs
    let (pk_rcv_0, sk_rcv_0) = generate_keypair(&mut rng);
    let (pk_rcv_1, sk_rcv_1) = generate_keypair(&mut rng);
    let (pk_rcv_2, sk_rcv_2) = generate_keypair(&mut rng);

    let recipient_keys = [pk_rcv_0.clone(), pk_rcv_1.clone(), pk_rcv_2.clone()];

    // Seal the sender's private key to all three recipients
    let encapsulation = VerifiableKeyEncapsulation::<N>::batch_seal(
        &sk_snd,
        &recipient_keys,
        range_dst,
        consistency_dst,
        &mut rng,
    );

    // Verification passes for the correct sender public key and recipient keys
    assert!(encapsulation
        .verify(
            &pk_snd,
            &recipient_keys,
            range_dst,
            consistency_dst,
            &mut rng
        )
        .is_ok());

    // Verification fails with a different range proof DST
    assert!(encapsulation
        .verify(
            &pk_snd,
            &recipient_keys,
            b"other",
            consistency_dst,
            &mut rng
        )
        .is_err());

    // Verification fails with a different key consistency DST
    assert!(encapsulation
        .verify(&pk_snd, &recipient_keys, range_dst, b"other", &mut rng)
        .is_err());

    // Verification fails with a wrong sender public key
    let (other_pk, _) = generate_keypair(&mut rng);
    assert!(encapsulation
        .verify(
            &other_pk,
            &recipient_keys,
            range_dst,
            consistency_dst,
            &mut rng
        )
        .is_err());

    // Each recipient can independently recover the sender's private key
    let recovered_0 = encapsulation
        .open(
            0,
            &sk_rcv_0,
            &recipient_keys,
            &pk_snd,
            &table,
            range_dst,
            consistency_dst,
            &mut rng,
        )
        .unwrap();
    let recovered_1 = encapsulation
        .open(
            1,
            &sk_rcv_1,
            &recipient_keys,
            &pk_snd,
            &table,
            range_dst,
            consistency_dst,
            &mut rng,
        )
        .unwrap();
    let recovered_2 = encapsulation
        .open(
            2,
            &sk_rcv_2,
            &recipient_keys,
            &pk_snd,
            &table,
            range_dst,
            consistency_dst,
            &mut rng,
        )
        .unwrap();

    assert_eq!(recovered_0.0, sk_snd.0);
    assert_eq!(recovered_1.0, sk_snd.0);
    assert_eq!(recovered_2.0, sk_snd.0);

    // A recipient cannot open another recipient's slot with their own key
    assert!(encapsulation
        .open(
            1,
            &sk_rcv_0,
            &recipient_keys,
            &pk_snd,
            &table,
            range_dst,
            consistency_dst,
            &mut rng
        )
        .is_err());
}

#[test]
fn test_fiat_shamir_regression() {
    use crate::encoding::{Encoding, Hex};
    let challenge_input = (
        "Accept the challenges",
        "so that you can feel the exhilaration of victory",
        7u64,
    );
    let expected = RistrettoScalar::from_byte_array(
        &Hex::decode("1e8fa9e453ab773a8ac1dd02d9602f45962c3d2061c543d7b9a33de8f51c4000")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let msg = bcs::to_bytes(&challenge_input).unwrap();
    let actual = RistrettoScalar::fiat_shamir_reduction_to_group_element(
        &bcs::to_bytes(&vec![b"".to_vec(), msg.clone()]).unwrap(),
    );
    assert_eq!(actual, expected);

    // A non-empty DST must change the challenge.
    assert_ne!(
        RistrettoScalar::fiat_shamir_reduction_to_group_element(
            &bcs::to_bytes(&vec![b"dst".to_vec(), msg.clone()]).unwrap(),
        ),
        expected
    );
}
