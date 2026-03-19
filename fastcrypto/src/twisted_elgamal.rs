// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bulletproofs::{Range, RangeProof};
use crate::error::FastCryptoError::{InvalidInput, InvalidProof};
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar, RISTRETTO_POINT_BYTE_LENGTH};
use crate::groups::{Doubling, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar};
use crate::hash::{HashFunction, Sha3_256};
use crate::nizk::DdhTupleNizk;
use crate::pedersen::{Blinding, PedersenCommitment, G, H};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use derive_more::{Add, Mul, Sub};
//use radix64::configs::Fast;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::successors;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateKey(RistrettoScalar);

#[derive(Debug, Serialize, Deserialize)]
pub struct ZeroProof(DdhTupleNizk<RistrettoPoint>);

pub fn generate_keypair(rng: &mut impl AllowedRng) -> (PublicKey, PrivateKey) {
    let sk = PrivateKey(RistrettoScalar::rand(rng));
    (pk_from_sk(&sk), sk)
}

pub fn pk_from_sk(sk: &PrivateKey) -> PublicKey {
    PublicKey(*G * sk.0)
}

/// Precompute discrete log table for use in decryption. This only needs to be computed once.
///
/// The table contains a mapping from Ristretto points <i>(2<sup>16</sup> x) G<i> to <i>x</i> for all <i>x</i> in the range <i>0, .., 2<sup>16</sup>-1</i>.
pub fn precompute_table() -> HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16> {
    let step = H.repeated_doubling(16);
    successors(Some(RistrettoPoint::zero()), |p| Some(p + step))
        .enumerate()
        .map(|(i, p)| (p.to_byte_array(), i as u16))
        .take(1 << 16)
        .collect()
}

// TODO: Encryptions of the same message can reuse commitments
#[derive(Debug, Clone, Add, Sub, Mul, Serialize, Deserialize)]
pub struct Ciphertext {
    commitment: PedersenCommitment,
    decryption_handle: RistrettoPoint,
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
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, Blinding, ConsistencyProof)> {
        let (ciphertext, blinding) = Self::encrypt(encryption_key, message, rng);
        let proof = ConsistencyProof::prove(
            &RistrettoScalar::from(message as u64),
            &ciphertext,
            &blinding,
            encryption_key,
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

    /// Create a PoK of a private key such that the given encryption is of the message 0.
    pub fn zero_proof(&self, private_key: &PrivateKey, rng: &mut impl AllowedRng) -> ZeroProof {
        let pk = pk_from_sk(private_key);
        ZeroProof(DdhTupleNizk::create(
            &private_key.0,
            &RistrettoPoint::generator(),
            &self.commitment.0,
            &pk.0,
            &self.decryption_handle,
            rng,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsistencyProof {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    a3: RistrettoPoint,
    z1: RistrettoScalar,
    z2: RistrettoScalar,
}

impl ConsistencyProof {
    pub fn prove(
        message: &RistrettoScalar,
        ciphertext: &Ciphertext,
        blinding: &Blinding,
        encryption_key: &PublicKey,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Self> {
        let r1 = RistrettoScalar::rand(rng);
        let r2 = RistrettoScalar::rand(rng);
        let a1 = encryption_key.0 * r1;
        let a2 = RistrettoPoint::multi_scalar_mul(&[r1, r2], &[*G, *H]).expect("Constant length");
        let a3 = *G * r2;

        let c = Self::challenge(&a1, &a2, ciphertext, encryption_key);
        let z1 = r1 + c * blinding.0;
        let z2 = r2 + c * message;

        Ok(Self { a1, a2, a3, z1, z2 })
    }

    pub fn challenge(
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        ciphertext: &Ciphertext,
        encryption_key: &PublicKey,
    ) -> RistrettoScalar {
        let output = Sha3_256::digest(
            bcs::to_bytes(&(
                &*G,
                &*H,
                a,
                b,
                &ciphertext.commitment,
                &ciphertext.decryption_handle,
                encryption_key,
            ))
            .unwrap(),
        );
        RistrettoScalar::fiat_shamir_reduction_to_group_element(&output.digest)
    }

    pub fn verify(
        &self,
        ciphertext: &Ciphertext,
        encryption_key: &PublicKey,
    ) -> FastCryptoResult<()> {
        let c = Self::challenge(&self.a1, &self.a2, ciphertext, encryption_key);
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
}

impl ZeroProof {
    pub fn verify(&self, encryption: &Ciphertext, pk: &PublicKey) -> FastCryptoResult<()> {
        self.0.verify(
            &RistrettoPoint::generator(),
            &encryption.commitment.0,
            &pk.0,
            &encryption.decryption_handle,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiRecipientCiphertext {
    commitment: PedersenCommitment,
    decryption_handles: Vec<RistrettoPoint>,
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

    // Encrypt a 32-bit ciphertext to multiple recipients where the decryption handles share the same blinding factor
    // while also computing consistency proofs showing that ciphertexts were created towards the given encryption keys.
    pub fn encrypt_with_consistency_proof(
        encryption_keys: &[PublicKey],
        message: u32,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, Blinding, Vec<ConsistencyProof>)> {
        let (multi_recipient_ciphertext, blinding) = Self::encrypt(encryption_keys, message, rng);
        let proofs = encryption_keys
            .iter()
            .enumerate()
            .map(|(i, encryption_key)| {
                ConsistencyProof::prove(
                    &RistrettoScalar::from(message as u64),
                    &multi_recipient_ciphertext.ciphertext(i)?,
                    &blinding,
                    encryption_key,
                    rng,
                )
            })
            .collect::<FastCryptoResult<Vec<ConsistencyProof>>>()?;
        Ok((multi_recipient_ciphertext, blinding, proofs))
    }

    /// Decrypt the ciphertext of a single recipient identified by the provided index.
    pub fn decrypt(
        &self,
        index: usize,
        decryption_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
    ) -> FastCryptoResult<u32> {
        if index > self.decryption_handles.len() {
            return Err(InvalidInput);
        }
        let mut c = self.commitment.0 - (self.decryption_handles[index] / decryption_key.0)?;
        for x_low in 0..1 << 16 {
            if let Some(&x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + ((x_high as u32) << 16));
            }
            c -= *H;
        }
        Err(InvalidInput)
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

    pub fn commitment(&self) -> FastCryptoResult<PedersenCommitment> {
        Ok(self.commitment.clone())
    }

    pub fn decryption_handle(&self, index: usize) -> FastCryptoResult<RistrettoPoint> {
        Ok(self.decryption_handles[index])
    }
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
    a3: [RistrettoPoint; N],
    z1: [RistrettoScalar; N],
    z2: [RistrettoScalar; N],
}

impl<const N: usize> KeyConsistencyProof<N> {
    pub fn prove(
        sender_private_key_limbs: &[u32; N],
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        ciphertexts: &[MultiRecipientCiphertext; N],
        blindings: &[Blinding; N],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Self> {
        // Sample N random a_i and b_i
        let a = (0..N)
            .map(|_| RistrettoScalar::rand(rng))
            .collect::<Vec<_>>();
        let b = (0..N)
            .map(|_| RistrettoScalar::rand(rng))
            .collect::<Vec<_>>();

        // A_1ij = a_i * pk_j for all (i, j) — N*m elements, ordered by limb then recipient
        let a1 = a
            .iter()
            .flat_map(|ai| recipient_encryption_keys.iter().map(move |pk| pk.0 * ai))
            .collect::<Vec<RistrettoPoint>>();

        // A_2i = a_i * G + b_i * H for all i
        let a2 = a
            .iter()
            .zip(b.iter())
            .map(|(ai, bi)| *G * ai + *H * bi)
            .collect::<Vec<RistrettoPoint>>();

        // A_3i = b_i * G for all i
        let a3 = b.iter().map(|bi| *G * bi).collect::<Vec<RistrettoPoint>>();

        // c = Hash(G, H, sender_public_key, recipient_encryption_keys, ciphertexts, a1, a2, a3)
        let c = Self::challenge(
            sender_public_key,
            recipient_encryption_keys,
            ciphertexts,
            &a1,
            &a2,
            &a3,
        );

        // z_1i = a_i + c * r_i
        let z1 = a
            .iter()
            .zip(blindings.iter())
            .map(|(ai, ri)| ai + c * ri.0)
            .collect::<Vec<RistrettoScalar>>();

        // z_2i = b_i + c * u_i
        let z2 = b
            .iter()
            .zip(sender_private_key_limbs.iter())
            .map(|(bi, ui)| bi + c * RistrettoScalar::from(*ui as u64))
            .collect::<Vec<RistrettoScalar>>();

        Ok(Self {
            a1,
            a2: a2.try_into().unwrap(),
            a3: a3.try_into().unwrap(),
            z1: z1.try_into().unwrap(),
            z2: z2.try_into().unwrap(),
        })
    }

    pub fn verify(
        &self,
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        ciphertexts: &[MultiRecipientCiphertext; N],
    ) -> FastCryptoResult<()> {
        let c = Self::challenge(
            sender_public_key,
            recipient_encryption_keys,
            ciphertexts,
            &self.a1,
            &self.a2,
            &self.a3,
        );

        // Batch all three groups of verification equations into a single MSM using hash-derived scalars.
        //
        // The three groups of equations that must hold for a valid proof are:
        //
        //   Check 1 (decryption handle consistency): Verifies that each decryption handle was formed with the same
        //   blinding r_i as the commitment via
        //     A1_ij + c * D_ij == z_1i * S_j
        //   for all limbs i and recipients j where D_ij = r_i * S_j is the decryption handle and S_j is recipient j's public key.
        //   Combined equations using scalars mu_ij = Hash("mu", c, i, j):
        //     \sum_j (\sum_i mu_ij * z_1i) * S_j - \sum_{i,j} mu_ij * A1_ij - \sum_{i,j} (c * mu_ij) * D_ij == 0
        //
        //   Check 2 (commitment consistency): Verifies knowledge of the blinding r_i and message u_i opening the
        //   commitment via
        //     A2_i + c * C_i == z_1i * G + z_2i * H
        //   for all limbs i where C_i = r_i * G + u_i * H is the Pedersen commitment.
        //   Combined equations using scalars rho_i = Hash("rho", c, i):
        //     (\sum_i rho_i * z_1i) * G + (\sum_i rho_i * z_2i) * H - \sum_i rho_i * A2_i - \sum_i (c * rho_i) * C_i == 0
        //
        //   Check 3 (public key consistency): Verifies that the encrypted 32-bit key limbs u_i reconstruct to the
        //   private key corresponding to U via
        //     (\sum_i z_2i * 2^{32i}) * G == (\sum_i A3_i * 2^{32i}) + c * U
        //   where U is the sender's public key.
        //
        //   We combine the individual checks as
        //     (check 1) + alpha * (check 2) + beta * (check 3) == 0
        //   using hash-derived outer scalars alpha = Hash("alpha", c) and beta = Hash("beta", c) to ensure soundness.

        let m = recipient_encryption_keys.len();

        // Compute inner scalars mu_ij = Hash("mu", c, i, j) for all i and j used in check 1
        let mu: Vec<RistrettoScalar> = (0..N)
            .flat_map(|i| {
                (0..m).map(move |j| {
                    let output = Sha3_256::digest(bcs::to_bytes(&("mu", &c, i, j)).unwrap());
                    RistrettoScalar::fiat_shamir_reduction_to_group_element(&output.digest)
                })
            })
            .collect();

        // Compute inner scalars rho_i = Hash("rho", c, i) for all i used in check 2
        let rho: Vec<RistrettoScalar> = (0..N)
            .map(|i| {
                let output = Sha3_256::digest(bcs::to_bytes(&("rho", &c, i)).unwrap());
                RistrettoScalar::fiat_shamir_reduction_to_group_element(&output.digest)
            })
            .collect();

        // Outer scalars alpha = Hash("alpha", c) and beta = Hash("beta", c) combine the three zero-expressions:
        //   (check 1) + alpha * (check 2) + beta * (check 3) == 0
        let alpha = {
            let output = Sha3_256::digest(bcs::to_bytes(&("alpha", &c)).unwrap());
            RistrettoScalar::fiat_shamir_reduction_to_group_element(&output.digest)
        };
        let beta = {
            let output = Sha3_256::digest(bcs::to_bytes(&("beta", &c)).unwrap());
            RistrettoScalar::fiat_shamir_reduction_to_group_element(&output.digest)
        };

        // Check 2: compute sum_i(rho_i * z_1i) and sum_i(rho_i * z_2i)
        let rho_z1 = rho
            .iter()
            .zip(&self.z1)
            .fold(RistrettoScalar::from(0u64), |acc, (rhoi, z1i)| {
                acc + *rhoi * *z1i
            });
        let rho_z2 = rho
            .iter()
            .zip(&self.z2)
            .fold(RistrettoScalar::from(0u64), |acc, (rhoi, z2i)| {
                acc + *rhoi * *z2i
            });

        // Check 3: compute z = \sum_i z_2i * 2^{32i}
        let b = RistrettoScalar::from(1u64 << 32);
        let mut exp = RistrettoScalar::from(1u64);
        let mut z = RistrettoScalar::from(0u64);
        for z2i in self.z2.iter() {
            z += *z2i * exp;
            exp *= b;
        }

        let mut scalars: Vec<RistrettoScalar> = vec![alpha * rho_z1 + beta * z, alpha * rho_z2];
        let mut points: Vec<RistrettoPoint> = vec![*G, *H];

        // Check 1: Append (\sum_i mu_ij * z_1i, S_j) terms for each recipient j
        for j in 0..m {
            let coeff = (0..N).fold(RistrettoScalar::from(0u64), |acc, i| {
                acc + mu[i * m + j] * self.z1[i]
            });
            scalars.push(coeff);
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
        for (rhoi, (a2i, ci)) in rho.iter().zip(self.a2.iter().zip(ciphertexts)) {
            scalars.push(-(alpha * *rhoi));
            points.push(*a2i);
            scalars.push(-(c * alpha * *rhoi));
            points.push(ci.commitment.0);
        }

        // Check 3: Append (-beta * c, U) and (-beta * 2^{32i}, A3_i) terms
        scalars.push(-(beta * c));
        points.push(sender_public_key.0);
        let mut exp = RistrettoScalar::from(1u64);
        for a3i in self.a3.iter() {
            scalars.push(-(beta * exp));
            points.push(*a3i);
            exp *= b;
        }

        if RistrettoPoint::multi_scalar_mul(&scalars, &points).expect("Consistent lengths")
            != RistrettoPoint::zero()
        {
            return Err(InvalidProof);
        }

        Ok(())
    }

    pub fn challenge(
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        ciphertexts: &[MultiRecipientCiphertext; N],
        a1: &[RistrettoPoint],
        a2: &[RistrettoPoint],
        a3: &[RistrettoPoint],
    ) -> RistrettoScalar {
        let output = Sha3_256::digest(
            bcs::to_bytes(&(
                &*G,
                &*H,
                sender_public_key,
                recipient_encryption_keys,
                ciphertexts.as_slice(),
                a1,
                a2,
                a3,
            ))
            .unwrap(),
        );
        RistrettoScalar::fiat_shamir_reduction_to_group_element(&output.digest)
    }
}

/// A verifiable key encapsulation allows to verifiably encrypt a private key to multiple recipients.
/// A batch range proof shows that each limb of the private key lies in the range [0, 2^32-1].
/// A key consistency proof shows that the 32-bit key limbs have been encrypted to the correct recipient public keys
/// and that they correspond to the provided sender public key.
pub struct VerifiableKeyEncapsulation<const N: usize> {
    pub ciphertexts: [MultiRecipientCiphertext; N],
    pub range_proof: RangeProof,
    pub consistency_proof: KeyConsistencyProof<N>,
}

impl<const N: usize> VerifiableKeyEncapsulation<N> {
    /// Verifiably encrypt a private key to multiple recipient public keys.
    pub fn batch_seal(
        sender_private_key: &PrivateKey,
        recipient_encryption_keys: &[PublicKey],
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation<N> {
        // Re-arrange private key into N 32-bit limbs
        let private_key_bytes = sender_private_key.0.to_byte_array();
        let limbs: [u32; N] = std::array::from_fn(|i| {
            u32::from_le_bytes(private_key_bytes[4 * i..4 * (i + 1)].try_into().unwrap())
        });

        // Encrypt all N 32-bit key limbs with Twisted ElGamal to the recipient public keys
        let (ciphertexts, blindings): (Vec<_>, Vec<_>) = limbs
            .iter()
            .map(|&li| MultiRecipientCiphertext::encrypt(recipient_encryption_keys, li, rng))
            .unzip();

        // Split results into ciphertexts and blindings arrays
        let ciphertexts: [MultiRecipientCiphertext; N] = ciphertexts.try_into().unwrap();
        let blindings: [Blinding; N] = blindings.try_into().unwrap();

        // Create range proof
        let range_proof =
            RangeProof::prove_batch(&limbs.map(|m| m as u64), &blindings, &Range::Bits32, rng)
                .unwrap();

        // Create consistency proof
        let consistency_proof = KeyConsistencyProof::prove(
            &limbs,
            &pk_from_sk(sender_private_key),
            recipient_encryption_keys,
            &ciphertexts,
            &blindings,
            rng,
        )
        .unwrap();

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
        rng: &mut impl AllowedRng,
    ) -> VerifiableKeyEncapsulation<N> {
        Self::batch_seal(
            sender_private_key,
            std::slice::from_ref(recipient_encryption_key),
            rng,
        )
    }

    /// Verify the range and key consistency proofs.
    pub fn verify(
        &self,
        sender_public_key: &PublicKey,
        recipient_encryption_keys: &[PublicKey],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<()> {
        // Verify range proof over the Pedersen commitments of all limb ciphertexts
        let commitments = self
            .ciphertexts
            .iter()
            .map(|c| c.commitment.clone())
            .collect::<Vec<_>>();
        self.range_proof
            .verify_batch(&commitments, &Range::Bits32, rng)?;

        // Verify key consistency proof
        self.consistency_proof.verify(
            sender_public_key,
            recipient_encryption_keys,
            &self.ciphertexts,
        )
    }

    /// Open the key encapsulation for a single recipient decryption key identified by the provided index using the
    /// provided 16-bit discrete log decryption table. All recipient public keys must be provided to verify the
    /// consistency proof, which is bound to the full set of recipients.
    pub fn open(
        &self,
        index: usize,
        recipient_decryption_key: &PrivateKey,
        recipient_public_keys: &[PublicKey],
        sender_public_key: &PublicKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<PrivateKey> {
        // Verify range and consistency proofs against all recipient keys
        self.verify(sender_public_key, recipient_public_keys, rng)?;

        // Decrypt each limb ciphertext using the recipient's decryption key
        let limbs = self
            .ciphertexts
            .iter()
            .map(|c| c.decrypt(index, recipient_decryption_key, table))
            .collect::<FastCryptoResult<Vec<u32>>>()?;

        // Reconstruct the private key from its 32-bit limbs
        let private_key_bytes = limbs
            .iter()
            .flat_map(|l| l.to_le_bytes())
            .collect::<Vec<_>>();
        let private_key = RistrettoScalar::from_byte_array(&private_key_bytes.try_into().unwrap())?;

        // Verify the recovered key corresponds to the sender's public key
        if pk_from_sk(&PrivateKey(private_key)) != *sender_public_key {
            return Err(InvalidInput);
        }
        Ok(PrivateKey(private_key))
    }
}

pub struct VerifiableCiphertext {
    pub ciphertexts: Vec<Ciphertext>,
    pub range_proof: RangeProof,
}

impl VerifiableCiphertext {
    pub fn seal(
        public_key: &PublicKey,
        messages: &[u32],
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<(Self, Vec<Blinding>)> {
        let (ciphertexts, blindings): (Vec<Ciphertext>, Vec<Blinding>) = messages
            .iter()
            .map(|&m| Ciphertext::encrypt(public_key, m, rng))
            .unzip();
        let messages_u64: Vec<u64> = messages.iter().map(|&m| m as u64).collect();
        let range_proof = RangeProof::prove_batch(&messages_u64, &blindings, &Range::Bits32, rng)?;
        Ok((
            Self {
                ciphertexts,
                range_proof,
            },
            blindings,
        ))
    }

    pub fn verify(&self, rng: &mut impl AllowedRng) -> FastCryptoResult<()> {
        let commitments: Vec<PedersenCommitment> = self
            .ciphertexts
            .iter()
            .map(|ct| ct.commitment.clone())
            .collect();
        self.range_proof
            .verify_batch(&commitments, &Range::Bits32, rng)
    }

    pub fn open(
        &self,
        private_key: &PrivateKey,
        table: &HashMap<[u8; RISTRETTO_POINT_BYTE_LENGTH], u16>,
        rng: &mut impl AllowedRng,
    ) -> FastCryptoResult<Vec<u32>> {
        self.verify(rng)?;
        self.ciphertexts
            .iter()
            .map(|ct| ct.decrypt(private_key, table))
            .collect()
    }
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
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let message = 1234567890u32;
    let (ciphertext, _, proof) =
        Ciphertext::encrypt_with_consistency_proof(&pk, message, &mut rand::thread_rng()).unwrap();
    assert!(proof.verify(&ciphertext, &pk).is_ok());

    let (other_pk, _) = generate_keypair(&mut rand::thread_rng());
    assert!(proof.verify(&ciphertext, &other_pk).is_err());

    // This table can be reused, so it only has to be computed once
    let table = precompute_table();
    assert_eq!(ciphertext.decrypt(&sk, &table).unwrap(), message);
}

#[test]
fn test_zero_proof() {
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, _) = Ciphertext::encrypt(&pk, 0, &mut rng);
    let zero_proof = ciphertext.zero_proof(&sk, &mut rng);
    zero_proof.verify(&ciphertext, &pk).unwrap();

    let (other_ciphertext, _) = Ciphertext::encrypt(&pk, 1, &mut rng);
    let other_zero_proof = other_ciphertext.zero_proof(&sk, &mut rng);
    other_zero_proof.verify(&ciphertext, &pk).unwrap_err();
}

#[test]
fn encrypt_and_range_proof() {
    let value = 1234u32;
    let range = crate::bulletproofs::Range::Bits32;
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(&mut rng);
    let (ciphertext, blinding) = Ciphertext::encrypt(&pk, value, &mut rng);
    let range_proof =
        crate::bulletproofs::RangeProof::prove(value as u64, &blinding, &range, &mut rng).unwrap();

    assert!(range_proof
        .verify(&ciphertext.commitment, &range, &mut rng)
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
fn test_equality() {
    let value = 123u32;
    let (pk, sk) = generate_keypair(&mut rand::thread_rng());
    let encryption_1 = Ciphertext::encrypt(&pk, value, &mut rand::thread_rng());
    let encryption_2 = Ciphertext::encrypt(&pk, value, &mut rand::thread_rng());

    let diff = encryption_1.0.clone() - encryption_2.0;

    let mut rng = rand::thread_rng();

    diff.zero_proof(&sk, &mut rng).verify(&diff, &pk).unwrap();

    let other_value = 1234u32;
    let encryption_3 = Ciphertext::encrypt(&pk, other_value, &mut rand::thread_rng());
    let other_diff = encryption_1.0 - encryption_3.0;
    other_diff
        .zero_proof(&sk, &mut rng)
        .verify(&other_diff, &pk)
        .unwrap_err();
}

#[test]
fn test_verifiable_ciphertext() {
    let mut rng = rand::thread_rng();
    let (public_key, private_key) = generate_keypair(&mut rng);
    let table = precompute_table();
    let messages: Vec<u32> = vec![1, 23, 456, 789, 987, 654, 32, 1];
    let (verifiable_ciphertext, _blindings) =
        VerifiableCiphertext::seal(&public_key, &messages, &mut rng).unwrap();
    assert!(verifiable_ciphertext.verify(&mut rng).is_ok());
    let decrypted_messages = verifiable_ciphertext
        .open(&private_key, &table, &mut rng)
        .unwrap();
    assert_eq!(messages, decrypted_messages);
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
    let proof = KeyConsistencyProof::<N>::prove(
        &limbs,
        &pk_snd,
        std::slice::from_ref(&pk_rcv),
        &ciphertexts,
        &blindings,
        &mut rng,
    )
    .unwrap();

    // Verification passes with correct sender public key
    assert!(proof
        .verify(&pk_snd, std::slice::from_ref(&pk_rcv), &ciphertexts)
        .is_ok());

    // Verification fails with a different sender public key
    let (other_pk_snd, _) = generate_keypair(&mut rng);
    assert!(proof
        .verify(&other_pk_snd, &[pk_rcv], &ciphertexts)
        .is_err());
}

#[test]
fn test_verifiable_key_encapsulation() {
    const N: usize = 8;
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
    let encapsulation =
        VerifiableKeyEncapsulation::<N>::batch_seal(&sk_snd, &recipient_keys, &mut rng);

    // Verification passes for the correct sender public key and recipient keys
    assert!(encapsulation
        .verify(&pk_snd, &recipient_keys, &mut rng)
        .is_ok());

    // Verification fails with a wrong sender public key
    let (other_pk, _) = generate_keypair(&mut rng);
    assert!(encapsulation
        .verify(&other_pk, &recipient_keys, &mut rng)
        .is_err());

    // Each recipient can independently recover the sender's private key
    let recovered_0 = encapsulation
        .open(0, &sk_rcv_0, &recipient_keys, &pk_snd, &table, &mut rng)
        .unwrap();
    let recovered_1 = encapsulation
        .open(1, &sk_rcv_1, &recipient_keys, &pk_snd, &table, &mut rng)
        .unwrap();
    let recovered_2 = encapsulation
        .open(2, &sk_rcv_2, &recipient_keys, &pk_snd, &table, &mut rng)
        .unwrap();

    assert_eq!(recovered_0.0, sk_snd.0);
    assert_eq!(recovered_1.0, sk_snd.0);
    assert_eq!(recovered_2.0, sk_snd.0);

    // A recipient cannot open another recipient's slot with their own key
    assert!(encapsulation
        .open(1, &sk_rcv_0, &recipient_keys, &pk_snd, &table, &mut rng)
        .is_err());
}
