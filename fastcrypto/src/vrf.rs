// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError;
use crate::traits::AllowedRng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Represents a public key of which is use to verify outputs for a verifiable random function (VRF).
pub trait VRFPublicKey: Serialize + DeserializeOwned + Eq + Debug {
    type PrivateKey: VRFPrivateKey<PublicKey = Self>;
}

/// Represents a private key used to compute outputs for a verifiable random function (VRF).
pub trait VRFPrivateKey: Serialize + DeserializeOwned + Eq + Debug {
    type PublicKey: VRFPublicKey<PrivateKey = Self>;
}

/// A keypair for a verifiable random function (VRF).
pub trait VRFKeyPair<const OUTPUT_SIZE: usize>: Serialize + DeserializeOwned + Eq + Debug {
    type Proof: VRFProof<OUTPUT_SIZE, PublicKey = Self::PublicKey>;
    type PrivateKey: VRFPrivateKey<PublicKey = Self::PublicKey>;
    type PublicKey: VRFPublicKey<PrivateKey = Self::PrivateKey>;

    /// Generate a new keypair using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;

    /// Generate a proof for the given input.
    fn prove(&self, input: &[u8]) -> Self::Proof;

    /// Compute both hash and proof for the given input.
    fn output(&self, input: &[u8]) -> ([u8; OUTPUT_SIZE], Self::Proof) {
        let proof = self.prove(input);
        let output = proof.to_hash();
        (output, proof)
    }
}

/// A proof that the output of a VRF was computed correctly.
pub trait VRFProof<const OUTPUT_SIZE: usize>: Serialize + DeserializeOwned + Eq + Debug {
    type PublicKey: VRFPublicKey;

    /// Verify the correctness of this proof.
    fn verify(&self, input: &[u8], public_key: &Self::PublicKey) -> Result<(), FastCryptoError>;

    /// Verify the correctness of this proof and VRF output.
    fn verify_output(
        &self,
        input: &[u8],
        public_key: &Self::PublicKey,
        output: [u8; OUTPUT_SIZE],
    ) -> Result<(), FastCryptoError> {
        self.verify(input, public_key)?;
        if self.to_hash() != output {
            return Err(FastCryptoError::GeneralError);
        }
        Ok(())
    }

    /// Compute the output of the VRF with this proof.
    fn to_hash(&self) -> [u8; OUTPUT_SIZE];
}

/// An implementation of an Elliptic Curve VRF (ECVRF) using the Ristretto255 group.
/// The implementation follows the specifications in draft-irtf-cfrg-vrf-15
/// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/).
pub mod ecvrf {
    use crate::error::FastCryptoError;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::{GroupElement, Scalar};
    use crate::hash::{HashFunction, Sha512};
    use crate::traits::AllowedRng;
    use crate::vrf::{VRFKeyPair, VRFPrivateKey, VRFProof, VRFPublicKey};
    use elliptic_curve::hash2curve::{ExpandMsg, Expander};
    use serde::{Deserialize, Serialize};
    use std::borrow::Borrow;

    /// draft-irtf-cfrg-vrf-15 specifies suites for suite-strings 0x00-0x04 and notes that future
    /// designs should specify a different suite_string constant, so we use 0x05 here.
    const SUITE_STRING: [u8; 1] = [0x05];

    /// Length of challenge. Must be smaller than the length of field elements which is 32 in this case.
    const C_LEN: usize = 16;

    /// Default hash function
    type H = Sha512;

    /// Domain seperation tak used in ecvrf_encode_to_curve
    const DST: &[u8; 43] = b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_5";

    const COFACTOR: u64 = 8;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFPublicKey(RistrettoPoint);

    impl VRFPublicKey for ECVRFPublicKey {
        type PrivateKey = ECVRFPrivateKey;
    }

    impl ECVRFPublicKey {
        /// Encode the given binary string as curve point. See section 5.4.1.2 of draft-irtf-cfrg-vrf-15.
        fn ecvrf_encode_to_curve(&self, alpha_string: &[u8]) -> RistrettoPoint {
            // This follows section 5.4.1.2 of draft-irtf-cfrg-vrf-15 for the ristretto255 group using
            // SHA-512. The hash-to-curve for ristretto255 follows appendix B of draft-irtf-cfrg-hash-to-curve-16.

            // Compute expand_message_xmd for the given message.
            let mut expanded_message =
                elliptic_curve::hash2curve::ExpandMsgXmd::<sha2::Sha512>::expand_message(
                    &[&self.0.compress(), alpha_string],
                    DST,
                    H::OUTPUT_SIZE,
                )
                .unwrap();

            let mut bytes = [0u8; H::OUTPUT_SIZE];
            expanded_message.fill_bytes(&mut bytes);
            RistrettoPoint::map_to_point::<H>(&bytes)
        }

        /// Implements ECVRF_validate_key which checks the validity of a public key.
        fn valid(&self) -> bool {
            // Follows section 5.4.5 of draft-irtf-cfrg-vrf-15.
            self.0 * RistrettoScalar::from(COFACTOR) != RistrettoPoint::zero()
        }
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFPrivateKey(RistrettoScalar);

    impl VRFPrivateKey for ECVRFPrivateKey {
        type PublicKey = ECVRFPublicKey;
    }

    impl ECVRFPrivateKey {
        /// Generate nonce from binary string. See section 5.4.2.2. of draft-irtf-cfrg-vrf-15.
        fn ecvrf_nonce_generation(&self, h_string: &[u8]) -> RistrettoScalar {
            let hashed_sk_string = Sha512::digest(bincode::serialize(&self.0).unwrap());
            let truncated_hashed_sk_string: [u8; 32] =
                hashed_sk_string.digest[32..64].try_into().unwrap();

            let mut hash_function = Sha512::default();
            hash_function.update(truncated_hashed_sk_string);
            hash_function.update(h_string);
            let k_string = hash_function.finalize();

            RistrettoScalar::hash_to_scalar(k_string.digest)
        }
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFKeyPair {
        pub pk: ECVRFPublicKey,
        pub sk: ECVRFPrivateKey,
    }

    /// Generate challenge from five points. See section 5.4.3. of draft-irtf-cfrg-vrf-15.
    fn ecvrf_challenge_generation(points: [&RistrettoPoint; 5]) -> Challenge {
        let mut hash = H::default();
        hash.update(SUITE_STRING);
        hash.update([0x02]); //challenge_generation_domain_separator_front
        points
            .into_iter()
            .for_each(|p| hash.update(p.borrow().compress()));
        hash.update([0x00]); //challenge_generation_domain_separator_back
        let digest = hash.finalize();

        Challenge(digest.digest[..C_LEN].try_into().unwrap())
    }

    /// Type representing a scalar of C_LEN bytes.
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Challenge([u8; C_LEN]);

    impl From<&Challenge> for RistrettoScalar {
        fn from(c: &Challenge) -> Self {
            let mut scalar = [0u8; 32];
            scalar[..C_LEN].copy_from_slice(&c.0);
            RistrettoScalar::from_bits(scalar)
        }
    }

    impl VRFKeyPair<64> for ECVRFKeyPair {
        type Proof = ECVRFProof;
        type PrivateKey = ECVRFPrivateKey;
        type PublicKey = ECVRFPublicKey;

        fn generate<R: AllowedRng>(rng: &mut R) -> Self {
            let s = RistrettoScalar::rand(rng);
            let p = RistrettoPoint::generator() * s;
            ECVRFKeyPair {
                pk: ECVRFPublicKey(p),
                sk: ECVRFPrivateKey(s),
            }
        }

        fn prove(&self, alpha_string: &[u8]) -> ECVRFProof {
            // Follows section 5.1 of draft-irtf-cfrg-vrf-15.

            let h = self.pk.ecvrf_encode_to_curve(alpha_string);
            let h_string = h.compress();
            let gamma = h * self.sk.0;
            let k = self.sk.ecvrf_nonce_generation(&h_string);

            let c = ecvrf_challenge_generation([
                &self.pk.0,
                &h,
                &gamma,
                &(RistrettoPoint::generator() * k),
                &(h * k),
            ]);
            let s = k + RistrettoScalar::from(&c) * self.sk.0;

            ECVRFProof { gamma, c, s }
        }
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFProof {
        gamma: RistrettoPoint,
        c: Challenge,
        s: RistrettoScalar,
    }

    impl VRFProof<64> for ECVRFProof {
        type PublicKey = ECVRFPublicKey;

        fn verify(
            &self,
            alpha_string: &[u8],
            public_key: &Self::PublicKey,
        ) -> Result<(), FastCryptoError> {
            // Follows section 5.3 of draft-irtf-cfrg-vrf-15.

            if !public_key.valid() {
                return Err(FastCryptoError::InvalidInput);
            }

            let h = public_key.ecvrf_encode_to_curve(alpha_string);

            let challenge = RistrettoScalar::from(&self.c);
            let u = RistrettoPoint::generator() * self.s - public_key.0 * challenge;
            let v = h * self.s - self.gamma * challenge;

            let c_prime = ecvrf_challenge_generation([&public_key.0, &h, &self.gamma, &u, &v]);

            if c_prime != self.c {
                return Err(FastCryptoError::GeneralError);
            }
            Ok(())
        }

        fn to_hash(&self) -> [u8; 64] {
            // Follows section 5.2 of draft-irtf-cfrg-vrf-15.
            let mut hash = H::default();
            hash.update(SUITE_STRING);
            hash.update([0x03]); // proof_to_hash_domain_separator_front
            hash.update((self.gamma * RistrettoScalar::from(COFACTOR)).compress());
            hash.update([0x00]); // proof_to_hash_domain_separator_back
            hash.finalize().digest
        }
    }
}
