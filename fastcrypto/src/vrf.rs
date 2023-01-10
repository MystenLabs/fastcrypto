// Copyright (c) 2023, Mysten Labs, Inc.
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
pub trait VRFProof<const OUTPUT_SIZE: usize> {
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
/// The implementation follows the specifications in https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04#section-5.
pub mod ecvrf {
    use crate::error::FastCryptoError;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::{GroupElement, Scalar};
    use crate::hash::{HashFunction, Sha256, Sha512};
    use crate::traits::AllowedRng;
    use crate::vrf::{VRFKeyPair, VRFPrivateKey, VRFProof, VRFPublicKey};
    use serde::{Deserialize, Serialize};
    use std::borrow::Borrow;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFPublicKey(RistrettoPoint);

    impl VRFPublicKey for ECVRFPublicKey {
        type PrivateKey = ECVRFPrivateKey;
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFPrivateKey(RistrettoScalar);

    impl VRFPrivateKey for ECVRFPrivateKey {
        type PublicKey = ECVRFPublicKey;
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ECVRFKeyPair {
        pub pk: ECVRFPublicKey,
        pub sk: ECVRFPrivateKey,
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04 specifies suites for suite-strings
    /// 0x00-0x04 and notes that future designs "should specify a different suite_string constant",
    /// so we use 0x05 here.
    const SUITE_STRING: [u8; 1] = [0x05];

    /// Implementation of hashing a list of points to a scalar. Follows https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04#section-5.4.3.
    fn ecvrf_hash_points<
        'a,
        H: HashFunction<32>,
        K: Borrow<RistrettoPoint> + 'a,
        I: IntoIterator<Item = &'a K>,
    >(
        points: I,
    ) -> RistrettoScalar {
        let mut hash = H::default();
        hash.update(SUITE_STRING);
        hash.update([0x02]);
        points
            .into_iter()
            .for_each(|p| hash.update(p.borrow().compress()));
        RistrettoScalar::from_bits(hash.finalize().digest)
    }

    impl VRFKeyPair<32> for ECVRFKeyPair {
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

        fn prove(&self, input: &[u8]) -> ECVRFProof {
            // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04#section-5.1

            let mut hash1 = Sha512::default();
            hash1.update(SUITE_STRING);
            hash1.update(self.pk.0.compress());
            hash1.update(input);
            let h = RistrettoPoint::map_to_point::<Sha512>(hash1.finalize().as_ref());
            let gamma = h * self.sk.0;

            let mut hash2 = Sha256::default();
            hash2.update(bincode::serialize(&self.sk.0).unwrap());
            hash2.update(h.compress());
            let k = RistrettoScalar::from_bits(hash2.finalize().digest);

            let c = ecvrf_hash_points::<Sha256, _, _>(vec![
                &h,
                &gamma,
                &(RistrettoPoint::generator() * k),
                &(h * k),
            ]);
            let s = k + c * self.sk.0;
            ECVRFProof { gamma, c, s }
        }
    }

    pub struct ECVRFProof {
        gamma: RistrettoPoint,
        c: RistrettoScalar,
        s: RistrettoScalar,
    }

    impl VRFProof<32> for ECVRFProof {
        type PublicKey = ECVRFPublicKey;

        fn verify(
            &self,
            input: &[u8],
            public_key: &Self::PublicKey,
        ) -> Result<(), FastCryptoError> {
            let mut hash = Sha512::default();
            hash.update(SUITE_STRING);
            hash.update(public_key.0.compress());
            hash.update(input);

            let h = RistrettoPoint::map_to_point::<Sha512>(hash.finalize().as_ref());

            let u = RistrettoPoint::generator() * self.s - public_key.0 * self.c;
            let v = h * self.s - self.gamma * self.c;

            let c_prime = ecvrf_hash_points::<Sha256, _, _>(vec![&h, &self.gamma, &u, &v]);

            if c_prime != self.c {
                return Err(FastCryptoError::GeneralError);
            }
            Ok(())
        }

        fn to_hash(&self) -> [u8; 32] {
            // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04#section-5.2
            let mut hash = Sha256::default();
            hash.update(SUITE_STRING);
            hash.update([0x03]);

            // The cofactor of the Ristretto group is 8
            hash.update((self.gamma * RistrettoScalar::from(8)).compress());
            hash.finalize().digest
        }
    }
}
