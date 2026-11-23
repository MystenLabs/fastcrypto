// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Verifies Groth16 proofs on BN254 or BLS12-381 the way Sui's `verify_groth16_proof_internal`
//! Move native does it, and prepares verifying keys the way `prepare_verifying_key_internal` does.
//! Each of the six inputs of verification (the four parts of a prepared verifying key, the public
//! inputs and the proof) and the verifying key are arbitrary bytes or a fixed valid input,
//! possibly changed.
//!
//! Invariants: nothing panics; on BLS12-381, verification agrees with arkworks; inputs only verify
//! with the fixed prepared verifying key and public inputs (the proof may change, since Groth16
//! proofs are malleable); and when a key prepares, `get_public_inputs_num` doesn't report fewer
//! public inputs than the key has. Sui checks the latter against its limit before preparing.

#![no_main]

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalDeserialize;
use arbitrary::Arbitrary;
use fastcrypto_zkp::bn254::verifier::PreparedVerifyingKey as Bn254PreparedVerifyingKey;
use fastcrypto_zkp::{bls12381, bn254};
use hex_literal::hex;
use libfuzzer_sys::fuzz_target;

/// Valid inputs: a verifying key in arkworks' format with one public input, and the four parts of
/// a prepared verifying key for two public inputs with a proof for them, from the tests of
/// fastcrypto-zkp.
const BN254_VK: &[u8] = &hex!("3c747dd28b1d21b2be3dae04a8c88152d2a5cec5efc800f7a4feea5f938e248298b4d9f57babfa38799f78172df2c303a754945bba9235b39be37826e4c15b273a0f051b814c50a489f6845bfe80521a1e99fbce0c6fda1ba521d4c29ea8d29e3cb543973711905d0cda7dee3c71e7b9460c34e9e7285e03d5fa519e2986a428754b79e5ddb20de39d9afb7b901b4a60c2366c20e658b476206a1710f99146914633127ccae0e459b3d2a8aa39db9a6d5aa91b5f7038bc2bbd7e9e713e6a9b2fb254de7356d1b449f95168ed30e5570715367c99b0e07fd8595517cdb042432b0200000000000000ada96147db3a3bef28beecff2d9bf2814bf07a62722e69486b6e2c3cd26844ac0779d941feabcdc6ae03c87f33fc46877f0261428e29bbf1087e8f858e1dfa88");
const BN254_PVK: [&[u8]; 4] = [
    &hex!("df35140d037b211901de04f62a417c53c304328304d738bcc4ff623b1e65698765c6fa5f804bac35ce67f2c26e37bd0cba6f8a944a6c8c17a2417c7b88254f000f87f4f3b509521fbd63e8460ef9082880ada8f342803fd2188e5ce75bbb0d06"),
    &hex!("b51f110c1840d39a3185436f5307ad47b375ff892acd78cfa2939556eb46d22112f76ffdd8f3be5fabcc44df3a6750edaaf65af3218f58988afedf6b4202b41066a18f1a8e6b06194838ab7331524da9389802cfd1cc87ef800cbf927fe65e1009fd4d603bf4790371ea2272d17f9a1d98f790b04af2fef1f35889b7e54cc210ce1e47a6ecece6f9d20e8c4514db8f74b96db01cd3528e49faf67d40b7e18f12cd4aadf7698d3fbca9d5a660f677a8c9bba800d3a125c9431e151fa9120c9d07c80d5f662fd6630f1c7441ce7c2f65cad89898222976d519fcadcd9a9beb7120625ee32258e4436e31b4661521c68dbd78027a0935423f2f3b74087c3dcc4b15f8c23a499e1b2e0e456d24274eb7e5c2a0ca3338c5e4ec4d31fd3392c32c790e05142edd5fe2e671260f33318826f2ce0e0cbadb2d347a1644d14824a1f2f402c2740188daef879da5139d06160b1bd44788a272e92d33553631cbc9db991f18606ba945064aff9ec7c0d6d0fde961d834783008718783f67c778dd952b1270f"),
    &hex!("04d7dbe72328896134ed56890042202827ce6805cd384ab00afa0997b26a8d0905b8d48c57bcbc7e9d8a2ff6771a50f90d96970636a9e7d89aaf7369ce7e4d9f"),
    &hex!("06639a71c443532e6c7797e0b18926ea09962bd2fdad9a7130df397463afd315b4bfda26cbef66c4f62f6e65a90d70f058df1f57216846e93890f9b2be68ce85"),
];
const BN254_PUBLIC_INPUTS: &[u8] = &hex!("7b00000000000000000000000000000000000000000000000000000000000000c801000000000000000000000000000000000000000000000000000000000000");
const BN254_PROOF: &[u8] = &hex!("537a1b8ba0fc0f2b456c59769a58f22fbf9228311f5cc9070e7358e28c51d2033984c58d47b747c7e07bc87520f14e19029042259a21a910040b87533bf3c32613261dbeffd2913f3627895532b49e9cf623fdfa94e4ef9c040086b397ad640c54c165811c46fa50a880a7b8616d2165848b8f631db25b1b1ebf7fe021f4a11a");
const BLS12381_VK: &[u8] = &hex!("a84d039ad1ae98eeeee4c8ba9af9b6c5d1cfcb98c3fc92ccfcebd77bcccffa1d170d39da29e9b4aa83b98680cb90bb25946b2b70f9e3565510c5361d5d65cb458a0b3177d612dd340b8f8f8493c2772454e3e8f577a3f77865df851d1a159b800c2ec5bae889029fc419678e83dee900465d60e7ef26f614940e719c6f7c0c7db57464fa0481a93c18d52cb2fbf8dcf0a398b153643614fc1071a54e288edb6402f1d9e00d3408c76d95c16885cc992dff5c6ebee3b739cb22359ab2d126026a1626c43ea7b898a7c1d2904c1bd4bbce5d0b1b16fab8535a52d1b08a5217df2e912ee1b0f4140892afa31d479f78dfbc82ab58a209ad00df6c86ab14841e8daa7a380a6853f28bacf38aad9903b6149fff4b119dea16de8aa3e5050b9d563a01009e061a950c233f66511c8fae2a8c58503059821df7f6defbba8f93d26e412cc07b66a9f3cdd740cce5c8488ce94fc8020000000000000081aabea18713222ac45a6ef3208a09f55ce2dde8a11cc4b12788be2ae77ae318176d631d36d80942df576af651b57a31a95f2e9bcaebbb53a588251634715599f7a7e9d51fe872fe312edf0b39d98f0d7f8b5554f96f759c041ea38b4b1e5e19");
const BLS12381_PVK: [&[u8]; 4] = [
    &hex!("896f65ec302f346365c3ebdf8812aa98dc003bd93c663f72d8f9cbb9f2b73b3a1ba0bad12678af22378ac625d414dda8a44e2ed104340b4d9e03fba0e2a3d27efcdfa41fcec60b1071c17089247d6b690bb18fccaccf8a3c0bd8416a160c7c8f8fcdf3f68ae2c9c84d4bc13ef6a64fb865ae36f077f45ee37fa4ebd43da333420a6102befa7fc2fc0c7e85d3722db89a"),
    &hex!("ce35f0234d308739dabe6687ea37d794a6542c802fde201625c6d4c55daf9a15fbdc6628b1a8d6db7fb930c58252750e61af062aeba4ea368bc95999f87dbd93995cfc0bd9c539844c3633b6f58951a9988bf1d96b49ef0aca6c98c84a16850557afaebb7e9c2b926ee436a96a3611161605d438b86a1d9933d87afbdaa9cace569b810ded82ec6f23801c3df1bd8203513fec813d706f23e5afe0187fa552d6ea8547e1b82740858e9ef4139ad9a952303a63395461dc7d78e05688afe2c50860ca60a5564f00344cbecdc4ce94ac9fb41106642d7c3d6445d6607b9b963cd05975f4ba9b4674159b5b7458092fce0f532f1a8dfd76aca31d3978a651e020dcd3577674cba022733afb97d96b91f8cc5590ea4147d6130fb24895210b5e2d02d37dcf6b30245ef98543086859016b1f38d56f79100fc608339367b9bf9608e8175e4e602c853281805cb110a1ea2a0ef8c7aa220a49224b2a7de996996d2350dce3905e6cd1e6ab850f3ccccefc1c0b84baa13c9054b32d0d42f869d17f6c06e6831e11b2e65d07fad4b25eb540630505d23635ef1effb35626042c394190d5c5b9062f296546cd5517c9a8352a4310b5469e4321cc1d86db15d6475c1d0652f8e57c220cfe8eb798b3595a516c51bcea81efb0d8dace2521bae3537d721919e8dbb45fbf2ecf47e7483c7d725dbb47ec191c5bf6de4f7487b23fc1c04c6ba7ce2001d64f6236d025b88aaadecdde1482812836fc6f4d6efcbeae1ba2836b5c57399c28b0f58649bf6c7a743bb2e1469d348e1bcfc75ff18976d825d72ab716"),
    &hex!("89a91d003a78b3580981407bfd5c1f70b329f7b7479fbbd244be8729def2a3538901ff7be9320cf6f9773e7ba4c2712a0b9061adfd335bf4e378414fe788766e8feb5cdf2a0e5368c8451a40ce1b1c54e5c0e997a37e1e97b228ac222ae49b95"),
    &hex!("8b0624cf881e828bd01eabe53992962f3bd9e444375900ed2a875a74c705597f80d5c77c5f698346082ca0dda33344f7059702c4ea9044f417e44575337b6d2f85202160a00c30d62a02ad84abc0dcbda1a834fb73021a1c500b0f021e41f868"),
];
const BLS12381_PUBLIC_INPUTS: &[u8] = &hex!("7b00000000000000000000000000000000000000000000000000000000000000c801000000000000000000000000000000000000000000000000000000000000");
const BLS12381_PROOF: &[u8] = &hex!("826a9c4a653a73bda4782c5ea566e1eb556cd516a820566ec3237f2bf50432777a11c32480ad09d9f7395785cbd4a338a53c93a906cb947d94a07524a57c852cc9daff85d50e6597327a12dd6b588dd39771e87e37ac276d59125714a15d0af204bff8ede3d42b85b8c76b842ae88209113afc886d8f9875ade9293c9059ecfe8a5483b023eb845f20cd0f422e8acdbba51e23ccf4feeaf82a05efd7b803cc9d7244cb53c119a1e4695b945e2663bfc90c639a6ec39237a01a24958585438ab3");

const BLS12381_G1_SIZE: usize = 48;
const BLS12381_SCALAR_SIZE: usize = 32;

/// One of the inputs: arbitrary bytes, or the fixed input, possibly changed.
#[derive(Arbitrary, Debug)]
enum Part {
    Raw(Vec<u8>),
    Fixed,
    SetByte(u16, u8),
    Truncate(u16),
    Append(Vec<u8>),
}

impl Part {
    fn bytes(&self, fixed: &[u8]) -> Vec<u8> {
        let mut bytes = fixed.to_vec();
        match self {
            Part::Raw(raw) => bytes = raw.clone(),
            Part::Fixed => (),
            Part::SetByte(index, value) => bytes[*index as usize % fixed.len()] = *value,
            Part::Truncate(len) => bytes.truncate(*len as usize % fixed.len()),
            Part::Append(suffix) => bytes.extend(suffix),
        }
        bytes
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    bls12381: bool,
    parts: [Part; 6],
    /// Replaces a proof (A, B, C) by (-A, -B, C), which verifies iff (A, B, C) does, by flipping
    /// the sign flags of A and B.
    negate_proof: bool,
    vk: Part,
}

/// Flips the sign flags of A and B in a proof (A, B, C), if it is long enough.
fn negate_proof(proof: &mut [u8], bls12381: bool) {
    // Arkworks' BN254 points have the flag in the top bit of their last byte, and zcash's
    // BLS12-381 points in the third bit of their first byte.
    let (positions, flag) = if bls12381 {
        ([0, 48], 0x20)
    } else {
        ([31, 95], 0x80)
    };
    if proof.len() > positions[1] {
        positions.iter().for_each(|i| proof[*i] ^= flag);
    }
}

/// Decodes a concatenation of compressed arkworks values of the given size.
fn decode_all<T: CanonicalDeserialize>(bytes: &[u8], size: usize) -> Option<Vec<T>> {
    if !bytes.len().is_multiple_of(size) {
        return None;
    }
    bytes
        .chunks(size)
        .map(|chunk| T::deserialize_compressed(chunk).ok())
        .collect()
}

/// Groth16 verification on BLS12-381 with arkworks, an independent implementation, or `None` if
/// the inputs don't decode. Wrong numbers of public inputs don't verify.
fn ark_verify(parts: &[Vec<u8>; 6]) -> Option<bool> {
    let [vk_gamma_abc, alpha_beta, gamma_neg, delta_neg, public_inputs, proof] = parts;
    let vk_gamma_abc: Vec<G1Affine> = decode_all(vk_gamma_abc, BLS12381_G1_SIZE)?;
    let alpha_beta = PairingOutput::<Bls12_381>::deserialize_compressed(&alpha_beta[..]).ok()?;
    let gamma_neg = G2Affine::deserialize_compressed(&gamma_neg[..]).ok()?;
    let delta_neg = G2Affine::deserialize_compressed(&delta_neg[..]).ok()?;
    let public_inputs: Vec<Fr> = decode_all(public_inputs, BLS12381_SCALAR_SIZE)?;
    let proof = ark_groth16_proof(proof)?;
    if vk_gamma_abc.len() != public_inputs.len() + 1 {
        return Some(false);
    }
    let prepared_inputs = public_inputs
        .iter()
        .zip(&vk_gamma_abc[1..])
        .fold(vk_gamma_abc[0].into_group(), |sum, (x, g)| sum + *g * x)
        .into_affine();
    let lhs = Bls12_381::multi_pairing(
        [proof.0, prepared_inputs, proof.2],
        [proof.1, gamma_neg, delta_neg],
    );
    Some(lhs == alpha_beta)
}

/// A BLS12-381 proof (A, B, C), which must have the exact length.
fn ark_groth16_proof(bytes: &[u8]) -> Option<(G1Affine, G2Affine, G1Affine)> {
    if bytes.len() != 192 {
        return None;
    }
    Some((
        G1Affine::deserialize_compressed(&bytes[..48]).ok()?,
        G2Affine::deserialize_compressed(&bytes[48..144]).ok()?,
        G1Affine::deserialize_compressed(&bytes[144..]).ok()?,
    ))
}

fn verify(parts: &[Vec<u8>; 6], bls12381: bool) -> Result<bool, fastcrypto::error::FastCryptoError> {
    let [vk_gamma_abc, alpha_beta, gamma_neg, delta_neg, public_inputs, proof] = parts;
    let verify = if bls12381 {
        bls12381::api::verify_groth16_in_bytes
    } else {
        bn254::api::verify_groth16_in_bytes
    };
    verify(vk_gamma_abc, alpha_beta, gamma_neg, delta_neg, public_inputs, proof)
}

fuzz_target!(|input: Input| {
    let (fixed_pvk, fixed_public_inputs, fixed_proof, fixed_vk) = if input.bls12381 {
        (BLS12381_PVK, BLS12381_PUBLIC_INPUTS, BLS12381_PROOF, BLS12381_VK)
    } else {
        (BN254_PVK, BN254_PUBLIC_INPUTS, BN254_PROOF, BN254_VK)
    };
    let fixed = [
        fixed_pvk[0],
        fixed_pvk[1],
        fixed_pvk[2],
        fixed_pvk[3],
        fixed_public_inputs,
        fixed_proof,
    ];
    let mut parts: [Vec<u8>; 6] = std::array::from_fn(|i| input.parts[i].bytes(fixed[i]));
    if input.negate_proof {
        negate_proof(&mut parts[5], input.bls12381);
    }

    let result = verify(&parts, input.bls12381);
    if input.bls12381 {
        if let Ok(result) = result {
            assert_eq!(ark_verify(&parts), Some(result), "disagrees with arkworks");
        }
    }
    if result == Ok(true) {
        // Public inputs have a single encoding. On BN254, the prepared verifying key may have
        // others, see the tests of fastcrypto-zkp.
        assert_eq!(parts[4], fixed[4], "verified other public inputs");
        if input.bls12381 {
            assert!(parts[..4].iter().eq(&fixed[..4]), "verified another key");
        } else {
            assert_eq!(
                Bn254PreparedVerifyingKey::deserialize(&parts[..4]).unwrap(),
                Bn254PreparedVerifyingKey::deserialize(&fixed[..4]).unwrap(),
                "verified another key"
            );
        }
    }

    let vk = input.vk.bytes(fixed_vk);
    let (prepared, num_public_inputs) = if input.bls12381 {
        (
            bls12381::api::prepare_pvk_bytes(&vk),
            bls12381::api::get_public_inputs_num(vk.len()),
        )
    } else {
        (
            bn254::api::prepare_pvk_bytes(&vk),
            bn254::api::get_public_inputs_num(vk.len()),
        )
    };
    if let (Ok(pvk), Ok(num_public_inputs)) = (prepared, num_public_inputs) {
        let g1_size = if input.bls12381 { BLS12381_G1_SIZE } else { 32 };
        assert!(pvk[0].len() / g1_size <= num_public_inputs + 1);
    }
});
