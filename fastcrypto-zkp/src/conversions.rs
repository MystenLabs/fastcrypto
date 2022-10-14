// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_ff::{Fp384, FromBytes, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeWithFlags, EmptyFlags};
use blst::{blst_fp, blst_fp12, blst_fp6, blst_fp_from_lendian, blst_p1_affine};
use blst::{blst_fp2, blst_p1_deserialize};
use blst::{blst_p1_affine_serialize, blst_uint64_from_fp};
use blst::{blst_p2_affine, blst_p2_affine_serialize, blst_p2_deserialize, BLST_ERROR};
use byte_slice_cast::AsByteSlice;

use ark_bls12_381::{Fq, Fq2, Fr as BlsFr};
use ark_bls12_381::{Fq12, G2Affine as BlsG2Affine};
use ark_bls12_381::{Fq6, G1Affine as BlsG1Affine};

use blst::{blst_fr, blst_fr_from_uint64, blst_uint64_from_fr};

const SCALAR_SIZE: usize = 32;
const G1_UNCOMPRESSED_SIZE: usize = 96;
const G2_UNCOMPRESSED_SIZE: usize = 192;

#[inline]
fn u64s_from_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

// Scalar Field conversions
pub fn bls_fr_to_blst_fr(fe: &BlsFr) -> blst_fr {
    debug_assert_eq!(fe.serialized_size(), SCALAR_SIZE);
    let mut bytes = [0u8; SCALAR_SIZE];
    fe.serialize_with_flags(&mut bytes[..], EmptyFlags).unwrap();

    let mut out = blst_fr::default();
    let bytes_u64 = u64s_from_bytes(&bytes);

    unsafe { blst_fr_from_uint64(&mut out, bytes_u64.as_ptr()) };
    out
}

pub fn blst_fr_to_bls_fr(fe: &blst_fr) -> BlsFr {
    let mut out = [0u64; 4];
    unsafe { blst_uint64_from_fr(out.as_mut_ptr(), fe) };
    let bytes = out.as_byte_slice();

    BlsFr::from_le_bytes_mod_order(bytes)
}

// Base Field conversions
pub fn bls_fq_to_blst_fp(f: &Fq) -> blst_fp {
    let mut fp_bytes_le = [0u8; G1_UNCOMPRESSED_SIZE / 2];
    f.serialize_uncompressed(&mut fp_bytes_le[..])
        .expect("fp size correct");

    let mut blst_fp = blst_fp::default();
    unsafe {
        blst_fp_from_lendian(&mut blst_fp, fp_bytes_le.as_ptr());
    }
    blst_fp
}

pub fn blst_fp_to_bls_fq(f: &blst_fp) -> Fq {
    let mut out = [0u64; 6];
    unsafe { blst_uint64_from_fp(out.as_mut_ptr(), f) };
    let bytes = out.as_byte_slice();
    <Fq as FromBytes>::read(bytes).unwrap()
}

// QFE conversions
pub fn bls_fq2_to_blst_fp2(f: &Fq2) -> blst_fp2 {
    let mut fp_bytes_le = [0u8; G2_UNCOMPRESSED_SIZE / 2];
    f.serialize_uncompressed(&mut fp_bytes_le[..])
        .expect("fp size correct");

    blst_fp2 {
        fp: fp_bytes_le
            .chunks(48)
            .map(|fp_bytes| {
                let mut blst_fp = blst_fp::default();
                unsafe {
                    blst_fp_from_lendian(&mut blst_fp, fp_bytes.as_ptr());
                }
                blst_fp
            })
            .collect::<Vec<blst_fp>>()
            .try_into()
            .unwrap(),
    }
}

pub fn blst_fp2_to_bls_fq2(f: &blst_fp2) -> Fq2 {
    let [fp1, fp2] = f.fp;
    let bls_fp1 = blst_fp_to_bls_fq(&fp1);
    let bls_fp2 = blst_fp_to_bls_fq(&fp2);
    Fq2::new(bls_fp1, bls_fp2)
}

// Target Field conversions
pub fn bls_fq6_to_blst_fp6(f: &Fq6) -> blst_fp6 {
    let c0 = bls_fq2_to_blst_fp2(&f.c0);
    let c1 = bls_fq2_to_blst_fp2(&f.c1);
    let c2 = bls_fq2_to_blst_fp2(&f.c2);
    blst_fp6 { fp2: [c0, c1, c2] }
}

pub fn blst_fp6_to_bls_fq6(f: &blst_fp6) -> Fq6 {
    let c0 = blst_fp2_to_bls_fq2(&f.fp2[0]);
    let c1 = blst_fp2_to_bls_fq2(&f.fp2[1]);
    let c2 = blst_fp2_to_bls_fq2(&f.fp2[2]);
    Fq6::new(c0, c1, c2)
}

pub fn bls_fq12_to_blst_fp12(f: &Fq12) -> blst_fp12 {
    let c0 = bls_fq6_to_blst_fp6(&f.c0);
    let c1 = bls_fq6_to_blst_fp6(&f.c1);
    blst_fp12 { fp6: [c0, c1] }
}

pub fn blst_fp12_to_bls_fq12(f: &blst_fp12) -> Fq12 {
    let c0 = blst_fp6_to_bls_fq6(&f.fp6[0]);
    let c1 = blst_fp6_to_bls_fq6(&f.fp6[1]);
    Fq12::new(c0, c1)
}

/// Affine point translations: those mostly allow us to receive the
/// proof points, provided in affine form.
pub fn bls_g1_affine_to_blst_g1_affine(pt: &BlsG1Affine) -> blst_p1_affine {
    debug_assert_eq!(pt.uncompressed_size(), G1_UNCOMPRESSED_SIZE);
    let tmp_p1 = blst_p1_affine {
        x: bls_fq_to_blst_fp(&pt.x),
        y: bls_fq_to_blst_fp(&pt.y),
    };
    // See https://github.com/arkworks-rs/curves/issues/14 for why the double serialize
    // we're in fact applying correct masks that arkworks does not use. This may be solved alternatively using
    // https://github.com/arkworks-rs/algebra/issues/308 in a later release of arkworks
    let mut tmp2 = [0u8; 96];
    unsafe {
        blst_p1_affine_serialize(tmp2.as_mut_ptr(), &tmp_p1);
    };
    let mut g1 = blst_p1_affine::default();

    assert!(unsafe { blst_p1_deserialize(&mut g1, tmp2.as_ptr()) } == BLST_ERROR::BLST_SUCCESS);
    g1
}

pub fn blst_g1_affine_to_bls_g1_affine(pt: &blst_p1_affine) -> BlsG1Affine {
    let mut out = [0u8; G1_UNCOMPRESSED_SIZE];
    unsafe {
        blst_p1_affine_serialize(out.as_mut_ptr(), pt);
    }
    let infinity = out[0] & (1 << 6) != 0;
    BlsG1Affine::new(
        Fp384::from_be_bytes_mod_order(&out[..48]),
        Fp384::from_be_bytes_mod_order(&out[48..]),
        infinity,
    )
}

pub fn bls_g2_affine_to_blst_g2_affine(pt: &BlsG2Affine) -> blst_p2_affine {
    debug_assert_eq!(pt.uncompressed_size(), G2_UNCOMPRESSED_SIZE);
    let tmp_p2 = blst_p2_affine {
        x: bls_fq2_to_blst_fp2(&pt.x),
        y: bls_fq2_to_blst_fp2(&pt.y),
    };
    // See https://github.com/arkworks-rs/curves/issues/14 for why the double serialize
    // we're in fact applying correct masks that arkworks does not use. This may be solved alternatively using
    // https://github.com/arkworks-rs/algebra/issues/308 in a later release of arkworks
    let mut tmp2 = [0u8; G2_UNCOMPRESSED_SIZE];
    unsafe {
        blst_p2_affine_serialize(tmp2.as_mut_ptr(), &tmp_p2);
    };

    let mut g2 = blst_p2_affine::default();
    assert!(unsafe { blst_p2_deserialize(&mut g2, tmp2.as_ptr()) } == BLST_ERROR::BLST_SUCCESS);
    g2
}

pub fn blst_g2_affine_to_bls_g2_affine(pt: &blst_p2_affine) -> BlsG2Affine {
    let ptx = blst_fp2_to_bls_fq2(&pt.x);
    let pty = blst_fp2_to_bls_fq2(&pt.y);

    // TODO: surely there's a better way to do this?
    let mut out = [0u8; G2_UNCOMPRESSED_SIZE];
    unsafe {
        blst_p2_affine_serialize(out.as_mut_ptr(), pt);
    }
    let infinity = out[0] & (1 << 6) != 0;
    BlsG2Affine::new(ptx, pty, infinity)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_bls12_381::{FqParameters, Fr as BlsFr};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::Field;
    use blst::{
        blst_encode_to_g1, blst_encode_to_g2, blst_fp_from_uint64, blst_fr, blst_fr_from_uint64,
        blst_p1, blst_p1_to_affine, blst_p2, blst_p2_to_affine,
    };
    use proptest::{collection, prelude::*};

    // Scalar roundtrips

    pub(crate) fn arb_bls_fr() -> impl Strategy<Value = BlsFr> {
        collection::vec(any::<u8>(), 32..=32)
            .prop_map(|bytes| BlsFr::from_random_bytes(&bytes[..]))
            .prop_filter("Valid field elements", Option::is_some)
            .prop_map(|opt_fr| opt_fr.unwrap())
            .no_shrink() // this is arbitrary
    }

    fn arb_blst_fr() -> impl Strategy<Value = blst_fr> {
        collection::vec(any::<u64>(), 4..=4)
            .prop_map(|u64s| {
                let mut out = blst_fr::default();
                unsafe { blst_fr_from_uint64(&mut out, u64s[..].as_ptr()) };
                out
            })
            .no_shrink() // this is arbitrary
    }

    proptest! {
        #[test]
        fn roundtrip_bls_fr(b in arb_bls_fr()) {
            let blst_variant = bls_fr_to_blst_fr(&b);
            let roundtrip = blst_fr_to_bls_fr(&blst_variant);
            prop_assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_fr(b in arb_blst_fr()) {
            let bls_variant = blst_fr_to_bls_fr(&b);
            let roundtrip = bls_fr_to_blst_fr(&bls_variant);
            prop_assert_eq!(b, roundtrip);
        }
    }

    // Base field rountrips

    fn arb_bls_fq() -> impl Strategy<Value = Fp384<FqParameters>> {
        collection::vec(any::<u8>(), 48..=48)
            .prop_map(|bytes| Fp384::from_random_bytes(&bytes[..]))
            .prop_filter("Valid field elements", Option::is_some)
            .prop_map(|opt_fr| opt_fr.unwrap())
            .no_shrink() // this is arbitrary
    }

    fn arb_blst_fp() -> impl Strategy<Value = blst_fp> {
        collection::vec(any::<u64>(), 6..=6)
            .prop_map(|u64s| {
                let mut out = blst_fp::default();
                unsafe { blst_fp_from_uint64(&mut out, u64s[..].as_ptr()) };
                out
            })
            .no_shrink() // this is arbitrary
    }

    proptest! {
        #[test]
        fn roundtrip_bls_fq(b in arb_bls_fq()) {
            let blst_variant = bls_fq_to_blst_fp(&b);
            let roundtrip = blst_fp_to_bls_fq(&blst_variant);
            prop_assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_fp(b in arb_blst_fp()) {
            let bls_variant = blst_fp_to_bls_fq(&b);
            let roundtrip = bls_fq_to_blst_fp(&bls_variant);
            prop_assert_eq!(b, roundtrip);
        }
    }

    // QFE roundtrips
    fn arb_bls_fq2() -> impl Strategy<Value = Fq2> {
        (arb_bls_fq(), arb_bls_fq()).prop_map(|(fp1, fp2)| Fq2::new(fp1, fp2))
    }

    fn arb_blst_fp2() -> impl Strategy<Value = blst_fp2> {
        (arb_blst_fp(), arb_blst_fp()).prop_map(|(fp1, fp2)| blst_fp2 { fp: [fp1, fp2] })
    }

    proptest! {
        #[test]
        fn roundtrip_bls_fq2(b in arb_bls_fq2()) {
            let blst_variant = bls_fq2_to_blst_fp2(&b);
            let roundtrip = blst_fp2_to_bls_fq2(&blst_variant);
            prop_assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_fp2(b in arb_blst_fp2()) {
            let bls_variant = blst_fp2_to_bls_fq2(&b);
            let roundtrip = bls_fq2_to_blst_fp2(&bls_variant);
            prop_assert_eq!(b, roundtrip);
        }
    }

    // Target field roundtrips

    fn arb_bls_fq6() -> impl Strategy<Value = Fq6> {
        (arb_bls_fq2(), arb_bls_fq2(), arb_bls_fq2())
            .prop_map(|(f_c0, f_c1, f_c2)| Fq6::new(f_c0, f_c1, f_c2))
    }

    fn arb_blst_fp6() -> impl Strategy<Value = blst_fp6> {
        (arb_blst_fp2(), arb_blst_fp2(), arb_blst_fp2()).prop_map(|(f_c0, f_c1, f_c2)| blst_fp6 {
            fp2: [f_c0, f_c1, f_c2],
        })
    }

    proptest! {
        #[test]
        fn roundtrip_bls_fq6(b in arb_bls_fq6()){
            let blst_variant = bls_fq6_to_blst_fp6(&b);
            let roundtrip = blst_fp6_to_bls_fq6(&blst_variant);
            prop_assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_fp6(b in arb_blst_fp6()){
            let bls_variant = blst_fp6_to_bls_fq6(&b);
            let roundtrip = bls_fq6_to_blst_fp6(&bls_variant);
            prop_assert_eq!(b, roundtrip);
        }
    }

    fn arb_bls_fq12() -> impl Strategy<Value = Fq12> {
        (arb_bls_fq6(), arb_bls_fq6()).prop_map(|(f_c0, f_c1)| Fq12::new(f_c0, f_c1))
    }

    fn arb_blst_fp12() -> impl Strategy<Value = blst_fp12> {
        (arb_blst_fp6(), arb_blst_fp6()).prop_map(|(f_c0, f_c1)| blst_fp12 { fp6: [f_c0, f_c1] })
    }

    proptest! {
        #[test]
        fn roundtrip_bls_fq12(b in arb_bls_fq12()) {
            let blst_variant = bls_fq12_to_blst_fp12(&b);
            let roundtrip = blst_fp12_to_bls_fq12(&blst_variant);
            prop_assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_fp12(b in arb_blst_fp12()) {
            let bls_variant = blst_fp12_to_bls_fq12(&b);
            let roundtrip = bls_fq12_to_blst_fp12(&bls_variant);
            prop_assert_eq!(b, roundtrip);
        }
    }

    // Affine point roundtrips

    pub(crate) fn arb_bls_g1_affine() -> impl Strategy<Value = BlsG1Affine> {
        // slow, but good enough for tests
        arb_bls_fr().prop_map(|s| {
            BlsG1Affine::prime_subgroup_generator()
                .mul(s.into_repr())
                .into_affine()
        })
    }

    pub(crate) fn arb_blst_g1_affine() -> impl Strategy<Value = blst_p1_affine> {
        collection::vec(any::<u8>(), 32..=32).prop_map(|msg| {
            // we actually hash to a G1Projective, then convert to affine
            let mut out = blst_p1::default();
            const DST: [u8; 16] = [0; 16];
            const AUG: [u8; 16] = [0; 16];

            unsafe {
                blst_encode_to_g1(
                    &mut out,
                    msg.as_ptr(),
                    msg.len(),
                    DST.as_ptr(),
                    DST.len(),
                    AUG.as_ptr(),
                    AUG.len(),
                )
            };

            let mut res = blst_p1_affine::default();

            unsafe { blst_p1_to_affine(&mut res, &out) };
            res
        })
    }

    proptest! {
        #[test]
        fn roundtrip_bls_g1_affine(b in arb_bls_g1_affine()) {
            let blst_variant = bls_g1_affine_to_blst_g1_affine(&b);
            let roundtrip = blst_g1_affine_to_bls_g1_affine(&blst_variant);
            assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_g1_affine(b in arb_blst_g1_affine()) {
            let bls_variant = blst_g1_affine_to_bls_g1_affine(&b);
            let roundtrip = bls_g1_affine_to_blst_g1_affine(&bls_variant);
            assert_eq!(b, roundtrip);
        }

    }

    fn arb_bls_g2_affine() -> impl Strategy<Value = BlsG2Affine> {
        // slow, but good enough for tests
        arb_bls_fr().prop_map(|s| {
            BlsG2Affine::prime_subgroup_generator()
                .mul(s.into_repr())
                .into_affine()
        })
    }

    pub(crate) fn arb_blst_g2_affine() -> impl Strategy<Value = blst_p2_affine> {
        collection::vec(any::<u8>(), 32..=32).prop_map(|msg| {
            // we actually hash to a G2Projective, then convert to affine
            let mut out = blst_p2::default();
            const DST: [u8; 16] = [0; 16];
            const AUG: [u8; 16] = [0; 16];

            unsafe {
                blst_encode_to_g2(
                    &mut out,
                    msg.as_ptr(),
                    msg.len(),
                    DST.as_ptr(),
                    DST.len(),
                    AUG.as_ptr(),
                    AUG.len(),
                )
            };

            let mut res = blst_p2_affine::default();

            unsafe { blst_p2_to_affine(&mut res, &out) };
            res
        })
    }

    proptest! {
        #[test]
        fn roundtrip_bls_g2_affine(b in arb_bls_g2_affine()) {
            let blst_variant = bls_g2_affine_to_blst_g2_affine(&b);
            let roundtrip = blst_g2_affine_to_bls_g2_affine(&blst_variant);
            assert_eq!(b, roundtrip);
        }

        #[test]
        fn roundtrip_blst_g2_affine(b in arb_blst_g2_affine()) {
            let bls_variant = blst_g2_affine_to_bls_g2_affine(&b);
            let roundtrip = bls_g2_affine_to_blst_g2_affine(&bls_variant);
            assert_eq!(b, roundtrip);
        }

    }
}
