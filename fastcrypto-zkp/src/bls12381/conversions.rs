// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_ff::{BigInteger384, Fp384, PrimeField, Zero};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeWithFlags, Compress, EmptyFlags};
use blst::{blst_fp, blst_fp12, blst_fp6, blst_fp_from_lendian, blst_p1_affine};
use blst::{blst_fp2, blst_p1_deserialize};
use blst::{blst_p1_affine_serialize, blst_uint64_from_fp};
use blst::{blst_p2_affine, blst_p2_affine_serialize, blst_p2_deserialize, BLST_ERROR};

pub use ark_bls12_381::Fr as BlsFr;
use ark_bls12_381::{Fq, Fq2};
use ark_bls12_381::{Fq12, G2Affine as BlsG2Affine};
use ark_bls12_381::{Fq6, G1Affine as BlsG1Affine};
use ark_ec::AffineRepr;

use ark_serialize::CanonicalDeserialize;
use blst::{blst_fr, blst_fr_from_uint64, blst_uint64_from_fr};
use byte_slice_cast::AsByteSlice;

/// Size of scalar elements.
pub const SCALAR_SIZE: usize = 32;
/// G1 affine point compressed size.
pub const G1_COMPRESSED_SIZE: usize = 48;
const G2_COMPRESSED_SIZE: usize = 96;

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
/// Convert an Arkworks BLS12-381 scalar field element to a blst scalar field element.
pub fn bls_fr_to_blst_fr(fe: &BlsFr) -> blst_fr {
    debug_assert_eq!(fe.serialized_size(Compress::Yes), SCALAR_SIZE);
    let mut bytes = [0u8; SCALAR_SIZE];
    fe.serialize_with_flags(&mut bytes[..], EmptyFlags).unwrap();

    let mut out = blst_fr::default();
    let bytes_u64 = u64s_from_bytes(&bytes);

    unsafe { blst_fr_from_uint64(&mut out, bytes_u64.as_ptr()) };
    out
}

/// Convert a blst scalar field element to an Arkworks BLS12-381 scalar field element.
pub fn blst_fr_to_bls_fr(fe: &blst_fr) -> BlsFr {
    let mut out = [0u64; 4];
    unsafe { blst_uint64_from_fr(out.as_mut_ptr(), fe) };
    let bytes = out.as_byte_slice();

    BlsFr::from_le_bytes_mod_order(bytes)
}

// Base Field conversions
/// Convert an Arkworks BLS12-381 prime field element to a blst prime field element.
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

/// Convert a blst prime field element to an Arkworks BLS12-381 prime field element.
pub fn blst_fp_to_bls_fq(f: &blst_fp) -> Fq {
    let mut out = [0u64; 6];
    unsafe { blst_uint64_from_fp(out.as_mut_ptr(), f) };
    let bytes = out.as_byte_slice();
    Fq::deserialize_compressed(bytes).unwrap()
}

// QFE conversions

/// Convert an Arkworks BLS12-381 quadratic extension field element to a blst quadratic extension
/// field element.
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

/// Convert a blst quadratic extension field element to an Arkworks BLS12-381 quadratic extension
/// field element.
pub fn blst_fp2_to_bls_fq2(f: &blst_fp2) -> Fq2 {
    let [fp1, fp2] = f.fp;
    let bls_fp1 = blst_fp_to_bls_fq(&fp1);
    let bls_fp2 = blst_fp_to_bls_fq(&fp2);
    Fq2::new(bls_fp1, bls_fp2)
}

// Target Field conversions

/// Convert an Arkworks BLS12-381 degree-6 extension field element to a blst degree-6 extension
/// field element.
pub fn bls_fq6_to_blst_fp6(f: &Fq6) -> blst_fp6 {
    let c0 = bls_fq2_to_blst_fp2(&f.c0);
    let c1 = bls_fq2_to_blst_fp2(&f.c1);
    let c2 = bls_fq2_to_blst_fp2(&f.c2);
    blst_fp6 { fp2: [c0, c1, c2] }
}

/// Convert a blst degree-6 extension field element to an Arkworks BLS12-381 degree-6 extension
/// field element.
pub fn blst_fp6_to_bls_fq6(f: &blst_fp6) -> Fq6 {
    let c0 = blst_fp2_to_bls_fq2(&f.fp2[0]);
    let c1 = blst_fp2_to_bls_fq2(&f.fp2[1]);
    let c2 = blst_fp2_to_bls_fq2(&f.fp2[2]);
    Fq6::new(c0, c1, c2)
}

/// Convert an Arkworks BLS12-381 target field element to a blst target field element.
pub fn bls_fq12_to_blst_fp12(f: &Fq12) -> blst_fp12 {
    let c0 = bls_fq6_to_blst_fp6(&f.c0);
    let c1 = bls_fq6_to_blst_fp6(&f.c1);
    blst_fp12 { fp6: [c0, c1] }
}

/// Convert a blst target field element to an Arkworks BLS12-381 target field element.
pub fn blst_fp12_to_bls_fq12(f: &blst_fp12) -> Fq12 {
    let c0 = blst_fp6_to_bls_fq6(&f.fp6[0]);
    let c1 = blst_fp6_to_bls_fq6(&f.fp6[1]);
    Fq12::new(c0, c1)
}

/// Affine point translations: those mostly allow us to receive the
/// proof points, provided in affine form.

fn blst_g1_affine_infinity() -> blst_p1_affine {
    blst_p1_affine {
        x: blst_fp::default(),
        y: blst_fp::default(),
    }
}

fn bls_g1_affine_infinity() -> BlsG1Affine {
    BlsG1Affine::zero()
}

/// Convert an Arkworks BLS12-381 affine G1 point to a blst affine G1 point.
pub fn bls_g1_affine_to_blst_g1_affine(pt: &BlsG1Affine) -> blst_p1_affine {
    debug_assert_eq!(pt.uncompressed_size(), G1_UNCOMPRESSED_SIZE);
    // BLST disagrees with Arkworks on the uncompressed representation of the infinity point on G1
    // https://github.com/supranational/blst/blob/6382d67c72119d563975892ed49ba32e92d3d0da/src/e1.c#L153-L162
    // the infinity bit notwithstanding,
    // Arkworks: x = Fq::zero(), y = Fq::one()
    // BLST: x = y = Fq::zero()
    // BLST follows the standard here (see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-10#appendix-C)
    if pt.infinity {
        return blst_g1_affine_infinity();
    }
    let tmp_p1 = blst_p1_affine {
        x: bls_fq_to_blst_fp(&pt.x),
        y: bls_fq_to_blst_fp(&pt.y),
    };
    // See https://github.com/arkworks-rs/curves/issues/14 for why the double serialize
    // we're in fact applying correct masks that arkworks does not use. This may be solved
    // alternatively using https://github.com/arkworks-rs/algebra/issues/308 in a later release of
    // Arkworks.
    // Note: this is an uncompressed serialization - deserialization.
    let mut tmp2 = [0u8; 96];
    unsafe {
        blst_p1_affine_serialize(tmp2.as_mut_ptr(), &tmp_p1);
    };

    let mut g1 = blst_p1_affine::default();
    debug_assert_eq!(
        unsafe { blst_p1_deserialize(&mut g1, tmp2.as_ptr()) },
        BLST_ERROR::BLST_SUCCESS
    );
    g1
}

/// Convert a blst affine G1 point to an Arkworks BLS12-381 affine G1 point.
pub fn blst_g1_affine_to_bls_g1_affine(pt: &blst_p1_affine) -> BlsG1Affine {
    let mut out = [0u8; G1_UNCOMPRESSED_SIZE];
    unsafe {
        blst_p1_affine_serialize(out.as_mut_ptr(), pt);
    }
    let infinity = out[0] == 0x40;
    // BLST disagrees with Arkworks on the uncompressed representation of the infinity point on G1
    // https://github.com/supranational/blst/blob/6382d67c72119d563975892ed49ba32e92d3d0da/src/e1.c#L153-L162
    // the infinity bit notwithstanding,
    // Arkworks: x = Fq::zero(), y = Fq::one()
    // BLST: x = y = Fq::zero()
    // BLST follows the standard here (see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-10#appendix-C)
    if infinity {
        return bls_g1_affine_infinity();
    }
    let y = Fp384::from_be_bytes_mod_order(&out[48..]);
    let x = {
        // Mask away the flag bits (which Arkworks doesn't use).
        out[0] &= 0b0001_1111;
        Fp384::from_be_bytes_mod_order(&out[..48])
    };
    BlsG1Affine::new(x, y)
}

fn blst_g2_affine_infinity() -> blst_p2_affine {
    blst_p2_affine {
        x: blst_fp2::default(),
        y: blst_fp2::default(),
    }
}

fn bls_g2_affine_infinity() -> BlsG2Affine {
    BlsG2Affine::zero()
}

/// Convert an Arkworks BLS12-381 affine G2 point to a blst affine G2 point.
pub fn bls_g2_affine_to_blst_g2_affine(pt: &BlsG2Affine) -> blst_p2_affine {
    debug_assert_eq!(pt.uncompressed_size(), G2_UNCOMPRESSED_SIZE);
    // BLST disagrees with Arkworks on the uncompressed representation of the infinity point on G2
    // https://github.com/supranational/blst/blob/6382d67c72119d563975892ed49ba32e92d3d0da/src/e2.c#L194-L203
    // the infinity bit notwithstanding,
    // Arkworks: x = Fq2::zero(), y = Fq2::one()
    // BLST: x = y = Fq2::zero()
    // BLST follows the standard here (see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-10#appendix-C)
    if pt.infinity {
        return blst_g2_affine_infinity();
    }
    let tmp_p2 = blst_p2_affine {
        x: bls_fq2_to_blst_fp2(&pt.x),
        y: bls_fq2_to_blst_fp2(&pt.y),
    };
    // See https://github.com/arkworks-rs/curves/issues/14 for why the double serialize
    // we're in fact applying correct masks that arkworks does not use. This may be solved
    // alternatively using https://github.com/arkworks-rs/algebra/issues/308 in a later release of
    // Arkworks.
    // Note: this is an uncompressed serialization - deserialization.
    let mut tmp2 = [0u8; G2_UNCOMPRESSED_SIZE];
    unsafe {
        blst_p2_affine_serialize(tmp2.as_mut_ptr(), &tmp_p2);
    };

    let mut g2 = blst_p2_affine::default();
    debug_assert_eq!(
        unsafe { blst_p2_deserialize(&mut g2, tmp2.as_ptr()) },
        BLST_ERROR::BLST_SUCCESS
    );
    g2
}

/// Convert a blst affine G2 point to an Arkworks BLS12-381 affine G2 point.
pub fn blst_g2_affine_to_bls_g2_affine(pt: &blst_p2_affine) -> BlsG2Affine {
    let ptx = blst_fp2_to_bls_fq2(&pt.x);
    let pty = blst_fp2_to_bls_fq2(&pt.y);

    let infinity = ptx == Fq2::zero();
    // BLST disagrees with Arkworks on the uncompressed representation of the infinity point on G2
    // https://github.com/supranational/blst/blob/6382d67c72119d563975892ed49ba32e92d3d0da/src/e2.c#L194-L203
    // the infinity bit notwithstanding,
    // Arkworks: x = Fq2::zero(), y = Fq2::one()
    // BLST: x = y = Fq2::zero()
    // BLST follows the standard here (see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-10#appendix-C)
    if infinity {
        bls_g2_affine_infinity()
    } else {
        BlsG2Affine::new(ptx, pty)
    }
}

/////////////////////////////////////////////////////////////
// Zcash point encodings to Arkworks points and back       //
/////////////////////////////////////////////////////////////

// The standard for serialization of compressed G1, G2 points of BLS12-381
// is not followed by Arkworks 0.3.0. This is a translation layer to allow
// us to use (and receive) the standard serialization format.
// See section 5.4.9.2 of https://zips.z.cash/protocol/protocol.pdf
// and https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/ Appendix A
// for its choice as a standard.

// A note on BLST: blst uses Zcash point encoding formats across the board.

fn bls_fq_to_zcash_bytes(field: &Fq) -> [u8; G1_COMPRESSED_SIZE] {
    let mut result = [0u8; G1_COMPRESSED_SIZE];

    let rep = field.into_bigint();

    result[0..8].copy_from_slice(&rep.0[5].to_be_bytes());
    result[8..16].copy_from_slice(&rep.0[4].to_be_bytes());
    result[16..24].copy_from_slice(&rep.0[3].to_be_bytes());
    result[24..32].copy_from_slice(&rep.0[2].to_be_bytes());
    result[32..40].copy_from_slice(&rep.0[1].to_be_bytes());
    result[40..48].copy_from_slice(&rep.0[0].to_be_bytes());

    result
}

fn bls_fq_from_zcash_bytes(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Option<Fq> {
    let mut tmp = BigInteger384::default();

    tmp.0[5] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    tmp.0[4] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    tmp.0[3] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    tmp.0[2] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    tmp.0[1] = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    tmp.0[0] = u64::from_be_bytes(bytes[40..48].try_into().unwrap());

    Fq::from_bigint(tmp)
}

struct EncodingFlags {
    is_compressed: bool,
    is_infinity: bool,
    is_lexicographically_largest: bool,
}

impl From<&[u8]> for EncodingFlags {
    fn from(bytes: &[u8]) -> Self {
        Self {
            is_compressed: ((bytes[0] >> 7) & 1) == 1,
            is_infinity: (bytes[0] >> 6) & 1 == 1,
            is_lexicographically_largest: (bytes[0] >> 5) & 1 == 1,
        }
    }
}

impl EncodingFlags {
    fn encode_flags(&self, bytes: &mut [u8]) {
        if self.is_compressed {
            bytes[0] |= 1 << 7;
        }

        if self.is_infinity {
            bytes[0] |= 1 << 6;
        }

        if self.is_compressed && !self.is_infinity && self.is_lexicographically_largest {
            bytes[0] |= 1 << 5;
        }
    }
}

/// This deserializes an Arkworks G1Affine point from a Zcash point encoding.
pub fn bls_g1_affine_from_zcash_bytes(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Option<BlsG1Affine> {
    // Obtain the three flags from the start of the byte sequence.
    let flags = EncodingFlags::from(&bytes[..]);

    if !flags.is_compressed {
        return None; // We only support compressed points.
    }

    if flags.is_infinity {
        return Some(BlsG1Affine::zero());
    }
    // Attempt to obtain the x-coordinate.
    let x = obtain_x_coordinate(bytes.as_slice())?;

    BlsG1Affine::get_point_from_x_unchecked(x, flags.is_lexicographically_largest)
}

/// This serializes an Arkworks G1Affine point into a Zcash point encoding.
pub fn bls_g1_affine_to_zcash_bytes(p: &BlsG1Affine) -> [u8; G1_COMPRESSED_SIZE] {
    let mut result = bls_fq_to_zcash_bytes(&p.x);
    let encoding = EncodingFlags {
        is_compressed: true,
        is_infinity: p.infinity,
        is_lexicographically_largest: p.y > -p.y,
    };
    encoding.encode_flags(&mut result[..]);
    result
}

/// This deserializes an Arkworks G2Affine point from a Zcash point encoding.
pub fn bls_g2_affine_from_zcash_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Option<BlsG2Affine> {
    // Obtain the three flags from the start of the byte sequence
    let flags = EncodingFlags::from(&bytes[..]);

    if !flags.is_compressed {
        return None; // We only support compressed points.
    }

    if flags.is_infinity {
        return Some(BlsG2Affine::default());
    }

    let xc1 = obtain_x_coordinate(bytes.as_slice())?;
    let xc0 = {
        let mut tmp = [0; G1_COMPRESSED_SIZE];
        tmp.copy_from_slice(&bytes[48..96]);

        bls_fq_from_zcash_bytes(&tmp)?
    };

    let x = Fq2::new(xc0, xc1);

    BlsG2Affine::get_point_from_x_unchecked(x, flags.is_lexicographically_largest)
}

/// This serializes an Arkworks G2Affine point into a Zcash point encoding.
pub fn bls_g2_affine_to_zcash_bytes(p: &BlsG2Affine) -> [u8; G2_COMPRESSED_SIZE] {
    let mut bytes = [0u8; G2_COMPRESSED_SIZE];

    let c1_bytes = bls_fq_to_zcash_bytes(&p.x.c1);
    let c0_bytes = bls_fq_to_zcash_bytes(&p.x.c0);
    bytes[0..48].copy_from_slice(&c1_bytes[..]);
    bytes[48..96].copy_from_slice(&c0_bytes[..]);

    let encoding = EncodingFlags {
        is_compressed: true,
        is_infinity: p.infinity,
        is_lexicographically_largest: p.y > -p.y,
    };

    encoding.encode_flags(&mut bytes[..]);
    bytes
}

// Attempt to obtain x_coordinate
fn obtain_x_coordinate(bytes: &[u8]) -> Option<Fq> {
    let mut tmp = [0; G1_COMPRESSED_SIZE];
    // this is safe as the private obtain_x_coordinate function is only invoked with G1 (48) and
    // G2 (96) size inputs.
    tmp.copy_from_slice(&bytes[0..G1_COMPRESSED_SIZE]);

    // Mask away the flag bits
    tmp[0] &= 0b0001_1111;

    bls_fq_from_zcash_bytes(&tmp)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_bls12_381::Fr as BlsFr;
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use blst::{
        blst_encode_to_g1, blst_encode_to_g2, blst_fp_from_uint64, blst_fr, blst_fr_from_uint64,
        blst_p1, blst_p1_affine_compress, blst_p1_to_affine, blst_p1_uncompress, blst_p2,
        blst_p2_affine_compress, blst_p2_to_affine, blst_p2_uncompress,
    };
    use proptest::{collection, prelude::*};
    use std::ops::Mul;

    // Scalar roundtrips.

    pub(crate) fn arb_bls_fr() -> impl Strategy<Value = BlsFr> {
        collection::vec(any::<u8>(), 32..=32)
            .prop_map(|bytes| BlsFr::from_random_bytes(&bytes[..]))
            .prop_filter("Valid field elements", Option::is_some)
            .prop_map(|opt_fr| opt_fr.unwrap())
            .no_shrink() // this is arbitrary.
    }

    fn arb_blst_fr() -> impl Strategy<Value = blst_fr> {
        collection::vec(any::<u64>(), 4..=4)
            .prop_map(|u64s| {
                let mut out = blst_fr::default();
                unsafe { blst_fr_from_uint64(&mut out, u64s[..].as_ptr()) };
                out
            })
            .no_shrink() // this is arbitrary.
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

    // Base field roundtrips.

    fn arb_bls_fq() -> impl Strategy<Value = Fq> {
        collection::vec(any::<u8>(), 48..=48)
            .prop_map(|bytes| Fp384::from_random_bytes(&bytes[..]))
            .prop_filter("Valid field elements", Option::is_some)
            .prop_map(|opt_fr| opt_fr.unwrap())
            .no_shrink() // this is arbitrary.
    }

    fn arb_blst_fp() -> impl Strategy<Value = blst_fp> {
        collection::vec(any::<u64>(), 6..=6)
            .prop_map(|u64s| {
                let mut out = blst_fp::default();
                unsafe { blst_fp_from_uint64(&mut out, u64s[..].as_ptr()) };
                out
            })
            .no_shrink() // this is arbitrary.
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

        #[test]
        fn roundtrip_bls_fq_to_zcash_bytes(b in arb_bls_fq()) {
            let zcash_bytes = bls_fq_to_zcash_bytes(&b);
            let roundtrip = bls_fq_from_zcash_bytes(&zcash_bytes);
            prop_assert_eq!(Some(b), roundtrip);
        }
    }

    // QFE roundtrips.

    fn arb_bls_fq2() -> impl Strategy<Value = Fq2> {
        (arb_bls_fq(), arb_bls_fq())
            .prop_map(|(fp1, fp2)| Fq2::new(fp1, fp2))
            .no_shrink()
    }

    fn arb_blst_fp2() -> impl Strategy<Value = blst_fp2> {
        (arb_blst_fp(), arb_blst_fp())
            .prop_map(|(fp1, fp2)| blst_fp2 { fp: [fp1, fp2] })
            .no_shrink()
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

    // Target field roundtrips.

    fn arb_bls_fq6() -> impl Strategy<Value = Fq6> {
        (arb_bls_fq2(), arb_bls_fq2(), arb_bls_fq2())
            .prop_map(|(f_c0, f_c1, f_c2)| Fq6::new(f_c0, f_c1, f_c2))
            .no_shrink()
    }

    fn arb_blst_fp6() -> impl Strategy<Value = blst_fp6> {
        (arb_blst_fp2(), arb_blst_fp2(), arb_blst_fp2())
            .prop_map(|(f_c0, f_c1, f_c2)| blst_fp6 {
                fp2: [f_c0, f_c1, f_c2],
            })
            .no_shrink()
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
        (arb_bls_fq6(), arb_bls_fq6())
            .prop_map(|(f_c0, f_c1)| Fq12::new(f_c0, f_c1))
            .no_shrink()
    }

    fn arb_blst_fp12() -> impl Strategy<Value = blst_fp12> {
        (arb_blst_fp6(), arb_blst_fp6())
            .prop_map(|(f_c0, f_c1)| blst_fp12 { fp6: [f_c0, f_c1] })
            .no_shrink()
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

    // Affine point roundtrips.

    fn bls_g1_affine_infinity() -> BlsG1Affine {
        BlsG1Affine::zero()
    }

    pub(crate) fn arb_bls_g1_affine() -> impl Strategy<Value = BlsG1Affine> {
        prop_oneof![
            // 1% chance of being the point at infinity.
            1 =>
            Just(bls_g1_affine_infinity()),
            99 =>  // slow, but good enough for tests.
            (arb_bls_fr()).prop_map(|s| {

                    BlsG1Affine::generator()
                        .mul(s)
                        .into()

            })
        ]
    }

    fn blst_g1_affine_infinity() -> blst_p1_affine {
        let mut res = [0u8; G1_UNCOMPRESSED_SIZE];
        res[0] = 0x40;
        let mut g1_infinity = blst_p1_affine::default();
        assert_eq!(
            unsafe { blst_p1_deserialize(&mut g1_infinity, res.as_ptr()) },
            BLST_ERROR::BLST_SUCCESS
        );
        g1_infinity
    }

    pub(crate) fn arb_blst_g1_affine() -> impl Strategy<Value = blst_p1_affine> {
        prop_oneof![
                // 1% chance of being the point at infinity.
                1 => Just(blst_g1_affine_infinity()),
                99 =>
                (collection::vec(any::<u8>(), 32..=32)).prop_map(|msg| {

                        // We actually hash to a G1Projective, then convert to affine.
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
                    }
                )
        ]
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

        #[test]
        fn roundtrip_bls_g1_affine_zcash(b in arb_bls_g1_affine()) {
            let zcash_bytes = bls_g1_affine_to_zcash_bytes(&b);
            let roundtrip = bls_g1_affine_from_zcash_bytes(&zcash_bytes).unwrap();
            assert_eq!(b, roundtrip);
        }

        #[test]
        fn compatibility_bls_blst_g1_affine_serde(b in arb_bls_g1_affine(), bt in arb_blst_g1_affine()) {
            let zcash_bytes = bls_g1_affine_to_zcash_bytes(&b);
            // blst accepts & expects Zcash encodings.
            let mut g1 = blst_p1_affine::default();
            assert_eq!(unsafe { blst_p1_uncompress(&mut g1, zcash_bytes.as_ptr()) }, BLST_ERROR::BLST_SUCCESS);

            // blst produces Zcash encodings.
            let mut tmp2 = [0u8; 48];
            unsafe {
                blst_p1_affine_compress(tmp2.as_mut_ptr(), &bt);
            };
            assert!(bls_g1_affine_from_zcash_bytes(&tmp2).is_some());
        }
    }

    fn bls_g2_affine_infinity() -> BlsG2Affine {
        BlsG2Affine::zero()
    }

    fn arb_bls_g2_affine() -> impl Strategy<Value = BlsG2Affine> {
        // slow, but good enough for tests.
        (arb_bls_fr(), any::<f32>()).prop_map(|(s, maybe_infinity)| {
            if maybe_infinity < 0.1 {
                bls_g2_affine_infinity()
            } else {
                BlsG2Affine::generator().mul(s).into()
            }
        })
    }

    fn blst_g2_affine_infinity() -> blst_p2_affine {
        let mut res = [0u8; G2_UNCOMPRESSED_SIZE];
        res[0] = 0x40;
        let mut g2_infinity = blst_p2_affine::default();
        assert_eq!(
            unsafe { blst_p2_deserialize(&mut g2_infinity, res.as_ptr()) },
            BLST_ERROR::BLST_SUCCESS
        );
        g2_infinity
    }

    pub(crate) fn arb_blst_g2_affine() -> impl Strategy<Value = blst_p2_affine> {
        prop_oneof![
            1 => // 1% chance of being the point at infinity.
                Just(blst_g2_affine_infinity()),
            99 => (collection::vec(any::<u8>(), 32..=32)).prop_map(|msg| {
                // We actually hash to a G2Projective, then convert to affine.
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
        ]
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

        #[test]
        fn roundtrip_bls_g2_affine_zcash(b in arb_bls_g2_affine()) {
            let zcash_bytes = bls_g2_affine_to_zcash_bytes(&b);
            let roundtrip = bls_g2_affine_from_zcash_bytes(&zcash_bytes).unwrap();
            assert_eq!(b, roundtrip);
        }

        #[test]
        fn compatibility_bls_blst_g2_affine_serde(b in arb_bls_g2_affine(), bt in arb_blst_g2_affine()) {
            let zcash_bytes = bls_g2_affine_to_zcash_bytes(&b);
            let mut g2 = blst_p2_affine::default();
            // blst accepts & expects Zcash encodings.
            assert!(unsafe { blst_p2_uncompress(&mut g2, zcash_bytes.as_ptr()) } == BLST_ERROR::BLST_SUCCESS);

            // blst produces Zcash encodings.
            let mut tmp2 = [0u8; 96];
            unsafe {
                blst_p2_affine_compress(tmp2.as_mut_ptr(), &bt);
            };
            assert!(bls_g2_affine_from_zcash_bytes(&tmp2).is_some());
        }
    }
}
