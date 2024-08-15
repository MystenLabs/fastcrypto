// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::DivAssign;

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;

use crate::class_group::discriminant::{Discriminant, DISCRIMINANT_3072};
use crate::class_group::QuadraticForm;
use crate::math::crt::solve_congruence_equation_system;
use crate::math::hash_prime::hash_prime_with_predicate;
use crate::math::jacobi::jacobi;
use crate::math::modular_sqrt::modular_square_root;
use crate::math::parameterized_group::MapToGroup;

pub struct BasisMapping<const N: usize> {
    basis: [u64; N],
    square_roots: [u64; N],
    security_parameter_in_bytes: u64,
    discriminant: Discriminant,
}

const PRIMES: [u64; 160] = [3, 5, 7, 13, 23, 31, 37, 61, 67, 71, 73, 83, 89, 97, 137, 149, 151, 157, 163, 173, 191, 223, 229, 233, 241, 251, 257, 269, 281, 317, 331, 359, 367, 379, 389, 401, 421, 431, 433, 439, 457, 463, 467, 479, 499, 503, 509, 521, 523, 547, 557, 563, 571, 577, 587, 593, 601, 607, 617, 619, 631, 641, 643, 673, 683, 701, 709, 719, 727, 739, 743, 751, 757, 769, 773, 797, 811, 827, 829, 853, 863, 887, 907, 911, 919, 937, 941, 953, 967, 971, 977, 983, 997, 1009, 1013, 1019, 1031, 1039, 1063, 1069, 1087, 1091, 1097, 1103, 1117, 1123, 1151, 1163, 1171, 1181, 1229, 1237, 1249, 1277, 1279, 1301, 1367, 1381, 1427, 1439, 1459, 1471, 1487, 1523, 1543, 1559, 1571, 1579, 1601, 1607, 1619, 1637, 1663, 1721, 1741, 1747, 1801, 1823, 1831, 1867, 1889, 1901, 1933, 1949, 1951, 1973, 1979, 1987, 1997, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2099, 2111, 2113, 2131];
const SQUARE_ROOTS: [u64; 160] = [1, 3, 4, 11, 3, 9, 9, 15, 35, 54, 59, 17, 40, 49, 132, 71, 69, 125, 36, 71, 154, 200, 126, 209, 11, 222, 50, 137, 94, 219, 234, 88, 181, 148, 255, 339, 138, 54, 205, 104, 68, 417, 202, 20, 439, 122, 222, 109, 44, 165, 338, 303, 61, 572, 360, 319, 418, 102, 550, 205, 609, 435, 29, 198, 76, 466, 349, 592, 399, 531, 437, 673, 595, 30, 483, 646, 167, 607, 294, 623, 152, 703, 107, 645, 392, 382, 152, 315, 873, 254, 98, 439, 490, 316, 636, 858, 179, 882, 288, 923, 814, 74, 867, 272, 241, 1000, 203, 858, 374, 803, 977, 707, 638, 648, 115, 1235, 515, 1367, 333, 936, 328, 980, 63, 202, 634, 662, 86, 368, 837, 872, 342, 1444, 359, 1243, 246, 1695, 1216, 1274, 1491, 1009, 115, 1192, 422, 267, 1220, 1968, 1395, 551, 1673, 1133, 70, 981, 1154, 1196, 287, 1654, 2009, 1689, 1929, 255];

impl <const N: usize> MapToGroup<QuadraticForm> for BasisMapping<N> {

    fn map(&self, data: &[u8]) -> FastCryptoResult<QuadraticForm> {
        if 8*data.len() != N {
            return Err(InvalidInput);
        }

        let mut factors = Vec::new();
        let mut square_roots = Vec::new();

        let hash = hash_to_prime(&data, &self.discriminant, self.security_parameter_in_bytes);
        square_roots.push(modular_square_root(&self.discriminant.as_bigint(), &hash.to_bigint().unwrap(), false).unwrap());
        factors.push(hash.to_bigint().unwrap());

        for i in 0..8*data.len() {
            if test_bit(&data, i) {
                factors.push(BigInt::from(self.basis[i]));
                square_roots.push(BigInt::from(self.square_roots[i]));
            }
        }

        let a= factors.iter().product();
        let mut b = solve_congruence_equation_system(&square_roots, &factors)
            .expect("The factors are distinct primes");

        // b must be odd but may be negative
        if b.is_even() {
            b -= &a;
        }
        // TODO: We can use the choice of b to store an extra bit?

        Ok(QuadraticForm::from_a_b_and_discriminant(a, b, &self.discriminant)
            .expect("a and b are constructed such that this never fails"))
    }

    fn inverse(&self, group_element: &QuadraticForm) -> FastCryptoResult<Vec<u8>> {

        let mut message = group_element.a.clone();

        let result = self.basis.chunks(8).map(|chunk| {
            let bits = chunk.iter().map(|p| {
                if message.is_multiple_of(&BigInt::from(*p)) {
                    message.div_assign(BigInt::from(*p));
                    true
                } else {
                    false
                }
            }).collect::<Vec<_>>();
            byte_from_bits(&bits)
        }).collect::<Vec<_>>();

        if message != hash_to_prime(&result, &self.discriminant, self.security_parameter_in_bytes).to_bigint().unwrap() {
            return Err(InvalidInput);
        }

        Ok(result)
    }
}

fn byte_from_bits(bits: &[bool]) -> u8 {
    assert_eq!(bits.len(), 8);
    let mut result = 0u8;
    for i in 0..8 {
        if bits[i] {
            result |= 1 << i
        }
    }
    result
}

fn test_bit(bytes: &[u8], index: usize) -> bool {
    if index >= 8 * bytes.len() {
        return false;
    }
    let byte = index >> 3;
    let shifted = bytes[byte] >> (index & 7);
    shifted & 1 != 0
}

fn hash_to_prime(seed: &[u8], discriminant: &Discriminant, size_in_bytes: u64) -> BigUint {
    hash_prime_with_predicate(seed, size_in_bytes as usize, |p| jacobi(&discriminant.as_bigint(), &p.to_bigint().unwrap()).unwrap() == 1)
}

#[test]
fn test_mapping() {

    let mut message = b"Hello, world!".to_vec();
    message.resize(20, 0);

    let mapping =     BasisMapping {
        basis: PRIMES,
        square_roots: SQUARE_ROOTS,
        security_parameter_in_bytes: 32,
        discriminant: DISCRIMINANT_3072.clone(),
    };

    let qf = mapping.map(&message).unwrap();

    assert!(qf.is_normal());
    assert!(qf.is_reduced_assuming_normal());

    let inverse = mapping.inverse(&qf).unwrap();

    assert_eq!(inverse, message);
}