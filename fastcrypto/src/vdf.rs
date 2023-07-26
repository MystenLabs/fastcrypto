// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;
use crate::error::{FastCryptoError, FastCryptoResult};
use class_group::primitives::vdf::VDF as ExternalVDF;
use curv::arithmetic::Converter;
use curv::BigInt;

pub trait VDF {
    type Output;

    fn evaluate(&self, input: &[u8], difficulty: u64) -> FastCryptoResult<Self::Output>;
    fn verify(&self, input: &[u8], output: &Self::Output, difficulty: u64) -> FastCryptoResult<bool>;
}

pub struct WesolowskiVDF {
    discriminant_size_in_bits: usize,
}

impl WesolowskiVDF {
    pub fn new(discriminant_size_in_bits: usize) -> Self {
        Self {
            discriminant_size_in_bits,
        }
    }
}

impl VDF for WesolowskiVDF {
    type Output = ExternalVDF;

    fn evaluate(&self, input: &[u8], difficulty: u64) -> FastCryptoResult<Self::Output> {
        let x = BigInt::from_bytes(input);
        let ab_triple = ExternalVDF::setup(self.discriminant_size_in_bits, &x);
        let t = BigInt::from(difficulty);

        Ok(ExternalVDF::eval(&ab_triple, &x, &t))
    }

    fn verify(&self, input: &[u8],  output: &ExternalVDF, difficulty: u64) -> FastCryptoResult<bool> {
        if BigInt::from_bytes(input) != output.x || BigInt::from(difficulty) != output.t {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(output.verify().is_ok())
    }
}

#[test]
fn test_wesolowski_vdf() {
    let vdf = WesolowskiVDF::new(4096);
    let input = b"hello world";
    let difficulty = 2500;
    let start = Instant::now();
    let output = vdf.evaluate(input, difficulty).unwrap();
    let duration1 = start.elapsed();
    let start = Instant::now();
    let verified = vdf.verify(input, &output, difficulty).unwrap();
    let duration2 = start.elapsed();
    assert!(verified);
    println!("WesolowskiVDF: evaluate: {:?}, verify: {:?}", duration1, duration2);
}