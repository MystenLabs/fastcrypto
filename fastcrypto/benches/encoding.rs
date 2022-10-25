// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod encoding_benches {
    use super::*;
    use criterion::*;
    use faster_hex::{
        hex_decode, hex_decode_fallback, hex_decode_unchecked, hex_encode_fallback, hex_string,
    };
    use rustc_hex::{FromHex, ToHex};

    struct TestMessage<'a> {
        name: &'a str,
        value: &'a [u8],
    }

    const TEST_MESSAGES: &[TestMessage] = &[
        TestMessage {
            name: "MSG_20B_ZERO",
            value: &[0u8; 20],
        },
        TestMessage {
            name: "MSG_32B_ZERO",
            value: &[0u8; 32],
        },
        TestMessage {
            name: "MSG_20B_RANDOM",
            value: b"this is a random msg",
        },
        TestMessage {
            name: "MSG_32B_RANDOM",
            value: b"this is a random msg: (32B long)",
        },
    ];

    // TODO: atm we compare against hex encoding crates only, please add base64, bech32, base58 and
    //  base58check.
    fn encode(c: &mut Criterion) {
        for test_message in TEST_MESSAGES {
            c.bench_function(
                &("rustc_hex_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret: String = test_message.value.to_hex();
                        black_box(ret);
                    })
                },
            );

            c.bench_function(&("hex_encode_".to_owned() + test_message.name), move |b| {
                b.iter(|| {
                    let ret = hex::encode(test_message.value);
                    black_box(ret);
                })
            });

            c.bench_function(
                &("faster_hex_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret = hex_string(test_message.value);
                        black_box(ret);
                    })
                },
            );

            c.bench_function(
                &("faster_hex_encode_fallback_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let bytes = test_message.value;
                        let mut buffer = vec![0; bytes.len() * 2];
                        hex_encode_fallback(bytes, &mut buffer);
                    })
                },
            );
        }
    }

    // TODO: atm we compare against hex decoding crates only, please add base64, bech32, base58 and
    //  base58check.
    fn decode(c: &mut Criterion) {
        for test_message in TEST_MESSAGES {
            c.bench_function(
                &("rustc_hex_decode_".to_owned() + test_message.name),
                move |b| {
                    let hex: String = test_message.value.to_hex();
                    b.iter(|| {
                        let ret: Vec<u8> = hex.from_hex().unwrap();
                        black_box(ret);
                    })
                },
            );

            c.bench_function(&("hex_decode_".to_owned() + test_message.name), move |b| {
                let hex: String = test_message.value.to_hex();
                b.iter(|| {
                    let ret: Vec<u8> = hex::decode(&hex).unwrap();
                    black_box(ret);
                })
            });

            c.bench_function(
                &("faster_hex_decode_".to_owned() + test_message.name),
                move |b| {
                    let hex: String = test_message.value.to_hex();
                    let len = test_message.value.len();
                    b.iter(|| {
                        let mut dst = vec![0; len];
                        dst.resize(len, 0);
                        hex_decode(hex.as_bytes(), &mut dst).unwrap();
                    })
                },
            );

            c.bench_function(
                &("faster_hex_decode_unchecked_".to_owned() + test_message.name),
                move |b| {
                    let hex: String = test_message.value.to_hex();
                    let len = test_message.value.len();
                    b.iter(|| {
                        let mut dst = vec![0; len];
                        dst.resize(len, 0);
                        hex_decode_unchecked(hex.as_bytes(), &mut dst);
                    })
                },
            );

            c.bench_function(
                &("faster_hex_decode_fallback_".to_owned() + test_message.name),
                move |b| {
                    let hex: String = test_message.value.to_hex();
                    let len = test_message.value.len();
                    b.iter(|| {
                        let mut dst = vec![0; len];
                        dst.resize(len, 0);
                        hex_decode_fallback(hex.as_bytes(), &mut dst);
                    })
                },
            );
        }
    }

    criterion_group! {
        name = encoding_benches;
        config = Criterion::default();
        targets =
            encode,
            decode,
    }
}

criterion_main!(encoding_benches::encoding_benches,);
