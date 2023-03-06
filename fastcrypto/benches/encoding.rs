// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod encoding_benches {
    use super::*;
    use base64::engine::general_purpose;
    use base64::Engine;
    use base64ct::{Base64 as b64ct, Encoding};
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
            name: "MSG_64B_ZERO",
            value: &[0u8; 64],
        },
        TestMessage {
            name: "MSG_20B_RANDOM",
            value: b"this is a random msg",
        },
        TestMessage {
            name: "MSG_32B_RANDOM",
            value: b"this is a random msg: (32B long)",
        },
        TestMessage {
            name: "MSG_64B_RANDOM",
            value: b"this is a random msg: (64B long)this is a random msg: (64B long)",
        },
    ];

    // Hex encoding bench.
    fn hex_encoding(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Hex encoding");
        for test_message in TEST_MESSAGES {
            group.bench_function(
                &("rustc_hex_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret: String = test_message.value.to_hex();
                        black_box(ret);
                    })
                },
            );

            group.bench_function(&("hex_encode_".to_owned() + test_message.name), move |b| {
                b.iter(|| {
                    let ret = hex::encode(test_message.value);
                    black_box(ret);
                })
            });

            group.bench_function(
                &("faster_hex_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret = hex_string(test_message.value);
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
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

    // Hex decoding bench.
    fn hex_decoding(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Hex decoding");
        for test_message in TEST_MESSAGES {
            group.bench_function(
                &("rustc_hex_decode_".to_owned() + test_message.name),
                move |b| {
                    let hex: String = test_message.value.to_hex();
                    b.iter(|| {
                        let ret: Vec<u8> = hex.from_hex().unwrap();
                        black_box(ret);
                    })
                },
            );

            group.bench_function(&("hex_decode_".to_owned() + test_message.name), move |b| {
                let hex: String = test_message.value.to_hex();
                b.iter(|| {
                    let ret: Vec<u8> = hex::decode(&hex).unwrap();
                    black_box(ret);
                })
            });

            group.bench_function(
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

            group.bench_function(
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

            group.bench_function(
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

    // Base64 encoding bench.
    fn base64_encoding(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Base64 encoding");
        for test_message in TEST_MESSAGES {
            group.bench_function(
                &("base64_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret = general_purpose::STANDARD.encode(test_message.value);
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
                &("base64ct_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret = b64ct::encode_string(test_message.value);
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
                &("radix64_encode_".to_owned() + test_message.name),
                move |b| {
                    b.iter(|| {
                        let ret = radix64::STD.encode(test_message.value);
                        black_box(ret);
                    })
                },
            );
        }
    }

    // Base64 decoding bench.
    fn base64_decoding(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Base64 encoding");
        for test_message in TEST_MESSAGES {
            group.bench_function(
                &("base64_decode_".to_owned() + test_message.name),
                move |b| {
                    let base64_string: String =
                        general_purpose::STANDARD.encode(test_message.value);
                    b.iter(|| {
                        let ret = general_purpose::STANDARD.encode(&base64_string);
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
                &("base64ct_decode_".to_owned() + test_message.name),
                move |b| {
                    let base64_string: String = b64ct::encode_string(test_message.value);
                    b.iter(|| {
                        let ret = b64ct::decode_vec(&base64_string).unwrap();
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
                &("radix64_decode_".to_owned() + test_message.name),
                move |b| {
                    let base64_string: String = radix64::STD.encode(test_message.value);
                    b.iter(|| {
                        let ret = radix64::STD.decode(&base64_string).unwrap();
                        black_box(ret);
                    })
                },
            );
        }
    }

    // Base58 encoding bench.
    fn base58_encoding(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Base58 encoding");
        for test_message in TEST_MESSAGES {
            group.bench_function(&("bs58_encode_".to_owned() + test_message.name), move |b| {
                b.iter(|| {
                    let ret = bs58::encode(test_message.value).into_string();
                    black_box(ret);
                })
            });

            group.bench_function(
                &("base58_encode_".to_owned() + test_message.name),
                move |b| {
                    use base58::ToBase58;
                    b.iter(|| {
                        let ret = test_message.value.to_base58();
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
                &("rust_base58_encode_".to_owned() + test_message.name),
                move |b| {
                    use rust_base58::ToBase58;
                    b.iter(|| {
                        let ret = test_message.value.to_base58();
                        black_box(ret);
                    })
                },
            );
        }
    }

    // Base58 decoding bench.
    fn base58_decoding(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Base58 decoding");
        for test_message in TEST_MESSAGES {
            group.bench_function(&("bs58_decode_".to_owned() + test_message.name), move |b| {
                let base58_string: String = bs58::encode(test_message.value).into_string();
                b.iter(|| {
                    let ret = bs58::decode(&base58_string).into_vec().unwrap();
                    black_box(ret);
                })
            });

            group.bench_function(
                &("base58_decode_".to_owned() + test_message.name),
                move |b| {
                    use base58::{FromBase58, ToBase58};
                    let base58_string: String = test_message.value.to_base58();
                    b.iter(|| {
                        let ret = base58_string.from_base58().unwrap();
                        black_box(ret);
                    })
                },
            );

            group.bench_function(
                &("rust_base58_decode_".to_owned() + test_message.name),
                move |b| {
                    use rust_base58::{FromBase58, ToBase58};
                    let base58_string: String = test_message.value.to_base58();
                    b.iter(|| {
                        let ret = base58_string.from_base58().unwrap();
                        black_box(ret);
                    })
                },
            );
        }
    }

    criterion_group! {
        name = encoding_benches;
        config = Criterion::default();
        targets =
            hex_encoding,
            hex_decoding,
            base64_encoding,
            base64_decoding,
            base58_encoding,
            base58_decoding,
    }
}

criterion_main!(encoding_benches::encoding_benches,);
