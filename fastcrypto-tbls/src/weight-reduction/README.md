# Weight reduction in distributed protocols

The implementation of the algorithms presented in the
*Weight reduction in distributed protocols: new algorithms and analysis*
[paper](https://eprint.iacr.org/2025/1076).
Written in Rust.

## Running the code

Example:
```
cargo run --release -- --algorithm super-swiper --alpha 1/3 --beta 1/2 --weights-path data/algorand.dat
```

To see all command line flags run:
```
cargo run --release -- --help
```

To run tests:
```
cargo test
```
