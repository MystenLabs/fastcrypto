# fastcrypto-vdf

An experimental crate that implements verifiable delay functions (VDFs).

Everything in this crate is gated behind the `experimental` feature flag. It has not been audited
and should not be used in production.

It contains:

- **VDF constructions** (`vdf`): the Wesolowski (`wesolowski`) and Pietrzak (`pietrzak`) VDFs,
  generic over the underlying group of unknown order.
- **Imaginary class groups** (`class_group`): elements represented as binary quadratic forms, with
  form reduction, discriminant generation and a hash-to-group construction whose output is uniform
  over a large subset of the group.
- **RSA groups** (`rsa_group`): an alternative group of unknown order, for comparison and testing.
- **Supporting math** (`math`): extended GCD, the Chinese remainder theorem, Jacobi symbols,
  modular square roots and hash-to-prime.

A command line tool for generating and verifying proofs is available in `fastcrypto-cli`:

```
$ cargo build --bin vdf-cli
$ target/debug/vdf-cli -h
```

## Benchmarks

```
$ cargo bench --features experimental
```

## License
This software is licensed as [Apache 2.0](LICENSE). A copy of the license is available in the root
repository of this source tree.
