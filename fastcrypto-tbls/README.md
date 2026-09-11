# fastcrypto-tbls

A crate that implements threshold BLS (tBLS) signatures, distributed key generation (DKG) and
threshold Schnorr signatures.

It contains:

- **Threshold BLS** (`tbls`): partial signing and aggregation of BLS signatures over a shared key,
  built on Shamir secret sharing over polynomials (`polynomial`).
- **DKG** (`dkg_v1`): a distributed key generation protocol over a weighted set of nodes
  (`nodes`), using ECIES encryption (`ecies_v1`) to deal shares and discrete-log NIZKs
  (`nizk`, `dl_verification`) to prove the dealings correct. `mocked_dkg` provides deterministic
  outputs for tests.
- **Weight reduction** (`knapsack_weight_reduction`): reduces the total weight of a weighted node
  set while preserving the threshold structure, which keeps protocol cost down for large
  committees.
- **Threshold Schnorr** (`threshold_schnorr`): asynchronous verifiable secret sharing, in plain
  (`avss`), batched (`batch_avss`) and AVID-backed (`avid`, `batch_avss_avid`) variants, together
  with presigning (`presigning`), signing (`signing`), key derivation (`key_derivation`),
  complaints and recovery proofs.
- **Random oracle** (`random_oracle`): domain-separated hashing shared by the protocols above.

> [!WARNING]
> The threshold Schnorr modules are still under development and have not been audited.

## Benchmarks

```
$ cargo bench
```

## License
This software is licensed as [Apache 2.0](LICENSE). A copy of the license is available in the root
repository of this source tree.
