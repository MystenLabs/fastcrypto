# SPHINCS+ / SLH-DSA (FIPS 205)

Hand-written Rust impl, gated behind `--features experimental`.

## Status

WOTS+ ✅ · ADRS ✅ · SHA2 tweakable hash ✅ · FORS ⏳ · XMSS ⏳ · Hypertree ⏳ · SLH-DSA ⏳

Individual components are planned to be built in a generic way:
- WOTS+ can be instantiated with any `n, lg_w` iff `8n % lg_w = 0` and `1 <= lg_w <= 8`

## Approved parameter sets (FIPS 205)

Columns: `n` (hash bytes), `h` (total tree height), `d` (hypertree layers),
`h'` (= h/d), `a` (FORS tree height), `k` (FORS trees), `lg_w`, `m` (digest
bytes), security category, pk / sig bytes.

| Parameter set               | n  | h  | d  | h' | a  | k  | lg_w | m  | cat | pk | sig    |
|-----------------------------|----|----|----|----|----|----|------|----|-----|----|--------|
| SLH-DSA-{SHA2,SHAKE}-128s   | 16 | 63 | 7  | 9  | 12 | 14 | 4    | 30 | 1   | 32 |  7,856 |
| SLH-DSA-{SHA2,SHAKE}-128f   | 16 | 66 | 22 | 3  | 6  | 33 | 4    | 34 | 1   | 32 | 17,088 |
| SLH-DSA-{SHA2,SHAKE}-192s   | 24 | 63 | 7  | 9  | 14 | 17 | 4    | 39 | 3   | 48 | 16,224 |
| SLH-DSA-{SHA2,SHAKE}-192f   | 24 | 66 | 22 | 3  | 8  | 33 | 4    | 42 | 3   | 48 | 35,664 |
| SLH-DSA-{SHA2,SHAKE}-256s   | 32 | 64 | 8  | 8  | 14 | 22 | 4    | 47 | 5   | 64 | 29,792 |
| SLH-DSA-{SHA2,SHAKE}-256f   | 32 | 68 | 17 | 4  | 9  | 35 | 4    | 49 | 5   | 64 | 49,856 |

All fix `lg_w = 4`. WOTS+ collapses to 3 configs by `n`: {16, 24, 32}.

## Draft parameter sets (SP 800-230 IPD, Apr 2026)

`2^24`-signature-limited sets. `d = 1` (single XMSS tree); `lg_w` varies.

| Parameter set               | n  | h  | d | h' | a  | k  | lg_w | m  | cat | pk | sig    |
|-----------------------------|----|----|---|----|----|----|------|----|-----|----|--------|
| SLH-DSA-{SHA2,SHAKE}-128-24 | 16 | 22 | 1 | 22 | 24 | 6  | 2    | 21 | 1   | 32 |  3,856 |
| SLH-DSA-{SHA2,SHAKE}-192-24 | 24 | 21 | 1 | 21 | 25 | 9  | 3    | 32 | 3   | 48 |  7,752 |
| SLH-DSA-{SHA2,SHAKE}-256-24 | 32 | 21 | 1 | 21 | 25 | 12 | 2    | 41 | 5   | 64 | 14,944 |

Adds new WOTS+ configs: `(n=16, lg_w=2)`, `(n=24, lg_w=3)`, `(n=32, lg_w=2)`.

## Run

```bash
cargo test  -p fastcrypto --features experimental sphincs
cargo bench -p fastcrypto --features experimental --bench winternitz_ots
```

## References

- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [SP 800-230 IPD](https://csrc.nist.gov/pubs/sp/800/230/ipd)
- [Reference C impl](https://github.com/sphincs/sphincsplus) (used for cross-check sub-vectors)
