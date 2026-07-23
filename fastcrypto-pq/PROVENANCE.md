# Provenance

`deps/mldsa-native` is a git submodule tracking [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native), a CBMC- and valgrind-verified C90 implementation of ML-DSA (FIPS 204).

- Pinned commit: `f10e8f117ca924500592e2cc22f4b5fa09e5fd0f` (2026-07-22, `git describe`: `v1.0.0-beta2-137-gf10e8f11`)
- License: Apache-2.0 OR ISC OR MIT (see `deps/mldsa-native/LICENSE`)
- Local modifications: **none.** The submodule is consumed exactly as pinned; all configuration happens through `MLD_CONFIG_*` defines in `build.rs`. Any future patch requirement must instead be reported (and fixed) upstream.

## Building

The submodule is not checked out automatically by `git clone`:

```bash
git submodule update --init fastcrypto-pq/deps/mldsa-native
```

## Updating the pin

```bash
cd fastcrypto-pq/deps/mldsa-native
git fetch origin
git checkout <new-commit-or-tag>
git branch -r --contains HEAD | grep -q origin/main
git describe --tags
cd ../../..
git add fastcrypto-pq/deps/mldsa-native
```

Then update the commit hash, date, and `git describe` string above, confirm the
"local modifications: none" statement still holds, and re-run the full
fastcrypto-pq test suite, including the differential tests.