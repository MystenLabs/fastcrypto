# Shamir

Shamir secret sharing, `fastcrypto_threshold::polynomial::Poly` over scalars.

There are no lemmas about the code yet: `polynomial.rs` is not translated. `Protocol/` has the
protocol-level theorems (recovery, privacy, summing dealings) and the lemmas they need from
`polynomial.rs`, which the theorems take as hypotheses. See `Protocol/README.md`.
