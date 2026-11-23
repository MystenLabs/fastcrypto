<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto_threshold::polynomial`

Shamir secret sharing, as implemented by `fastcrypto_threshold::polynomial::Poly` over scalars.
The theorems are proved in `Protocol/` with the functions of `polynomial.rs` as black boxes, from
properties of those functions (listed [below](#what-is-assumed)). `polynomial.rs` is not
translated yet, so there are no theorems about the code itself. Every declaration has a doc
comment stating it in Rust terms.

## Theorems

### Protocols

1. **`recover_dealt_secret` and `recover_agrees`: shares recover the secret.** `recover_c0` on any
   `t` distinct shares of `rand_fixed_c0(t - 1, s)` returns `s`, so any two such sets of `t`
   shares recover the same secret.

2. **`shares_independent_of_secret`: few shares reveal nothing.** Fewer than `t` shares of
   `rand_fixed_c0(t - 1, s)` have the same distribution for every secret `s`.

3. **`recover_sum_of_dealings`: summed dealings share the summed secret.** `recover_c0` on `t`
   summed shares of several dealings returns the sum of their secrets. This is the core of
   `complete_dkg`.

## What is assumed

The theorems assume these properties of `polynomial.rs` (the fields of `Contracts`), and take
them as hypotheses. None is proved for the code: `polynomial.rs` is not translated (it is opaque
in `../avss/Generated`). There is no `sorry` and no axiom.

| Property | Statement |
|---|---|
| `rand_c0` | `rand_fixed_c0(d, s)` has constant term `s`. |
| `rand_degree` | `rand_fixed_c0(d, s)` has `degree_bound() = d`. |
| `eval_index` | `p.eval(i)` has index `i`. |
| `add_eval`, `add_c0`, `add_degree` | `p + q` evaluates and has constant term `p + q` pointwise, with the larger degree bound. |
| `mul_eval`, `mul_c0`, `mul_degree` | `p * a` evaluates and has constant term `p * a` pointwise, with no larger degree bound. |
| `recover_c0` | `recover_c0` on `t` distinct evaluations of `p` with `degree_bound() < t` returns `p.c0()`. |
| `recover_c0_linear` | On fixed distinct indices, `recover_c0` is a fixed linear combination of the values. |
| `rand_shift` | Adding `q` to `rand_fixed_c0(d, s)` gives the distribution of `rand_fixed_c0(d, s + q.c0())`. |
| `vanishing_exists` | For fewer than `t` indices there is a polynomial with any constant term that vanishes on them. |

## What is not proved

* `polynomial.rs` is not translated, so its properties are assumed.

## Files

| File | Contents |
|---|---|
| `Protocol/Steps.lean` | The functions of `polynomial.rs` as black boxes (`Api`) and their properties (`Contracts`). |
| `Protocol/Recovery.lean` | Theorem 1. |
| `Protocol/Privacy.lean` | Theorem 2. |
| `Protocol/Dkg.lean` | Theorem 3. |
