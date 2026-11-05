/-
Shamir secret sharing as implemented by `fastcrypto_tbls::polynomial::Poly` over scalars: the
functions as black boxes (`Api`) and what we expect from them (`Contracts`).
-/
import Mathlib

namespace Shamir

/-- `fastcrypto_tbls::types::ShareIndex` (`NonZeroU16`): a natural number in `[1, 2^16)`. -/
abbrev ShareIndex := { i : ℕ // 0 < i ∧ i < 2 ^ 16 }

/-- `fastcrypto_tbls::polynomial::Eval`: a share, i.e. a value together with the share index it
belongs to. -/
@[ext]
structure Eval (F : Type) where
  index : ShareIndex
  value : F

/-- `FastCryptoError`, as far as it matters here. -/
inductive Error where
  | invalidInput

/-- The scalar-polynomial API of `Poly<S>` in polynomial.rs, as black boxes over the scalar field
`F`, with the names and inputs/outputs of the Rust functions and no implementation.

The functions are total and pure. Field arithmetic is exact. -/
structure Api (F : Type) where
  /-- `fastcrypto_tbls::polynomial::Poly`, for scalars. -/
  Poly : Type
  /-- `fastcrypto_tbls::polynomial::Poly::c0`: the constant term, i.e. the shared secret. -/
  c0 : Poly → F
  /-- `fastcrypto_tbls::polynomial::Poly::degree_bound`: the length of the coefficient vector minus
  one. -/
  degreeBound : Poly → ℕ
  /-- `fastcrypto_tbls::polynomial::Poly::rand_fixed_c0`: the distribution of the polynomial it
  returns, over the randomness of `rng`. "`p` can be returned" means
  `p ∈ (randFixedC0 d s).support`. -/
  randFixedC0 : (degree : ℕ) → (c0 : F) → PMF Poly
  /-- `fastcrypto_tbls::polynomial::Poly::eval`. -/
  eval : Poly → ShareIndex → Eval F
  /-- `fastcrypto_tbls::polynomial::Poly::add` (`impl Add<&Poly<C>> for Poly<C>`). -/
  add : Poly → Poly → Poly
  /-- `fastcrypto_tbls::polynomial::Poly::recover_c0`. `Err` is `.error`; a panic cannot be
  represented, so a contract saying it returns `.ok` also claims that it does not panic on those
  inputs. -/
  recoverC0 : (t : ℕ) → List (Eval F) → Except Error F

variable {F : Type} [Field F]

/-- What we expect from the Rust functions. -/
structure Contracts (A : Api F) : Prop where
  /-- `rand_fixed_c0(d, s).c0() = s` for all `d`, `s`. -/
  rand_c0 : ∀ d s p, p ∈ (A.randFixedC0 d s).support → A.c0 p = s
  /-- `rand_fixed_c0(d, s).degree_bound() = d` for all `d`, `s`. -/
  rand_degree : ∀ d s p, p ∈ (A.randFixedC0 d s).support → A.degreeBound p = d
  /-- `p.eval(i).index = i`. -/
  eval_index : ∀ p i, (A.eval p i).index = i
  /-- `(p + q).eval(i) = p.eval(i) + q.eval(i)`, also when `p` and `q` have different degrees. -/
  add_eval : ∀ p q i, (A.eval (A.add p q) i).value = (A.eval p i).value + (A.eval q i).value
  /-- `(p + q).c0() = p.c0() + q.c0()`. -/
  add_c0 : ∀ p q, A.c0 (A.add p q) = A.c0 p + A.c0 q
  /-- `(p + q).degree_bound() = max(p.degree_bound(), q.degree_bound())`. -/
  add_degree : ∀ p q, A.degreeBound (A.add p q) = max (A.degreeBound p) (A.degreeBound q)
  /-- `recover_c0(t, [p.eval(i₁), …, p.eval(iₜ)]) = Ok(p.c0())` if `p.degree_bound() < t` and
  `i₁, …, iₜ` are distinct. -/
  recover_c0 : ∀ t p (idx : List ShareIndex), A.degreeBound p < t → idx.Nodup →
    idx.length = t → A.recoverC0 t (idx.map (A.eval p)) = .ok (A.c0 p)
  /-- `rand_fixed_c0(d, s) + q` and `rand_fixed_c0(d, s + q.c0())` have the same distribution if
  `q.degree_bound() ≤ d`. -/
  rand_shift : ∀ d s q, A.degreeBound q ≤ d →
    (A.randFixedC0 d s).map (fun p => A.add p q) = A.randFixedC0 d (s + A.c0 q)
  /-- For any `c` and `i₁, …, iₖ` with `k < t`, there is a `q` with `q.degree_bound() ≤ t - 1`,
  `q.c0() = c` and `q.eval(iⱼ) = 0` for all `j`. -/
  vanishing_exists : ∀ (t : ℕ) (c : F) (idx : List ShareIndex), idx.length < t →
    ∃ q, A.degreeBound q ≤ t - 1 ∧ A.c0 q = c ∧ ∀ i ∈ idx, (A.eval q i).value = 0

end Shamir
