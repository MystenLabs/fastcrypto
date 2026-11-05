/-
Recovery: `recover_c0` on `t` shares of a dealt polynomial returns the dealt secret.
-/
import Shamir.Steps

namespace Shamir

variable {F : Type} [Field F] {A : Api F}

/-- **Dealing.** Let `t > 0` and let `p` be a polynomial that `rand_fixed_c0(t - 1, s)` can
return. For every list `idx` of exactly `t` distinct share indices, `recover_c0` on the shares
`p.eval(i)` for `i` in `idx` returns `Ok(s)`. -/
theorem recover_dealt_secret (hA : Contracts A) {t : ℕ} (ht : 0 < t) {s : F} {p : A.Poly}
    (hp : p ∈ (A.randFixedC0 (t - 1) s).support) (idx : List ShareIndex) (hnodup : idx.Nodup)
    (hlen : idx.length = t) :
    A.recoverC0 t (idx.map (A.eval p)) = .ok s := by
  rw [hA.recover_c0 t p idx (by rw [hA.rand_degree _ _ _ hp]; omega) hnodup hlen,
    hA.rand_c0 _ _ _ hp]

/-- **Agreement.** Under the hypotheses of `recover_dealt_secret`, any two lists `idx` and `idx'`
of exactly `t` distinct share indices give the same result of `recover_c0`. -/
theorem recover_agrees (hA : Contracts A) {t : ℕ} (ht : 0 < t) {s : F} {p : A.Poly}
    (hp : p ∈ (A.randFixedC0 (t - 1) s).support) (idx idx' : List ShareIndex)
    (h : idx.Nodup ∧ idx.length = t) (h' : idx'.Nodup ∧ idx'.length = t) :
    A.recoverC0 t (idx.map (A.eval p)) = A.recoverC0 t (idx'.map (A.eval p)) := by
  rw [recover_dealt_secret hA ht hp idx h.1 h.2, recover_dealt_secret hA ht hp idx' h'.1 h'.2]

end Shamir
