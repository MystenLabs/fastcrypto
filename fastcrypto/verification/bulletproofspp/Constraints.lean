-- THIS FILE IS AI-ONLY
import bulletproofspp.Laurent
import bulletproofspp.Model.Constraints

/-!
The generated functions of `constraints.rs` compute the functions of `Model/Constraints.lean`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar

/-- A loop that pushes, for `i` from `i₀` to `n - 1`, a value that `ψ` maps to `g i`. -/
lemma push_loop_specψ {α β : Type} {body : alloc.vec.Vec α × Usize →
      Result (ControlFlow (alloc.vec.Vec α × Usize) (alloc.vec.Vec α))}
    (n : ℕ) (ψ : α → β) (g : ℕ → β)
    (hbody : ∀ v i, v.length = i.val → i.val < n →
      body (v, i) ⦃ r => ∃ v' i', r = .cont (v', i') ∧ (∃ x, v'.val = v.val ++ [x] ∧ ψ x = g i.val) ∧
        i'.val = i.val + 1 ⦄)
    (hdone : ∀ v i, v.length = i.val → n ≤ i.val → body (v, i) ⦃ r => r = .done v ⦄)
    (v : alloc.vec.Vec α) (i : Usize) (hv : v.length = i.val) (hi : i.val ≤ n) :
    loop body (v, i) ⦃ r =>
      r.val.map ψ = v.val.map ψ ++ (List.range' i.val (n - i.val)).map g ⦄ := by
  apply loop.spec_decr_nat (fun p => n - p.2.val)
    (fun p => p.1.length = p.2.val ∧ p.2.val ≤ n ∧
      p.1.val.map ψ ++ (List.range' p.2.val (n - p.2.val)).map g =
        v.val.map ψ ++ (List.range' i.val (n - i.val)).map g)
  · rintro ⟨v', i'⟩ ⟨hv', hi', heq⟩
    by_cases hlt : i'.val < n
    · apply WP.spec_mono (hbody v' i' hv' hlt)
      rintro r ⟨v'', i'', rfl, ⟨x, hv'', hx⟩, hi''⟩
      dsimp only
      refine ⟨⟨by simp [alloc.vec.Vec.length, hv'', hi'']; scalar_tac, by omega, ?_⟩, by omega⟩
      rw [← heq, hv'', hi'', show n - i'.val = (n - (i'.val + 1)) + 1 by omega,
        List.range'_succ]
      simp [hx]
    · apply WP.spec_mono (hdone v' i' hv' (by omega))
      intro r hr
      subst hr
      rw [← heq, show n - i'.val = 0 by omega]
      simp
  · exact ⟨hv, hi, rfl⟩

lemma usize_cast_u64 (k : Usize) : (UScalar.cast .U64 k).val = k.val := by
  rw [UScalar.cast_val_eq]
  apply Nat.mod_eq_of_lt
  have := k.hBounds
  cases System.Platform.numBits_eq <;> simp_all [UScalarTy.numBits]; omega

lemma denominators_loop_spec (hs : ScalarModel F φ) (alpha : S) (nw : alloc.vec.Vec S)
    (bm1 : Usize) (hbm : bm1.val ≤ nw.length) (out : alloc.vec.Vec S) (k : Usize)
    (ho : out.length = k.val) (hk : k.val ≤ bm1.val) :
    bulletproofspp.constraints.Constraints.new_loop2 alpha nw bm1 out k ⦃ r =>
      r.val.map φ = out.val.map φ ++ (List.range' k.val (bm1.val - k.val)).map fun j =>
        φ alpha * (φ alpha + ((j + 1 : ℕ) : F)) * (nw.val.map φ).getD j 0 ⦄ := by
  unfold bulletproofspp.constraints.Constraints.new_loop2
  apply push_loop_specψ bm1.val φ _ _ _ out k ho hk
  · intro v j hv hj
    unfold bulletproofspp.constraints.Constraints.new_loop2.body
    have hjlt : j < bm1 := by scalar_tac
    have hc : (UScalar.cast .U64 j).val = j.val := usize_cast_u64 j
    have hjl : j.val < nw.val.length := by
      have : nw.length = nw.val.length := rfl
      omega
    have hjm : j.val < Usize.max := by
      have := nw.property; omega
    simp only [hjlt, ite_true, hs.add_eq, hs.mul_eq]
    step*
    · have := usize_max_le_u64; scalar_tac
    · simp only [hs.from_u64_eq, bind_ok]
      step*
      refine ⟨_, _, rfl, ⟨_, denominators1_post, ?_⟩, k1_post⟩
      simp [rs3_post, i1_post, i_post, hc, List.getElem?_eq_getElem hjl]
  · intro v i hv hi
    unfold bulletproofspp.constraints.Constraints.new_loop2.body
    have : ¬ i < bm1 := by scalar_tac
    simp [this]

lemma cn_o_loop_spec (hs : ScalarModel F φ) (lam : S) (bm1 : Usize) (inv : alloc.vec.Vec S)
    (hbm : bm1.val ≤ inv.length) (out : alloc.vec.Vec S) (k : Usize)
    (ho : out.length = k.val) (hk : k.val ≤ bm1.val) :
    bulletproofspp.constraints.Constraints.new_loop3 lam bm1 inv out k ⦃ r =>
      r.val.map φ = out.val.map φ ++ (List.range' k.val (bm1.val - k.val)).map fun j =>
        ((j + 1 : ℕ) : F) * φ lam * (inv.val.map φ).getD j 0 ⦄ := by
  unfold bulletproofspp.constraints.Constraints.new_loop3
  apply push_loop_specψ bm1.val φ _ _ _ out k ho hk
  · intro v j hv hj
    unfold bulletproofspp.constraints.Constraints.new_loop3.body
    have hjlt : j < bm1 := by scalar_tac
    have hc : (UScalar.cast .U64 j).val = j.val := usize_cast_u64 j
    have hjl : j.val < inv.val.length := by
      have : inv.length = inv.val.length := rfl
      omega
    have hjm : j.val < Usize.max := by
      have := inv.property; omega
    simp only [hjlt, ite_true, hs.mul_eq]
    step*
    · have := usize_max_le_u64; scalar_tac
    · simp only [hs.from_u64_eq, bind_ok]
      step*
      refine ⟨_, _, rfl, ⟨_, cn_o1_post, ?_⟩, k1_post⟩
      simp [rs2_post, i1_post, i_post, hc, List.getElem?_eq_getElem hjl]
  · intro v i hv hi
    unfold bulletproofspp.constraints.Constraints.new_loop3.body
    have : ¬ i < bm1 := by scalar_tac
    simp [this]

lemma cl_v_loop_spec (nm : Usize) (shape : alloc.vec.Vec S)
    (hsh : nm.val + 7 ≤ shape.length) (out : alloc.vec.Vec S) (p : Usize)
    (ho : out.length = p.val) (hp : 1 ≤ p.val) (hp' : p.val ≤ 8) :
    bulletproofspp.constraints.Constraints.new_loop4 nm shape out p ⦃ r =>
      r.val.map φ = out.val.map φ ++ (List.range' p.val (8 - p.val)).map fun j =>
        (shape.val.map φ).getD (nm.val + j - 1) 0 ⦄ := by
  unfold bulletproofspp.constraints.Constraints.new_loop4
  have hH : (bulletproofspp.crs.H_LEN).val = 8 := by simp [bulletproofspp.crs.H_LEN]
  apply loop.spec_decr_nat (fun q => 8 - q.2.val)
    (fun q => q.1.length = q.2.val ∧ 1 ≤ q.2.val ∧ q.2.val ≤ 8 ∧
      q.1.val.map φ ++ (List.range' q.2.val (8 - q.2.val)).map
        (fun j => (shape.val.map φ).getD (nm.val + j - 1) 0) =
      out.val.map φ ++ (List.range' p.val (8 - p.val)).map
        (fun j => (shape.val.map φ).getD (nm.val + j - 1) 0))
  · rintro ⟨v, j⟩ ⟨hv, hj1, hj8, heq⟩
    dsimp only at hv hj1 hj8 heq
    unfold bulletproofspp.constraints.Constraints.new_loop4.body
    have hsl : shape.length = shape.val.length := rfl
    have hsm : shape.val.length ≤ Usize.max := shape.property
    step*
    · have hjl : nm.val + j.val - 1 < shape.val.length := by scalar_tac
      refine ⟨by simp [alloc.vec.Vec.length, cl_v1_post]; scalar_tac, by scalar_tac, by scalar_tac,
        ?_, by scalar_tac⟩
      rw [← heq, cl_v1_post, p1_post, show 8 - j.val = (8 - (j.val + 1)) + 1 by scalar_tac,
        List.range'_succ]
      simp [rs_post, i1_post, i_post, List.getElem?_eq_getElem hjl]
    · rw [← heq, show 8 - j.val = 0 by scalar_tac]
      simp
  · exact ⟨ho, hp, hp', rfl⟩

lemma iterate_succ_append {α : Type} (f : α → α) (a : α) (n : ℕ) :
    List.iterate f a (n + 1) = List.iterate f a n ++ [f^[n] a] := by
  apply List.ext_getElem (by simp)
  intro i h1 h2
  simp only [List.getElem_iterate]
  rw [List.getElem_append]
  split
  · simp
  · rename_i hlt
    simp at h1 hlt ⊢
    have : i = n := by omega
    subst this; simp

lemma shape_loop_spec (hs : ScalarModel F φ) (lam : S) (n : Usize) (out : alloc.vec.Vec S)
    (x : S) (i : Usize) (ho : out.length = i.val) (hi : i.val ≤ n.val) (a : F)
    (hout : out.val.map φ = List.iterate (· * φ lam) a i.val)
    (hx : φ x = (· * φ lam)^[i.val] a) :
    bulletproofspp.constraints.Constraints.new_loop0 lam n out x i ⦃ r =>
      r.val.map φ = List.iterate (· * φ lam) a n.val ⦄ := by
  unfold bulletproofspp.constraints.Constraints.new_loop0
  apply loop.spec_decr_nat (fun q => n.val - q.2.2.val)
    (fun q => q.1.length = q.2.2.val ∧ q.2.2.val ≤ n.val ∧
      q.1.val.map φ = List.iterate (· * φ lam) a q.2.2.val ∧
      φ q.2.1 = (· * φ lam)^[q.2.2.val] a)
  · rintro ⟨v, y, j⟩ ⟨hv, hj, heq, hy⟩
    dsimp only at hv hj heq hy
    unfold bulletproofspp.constraints.Constraints.new_loop0.body
    simp only [hs.mul_assign_eq]
    step*
    · refine ⟨by simp [alloc.vec.Vec.length, shape1_post]; scalar_tac, by scalar_tac, ?_, ?_,
        by scalar_tac⟩
      · rw [shape1_post, i1_post, iterate_succ_append]
        simp [heq, hy]
      · rw [i1_post, hs.φ_mulAF, hy, Function.iterate_succ_apply']
  · exact ⟨ho, hi, hout, hx⟩

/-- The state of the main loop of `Constraints::new`. -/
abbrev LoopState := alloc.vec.Vec S × alloc.vec.Vec S × alloc.vec.Vec S × alloc.vec.Vec S ×
  S × S × S × S

/-- The model of the state of the main loop. -/
def toLoop (φ : S → F) (st : LoopState) : Bppp.Constraints.Loop F :=
  ⟨st.1.val.map φ, st.2.1.val.map φ, st.2.2.1.val.map φ, st.2.2.2.1.val.map φ, φ st.2.2.2.2.1,
    φ st.2.2.2.2.2.1, φ st.2.2.2.2.2.2.1, φ st.2.2.2.2.2.2.2⟩

lemma main_loop_spec (hs : ScalarModel F φ) (pm : Bppp.CircuitParams)
    (alpha mu mu_inv base lam_m : S) (d n_d nm : Usize) (lambdas shape : alloc.vec.Vec S)
    (hd : 0 < d.val) (hpd : pm.d = d.val) (hpnd : pm.n_d = n_d.val)
    (hnd : n_d.val = pm.m * d.val) (hlam : lambdas.length = pm.m + 1)
    (hlm : φ lam_m = (lambdas.val.map φ).getD pm.m 0) (hbase : φ base = 16)
    (hsh : nm.val ≤ shape.length)
    (st : LoopState) (k : Usize) (hk : k.val ≤ nm.val)
    (hlen : st.1.length = k.val ∧ st.2.1.length = k.val ∧ st.2.2.1.length = k.val ∧
      st.2.2.2.1.length = k.val)
    (hst : toLoop φ st = (List.range k.val).foldl
      (Bppp.Constraints.loop_step pm (φ alpha) (φ mu) (φ mu_inv) (lambdas.val.map φ)
        (shape.val.map φ)) ⟨[], [], [], [], 0, Bppp.one, Bppp.one, Bppp.one⟩) :
    bulletproofspp.constraints.Constraints.new_loop1 hs.z hs.o alpha mu d n_d nm mu_inv lambdas
      lam_m shape base st.1 st.2.1 st.2.2.1 st.2.2.2.1 st.2.2.2.2.1 st.2.2.2.2.2.1
      st.2.2.2.2.2.2.1 st.2.2.2.2.2.2.2 k ⦃ r =>
      ∃ st', r = (st'.1, st'.2.1, st'.2.2.1, st'.2.2.2.1, st'.2.2.2.2.1) ∧
        toLoop φ st' = (List.range nm.val).foldl
          (Bppp.Constraints.loop_step pm (φ alpha) (φ mu) (φ mu_inv) (lambdas.val.map φ)
            (shape.val.map φ)) ⟨[], [], [], [], 0, Bppp.one, Bppp.one, Bppp.one⟩ ⦄ := by
  unfold bulletproofspp.constraints.Constraints.new_loop1
  obtain ⟨nw, cl, cr, cv, ma, mp, mip, bp⟩ := st
  dsimp only at hlen hst ⊢
  let step := Bppp.Constraints.loop_step pm (φ alpha) (φ mu) (φ mu_inv) (lambdas.val.map φ)
    (shape.val.map φ)
  let init : Bppp.Constraints.Loop F := ⟨[], [], [], [], 0, Bppp.one, Bppp.one, Bppp.one⟩
  apply loop.spec_decr_nat (fun q => nm.val - q.2.2.2.2.2.2.2.2.val)
    (fun q => q.2.2.2.2.2.2.2.2.val ≤ nm.val ∧
      q.1.length = q.2.2.2.2.2.2.2.2.val ∧ q.2.1.length = q.2.2.2.2.2.2.2.2.val ∧
      q.2.2.1.length = q.2.2.2.2.2.2.2.2.val ∧ q.2.2.2.1.length = q.2.2.2.2.2.2.2.2.val ∧
      toLoop φ (q.1, q.2.1, q.2.2.1, q.2.2.2.1, q.2.2.2.2.1, q.2.2.2.2.2.1, q.2.2.2.2.2.2.1,
        q.2.2.2.2.2.2.2.1) = (List.range q.2.2.2.2.2.2.2.2.val).foldl step init)
  · rintro ⟨nw, cl, cr, cv, ma, mp, mip, bp, j⟩ ⟨hj, h1, h2, h3, h4, hinv⟩
    dsimp only at hj h1 h2 h3 h4 hinv
    unfold bulletproofspp.constraints.Constraints.new_loop1.body
    simp only [hs.mul_assign_eq, hs.mul_eq, hs.add_assign_eq, hs.add_eq]
    step*
    have hjn : j.val < nm.val := by scalar_tac
    have hrng : List.range (j.val + 1) = List.range j.val ++ [j.val] := List.range_succ
    have hsl : j.val < shape.val.length := by
      have : shape.length = shape.val.length := rfl
      omega
    by_cases hjd : j < n_d
    · have hjd' : j.val < pm.n_d := by rw [hpnd]; scalar_tac
      have hdiv : j.val / d.val < lambdas.val.length := by
        have : lambdas.length = lambdas.val.length := rfl
        rw [Nat.div_lt_iff_lt_mul hd]
        have : lambdas.val.length = pm.m + 1 := hlam
        rw [this, Nat.add_mul, one_mul]
        omega
      simp only [hjd, ite_true]
      step*
      have hif : (if x = 0#usize then (ok hs.o : Result S) else ok bp) =
          ok (if j.val % d.val = 0 then hs.o else bp) := by
        by_cases h : j.val % d.val = 0
        · have : x = 0#usize := by
            apply UScalar.eq_of_val_eq; rw [x_post, h]; rfl
          simp [this, h]
        · have : x ≠ 0#usize := by
            intro hx; apply h; rw [← x_post, hx]; rfl
          simp [this, h]
      rw [hif, bind_ok]
      step*
      rename_i cl2 _ hcl2 _ _ _
      have e1 : nw.length = nw.val.length := rfl
      have e2 : cl.length = cl.val.length := rfl
      have e3 : cr.length = cr.val.length := rfl
      have e4 : cv.length = cv.val.length := rfl
      rename_i q _ hq lv _ hlv _ _ _ _
      refine ⟨by scalar_tac, ?_, ?_, ?_, ?_, ?_, by scalar_tac⟩
      · simp [alloc.vec.Vec.length, norm_weights1_post]; omega
      · simp [alloc.vec.Vec.length, hcl2]; omega
      · simp [alloc.vec.Vec.length, x_post]; omega
      · simp [alloc.vec.Vec.length, cn_v1_post]; omega
      rw [k1_post, hrng, List.foldl_append, ← hinv]
      have hsg : (Option.map φ (shape.val[j.val]?)).getD 0 = φ rs := by
        rw [rs_post]; simp [List.getElem?_eq_getElem hsl]
      have hqv : q.val = j.val / d.val := hq
      have hlg : (Option.map φ (lambdas.val[j.val / pm.d]?)).getD 0 = φ lv := by
        rw [hlv, hpd]; simp [List.getElem?_eq_getElem hdiv, hqv]
      have hlm' : (Option.map φ (lambdas.val[pm.m]?)).getD 0 = φ lam_m := by
        rw [hlm]; simp
      have hmd : (j.val % pm.d = 0) = (j.val % d.val = 0) := by rw [hpd]
      simp only [toLoop, step, Bppp.Constraints.loop_step, hjd', ite_true, List.foldl_cons,
        List.foldl_nil]
      simp [norm_weights1_post, hcl2, x_post, cn_v1_post, hsg, hlg, hlm', hmd, hbase, Bppp.BASE]
      split <;> simp [Bppp.one]
    · have hjd' : ¬ j.val < pm.n_d := by rw [hpnd]; scalar_tac
      simp only [hjd, ite_false]
      step*
      rename_i cl2 _ hcl2 _ _ _
      have e1 : nw.length = nw.val.length := rfl
      have e2 : cl.length = cl.val.length := rfl
      have e3 : cr.length = cr.val.length := rfl
      have e4 : cv.length = cv.val.length := rfl
      refine ⟨by scalar_tac, ?_, ?_, ?_, ?_, ?_, by scalar_tac⟩
      · simp [alloc.vec.Vec.length, norm_weights1_post]; omega
      · simp [alloc.vec.Vec.length, hcl2]; omega
      · simp [alloc.vec.Vec.length, x_post]; omega
      · simp [alloc.vec.Vec.length, cn_v1_post]; omega
      rw [k1_post, hrng, List.foldl_append, ← hinv]
      have hsg : (Option.map φ (shape.val[j.val]?)).getD 0 = φ rs := by
        rw [rs_post]; simp [List.getElem?_eq_getElem hsl]
      simp [toLoop, step, Bppp.Constraints.loop_step, hjd', norm_weights1_post, hcl2, x_post,
        cn_v1_post, hsg]
  · exact ⟨hk, hlen.1, hlen.2.1, hlen.2.2.1, hlen.2.2.2, hst⟩

lemma loop_nw_length (pm : Bppp.CircuitParams) (alpha mu mu_inv : F) (lambdas shape : List F)
    (n : ℕ) :
    ((List.range n).foldl (Bppp.Constraints.loop_step pm alpha mu mu_inv lambdas shape)
      ⟨[], [], [], [], 0, Bppp.one, Bppp.one, Bppp.one⟩).norm_weights.length = n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    simp only [Bppp.Constraints.loop_step]
    by_cases h : n < pm.n_d <;> simp [ih]

@[simp] lemma except_error_bind {ε α β : Type} (e : ε) (f : α → Except ε β) :
    ((Except.error e : Except ε α) >>= f) = .error e := rfl

@[simp] lemma except_ok_bind {ε α β : Type} (a : α) (f : α → Except ε β) :
    ((Except.ok a : Except ε α) >>= f) = f a := rfl

lemma batch_invert_length (l l' : List F) (h : Bppp.batch_invert l = .ok l') :
    l'.length = l.length := by
  unfold Bppp.batch_invert at h
  have hpre : ∀ (m : List F) (p : List F) (a : F),
      (m.foldl (fun (pre, acc) x => (pre ++ [acc], acc * x)) (p, a)).1.length =
        p.length + m.length := by
    intro m; induction m with
    | nil => simp
    | cons x m ih => intro p a; simp [ih]; omega
  have hfr : ∀ (m : List (F × F)) (s : F),
      (m.foldr (fun (x, p) (out, s) => (s * p :: out, s * x)) ([], s)).1.length = m.length := by
    intro m; induction m with
    | nil => simp
    | cons x m ih => intro s; simp [ih]
  simp only [Bppp.inverse] at h
  split at h
  · simp at h
  · simp only [except_ok_bind] at h
    have h' := Except.ok.inj h
    rw [← h', hfr, List.length_zip, hpre]
    simp

/-- The model of generated constraints. -/
def toC (φ : S → F) (c : bulletproofspp.constraints.Constraints) : Bppp.Constraints F :=
  ⟨c.norm_weights.val.map φ, c.cn_l.val.map φ, c.cn_r.val.map φ, c.cn_o.val.map φ,
    c.cn_v.val.map φ, c.cl_v.val.map φ, φ c.lambda_al, φ c.mu_am, c.lambdas.val.map φ⟩

/-- Generated circuit parameters that match the model's `pm`, with the conditions
`Constraints::new` needs: `d > 0`, `n_d = m d`, `15 ≤ nm` and no `usize` overflow. -/
structure ParamsOK (pm : Bppp.CircuitParams) (p : bulletproofspp.circuit.CircuitParams) : Prop where
  m : pm.m = p.m.val
  d : pm.d = p.d.val
  n_d : pm.n_d = p.n_d.val
  nm : pm.nm = p.nm.val
  d_pos : 0 < p.d.val
  n_d_eq : p.n_d.val = p.m.val * p.d.val
  nm_ge : 15 ≤ p.nm.val
  m_lt : p.m.val + 1 ≤ Usize.max
  nm_lt : p.nm.val + 8 ≤ Usize.max

lemma constraints_new_spec (hs : ScalarModel F φ) (pm : Bppp.CircuitParams)
    (p : bulletproofspp.circuit.CircuitParams) (hp : ParamsOK pm p) (alpha mu lambda : S) :
    bulletproofspp.constraints.Constraints.new p alpha mu lambda ⦃ r =>
      match Bppp.Constraints.new pm (φ alpha) (φ mu) (φ lambda) with
      | .ok c => ∃ c', r = .Ok c' ∧ toC φ c' = c
      | .error _ => r = .Err .InvalidInput ⦄ := by
  obtain ⟨hm, hpd, hpnd, hpnm, hd, hnd, hnm, hml, hnml⟩ := hp
  unfold bulletproofspp.constraints.Constraints.new
  by_cases hmu : φ mu = 0
  · rw [hs.inverse_zero mu hmu]
    have hmod : Bppp.Constraints.new pm (φ alpha) (φ mu) (φ lambda) = .error .InvalidInput := by
      simp [Bppp.Constraints.new, Bppp.inverse, hmu]
    rw [hmod]
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  obtain ⟨mi, hmi, hmiv⟩ := hs.inverse mu hmu
  rw [hmi]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
  step*
  apply WP.spec_bind (power_vector_spec hs lambda i)
  intro lambdas hlam
  have hlaml : lambdas.val.length = p.m.val + 1 := by
    have := congrArg List.length hlam
    rw [List.length_map, power_vector_eq, List.length_map, List.length_range] at this
    rw [this]; scalar_tac
  have hH : (bulletproofspp.crs.H_LEN).val = 8 := by simp [bulletproofspp.crs.H_LEN]
  step*
  simp only [hs.mul_eq, bind_ok]
  have hlm : φ lam_m = (lambdas.val.map φ).getD pm.m 0 := by
    rw [lam_m_post, hm]; simp [List.getElem?_eq_getElem (by omega : p.m.val < lambdas.val.length)]
  apply WP.spec_bind (shape_loop_spec hs lam_m shape_len _ _ 0#usize (by simp) (by simp)
    (φ (hs.mulF lambda lam_m)) (by simp) (by simp))
  intro shape hshape
  have hshl : shape.val.length = p.nm.val + 7 := by
    have := congrArg List.length hshape
    simp at this; rw [this, shape_len_post, i1_post, hH]; omega
  simp only [hs.from_u64_eq, hs.zero_eq, one_spec hs, bind_ok]
  apply WP.spec_bind (main_loop_spec hs pm alpha mu mi (hs.fromF bulletproofspp.crs.BASE) lam_m
    p.d p.n_d p.nm lambdas shape hd hpd hpnd (by rw [hm]; exact hnd)
    (by show lambdas.val.length = _; rw [hm]; exact hlaml) hlm
    (by simp [bulletproofspp.crs.BASE]) (by simp [alloc.vec.Vec.length, hshl])
    (alloc.vec.Vec.with_capacity S p.nm, alloc.vec.Vec.with_capacity S p.nm,
      alloc.vec.Vec.with_capacity S p.nm, alloc.vec.Vec.with_capacity S p.nm, hs.z, hs.o, hs.o,
      hs.o) 0#usize (by simp) (by simp)
    (by simp [toLoop, Bppp.one]))
  rintro r ⟨st, rfl, hst⟩
  simp only [Std.uncurry_apply_pair]
  have hnwl : st.1.val.length = p.nm.val := by
    have := congrArg (fun L => L.norm_weights.length) hst
    simp only [toLoop, List.length_map] at this
    rw [this, loop_nw_length]
  simp only [bulletproofspp.crs.BASE]
  step*
  have hbm : bm1.val = 15 := by
    rw [bm1_post, UScalar.cast_val_eq, i2_post]
    cases System.Platform.numBits_eq <;> simp [*]
  apply WP.spec_bind (denominators_loop_spec hs alpha st.1 bm1
    (by show bm1.val ≤ st.1.val.length; omega) _ 0#usize (by simp) (by simp))
  intro den hden
  -- the model, up to the batch inversion
  set stm := (List.range pm.nm).foldl (Bppp.Constraints.loop_step pm (φ alpha) (φ mu) (φ mi)
    (lambdas.val.map φ) (shape.val.map φ)) ⟨[], [], [], [], 0, Bppp.one, Bppp.one, Bppp.one⟩
    with hstm
  have hst' : toLoop φ st = stm := by rw [hst, hstm, hpnm]
  have hdenm : (alloc.vec.Vec.deref den).val.map φ = (List.range (Bppp.BASE - 1)).map fun k =>
      φ alpha * (φ alpha + ((k + 1 : ℕ) : F)) * stm.norm_weights.getD k 0 := by
    have : (alloc.vec.Vec.deref den).val = den.val := by simp [alloc.vec.Vec.deref]
    rw [this, hden, hbm, ← hst']
    simp [toLoop, Bppp.BASE, List.range_eq_range']
  have hmod : Bppp.Constraints.new pm (φ alpha) (φ mu) (φ lambda) = (do
      let inverses ← Bppp.batch_invert ((List.range (Bppp.BASE - 1)).map fun k =>
        φ alpha * (φ alpha + ((k + 1 : ℕ) : F)) * stm.norm_weights.getD k 0)
      let lam_m := (lambdas.val.map φ).getD pm.m 0
      let cn_o := Bppp.pad_to ((List.range (Bppp.BASE - 1)).map fun k =>
        ((k + 1 : ℕ) : F) * lam_m * inverses.getD k 0) pm.nm
      let lambda_al := (pm.n_d : F) * lam_m * (← Bppp.inverse (φ alpha))
      let cl_v := 0 :: (List.range' 1 (Bppp.H_LEN - 1)).map fun q =>
        (shape.val.map φ).getD (pm.nm + q - 1) 0
      return (⟨stm.norm_weights, stm.cn_l, stm.cn_r, cn_o, stm.cn_v, cl_v, lambda_al, stm.mu_am,
        lambdas.val.map φ⟩ : Bppp.Constraints F)) := by
    have hpv : Bppp.power_vector (φ lambda) (pm.m + 1) = lambdas.val.map φ := by
      rw [hlam, i_post, hm]
    have hsh : List.iterate (· * (lambdas.val.map φ).getD pm.m 0)
        (φ lambda * (lambdas.val.map φ).getD pm.m 0) (pm.nm + Bppp.H_LEN - 1) =
        shape.val.map φ := by
      rw [hshape, ← hlm, hpnm, shape_len_post, i1_post, hH]
      simp [Bppp.H_LEN]
    simp only [Bppp.Constraints.new, Bppp.inverse, hmu, ite_false, except_ok_bind, hpv, hsh,
      ← hmiv]
    rfl
  rw [hmod]
  apply WP.spec_bind (batch_invert_spec hs (alloc.vec.Vec.deref den))
  intro r1 hr1
  rw [hdenm] at hr1
  cases hbi : Bppp.batch_invert ((List.range (Bppp.BASE - 1)).map fun k =>
      φ alpha * (φ alpha + ((k + 1 : ℕ) : F)) * stm.norm_weights.getD k 0) with
  | error e =>
    rw [hbi] at hr1
    subst hr1
    simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | ok l =>
    rw [hbi] at hr1
    obtain ⟨inv, rfl, hinv⟩ := hr1
    have hinvl : inv.val.length = 15 := by
      have := congrArg List.length hinv
      rw [List.length_map, batch_invert_length _ _ hbi] at this
      simpa [Bppp.BASE] using this
    simp only [bind_ok]
    apply WP.spec_bind (cn_o_loop_spec hs lam_m bm1 inv
      (by show bm1.val ≤ inv.val.length; omega) _ 0#usize (by simp) (by simp))
    intro co hco
    have hcol : co.val.length = 15 := by
      have := congrArg List.length hco; simp at this; omega
    step*
    all_goals simp [hs.clone]
    have hcast : (UScalar.cast .U64 p.n_d).val = p.n_d.val := usize_cast_u64 p.n_d
    by_cases ha : φ alpha = 0
    · rw [hs.inverse_zero alpha ha]
      simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
        Bppp.inverse, ha]
    obtain ⟨ai, hai, haiv⟩ := hs.inverse alpha ha
    rw [hai]
    simp only [bind_ok]
    have hH : (bulletproofspp.crs.H_LEN).val = 8 := by simp [bulletproofspp.crs.H_LEN]
    step*
    · simp; scalar_tac
    apply WP.spec_bind (cl_v_loop_spec (φ := φ) p.nm shape (by simp [alloc.vec.Vec.length]; omega)
      cl_v1 1#usize (by simp [alloc.vec.Vec.length, cl_v1_post]) (by simp) (by simp))
    intro cv hcv
    simp only [WP.spec_ok, Bppp.inverse, ha, ite_false, except_ok_bind]
    refine ⟨_, rfl, ?_⟩
    have e1 := congrArg Bppp.Constraints.Loop.norm_weights hst'
    have e2 := congrArg Bppp.Constraints.Loop.cn_l hst'
    have e3 := congrArg Bppp.Constraints.Loop.cn_r hst'
    have e4 := congrArg Bppp.Constraints.Loop.cn_v hst'
    have e5 := congrArg Bppp.Constraints.Loop.mu_am hst'
    simp only [toLoop] at e1 e2 e3 e4 e5
    have hlm' : φ lam_m = (Option.map φ (lambdas.val[pm.m]?)).getD 0 := by rw [hlm]; simp
    simp only [toC, e1, e2, e3, e4, e5, Bppp.Constraints.mk.injEq, true_and, and_true]
    refine ⟨?_, ?_, ?_⟩
    · rw [cn_o2_post, List.resize]
      simp only [ge_iff_le, zero_le, ite_true, List.map_append, List.map_take, List.map_replicate,
        hs.φ_z, hco, with_capacity_val, List.map_nil, List.nil_append, hbm, Bppp.pad_to, hpnm,
        hcol]
      simp [Bppp.BASE, List.range_eq_range', hlm', hinv]
      rw [List.take_of_length_le (by simp; omega), List.take_of_length_le (by simp; omega)]
    · rw [hcv, cl_v1_post]
      simp [hpnm, Bppp.H_LEN]
    · simp [hlm', haiv, i3_post, hcast, hpnd]

lemma p_n_spec (hs : ScalarModel F φ) (c : bulletproofspp.constraints.Constraints) (n : ℕ)
    (hv : c.cn_v.length = n) (hr : c.cn_r.length = n) (hl : c.cn_l.length = n)
    (ho : c.cn_o.length = n) (delta_inv : S) :
    bulletproofspp.constraints.Constraints.p_n c delta_inv ⦃ r =>
      WF (VecLen n) r ∧ Half r ∧ toL (vecψ φ) r = (toC φ c).p_n (φ delta_inv) ⦄ := by
  unfold bulletproofspp.constraints.Constraints.p_n
  simp only [vec_clone_eq hs, bind_ok]
  apply WP.spec_bind (vec_scalar_mul_spec hs delta_inv (alloc.vec.Vec.deref c.cn_o))
  intro o ho'
  have hol : o.length = n := by
    have := congrArg List.length ho'
    simp [Bppp.vec_scalar_mul, alloc.vec.Vec.deref] at this
    show o.val.length = n
    rw [this]; exact ho
  step*
  apply WP.spec_mono (new_spec _ 0#i32 _ (by simp [y_post]))
  intro r hr
  subst hr
  refine ⟨⟨by simp [y_post], ?_, by simp [powBound], ?_⟩, ⟨by simp [powBound], ?_⟩, ?_⟩
  · intro x hx
    simp [y_post] at hx
    rcases hx with rfl | rfl | rfl | rfl <;> assumption
  · simp [y_post, alloc.vec.Vec.length, powBound]
  · simp [y_post, alloc.vec.Vec.length, powBound]
  · simp only [toL, y_post, Bppp.Constraints.p_n, Bppp.Laurent.new, toC]
    simp [vecψ, ho', alloc.vec.Vec.deref]

end BpppProofs
