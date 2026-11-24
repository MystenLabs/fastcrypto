-- THIS FILE IS AI-ONLY
import bulletproofspp.CircuitWitness

/-!
The functions of `circuit.rs` on the opening of the combined commitment `C(T)` compute the
model's: `CombinedOpening`, `f`, `solve_r_s`, `opening_without_r_s` and `commit_c_s`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar

/-- The model of a generated combined opening. -/
def toCO (φ : S → F) (co : bulletproofspp.circuit.CombinedOpening) :
    Bppp.Circuit.CombinedOpening F :=
  ⟨toL φ co.sigma, toL (vecψ φ) co.l, toL (vecψ φ) co.n⟩

/-- A generated combined opening with `H_LEN` and `nm` coordinates, whose powers lie in
`[lo, hi)`. -/
structure COK (nm : ℕ) (lo hi : ℤ) (co : bulletproofspp.circuit.CombinedOpening) : Prop where
  sigma : WF (fun _ => True) co.sigma
  l : WF (VecLen 8) co.l
  n : WF (VecLen nm) co.n
  sigma_spans : Spans (toL φ co.sigma) lo hi
  l_spans : Spans (toL (vecψ φ) co.l) lo hi
  n_spans : Spans (toL (vecψ φ) co.n) lo hi

lemma from_terms_loop_co_spec (hs : ScalarModel F φ)
    (terms : Slice (I32 × bulletproofspp.norm_linear.Opening))
    (sigma : alloc.vec.Vec (I32 × S)) (l n : alloc.vec.Vec (I32 × alloc.vec.Vec S)) (i : Usize)
    (hi : i.val ≤ terms.length)
    (hsg : sigma.val = (terms.val.take i.val).map fun t => (t.1, t.2.sigma))
    (hl : l.val = (terms.val.take i.val).map fun t => (t.1, t.2.l))
    (hn : n.val = (terms.val.take i.val).map fun t => (t.1, t.2.n)) :
    bulletproofspp.circuit.CombinedOpening.from_terms_loop terms sigma l n i ⦃ r =>
      r.1.val = terms.val.map (fun t => (t.1, t.2.sigma)) ∧
      r.2.1.val = terms.val.map (fun t => (t.1, t.2.l)) ∧
      r.2.2.val = terms.val.map (fun t => (t.1, t.2.n)) ⦄ := by
  unfold bulletproofspp.circuit.CombinedOpening.from_terms_loop
  have et : terms.len.val = terms.val.length := rfl
  have etl : terms.length = terms.val.length := rfl
  apply loop.spec_decr_nat (fun x => terms.length - x.2.2.2.val)
    (fun x => x.2.2.2.val ≤ terms.length ∧
      x.1.val = (terms.val.take x.2.2.2.val).map (fun t => (t.1, t.2.sigma)) ∧
      x.2.1.val = (terms.val.take x.2.2.2.val).map (fun t => (t.1, t.2.l)) ∧
      x.2.2.1.val = (terms.val.take x.2.2.2.val).map (fun t => (t.1, t.2.n)))
  · rintro ⟨sg, ll, nn, k⟩ ⟨hk, h1, h2, h3⟩
    simp only at hk h1 h2 h3
    unfold bulletproofspp.circuit.CombinedOpening.from_terms_loop.body
    simp only [vec_clone_eq hs]
    have hsgl : sg.length = sg.val.length := rfl
    have hlll : ll.length = ll.val.length := rfl
    have hnnl : nn.length = nn.val.length := rfl
    have hsgk : sg.val.length = k.val := by rw [h1]; simp; omega
    have hllk : ll.val.length = k.val := by rw [h2]; simp; omega
    have hnnk : nn.val.length = k.val := by rw [h3]; simp; omega
    step*
    · have hk' : k.val < terms.val.length := by scalar_tac
      have htk : terms.val.take (k.val + 1) = terms.val.take k.val ++ [terms.val[k.val]] :=
        List.take_succ_eq_append_getElem hk'
      refine ⟨by scalar_tac, ?_, ?_, ?_, by scalar_tac⟩ <;>
        rw [i3_post, htk, List.map_append, ← i2_post] <;>
        simp only [sigma1_post, l1_post, n1_post, h1, h2, h3, List.map_cons, List.map_nil]
    · have hk' : k.val = terms.val.length := by scalar_tac
      refine ⟨?_, ?_, ?_⟩ <;> simp only [h1, h2, h3, hk', List.take_length]
  · exact ⟨hi, hsg, hl, hn⟩

lemma spans_from_terms' {Cm : Type} [Inhabited Cm] [Bppp.Coefficient F Cm] (L : List (ℤ × Cm))
    (lo hi : ℤ) (hne : L ≠ []) (h : ∀ x ∈ L, lo ≤ x.1 ∧ x.1 + 1 ≤ hi) :
    Spans (Bppp.Laurent.from_terms L) lo hi := by
  obtain ⟨t, ts, rfl⟩ := List.exists_cons_of_ne_nil hne
  exact spans_from_terms t ts lo hi h

lemma co_from_terms_spec (hs : ScalarModel F φ) (nm : ℕ)
    (terms : Slice (I32 × bulletproofspp.norm_linear.Opening)) (lo hi : ℤ) (hne : terms.val ≠ [])
    (ht : ∀ t ∈ terms.val, lo ≤ t.1.val ∧ t.1.val + 1 ≤ hi ∧ t.2.l.length = 8 ∧
      t.2.n.length = nm)
    (hlo : -powBound ≤ lo) (hhi : hi ≤ powBound) :
    bulletproofspp.circuit.CombinedOpening.from_terms terms ⦃ r =>
      COK (φ := φ) nm lo hi r ∧
      toCO φ r = Bppp.Circuit.CombinedOpening.from_terms
        (terms.val.map fun t => (t.1.val, toO φ t.2)) ⦄ := by
  unfold bulletproofspp.circuit.CombinedOpening.from_terms
  apply WP.spec_bind (from_terms_loop_co_spec hs terms _ _ _ 0#usize (by simp) (by simp)
    (by simp) (by simp))
  rintro ⟨sg, ll, nn⟩ ⟨h1, h2, h3⟩
  simp only at h1 h2 h3
  have hne1 : sg.val ≠ [] := by rw [h1]; simpa using hne
  have hne2 : ll.val ≠ [] := by rw [h2]; simpa using hne
  have hne3 : nn.val ≠ [] := by rw [h3]; simpa using hne
  apply WP.spec_bind (from_terms_spec hs (scalar_coeff_model hs) sg hne1 (by
    intro t ht'
    rw [h1] at ht'
    obtain ⟨u, hu, rfl⟩ := List.mem_map.mp ht'
    have := ht u hu
    exact ⟨trivial, by simp only [powBound] at *; omega, by simp only [powBound] at *; omega⟩))
  rintro s1 ⟨hw1, hm1⟩
  apply WP.spec_bind (from_terms_spec hs (vec_coeff_model hs 8) ll hne2 (by
    intro t ht'
    rw [h2] at ht'
    obtain ⟨u, hu, rfl⟩ := List.mem_map.mp ht'
    have := ht u hu
    exact ⟨this.2.2.1, by simp only [powBound] at *; omega, by simp only [powBound] at *; omega⟩))
  rintro s2 ⟨hw2, hm2⟩
  apply WP.spec_bind (from_terms_spec hs (vec_coeff_model hs nm) nn hne3 (by
    intro t ht'
    rw [h3] at ht'
    obtain ⟨u, hu, rfl⟩ := List.mem_map.mp ht'
    have := ht u hu
    exact ⟨this.2.2.2, by simp only [powBound] at *; omega, by simp only [powBound] at *; omega⟩))
  rintro s3 ⟨hw3, hm3⟩
  rw [WP.spec_ok]
  have hsp : ∀ {Cm : Type} [Inhabited Cm] [Bppp.Coefficient F Cm] (g : bulletproofspp.norm_linear.Opening → Cm),
      Spans (Bppp.Laurent.from_terms (terms.val.map fun t => (t.1.val, g t.2))) lo hi := by
    intro Cm _ _ g
    apply spans_from_terms' _ _ _ (by simpa using hne)
    intro x hx
    obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hx
    have := ht u hu
    exact ⟨this.1, this.2.1⟩
  have e1 : toL φ s1 = Bppp.Laurent.from_terms (terms.val.map fun t => (t.1.val, φ t.2.sigma)) := by
    rw [hm1, h1, List.map_map]; rfl
  have e2 : toL (vecψ φ) s2 =
      Bppp.Laurent.from_terms (terms.val.map fun t => (t.1.val, vecψ φ t.2.l)) := by
    rw [hm2, h2, List.map_map]; rfl
  have e3 : toL (vecψ φ) s3 =
      Bppp.Laurent.from_terms (terms.val.map fun t => (t.1.val, vecψ φ t.2.n)) := by
    rw [hm3, h3, List.map_map]; rfl
  refine ⟨⟨hw1, hw2, hw3, ?_, ?_, ?_⟩, ?_⟩
  · rw [e1]; exact hsp (fun o => φ o.sigma)
  · rw [e2]; exact hsp (fun o => vecψ φ o.l)
  · rw [e3]; exact hsp (fun o => vecψ φ o.n)
  · simp only [toCO, Bppp.Circuit.CombinedOpening.from_terms, e1, e2, e3, List.map_map]
    rfl

lemma laurent_clone_eq (hs : ScalarModel F φ) (l : bulletproofspp.laurent.Laurent S) :
    bulletproofspp.laurent.Laurent.Insts.CoreCloneClone.clone
      groups.ristretto255.RistrettoScalar.Insts.CoreCloneClone l = ok l := by
  unfold bulletproofspp.laurent.Laurent.Insts.CoreCloneClone.clone
  simp [vec_clone_eq hs, lift]

lemma c_s_power_val : (bulletproofspp.circuit.C_S_POWER).val = -1 := by
  unfold bulletproofspp.circuit.C_S_POWER; rfl

lemma with_r_s_spec (hs : ScalarModel F φ) (nm : ℕ) (co : bulletproofspp.circuit.CombinedOpening)
    (lo hi : ℤ) (hco : COK (φ := φ) nm lo hi co) (r_s0 : S) (h : alloc.vec.Vec S)
    (hh : h.length = 8) :
    bulletproofspp.circuit.CombinedOpening.with_r_s co r_s0 h ⦃ r =>
      COK (φ := φ) nm (min lo (-1)) (max hi 0) r ∧
      toCO φ r = (toCO φ co).with_r_s (φ r_s0) (h.val.map φ) ⦄ := by
  unfold bulletproofspp.circuit.CombinedOpening.with_r_s
  have tk : ∀ {C : Type} (P : C → Prop) (c : C), P c →
      TermOK P (bulletproofspp.circuit.C_S_POWER, c) := by
    intro C P c hc
    exact ⟨hc, by rw [c_s_power_val]; norm_num [powBound], by rw [c_s_power_val]; norm_num [powBound]⟩
  apply WP.spec_bind (monomial_wf (ψ := φ) _ (tk (fun _ => True) r_s0 trivial))
  rintro m1 ⟨hw1, hm1⟩
  apply WP.spec_bind (add_spec hs (scalar_coeff_model hs) _ _ hco.sigma hw1)
  rintro s1 ⟨hws1, hs1⟩
  apply WP.spec_bind (monomial_wf (ψ := vecψ φ) _ (tk (VecLen 8) h hh))
  rintro m2 ⟨hw2, hm2⟩
  apply WP.spec_bind (add_spec hs (vec_coeff_model hs 8) _ _ hco.l hw2)
  rintro s2 ⟨hws2, hs2⟩
  rw [WP.spec_ok]
  simp only [c_s_power_val] at hm1 hm2
  have sm : ∀ {Cm : Type} [Inhabited Cm] [Bppp.Coefficient F Cm] (c : Cm),
      Spans (Bppp.Laurent.monomial (-1) c) (-1) 0 := fun c => spans_monomial (-1) c
  refine ⟨⟨hws1, hws2, hco.n, ?_, ?_, spans_mono hco.n_spans (min_le_left _ _) (le_max_left _ _)⟩, ?_⟩
  · rw [hs1, hm1]; exact spans_add hco.sigma_spans (sm _)
  · rw [hs2, hm2]; exact spans_add hco.l_spans (sm _)
  · simp only [toCO, Bppp.Circuit.CombinedOpening.with_r_s, hs1, hs2, hm1, hm2,
      Bppp.Circuit.C_S_POWER]
    rfl

lemma co_eval_spec (hs : ScalarModel F φ) (nm : ℕ) (co : bulletproofspp.circuit.CombinedOpening)
    (lo hi : ℤ) (hco : COK (φ := φ) nm lo hi co) (tau : S) :
    bulletproofspp.circuit.CombinedOpening.eval co tau ⦃ r =>
      match (toCO φ co).eval (φ tau) with
      | .ok o => ∃ o', r = .Ok o' ∧ toO φ o' = o ∧ o'.l.length = 8 ∧ o'.n.length = nm
      | .error _ => r = .Err .InvalidInput ⦄ := by
  unfold bulletproofspp.circuit.CombinedOpening.eval
  apply WP.spec_bind (eval_spec hs (scalar_coeff_model hs) _ hco.sigma tau)
  intro r1 h1
  simp only [toCO, Bppp.Circuit.CombinedOpening.eval]
  split at h1
  · rename_i c1 hc1
    obtain ⟨c1', rfl, -, hc1'⟩ := h1
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hc1, except_ok_bind]
    apply WP.spec_bind (eval_spec hs (vec_coeff_model hs 8) _ hco.l tau)
    intro r2 h2
    split at h2
    · rename_i c2 hc2
      obtain ⟨c2', rfl, hl2, hc2'⟩ := h2
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hc2, except_ok_bind]
      apply WP.spec_bind (eval_spec hs (vec_coeff_model hs nm) _ hco.n tau)
      intro r3 h3
      split at h3
      · rename_i c3 hc3
        obtain ⟨c3', rfl, hl3, hc3'⟩ := h3
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hc3, except_ok_bind,
          WP.spec_ok]
        exact ⟨_, rfl, by simp only [toO, hc1', ← hc2', ← hc3', vecψ], hl2, hl3⟩
      · rename_i e3 he3
        subst h3
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, he3,
          except_error_bind]
    · rename_i e2 he2
      subst h2
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, he2,
        except_error_bind]
  · rename_i e1 he1
    subst h1
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, he1,
      except_error_bind]

lemma f_spec (hs : ScalarModel F φ) (nm : ℕ) (co : bulletproofspp.circuit.CombinedOpening)
    (lo hi : ℤ) (hco : COK (φ := φ) nm lo hi co) (hlo : -(powBound / 2) ≤ lo)
    (hhi : hi ≤ powBound / 2) (c : bulletproofspp.laurent.Laurent (alloc.vec.Vec S))
    (hc : WF (VecLen 8) c) (hch : Half c) (nw : Slice S) (hnw : nw.length = nm) :
    bulletproofspp.circuit.f co c nw ⦃ r =>
      WF (fun _ => True) r ∧
      toL φ r = Bppp.Circuit.f (toCO φ co) (toL (vecψ φ) c) (nw.val.map φ) ⦄ := by
  unfold bulletproofspp.circuit.f
  simp only [laurent_clone_eq hs, bind_ok]
  have hl : Half co.l := half_of_spans rfl hco.l_spans hlo hhi
  have hn : Half co.n := half_of_spans rfl hco.n_spans hlo hhi
  apply WP.spec_bind (inner_product_spec' hs 8 c co.l hc hco.l hch hl)
  rintro l1 ⟨hw1, h1⟩
  apply WP.spec_bind (sub_spec hs (scalar_coeff_model hs) _ _ hco.sigma hw1)
  rintro l2 ⟨hw2, h2⟩
  apply WP.spec_bind (weighted_inner_product_spec' hs nm co.n co.n hco.n hco.n hn hn nw hnw)
  rintro l3 ⟨hw3, h3⟩
  apply WP.spec_mono (sub_spec hs (scalar_coeff_model hs) _ _ hw2 hw3)
  rintro r ⟨hwr, hr⟩
  refine ⟨hwr, ?_⟩
  rw [hr, h2, h1, h3]
  rfl

lemma inverse_spec' (hs : ScalarModel F φ) (a : S) :
    groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.inverse a ⦃ r =>
      match Bppp.inverse (φ a) with
      | .ok b => ∃ b', r = .Ok b' ∧ φ b' = b
      | .error _ => r = .Err .InvalidInput ⦄ := by
  by_cases h : φ a = 0
  · rw [hs.inverse_zero a h, WP.spec_ok]
    simp [Bppp.inverse, h]
  · obtain ⟨b, hb, hbv⟩ := hs.inverse a h
    rw [hb, WP.spec_ok]
    simp [Bppp.inverse, h, hbv]

lemma solve_r_s_spec (hs : ScalarModel F φ) (cons : bulletproofspp.constraints.Constraints)
    (hcl : cons.cl_v.length = 8) (f_bar : bulletproofspp.laurent.Laurent S)
    (hf : WF (fun _ => True) f_bar) (l_s beta : S) :
    bulletproofspp.circuit.solve_r_s cons f_bar l_s beta ⦃ r =>
      match Bppp.Circuit.solve_r_s (toC φ cons) (toL φ f_bar) (φ l_s) (φ beta) with
      | .ok (a, h) => ∃ a' h', r = .Ok (a', h') ∧ φ a' = a ∧ h'.val.map φ = h ∧ h'.length = 8
      | .error _ => r = .Err .InvalidInput ⦄ := by
  unfold bulletproofspp.circuit.solve_r_s
  apply WP.spec_bind (inverse_spec' hs beta)
  intro r hr
  simp only [Bppp.Circuit.solve_r_s]
  split at hr
  · rename_i binv hbinv
    obtain ⟨b', rfl, hb'⟩ := hr
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hbinv, except_ok_bind]
    unfold bulletproofspp.circuit.solve_r_s_loop
    apply WP.spec_bind (push_loop_off
      (body := fun x => bulletproofspp.circuit.solve_r_s_loop.body f_bar b' x.1 x.2) 0 0 7 φ
      (fun j => (toL φ f_bar).coeff (Bppp.Circuit.CR_POWERS.getD j 0 - 1) * binv)
      (fun v j hv hj => by
        dsimp only
        unfold bulletproofspp.circuit.solve_r_s_loop.body
        have hl : (Array.to_slice bulletproofspp.circuit.CR_POWERS).len.val = 7 := by
          simp [cr_len]
        have hcrb := cr_getD_bounds j.val
        rw [cr_getD_eq _ hj] at hcrb
        step*
        apply WP.spec_bind (coeff_spec hs (scalar_coeff_model hs) f_bar hf _ (by
          simp only [powBound]; scalar_tac))
        rintro c ⟨-, hc⟩
        simp only [hs.mul_eq, bind_ok]
        step*
        refine ⟨_, _, rfl, ⟨_, h1_post, ?_⟩, j1_post⟩
        rw [hs.φ_mulF, hc, hb', cr_getD_eq _ hj, i2_post, i1_post])
      (fun v j hv hj => by
        dsimp only
        unfold bulletproofspp.circuit.solve_r_s_loop.body
        have hl : (Array.to_slice bulletproofspp.circuit.CR_POWERS).len.val = 7 := by
          simp [cr_len]
        step*)
      _ 0#usize (by simp) (by simp))
    intro h1 hh1
    have h00 : ((0#usize : Usize).val) = 0 := rfl
    simp only [with_capacity_val, List.map_nil, List.nil_append, h00, Nat.sub_zero] at hh1
    have hh1l : h1.val.length = 7 := by
      have := congrArg List.length hh1
      simpa using this
    have hh1l' : h1.length = h1.val.length := rfl
    step*
    have hh2 : h2.val.map φ = Bppp.Circuit.CR_POWERS.map
        (fun a => (toL φ f_bar).coeff (a - 1) * binv) ++ [φ l_s] := by
      rw [h2_post, List.map_append, hh1]
      simp [Bppp.Circuit.CR_POWERS, List.range']
    have hh2l : h2.val.length = 8 := by rw [h2_post]; simp [hh1l]
    apply WP.spec_bind (inner_product_spec hs _ _ (by
      simp only [Slice.length, deref_val, hh2l]; exact hcl))
    intro ip hip
    apply WP.spec_bind (coeff_spec hs (scalar_coeff_model hs) f_bar hf (-1)#i32 (by
      simp only [powBound]; decide))
    rintro c1 ⟨-, hc1⟩
    simp only [hs.sub_eq, bind_ok, WP.spec_ok]
    refine ⟨_, _, rfl, ?_, hh2, hh2l⟩
    simp only [hs.φ_subF, hip, hc1, deref_val, hh2]
    rfl
  · rename_i e he
    subst hr
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, he,
      except_error_bind]

/-- The lengths of generated constraints that the circuit uses. -/
structure ConsLen (m nm : ℕ) (c : bulletproofspp.constraints.Constraints) : Prop where
  lambdas : m ≤ c.lambdas.length
  norm_weights : c.norm_weights.length = nm
  cn_l : c.cn_l.length = nm
  cn_r : c.cn_r.length = nm
  cn_o : c.cn_o.length = nm
  cn_v : c.cn_v.length = nm
  cl_v : c.cl_v.length = 8

/-- The lengths of an honest generated witness. -/
structure WitLen (m nm : ℕ) (w : bulletproofspp.circuit.Witness) : Prop where
  values : w.values.length = m
  blindings : w.blindings.length = m
  off_plane : w.off_plane.val = []
  n_l : w.n_l.length = nm
  n_o : w.n_o.length = nm
  n_s : w.n_s.length = nm
  r_o : w.r_o.length = 8
  r_l : w.r_l.length = 8
  r_r : w.r_r.length = 8

lemma weights_loop_spec (hs : ScalarModel F φ) (m : Usize)
    (cons : bulletproofspp.constraints.Constraints) (two : S) (w : alloc.vec.Vec S) (i : Usize)
    (hl : w.val.length = i.val) (hi : i.val ≤ m.val) (hlam : m.val ≤ cons.lambdas.length)
    (hw : w.val.map φ = ((cons.lambdas.val.map φ).take i.val).map (φ two * ·)) :
    bulletproofspp.circuit.opening_without_r_s_loop0 m cons two w i ⦃ r =>
      r.1 = cons ∧ r.2.val.map φ = ((cons.lambdas.val.map φ).take m.val).map (φ two * ·) ∧
        r.2.val.length = m.val ⦄ := by
  unfold bulletproofspp.circuit.opening_without_r_s_loop0
  have el : cons.lambdas.length = cons.lambdas.val.length := rfl
  apply loop.spec_decr_nat (fun x => m.val - x.2.val)
    (fun x => x.1.val.length = x.2.val ∧ x.2.val ≤ m.val ∧
      x.1.val.map φ = ((cons.lambdas.val.map φ).take x.2.val).map (φ two * ·))
  · rintro ⟨v, k⟩ ⟨hl1, hk, hv⟩
    simp only at hl1 hk hv
    unfold bulletproofspp.circuit.opening_without_r_s_loop0.body
    simp only [hs.mul_eq]
    have : v.length = v.val.length := rfl
    step*
    · refine ⟨by simp [*], by scalar_tac, ?_, by scalar_tac⟩
      rw [weights1_post, i2_post, List.map_append, hv,
        List.take_succ_eq_append_getElem (by simp; scalar_tac)]
      simp [rs_post]
  · exact ⟨hl, hi, hw⟩

lemma loop_done {α β : Type} (body : α → Result (ControlFlow α β)) (x : α) (y : β)
    (h : body x = ok (.done y)) : loop body x = ok y := by
  rw [loop]
  simp [h]

lemma opening_without_r_s_spec (hs : ScalarModel F φ) (pm : Bppp.CircuitParams)
    (p : bulletproofspp.circuit.CircuitParams) (hp : ParamsOK pm p)
    (cons : bulletproofspp.constraints.Constraints) (hc : ConsLen p.m.val p.nm.val cons)
    (w : bulletproofspp.circuit.Witness) (hw : WitLen p.m.val p.nm.val w)
    (n_r : alloc.vec.Vec S) (hnr : n_r.length = p.nm.val) (delta delta_inv : S) :
    bulletproofspp.circuit.opening_without_r_s p cons w n_r delta delta_inv ⦃ r =>
      COK (φ := φ) p.nm.val (-1) 7 r ∧
      toCO φ r = Bppp.Circuit.opening_without_r_s pm (toC φ cons) (toWit φ w) (n_r.val.map φ)
        (φ delta) (φ delta_inv) ⦄ := by
  obtain ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ := hp
  unfold bulletproofspp.circuit.opening_without_r_s
  simp only [hs.from_u64_eq, bind_ok]
  apply WP.spec_bind (weights_loop_spec hs p.m cons _ _ 0#usize (by simp) (by simp) hc.lambdas
    (by simp))
  rintro ⟨c1, weights⟩ ⟨hc1, hwts, hwl⟩
  simp only at hc1 hwts hwl
  subst hc1
  have hwl' : weights.length = weights.val.length := rfl
  apply WP.spec_bind (inner_product_spec hs _ _ (by
    simp only [Slice.length, deref_val, hwl]; exact hw.values.symm))
  intro rs hrs
  simp only [hs.zero_eq, bulletproofspp.crs.H_LEN, bind_ok]
  have hnml' : p.nm.val ≤ Usize.max := by omega
  step*
  all_goals try exact hs.clone _
  apply WP.spec_bind (inner_product_spec hs _ _ (by
    simp only [Slice.length, deref_val, hwl]; exact hw.blindings.symm))
  intro rs2 hrs2
  step*
  have hop : w.off_plane.len = 0#usize := by
    apply UScalar.eq_of_val_eq
    show w.off_plane.val.length = 0
    rw [hw.off_plane]; rfl
  have hloop : bulletproofspp.circuit.opening_without_r_s_loop1 w.off_plane weights
      (index_mut_back rs2) v1 0#usize = ok (index_mut_back rs2, v1) := by
    unfold bulletproofspp.circuit.opening_without_r_s_loop1
    apply loop_done
    unfold bulletproofspp.circuit.opening_without_r_s_loop1.body
    simp [hop]
  rw [hloop, bind_ok]
  simp only [Std.uncurry_apply_pair, vec_clone_eq hs, bind_ok]
  apply WP.spec_bind (message_opening_spec hs _ w.n_o (by simp [Slice.length, deref_val, hw.r_o]))
  rintro o ⟨ho, hol, hon⟩
  simp only [hs.mul_eq, bind_ok]
  apply WP.spec_bind (vec_scalar_mul_spec hs delta (alloc.vec.Vec.deref o.l))
  intro v6 hv6
  apply WP.spec_bind (vec_scalar_mul_spec hs delta (alloc.vec.Vec.deref o.n))
  intro v7 hv7
  apply WP.spec_bind (message_opening_spec hs _ w.n_l (by simp [Slice.length, deref_val, hw.r_l]))
  rintro o1 ⟨ho1, hol1, hon1⟩
  apply WP.spec_bind (message_opening_spec hs _ n_r (by simp [Slice.length, deref_val, hw.r_r]))
  rintro o2 ⟨ho2, hol2, hon2⟩
  step*
  have hco : (bulletproofspp.circuit.C_O_POWER).val = 0 := by
    unfold bulletproofspp.circuit.C_O_POWER; rfl
  have hcl : (bulletproofspp.circuit.C_L_POWER).val = 1 := by
    unfold bulletproofspp.circuit.C_L_POWER; rfl
  have hcr : (bulletproofspp.circuit.C_R_POWER).val = 2 := by
    unfold bulletproofspp.circuit.C_R_POWER; rfl
  have hcv : (bulletproofspp.circuit.V_HAT_POWER).val = 3 := by
    unfold bulletproofspp.circuit.V_HAT_POWER; rfl
  have hs9 : s9.val = [(bulletproofspp.circuit.C_O_POWER, ⟨hs.mulF delta o.sigma, v6, v7⟩),
      (bulletproofspp.circuit.C_L_POWER, o1), (bulletproofspp.circuit.C_R_POWER, o2),
      (bulletproofspp.circuit.V_HAT_POWER, ⟨rs, index_mut_back rs2, v1⟩)] := by
    rw [s9_post]; rfl
  have hderef : ∀ v : alloc.vec.Vec S, (alloc.vec.Vec.deref v).length = v.length := fun v => by
    simp [Slice.length, deref_val, alloc.vec.Vec.length]
  have hv6l : v6.length = 8 := by
    have := congrArg List.length hv6
    simp only [List.length_map, Bppp.vec_scalar_mul, deref_val] at this
    show v6.val.length = 8
    rw [this]; have h' := hol; rw [hderef] at h'; exact h'.trans hw.r_o
  have hv7l : v7.length = p.nm.val := by
    have := congrArg List.length hv7
    simp only [List.length_map, Bppp.vec_scalar_mul, deref_val, hon] at this
    show v7.val.length = _
    rw [this]; exact hw.n_o
  have himl : (index_mut_back rs2).length = 8 := by
    rw [index_mut_back_post]; simp [v_post1]
  apply WP.spec_bind (co_from_terms_spec hs p.nm.val s9 0 4 (by simp [hs9]) (by
      intro t ht
      rw [hs9] at ht
      simp only [List.mem_cons, List.not_mem_nil, or_false] at ht
      rcases ht with rfl | rfl | rfl | rfl
      · exact ⟨by simp [hco], by simp [hco], hv6l, hv7l⟩
      · exact ⟨by simp [hcl], by simp [hcl], by rw [hol1, hderef]; exact hw.r_l, by rw [hon1]; exact hw.n_l⟩
      · exact ⟨by simp [hcr], by simp [hcr], by rw [hol2, hderef]; exact hw.r_r, by rw [hon2]; exact hnr⟩
      · exact ⟨by simp [hcv], by simp [hcv], himl, v1_post1⟩)
    (by norm_num [powBound]) (by norm_num [powBound]))
  rintro co ⟨hcok, hcoe⟩
  apply WP.spec_bind (p_n_spec hs c1 p.nm.val hc.cn_v hc.cn_r hc.cn_l hc.cn_o delta_inv)
  rintro pn ⟨hpw, hph, hpe⟩
  apply WP.spec_bind (weighted_inner_product_spec' hs p.nm.val pn pn hpw hpw hph hph _ (by
    simp only [Slice.length, deref_val]; exact hc.norm_weights))
  rintro l ⟨hlw, hle⟩
  simp only [hs.add_eq, bind_ok]
  have tk3 : TermOK (fun _ => True) (3#i32, hs.mulF (hs.fromF 2#u64) (hs.addF c1.lambda_al c1.mu_am)) :=
    ⟨trivial, by norm_num [powBound], by norm_num [powBound]⟩
  apply WP.spec_bind (monomial_wf (ψ := φ) _ tk3)
  rintro m1 ⟨hm1w, hm1e⟩
  apply WP.spec_bind (add_spec hs (scalar_coeff_model hs) _ _ hlw hm1w)
  rintro ps ⟨hpsw, hpse⟩
  apply WP.spec_bind (add_spec hs (scalar_coeff_model hs) _ _ hcok.sigma hpsw)
  rintro l2 ⟨hl2w, hl2e⟩
  have tks : TermOK (VecLen p.nm.val) (bulletproofspp.circuit.C_S_POWER, w.n_s) :=
    ⟨hw.n_s, by rw [c_s_power_val]; norm_num [powBound], by rw [c_s_power_val]; norm_num [powBound]⟩
  apply WP.spec_bind (monomial_wf (ψ := vecψ φ) _ tks)
  rintro m2 ⟨hm2w, hm2e⟩
  apply WP.spec_bind (add_spec hs (vec_coeff_model hs p.nm.val) _ _ hcok.n hm2w)
  rintro l4 ⟨hl4w, hl4e⟩
  apply WP.spec_bind (add_spec hs (vec_coeff_model hs p.nm.val) _ _ hl4w hpw)
  rintro l5 ⟨hl5w, hl5e⟩
  rw [WP.spec_ok]
  simp only [c_s_power_val] at hm2e
  have hpsp : Spans (toL (vecψ φ) pn) 0 4 := by
    rw [hpe]; simp [Spans, Bppp.Constraints.p_n, Bppp.Laurent.new]
  refine ⟨⟨hl2w, hcok.l, hl5w, ?_, ?_, ?_⟩, ?_⟩
  · rw [hl2e, hpse, hle, hm1e]
    exact spans_mono (spans_add hcok.sigma_spans
      (spans_add (spans_weighted_inner_product hpsp hpsp _) (spans_monomial 3 _)))
      (by norm_num) (by norm_num)
  · exact spans_mono hcok.l_spans (by norm_num) (by norm_num)
  · rw [hl5e, hl4e, hm2e]
    exact spans_mono (spans_add (spans_add hcok.n_spans (spans_monomial (-1) _)) hpsp)
      (by norm_num) (by norm_num)
  · simp only [deref_val] at ho ho1 ho2 hrs hrs2 hv6 hv7 hle
    have h2 : φ (hs.fromF 2#u64) = 2 := by simp
    have hwts' : weights.val.map φ = ((toC φ c1).lambdas.take pm.m).map (fun x => 2 * x) := by
      rw [hwts, h2, hm]; rfl
    have hset : ((List.replicate Bppp.H_LEN (0 : F)).set 0 (φ rs2)).set (Bppp.H_LEN - 1) 0 =
        (List.replicate 8 (0 : F)).set 0 (φ rs2) := rfl
    have hcoe' : toCO φ co = Bppp.Circuit.CombinedOpening.from_terms
        [(Bppp.Circuit.C_O_POWER,
          ⟨φ delta * (Bppp.Circuit.message_opening (w.r_o.val.map φ) (w.n_o.val.map φ)).sigma,
            Bppp.vec_scalar_mul (φ delta)
              (Bppp.Circuit.message_opening (w.r_o.val.map φ) (w.n_o.val.map φ)).l,
            Bppp.vec_scalar_mul (φ delta)
              (Bppp.Circuit.message_opening (w.r_o.val.map φ) (w.n_o.val.map φ)).n⟩),
         (Bppp.Circuit.C_L_POWER, Bppp.Circuit.message_opening (w.r_l.val.map φ) (w.n_l.val.map φ)),
         (Bppp.Circuit.C_R_POWER, Bppp.Circuit.message_opening (w.r_r.val.map φ) (n_r.val.map φ)),
         (Bppp.Circuit.V_HAT_POWER,
          ⟨Bppp.inner_product (((toC φ c1).lambdas.take pm.m).map (fun x => 2 * x))
              (w.values.val.map φ),
            ((List.replicate Bppp.H_LEN 0).set 0
              (Bppp.inner_product (((toC φ c1).lambdas.take pm.m).map (fun x => 2 * x))
                (w.blindings.val.map φ))).set (Bppp.H_LEN - 1) 0,
            List.replicate pm.nm 0⟩)] := by
      rw [hcoe, hs9, ← ho, ← ho1, ← ho2, ← hwts', ← hrs, ← hrs2, hset]
      simp only [List.map_cons, List.map_nil, hco, hcl, hcr, hcv, toO, hv6, hv7, ← hpnm,
        index_mut_back_post, v_post, v1_post, ScalarModel.φ_mulF, ScalarModel.φ_z, List.map_replicate,
        Bppp.Circuit.C_O_POWER, Bppp.Circuit.C_L_POWER, Bppp.Circuit.C_R_POWER,
        Bppp.Circuit.V_HAT_POWER, List.map_set, alloc.vec.Vec.set_val_eq]
      rfl
    simp only [toCO] at hcoe'
    simp only [toCO, Bppp.Circuit.opening_without_r_s, toWit, hw.off_plane, List.map_nil,
      List.zip_nil_left, List.foldl_nil, ← hcoe', Bppp.Circuit.CombinedOpening.mk.injEq]
    refine ⟨?_, trivial, ?_⟩
    · rw [hl2e, hpse, hle, hm1e, hpe]
      simp [toC]
    · rw [hl5e, hl4e, hm2e, hpe]
      rfl

end BpppProofs
