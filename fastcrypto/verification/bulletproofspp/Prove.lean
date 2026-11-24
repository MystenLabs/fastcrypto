-- THIS FILE IS AI-ONLY
import bulletproofspp.LazyBases

/-!
The generated `norm_linear::prove` computes the model's.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- The model of generated rounds. -/
def roundsψ (ψ : P → E) (r : List (P × P)) : List (E × E) := r.map fun (a, b) => (ψ a, ψ b)

/-- The model of a generated norm-linear proof. -/
def toProof (φ : S → F) (ψ : P → E) (pr : bulletproofspp.norm_linear.NormLinearProof) :
    Bppp.NormLinearProof F E :=
  ⟨roundsψ ψ pr.rounds.val, φ pr.l_final, pr.n_final.val.map φ⟩

/-- The result of a generated `prove`, with the rounds `pre` already sent, matches the model's
run: the same proof under the models, after `pre`, and the same transcript; or the same error. -/
def ProveMatches (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E) (pre : List (E × E))
    (r : core.result.Result bulletproofspp.norm_linear.NormLinearProof error.FastCryptoError ×
      bulletproofspp.transcript.BpppTranscript)
    (m : Except Bppp.Error (Bppp.NormLinearProof F E × Bppp.BpppTranscript F E)) : Prop :=
  match m with
  | .ok (pm, T) => ∃ pr, r.1 = .Ok pr ∧ τ r.2 = T ∧
    toProof φ ψ pr = { pm with rounds := pre ++ pm.rounds }
  | .error _ => r.1 = .Err .InvalidInput

lemma round_challenge_spec {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (t : bulletproofspp.transcript.BpppTranscript) (x r : P) :
    bulletproofspp.norm_linear.round_challenge t x r ⦃ q => ∃ T1 T2,
      (Bppp.BpppTranscript.append_point "X" (ψ x)).run (τ t) = .ok ((), T1) ∧
      (Bppp.BpppTranscript.append_point "R" (ψ r)).run T1 = .ok ((), T2) ∧
      (Bppp.BpppTranscript.challenge_scalar "gamma").run T2 = .ok (φ q.1, τ q.2) ⦄ := by
  unfold bulletproofspp.norm_linear.round_challenge
  obtain ⟨t1, h1, m1⟩ := ht.append_point t .X x
  obtain ⟨t2, h2, m2⟩ := ht.append_point t1 .R r
  obtain ⟨c, t3, h3, m3⟩ := ht.challenge_scalar t2 .Gamma
  rw [h1, bind_ok, h2, bind_ok, h3, WP.spec_ok]
  simp only [labelStr] at m1 m2 m3
  exact ⟨_, _, m1, m2, m3⟩

lemma is_base_case_spec (a b : Usize) (h : a.val + b.val ≤ Usize.max) :
    bulletproofspp.norm_linear.is_base_case a b =
      ok (Bppp.NormLinear.is_base_case a.val b.val) := by
  unfold bulletproofspp.norm_linear.is_base_case Bppp.NormLinear.is_base_case
  by_cases ha : a.val ≤ 1
  · have : a ≤ 1#usize := by scalar_tac
    simp only [this, ite_true]
    have hs := Usize.add_spec (x := a) (y := b) h
    obtain ⟨z, hz, hzv⟩ := spec_eq_ok' hs
    rw [hz, bind_ok]
    simp [ha, bulletproofspp.norm_linear.FOLD_THRESHOLD, Bppp.FOLD_THRESHOLD, hzv]
    exact decide_eq_decide.mpr Iff.rfl
  · have : ¬ a ≤ 1#usize := by scalar_tac
    simp [this, ha]

/-- The model's run of the prove loop from a generated state. -/
noncomputable def proveM (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (gens : bulletproofspp.crs.Generators) (t : bulletproofspp.transcript.BpppTranscript)
    (bases : bulletproofspp.norm_linear.LazyBases) (c : alloc.vec.Vec S) (rho : S)
    (l n : alloc.vec.Vec S) :
    Except Bppp.Error (Bppp.NormLinearProof F E × Bppp.BpppTranscript F E) :=
  (Bppp.NormLinear.prove_loop (toLB φ ψ gens bases) (c.val.map φ) (φ rho) (l.val.map φ)
    (n.val.map φ)).run (τ t)

/-- The model's run with the rounds `pre` put first. -/
def withPre (pre : List (E × E)) (m : Except Bppp.Error (Bppp.NormLinearProof F E ×
    Bppp.BpppTranscript F E)) : Except Bppp.Error (Bppp.NormLinearProof F E ×
    Bppp.BpppTranscript F E) :=
  m.map fun (pm, T) => ({ pm with rounds := pre ++ pm.rounds }, T)

lemma proveMatches_withPre (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (pre : List (E × E)) (r) (m : Except Bppp.Error (Bppp.NormLinearProof F E ×
      Bppp.BpppTranscript F E)) :
    ProveMatches φ ψ τ pre r m ↔ ProveMatches φ ψ τ [] r (withPre pre m) := by
  cases m with
  | error e => simp [ProveMatches, withPre, Except.map]
  | ok v => obtain ⟨pm, T⟩ := v; simp [ProveMatches, withPre, Except.map]

lemma prove_base_spec {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators)
    (t : bulletproofspp.transcript.BpppTranscript) (bases : bulletproofspp.norm_linear.LazyBases)
    (c : alloc.vec.Vec S) (rho : S) (l n : alloc.vec.Vec S)
    (rounds : alloc.vec.Vec (P × P)) (hl : l.val.length = 1)
    (hb : Bppp.NormLinear.is_base_case (l.val.length) (n.val.length) = true)
    (hlen : l.val.length + n.val.length ≤ Usize.max) :
    bulletproofspp.norm_linear.prove_loop.body gens.g gens.h_vec gens.g_vec gens.precomp t bases c
      rho l n rounds ⦃ cf => match cf with
        | .done r => ProveMatches φ ψ τ (roundsψ ψ rounds.val) r
            (proveM φ ψ τ gens t bases c rho l n)
        | .cont _ => False ⦄ := by
  unfold bulletproofspp.norm_linear.prove_loop.body
  have el : l.len.val = l.val.length := rfl
  have en : n.len.val = n.val.length := rfl
  simp only []
  rw [is_base_case_spec l.len n.len (by rw [el, en]; exact hlen), el, en, hb, bind_ok]
  simp only [ite_true]
  obtain ⟨t1, h1, m1⟩ := ht.append_scalars t .LFinal (alloc.vec.Vec.deref l)
  obtain ⟨t2, h2, m2⟩ := ht.append_scalars t1 .NFinal (alloc.vec.Vec.deref n)
  rw [h1, bind_ok, h2, bind_ok]
  step*
  simp only [ProveMatches, proveM]
  rw [Bppp.NormLinear.prove_loop, dif_pos (by simpa using hb)]
  simp only [labelStr, deref_val] at m1 m2
  simp only [StateT.run_bind, m1, except_ok_bind, m2, StateT.run_pure]
  refine ⟨_, rfl, rfl, ?_⟩
  obtain ⟨a, ha⟩ : ∃ a, l.val = [a] := List.length_eq_one_iff.mp hl
  simp [toProof, rs_post, ha]

@[simp] lemma liftM_ok_run {σ ε α : Type} (a : α) (st : σ) :
    (liftM (Except.ok a : Except ε α) : StateT σ (Except ε) α).run st = .ok (a, st) := rfl

@[simp] lemma liftM_error_run {σ ε α : Type} (e : ε) (st : σ) :
    (liftM (Except.error e : Except ε α) : StateT σ (Except ε) α).run st = .error e := rfl

lemma withPre_snoc (pre : List (E × E)) (a : E × E)
    (R : Except Bppp.Error (Bppp.NormLinearProof F E × Bppp.BpppTranscript F E)) :
    withPre (pre ++ [a]) R = withPre pre (do
      let p ← R
      Except.pure ({ rounds := a :: p.1.rounds, l_final := p.1.l_final, n_final := p.1.n_final },
        p.2)) := by
  cases R with
  | error e => rfl
  | ok v => simp [withPre, Except.map, Except.pure]

/-- The weights of lazy bases have length `1`, `2`, `4` or `8`. -/
def WPow (lb : bulletproofspp.norm_linear.LazyBases) : Prop :=
  lb.w_h.length = 1 ∨ lb.w_h.length = 2 ∨ lb.w_h.length = 4 ∨ lb.w_h.length = 8

/-- What the round loop keeps: lazy bases as `LBInv` and `WPow`, `c` as long as `l`, `l` not
empty, and the rounds and vectors within `B`, where `4 B ≤ usize::MAX`. -/
structure ProveInv (gens : bulletproofspp.crs.Generators) (B : ℕ)
    (bases : bulletproofspp.norm_linear.LazyBases) (c l n : alloc.vec.Vec S)
    (rounds : alloc.vec.Vec (P × P)) : Prop where
  lb : LBInv gens bases
  pow : WPow bases
  cl : c.val.length = l.val.length
  l_pos : 1 ≤ l.val.length
  size : rounds.val.length + l.val.length + n.val.length ≤ B

lemma prove_round_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (B : ℕ) (hB : 4 * B + 8 ≤ Usize.max)
    (hgl : 1 + gens.h_vec.length + gens.g_vec.length + 8 ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (bases : bulletproofspp.norm_linear.LazyBases)
    (c : alloc.vec.Vec S) (rho : S) (l n : alloc.vec.Vec S) (rounds : alloc.vec.Vec (P × P))
    (hinv : ProveInv gens B bases c l n rounds)
    (hb : Bppp.NormLinear.is_base_case (l.val.length) (n.val.length) = false) :
    bulletproofspp.norm_linear.prove_loop.body gens.g gens.h_vec gens.g_vec gens.precomp t bases c
      rho l n rounds ⦃ cf => match cf with
        | .done r => ProveMatches φ ψ τ (roundsψ ψ rounds.val) r
            (proveM φ ψ τ gens t bases c rho l n)
        | .cont (t', bases', c', rho', l', n', rounds') =>
          ProveInv gens B bases' c' l' n' rounds' ∧
          l'.val.length + n'.val.length < l.val.length + n.val.length ∧
          withPre (roundsψ ψ rounds'.val) (proveM φ ψ τ gens t' bases' c' rho' l' n') =
            withPre (roundsψ ψ rounds.val) (proveM φ ψ τ gens t bases c rho l n) ⦄ := by
  obtain ⟨hlb, hpow, hcl, hl1, hsz⟩ := hinv
  unfold bulletproofspp.norm_linear.prove_loop.body
  have el : l.len.val = l.val.length := rfl
  have en : n.len.val = n.val.length := rfl
  simp only []
  rw [is_base_case_spec l.len n.len (by rw [el, en]; omega), el, en, hb, bind_ok]
  simp only [Bool.false_eq_true, ite_false]
  apply WP.spec_bind (split_even_odd_spec hs l (by omega))
  rintro ⟨l0, l1⟩ hl01
  apply WP.spec_bind (split_even_odd_spec hs n (by omega))
  rintro ⟨n0, n1⟩ hn01
  apply WP.spec_bind (split_even_odd_spec hs c (by omega))
  rintro ⟨c0, c1⟩ hc01
  dsimp only at hl01 hn01 hc01 ⊢
  simp only [hs.mul_eq, bind_ok]
  -- the model, unfolded once
  simp only [proveM]
  rw [Bppp.NormLinear.prove_loop, dif_neg (by simpa using hb)]
  dsimp only
  -- lengths of the halves
  have hsl := Bppp.NormLinear.split_even_odd_length (l.val.map φ)
  have hsn := Bppp.NormLinear.split_even_odd_length (n.val.map φ)
  have hsc := Bppp.NormLinear.split_even_odd_length (c.val.map φ)
  rw [← hl01] at hsl; rw [← hn01] at hsn; rw [← hc01] at hsc
  simp only [List.length_map] at hsl hsn hsc
  obtain ⟨hl0l, hl1l⟩ := hsl
  obtain ⟨hn0l, hn1l⟩ := hsn
  obtain ⟨hc0l, hc1l⟩ := hsc
  have hL0 : (l.val.map φ |> Bppp.NormLinear.split_even_odd).1 = l0.val.map φ :=
    (congrArg Prod.fst hl01).symm
  have hL1 : (l.val.map φ |> Bppp.NormLinear.split_even_odd).2 = l1.val.map φ :=
    (congrArg Prod.snd hl01).symm
  have hN0 : (n.val.map φ |> Bppp.NormLinear.split_even_odd).1 = n0.val.map φ :=
    (congrArg Prod.fst hn01).symm
  have hN1 : (n.val.map φ |> Bppp.NormLinear.split_even_odd).2 = n1.val.map φ :=
    (congrArg Prod.snd hn01).symm
  have hC0 : (c.val.map φ |> Bppp.NormLinear.split_even_odd).1 = c0.val.map φ :=
    (congrArg Prod.fst hc01).symm
  have hC1 : (c.val.map φ |> Bppp.NormLinear.split_even_odd).2 = c1.val.map φ :=
    (congrArg Prod.snd hc01).symm
  simp only [hL0, hL1, hN0, hN1, hC0, hC1]
  by_cases hr0 : φ rho = 0
  · rw [hs.inverse_zero rho hr0]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, WP.spec_ok]
    simp [ProveMatches, Bppp.inverse, hr0]
  obtain ⟨ri, hri, hriv⟩ := hs.inverse rho hr0
  simp only [hri, core.result.Result.Insts.CoreOpsTry.branch, bind_ok, Bppp.inverse, hr0, ite_false]
  obtain ⟨two, htwo, htwov⟩ := hs.from_u64 2#u64
  simp only [htwo, bind_ok]
  have e1 : ∀ v : alloc.vec.Vec S, (alloc.vec.Vec.deref v).length = v.val.length := fun v => by
    simp [Slice.length]
  have hn01l : (alloc.vec.Vec.deref n0).length = (alloc.vec.Vec.deref n1).length := by
    rw [e1, e1, hn0l, hn1l]
  have hc0l1 : (alloc.vec.Vec.deref c0).length = (alloc.vec.Vec.deref l1).length := by
    rw [e1, e1, hc0l, hl1l, hcl]
  have hc1l0 : (alloc.vec.Vec.deref c1).length = (alloc.vec.Vec.deref l0).length := by
    rw [e1, e1, hc1l, hl0l, hcl]
  have hc1l1 : (alloc.vec.Vec.deref c1).length = (alloc.vec.Vec.deref l1).length := by
    rw [e1, e1, hc1l, hl1l, hcl]
  apply WP.spec_bind (weighted_inner_product_spec hs _ _ _ hn01l)
  intro rs1 hrs1
  apply WP.spec_bind (inner_product_spec hs _ _ hc0l1)
  intro rs3 hrs3
  simp only [hs.add_eq, bind_ok]
  apply WP.spec_bind (inner_product_spec hs _ _ hc1l0)
  intro rs5 hrs5
  apply WP.spec_bind (weighted_norm_spec hs _ _)
  intro rs6 hrs6
  apply WP.spec_bind (inner_product_spec hs _ _ hc1l1)
  intro rs7 hrs7
  have hl10 : (alloc.vec.Vec.deref l1).length = (alloc.vec.Vec.deref l0).length := by
    rw [e1, e1, hl1l, hl0l]
  apply WP.spec_bind (interleave_spec (F := F) (φ := φ) _ _ hl10 (by rw [e1]; omega))
  intro v2 hv2
  apply WP.spec_bind (vec_scalar_mul_spec hs rho (alloc.vec.Vec.deref n1))
  intro v3 hv3
  apply WP.spec_bind (vec_scalar_mul_spec hs ri (alloc.vec.Vec.deref n0))
  intro v4 hv4
  have hv3l : v3.val.length = n1.val.length := by
    have := congrArg List.length hv3; simpa [Bppp.vec_scalar_mul] using this
  have hv4l : v4.val.length = n0.val.length := by
    have := congrArg List.length hv4; simpa [Bppp.vec_scalar_mul] using this
  apply WP.spec_bind (interleave_spec (F := F) (φ := φ) (alloc.vec.Vec.deref v3) (alloc.vec.Vec.deref v4)
    (by rw [e1, e1, hv3l, hv4l, hn0l, hn1l]) (by rw [e1, hv3l, hn1l]; omega))
  intro v5 hv5
  have hlb1 := hlb
  apply WP.spec_bind (lazy_msm_spec (φ := φ) (ψ := ψ) hs hp gens hg hgl bases hlb _
    (alloc.vec.Vec.deref v2) (alloc.vec.Vec.deref v5))
  rintro ⟨r1, bases1⟩ hm1
  unfold LazyMatches at hm1
  simp only [deref_val] at hm1 hrs1 hrs3 hrs5 hrs6 hrs7 hv2 hv3 hv4 hv5
  rw [hv2, hv5, hv3, hv4] at hm1
  simp only [hs.φ_addF, hs.φ_mulF, hrs1, hrs3, hrs5, htwov, hriv] at hm1
  -- the model's run, up to the first MSM
  simp only [StateT.run_bind, StateT.run_pure, pure_bind, liftM_ok_run, except_ok_bind]
  have h2 : (((2#u64 : U64).val : ℕ) : F) = 2 := by simp
  rw [h2] at hm1
  cases hmm1 : (toLB φ ψ gens bases).msm
      (2 * (φ rho)⁻¹ * Bppp.weighted_inner_product (List.map φ ↑n0) (List.map φ ↑n1)
          (φ rho * φ rho * (φ rho * φ rho)) +
        Bppp.inner_product (List.map φ ↑c0) (List.map φ ↑l1) +
        Bppp.inner_product (List.map φ ↑c1) (List.map φ ↑l0))
      (Bppp.NormLinear.interleave (List.map φ ↑l1) (List.map φ ↑l0))
      (Bppp.NormLinear.interleave (Bppp.vec_scalar_mul (φ rho) (List.map φ ↑n1))
        (Bppp.vec_scalar_mul (φ rho)⁻¹ (List.map φ ↑n0))) with
  | error e =>
    rw [hmm1] at hm1
    subst hm1
    simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      ProveMatches]
  | ok v =>
    obtain ⟨x, b1m⟩ := v
    rw [hmm1] at hm1
    obtain ⟨xp, hxp, hxv, hb1, hlb1', hw1⟩ := hm1
    subst hxp
    simp only [except_ok_bind, liftM_ok_run]
    simp only [Std.uncurry_apply_pair, bind_ok]
    apply WP.spec_bind (odd_only_spec hs (alloc.vec.Vec.deref l1) (by rw [e1]; omega))
    intro v6 hv6
    apply WP.spec_bind (odd_only_spec hs (alloc.vec.Vec.deref n1) (by rw [e1]; omega))
    intro v7 hv7
    apply WP.spec_bind (lazy_msm_spec (φ := φ) (ψ := ψ) hs hp gens hg hgl bases1 hlb1' _
      (alloc.vec.Vec.deref v6) (alloc.vec.Vec.deref v7))
    rintro ⟨r2, bases2⟩ hm2
    unfold LazyMatches at hm2
    simp only [deref_val] at hm2 hv6 hv7
    rw [hv6, hv7, hb1] at hm2
    simp only [hs.φ_addF, hs.φ_mulF, hrs6, hrs7] at hm2
    cases hmm2 : b1m.msm (Bppp.weighted_norm (List.map φ ↑n1) (φ rho * φ rho * (φ rho * φ rho)) +
        Bppp.inner_product (List.map φ ↑c1) (List.map φ ↑l1))
        (Bppp.NormLinear.odd_only (List.map φ ↑l1)) (Bppp.NormLinear.odd_only (List.map φ ↑n1)) with
    | error e =>
      rw [hmm2] at hm2
      subst hm2
      simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
        ProveMatches]
    | ok v =>
      obtain ⟨rpt, b2m⟩ := v
      rw [hmm2] at hm2
      obtain ⟨rp', hrp, hrv, hb2, hlb2, hw2⟩ := hm2
      subst hrp
      simp only [Std.uncurry_apply_pair, bind_ok, except_ok_bind, liftM_ok_run]
      apply WP.spec_bind (round_challenge_spec ht t xp rp')
      rintro ⟨gamma, t1⟩ ⟨T1, T2, hX, hR, hG⟩
      dsimp only at hG
      simp only [Std.uncurry_apply_pair]
      have hw2pow : bases2.w_h.length ≠ 8 ∧ 2 * bases2.w_h.length ≤ 8 := by
        rw [hw2, hw1]
        rcases hpow with h | h | h | h <;> simp [h]
      have hw2g : bases2.w_g.length = bases2.w_h.length := hlb2.eq
      apply WP.spec_bind (fold_spec (ψ := ψ) hs gens bases2 rho gamma (by omega) (by omega))
      rintro bases3 ⟨hb3, hb3p, hb3h, hb3g⟩
      apply WP.spec_bind (vec_scalar_mul_spec hs gamma (alloc.vec.Vec.deref c1))
      intro v8 hv8
      have hc1v8 : (alloc.vec.Vec.deref c0).length = (alloc.vec.Vec.deref v8).length := by
        have := congrArg List.length hv8
        simp [Bppp.vec_scalar_mul] at this
        rw [e1, e1, this, hc0l, hc1l]
      apply WP.spec_bind (vec_add_spec hs _ _ hc1v8)
      intro c2 hc2
      apply WP.spec_bind (vec_scalar_mul_spec hs gamma (alloc.vec.Vec.deref l1))
      intro v9 hv9
      have hl0v9 : (alloc.vec.Vec.deref l0).length = (alloc.vec.Vec.deref v9).length := by
        have := congrArg List.length hv9
        simp [Bppp.vec_scalar_mul] at this
        rw [e1, e1, this, hl0l, hl1l]
      apply WP.spec_bind (vec_add_spec hs _ _ hl0v9)
      intro l2 hl2
      apply WP.spec_bind (vec_scalar_mul_spec hs ri (alloc.vec.Vec.deref n0))
      intro v10 hv10
      apply WP.spec_bind (vec_scalar_mul_spec hs gamma (alloc.vec.Vec.deref n1))
      intro v11 hv11
      have hv1011 : (alloc.vec.Vec.deref v10).length = (alloc.vec.Vec.deref v11).length := by
        have h1 := congrArg List.length hv10
        have h2 := congrArg List.length hv11
        simp [Bppp.vec_scalar_mul] at h1 h2
        rw [e1, e1, h1, h2, hn0l, hn1l]
      apply WP.spec_bind (vec_add_spec hs _ _ hv1011)
      intro n2 hn2
      have erl : rounds.length = rounds.val.length := rfl
      step*
      simp only [deref_val] at hc2 hl2 hn2 hv8 hv9 hv10 hv11
      have hc2l : c2.val.length = (l.val.length + 1) / 2 := by
        have h1 := congrArg List.length hc2; have h2 := congrArg List.length hv8
        simp [Bppp.vec_add, Bppp.vec_scalar_mul] at h1 h2; omega
      have hl2l : l2.val.length = (l.val.length + 1) / 2 := by
        have h1 := congrArg List.length hl2; have h2 := congrArg List.length hv9
        simp [Bppp.vec_add, Bppp.vec_scalar_mul] at h1 h2; omega
      have hn2l : n2.val.length = (n.val.length + 1) / 2 := by
        have h1 := congrArg List.length hn2; have h2 := congrArg List.length hv10
        have h3 := congrArg List.length hv11
        simp [Bppp.vec_add, Bppp.vec_scalar_mul] at h1 h2 h3; omega
      have hdec : l2.val.length + n2.val.length < l.val.length + n.val.length := by
        rw [hl2l, hn2l]
        simp [Bppp.NormLinear.is_base_case, Bppp.FOLD_THRESHOLD] at hb
        by_cases hl2 : l.val.length ≤ 1
        · have := hb hl2
          have h6 := of_decide_eq_false this
          omega
        · omega
      refine ⟨⟨?_, ?_, ?_, ?_, ?_⟩, hdec, ?_⟩
      rotate_left 2
      · omega
      · omega
      rotate_right 2
      · have := hlb2.pos
        exact ⟨by omega, by omega, by omega, by simp [lbLen, hb3p]; exact hlb2.h_le,
          by simp [lbLen, hb3p]; exact hlb2.g_le⟩
      · unfold WPow; rw [hb3h, hw2, hw1]; rcases hpow with h | h | h | h <;> simp [h]
      · have : rounds1.val.length = rounds.val.length + 1 := by simp [rounds1_post]
        omega
      · rw [← hxv, ← hrv, hX]
        simp only [except_ok_bind, hR, hG]
        rw [← hb2, ← hb3, show (φ (hs.mulF rho rho)) = φ rho * φ rho by simp]
        rw [hv8] at hc2; rw [hv9] at hl2; rw [hv10, hv11, hriv] at hn2
        rw [← hc2, ← hl2, ← hn2]
        have hr1 : roundsψ ψ rounds1.val = roundsψ ψ rounds.val ++ [(ψ xp, ψ rp')] := by
          simp [roundsψ, rounds1_post]
        rw [hr1, withPre_snoc]

lemma prove_loop_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (B : ℕ) (hB : 4 * B + 8 ≤ Usize.max)
    (hgl : 1 + gens.h_vec.length + gens.g_vec.length + 8 ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (bases : bulletproofspp.norm_linear.LazyBases)
    (c : alloc.vec.Vec S) (rho : S) (l n : alloc.vec.Vec S) (rounds : alloc.vec.Vec (P × P))
    (hinv : ProveInv gens B bases c l n rounds) :
    bulletproofspp.norm_linear.prove_loop t gens.g gens.h_vec gens.g_vec gens.precomp bases c rho
      l n rounds ⦃ r =>
      ProveMatches φ ψ τ [] r (withPre (roundsψ ψ rounds.val)
        (proveM φ ψ τ gens t bases c rho l n)) ⦄ := by
  unfold bulletproofspp.norm_linear.prove_loop
  apply loop.spec_decr_nat (fun q => q.2.2.2.2.1.val.length + q.2.2.2.2.2.1.val.length)
    (fun q => ProveInv gens B q.2.1 q.2.2.1 q.2.2.2.2.1 q.2.2.2.2.2.1 q.2.2.2.2.2.2 ∧
      withPre (roundsψ ψ q.2.2.2.2.2.2.val)
        (proveM φ ψ τ gens q.1 q.2.1 q.2.2.1 q.2.2.2.1 q.2.2.2.2.1 q.2.2.2.2.2.1) =
      withPre (roundsψ ψ rounds.val) (proveM φ ψ τ gens t bases c rho l n))
  · rintro ⟨t', b', c', rho', l', n', r'⟩ ⟨hi, heq⟩
    dsimp only at hi heq ⊢
    by_cases hb : Bppp.NormLinear.is_base_case (l'.val.length) (n'.val.length) = true
    · have hl1 : l'.val.length = 1 := by
        have := hi.l_pos
        simp [Bppp.NormLinear.is_base_case] at hb; omega
      apply WP.spec_mono (prove_base_spec ht gens t' b' c' rho' l' n' r' hl1 hb
        (by have := hi.size; omega))
      intro cf hcf
      cases cf with
      | done r => dsimp only; rw [← heq, ← proveMatches_withPre]; exact hcf
      | cont _ => exact hcf.elim
    · apply WP.spec_mono (prove_round_spec hs hp ht gens hg B hB hgl t' b' c' rho' l' n' r' hi
        (by simpa using hb))
      intro cf hcf
      cases cf with
      | done r => dsimp only; rw [← heq, ← proveMatches_withPre]; exact hcf
      | cont q =>
        obtain ⟨t2, b2, c2, rho2, l2, n2, r2⟩ := q
        obtain ⟨hi2, hdec, heq2⟩ := hcf
        dsimp only
        exact ⟨⟨hi2, heq2.trans heq⟩, hdec⟩
  · exact ⟨hinv, rfl⟩

lemma prove_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (hgl : 1 + gens.h_vec.length + gens.g_vec.length + 8 ≤ Usize.max)
    (hgB : 4 * (gens.h_vec.length + gens.g_vec.length) + 8 ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (c : Slice S) (rho : S)
    (opening : bulletproofspp.norm_linear.Opening)
    (hl : opening.l.length = gens.h_vec.length) (hc : c.length = gens.h_vec.length)
    (hn : opening.n.length = gens.g_vec.length) (hl1 : 1 ≤ gens.h_vec.length) :
    bulletproofspp.norm_linear.prove t gens c rho opening ⦃ r =>
      ProveMatches φ ψ τ [] r ((Bppp.NormLinear.prove (toGens ψ gens) (c.val.map φ) (φ rho)
        (toO φ opening)).run (τ t)) ⦄ := by
  unfold bulletproofspp.norm_linear.prove
  have e1 : opening.l.length = opening.l.val.length := rfl
  have e2 : opening.n.length = opening.n.val.length := rfl
  have e3 : c.length = c.val.length := rfl
  have e4 : gens.h_vec.length = gens.h_vec.val.length := rfl
  have e5 : gens.g_vec.length = gens.g_vec.val.length := rfl
  obtain ⟨t1, h1, m1⟩ := ht.domain_sep t .NormLinear
  step*
  rw [h1, bind_ok]
  apply WP.spec_bind (lazy_new_spec (ψ := ψ) hs gens)
  rintro bases ⟨hb, hbh, hbg, hbp⟩
  apply WP.spec_bind (alloc.slice.Slice.to_vec_spec _ c (fun x _ => hs.clone x))
  intro c1 hc1
  apply WP.spec_bind (alloc.slice.Slice.to_vec_spec _ _ (fun x _ => hs.clone x))
  intro l hl'
  apply WP.spec_bind (alloc.slice.Slice.to_vec_spec _ _ (fun x _ => hs.clone x))
  intro n hn'
  have hc1v : c1.val = c.val := by
    have := congrArg (fun s : Slice S => s.val) hc1; rw [this]; rfl
  have hlv : l.val = opening.l.val := by
    have := congrArg (fun s : Slice S => s.val) hl'
    rw [deref_val] at this; exact this.symm
  have hnv : n.val = opening.n.val := by
    have := congrArg (fun s : Slice S => s.val) hn'
    rw [deref_val] at this; exact this.symm
  apply WP.spec_mono (prove_loop_spec hs hp ht gens hg (gens.h_vec.length + gens.g_vec.length)
    hgB hgl t1 bases c1 rho l n (alloc.vec.Vec.new _)
    ⟨⟨by omega, by omega, by omega, by simp [lbLen, hbp], by simp [lbLen, hbp]⟩,
      by unfold WPow; omega, by rw [hc1v, hlv]; omega, by rw [hlv]; omega,
      by simp [hlv, hnv]; omega⟩)
  intro r hr
  convert hr using 2
  simp only [withPre, roundsψ, alloc.vec.Vec.new, List.map_nil, List.nil_append]
  simp only [Bppp.NormLinear.prove, StateT.run_bind]
  simp only [labelStr] at m1
  rw [m1]
  simp [proveM, hb, hc1v, hlv, hnv, toO, Except.map]
  generalize StateT.run _ (τ t1) = R
  cases R <;> rfl

end BpppProofs
