-- THIS FILE IS AI-ONLY
import bulletproofspp.CircuitProve
import bulletproofspp.Verify

/-!
`circuit::verify` computes `Bppp.Circuit.verify`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- The result of a generated verifier matches the model's run: success with the same
transcript, or failure. -/
def VMatches (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (r : core.result.Result Unit error.FastCryptoError × bulletproofspp.transcript.BpppTranscript)
    (m : Except Bppp.Error (Unit × Bppp.BpppTranscript F E)) : Prop :=
  match m with
  | .ok (_, T) => r.1 = .Ok () ∧ τ r.2 = T
  | .error _ => ∃ e, r.1 = .Err e

lemma vmatches_of_unit {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {r : core.result.Result Unit error.FastCryptoError × bulletproofspp.transcript.BpppTranscript}
    {m : Except Bppp.Error (Unit × Bppp.BpppTranscript F E)} (h : UnitMatches τ r m) :
    VMatches τ r m := by
  rcases m with e | ⟨_, T⟩
  · exact ⟨_, h⟩
  · exact h

lemma tau_pow_spec (hs : ScalarModel F φ) (tau : S) (pw : I32) (hpw : -1 ≤ pw.val ∧ pw.val ≤ 3) :
    bulletproofspp.circuit.tau_pow tau pw ⦃ r =>
      match (Bppp.Laurent.monomial pw.val (Bppp.one : F)).eval (φ tau) with
      | .ok c => ∃ c', r = .Ok c' ∧ φ c' = c
      | .error _ => r = .Err .InvalidInput ⦄ := by
  unfold bulletproofspp.circuit.tau_pow
  rw [one_spec hs, bind_ok]
  apply WP.spec_bind (monomial_wf (ψ := φ) (pw, hs.o)
    (show TermOK (fun _ : S => True) (pw, hs.o) from
      ⟨trivial, by simp only [powBound]; omega, by simp only [powBound]; omega⟩))
  rintro l ⟨hw, hl⟩
  apply WP.spec_mono (eval_spec hs (scalar_coeff_model hs) l hw tau)
  intro r hr
  rw [hl] at hr
  simp only [ScalarModel.φ_o] at hr
  have h1 : (1 : F) = Bppp.one := rfl
  rw [h1] at hr
  split at hr
  · rename_i c hc
    rw [hc]
    obtain ⟨c', rfl, -, hc'⟩ := hr
    exact ⟨c', rfl, hc'⟩
  · rename_i e he
    rw [he]
    exact hr

lemma extra_loop_spec (hs : ScalarModel F φ) (vcs : Slice pedersen.PedersenCommitment)
    (lambdas : alloc.vec.Vec S) (hl : vcs.length ≤ lambdas.length) (vhw : S)
    (extra : alloc.vec.Vec (S × P)) (he : extra.length = 4)
    (hmax : vcs.length + 4 ≤ Usize.max) :
    bulletproofspp.circuit.verify_loop vcs lambdas extra vhw 0#usize ⦃ r =>
      r.val.map (pairψ φ ψ) = extra.val.map (pairψ φ ψ) ++
        vcs.val.zipIdx.map fun (v_i, i) => (φ vhw * (lambdas.val.map φ).getD i 0, ψ v_i) ⦄ := by
  unfold bulletproofspp.circuit.verify_loop
  have ev : vcs.len.val = vcs.val.length := rfl
  have evl : vcs.length = vcs.val.length := rfl
  have el : lambdas.length = lambdas.val.length := rfl
  apply WP.spec_mono (push_loop_off
    (body := fun x => bulletproofspp.circuit.verify_loop.body vcs lambdas vhw x.1 x.2)
    0 4 vcs.length (pairψ φ ψ)
    (fun i => (φ vhw * (lambdas.val.map φ).getD i 0, (vcs.val.map ψ).getD i 0))
    (fun v i hv hi => by
      dsimp only
      unfold bulletproofspp.circuit.verify_loop.body
      simp only [hs.mul_eq]
      have : v.length = v.val.length := rfl
      step*
      refine ⟨_, _, rfl, ⟨_, extra1_post, ?_⟩, i2_post⟩
      have h1 : i.val < lambdas.val.length := by omega
      have h2 : i.val < vcs.val.length := by omega
      simp [pairψ, rs_post, pc_post, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h1,
        List.getElem?_eq_getElem h2])
    (fun v i hv hi => by
      dsimp only
      unfold bulletproofspp.circuit.verify_loop.body
      step*)
    extra 0#usize (by simp [he]) (by simp))
  intro r hr
  rw [hr]
  congr 1
  have h00 : ((0#usize : Usize).val) = 0 := rfl
  rw [h00, Nat.sub_zero]
  refine List.ext_getElem (by simp [evl]) (fun k h1 h2 => ?_)
  simp only [List.length_map, List.length_range'] at h1
  have hk : k < vcs.val.length := by omega
  simp [List.getElem_zipIdx, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]

lemma except_bind_assoc {ε α β γ : Type} (x : Except ε α) (g : α → Except ε β)
    (f : β → Except ε γ) : ((x >>= g) >>= f) = x >>= fun a => g a >>= f := by
  cases x <;> rfl

lemma lift_step {σ ε α β : Type} (x : Except ε α) (f : α → StateT σ (Except ε) β)
    (g : α → Except ε (β × σ)) (s : σ) (h : ∀ a, (f a).run s = g a) :
    ((liftM x : StateT σ (Except ε) α) >>= f).run s = x >>= g := by
  cases x
  · rfl
  · exact h _

lemma liftM_run' {σ ε α : Type} (x : Except ε α) (s : σ) :
    (liftM x : StateT σ (Except ε) α).run s = x >>= fun a => .ok (a, s) := by
  cases x <;> rfl

section ModelRun

variable {T0 T1 T2 T3 T4 T5 T6 T7 T8 T9 T11 T12 : Bppp.BpppTranscript F E}
  {alpha rho lambda beta tau : F}

/-- The run of the model's circuit verifier, given the run of its transcript operations: the
checks that do not touch the transcript, then the norm-linear verifier. -/
lemma model_verify_run (gens : Bppp.Generators E) (pm : Bppp.CircuitParams)
    (proof : Bppp.Circuit.CircuitProof F E) (vcs : List (Bppp.PedersenCommitment E))
    (hcond : ¬(vcs.length ≠ pm.m ∨ gens.g_vec.length ≠ pm.nm))
    (m1 : (Bppp.BpppTranscript.domain_sep "bppp_circuit").run T0 = .ok ((), T1))
    (m2 : (Bppp.BpppTranscript.append_commits "V" vcs).run T1 = .ok ((), T2))
    (m3 : (Bppp.BpppTranscript.append_point "C_L" proof.c_l).run T2 = .ok ((), T3))
    (m4 : (Bppp.BpppTranscript.append_point "C_O" proof.c_o).run T3 = .ok ((), T4))
    (m5 : (Bppp.BpppTranscript.challenge_scalar "alpha").run T4 = .ok (alpha, T5))
    (m6 : (Bppp.BpppTranscript.append_point "C_R" proof.c_r).run T5 = .ok ((), T6))
    (m7 : (Bppp.BpppTranscript.challenge_scalar "rho").run T6 = .ok (rho, T7))
    (m8 : (Bppp.BpppTranscript.challenge_scalar "lambda").run T7 = .ok (lambda, T8))
    (m9 : (Bppp.BpppTranscript.challenge_scalar "beta").run T8 = .ok (beta, T9))
    (m11 : (Bppp.BpppTranscript.append_point "C_S" proof.c_s).run T9 = .ok ((), T11))
    (m12 : (Bppp.BpppTranscript.challenge_scalar "tau").run T11 = .ok (tau, T12)) :
    (Bppp.Circuit.verify gens pm proof vcs).run T0 =
      (do
        let constraints ← Bppp.Constraints.new pm alpha (rho * rho) lambda
        let p_n_tau ← constraints.p_n.eval tau
        let t3 ← (Bppp.Laurent.monomial 3 Bppp.one).eval tau
        let c_tau ← (Bppp.Circuit.c constraints beta).eval tau
        let x1 ← (Bppp.Laurent.monomial Bppp.Circuit.C_S_POWER Bppp.one).eval tau
        let x2 ← (Bppp.Laurent.monomial Bppp.Circuit.C_O_POWER Bppp.one).eval tau
        let x3 ← (Bppp.Laurent.monomial Bppp.Circuit.C_L_POWER Bppp.one).eval tau
        let x4 ← (Bppp.Laurent.monomial Bppp.Circuit.C_R_POWER Bppp.one).eval tau
        let x5 ← (Bppp.Laurent.monomial Bppp.Circuit.V_HAT_POWER Bppp.one).eval tau
        (Bppp.NormLinear.verify gens c_tau
          (Bppp.weighted_norm p_n_tau (rho * rho) +
            2 * (constraints.lambda_al + constraints.mu_am) * t3) p_n_tau
          ([(x1, proof.c_s), (x2, proof.c_o), (x3, proof.c_l), (x4, proof.c_r)] ++
            vcs.zipIdx.map fun (v_i, i) => (2 * x5 * constraints.lambdas.getD i 0, v_i.point))
          rho proof.nl_proof).run T12 : Except Bppp.Error (Unit × Bppp.BpppTranscript F E)) := by
  unfold Bppp.Circuit.verify
  rw [if_neg hcond]
  dsimp only
  rw [StateT.run_bind, m1, except_ok_bind]
  rw [StateT.run_bind, m2, except_ok_bind]
  rw [StateT.run_bind, m3, except_ok_bind]
  rw [StateT.run_bind, m4, except_ok_bind]
  rw [StateT.run_bind, m5, except_ok_bind]
  rw [StateT.run_bind, m6, except_ok_bind]
  rw [StateT.run_bind, m7, except_ok_bind]
  rw [StateT.run_bind, m8, except_ok_bind]
  rw [StateT.run_bind, m9, except_ok_bind]
  rw [StateT.run_bind, m11, except_ok_bind, StateT.run_bind, m12, except_ok_bind]
  dsimp only
  refine lift_step _ _ _ _ (fun C => ?_)
  refine lift_step _ _ _ _ (fun pnt => ?_)
  refine lift_step _ _ _ _ (fun t3 => ?_)
  refine lift_step _ _ _ _ (fun ct => ?_)
  refine lift_step _ _ _ _ (fun x1 => ?_)
  refine lift_step _ _ _ _ (fun x2 => ?_)
  refine lift_step _ _ _ _ (fun x3 => ?_)
  refine lift_step _ _ _ _ (fun x4 => ?_)
  refine lift_step _ _ _ _ (fun x5 => ?_)
  rfl

end ModelRun

set_option maxHeartbeats 4000000 in
lemma circuit_verify_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (pm : Bppp.CircuitParams) (p : bulletproofspp.circuit.CircuitParams) (hpo : ParamsOK pm p)
    (hnd : p.n_d.val ≤ p.nm.val) (hgh : gens.h_vec.length = 8)
    (hgB : 4 * (gens.h_vec.length + gens.g_vec.length) + 8 ≤ Usize.max)
    (hR : 2 * 2 ^ (Bppp.NormLinear.proof_shape gens.h_vec.length gens.g_vec.length).1 ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (proof : bulletproofspp.circuit.CircuitProof)
    (vcs : Slice pedersen.PedersenCommitment) :
    bulletproofspp.circuit.verify t gens p proof vcs ⦃ r =>
      VMatches τ r ((Bppp.Circuit.verify (toGens ψ gens) pm (toCP φ ψ proof)
        (vcs.val.map (toPC ψ))).run (τ t)) ⦄ := by
  have hpo' := hpo
  obtain ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ := hpo'
  have ev : vcs.len.val = vcs.val.length := rfl
  have eg : gens.g_vec.len.val = gens.g_vec.val.length := rfl
  have evl : vcs.length = vcs.val.length := rfl
  unfold bulletproofspp.circuit.verify
  by_cases h1 : vcs.val.length = p.m.val
  swap
  · have : (vcs.len != p.m) = true := by
      simp only [bne_iff_ne, ne_eq]; intro h; apply h1; rw [← ev, h]
    rw [if_pos this, WP.spec_ok]
    unfold Bppp.Circuit.verify
    rw [if_pos (Or.inl (by simp [hm, h1]))]
    exact ⟨_, rfl⟩
  have : (vcs.len != p.m) = false := by
    simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [ev, h1]
  rw [if_neg (by simp [this])]
  by_cases h3 : gens.g_vec.val.length = p.nm.val
  swap
  · have : (gens.g_vec.len != p.nm) = true := by
      simp only [bne_iff_ne, ne_eq]; intro h; apply h3; rw [← eg, h]
    rw [if_pos this, WP.spec_ok]
    unfold Bppp.Circuit.verify
    rw [if_pos (Or.inr (by simp [hpnm, h3, toGens]))]
    exact ⟨_, rfl⟩
  have : (gens.g_vec.len != p.nm) = false := by
    simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [eg, h3]
  rw [if_neg (by simp [this])]
  have hcond : ¬ ((vcs.val.map (toPC ψ)).length ≠ pm.m ∨ (toGens ψ gens).g_vec.length ≠ pm.nm) := by
    simp [toGens, hm, hpnm, h1, h3]
  obtain ⟨t1, e1, m1⟩ := ht.domain_sep t .Circuit
  obtain ⟨t2, e2, m2⟩ := ht.append_commits t1 .V vcs
  obtain ⟨t3, e3, m3⟩ := ht.append_point t2 .CL proof.c_l
  obtain ⟨t4, e4, m4⟩ := ht.append_point t3 .CO proof.c_o
  obtain ⟨alpha, t5, e5, m5⟩ := ht.challenge_scalar t4 .Alpha
  obtain ⟨t6, e6, m6⟩ := ht.append_point t5 .CR proof.c_r
  obtain ⟨rho, t7, e7, m7⟩ := ht.challenge_scalar t6 .Rho
  obtain ⟨lambda, t8, e8, m8⟩ := ht.challenge_scalar t7 .Lambda
  obtain ⟨beta, t9, e9, m9⟩ := ht.challenge_scalar t8 .Beta
  obtain ⟨t11, e11, m11⟩ := ht.append_point t9 .CS proof.c_s
  obtain ⟨tau, t12, e12, m12⟩ := ht.challenge_scalar t11 .Tau
  have m2' : StateT.run (Bppp.BpppTranscript.append_commits "V" (vcs.val.map (toPC ψ))) (τ t1) =
      .ok ((), τ t2) := m2
  simp only [labelStr] at m1 m3 m4 m5 m6 m7 m8 m9 m11 m12
  rw [model_verify_run (toGens ψ gens) pm (toCP φ ψ proof) _ hcond m1 m2' m3 m4 m5 m6 m7 m8 m9
    m11 m12]
  simp only [e1, e2, e3, e4, e5, e6, e7, e8, e9, e11, e12, bind_ok, Std.uncurry_apply_pair, hs.mul_eq]
  have hres : ∀ (x : core.result.Result Unit error.FastCryptoError)
      (tt : bulletproofspp.transcript.BpppTranscript) (e : Bppp.Error),
      (∃ e', x = .Err e') → VMatches τ (x, tt) (.error e) := fun _ _ _ h => h
  -- constraints
  apply WP.spec_bind (constraints_new_spec hs pm p hpo alpha (hs.mulF rho rho) lambda)
  intro r1 hr1
  simp only [ScalarModel.φ_mulF] at hr1
  split at hr1
  rotate_left
  · rename_i e he
    subst hr1
    rw [he, except_error_bind]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i C hC
  obtain ⟨c', rfl, hc'⟩ := hr1
  rw [hC, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
  obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := cons_new_len pm _ _ _ C hC (by omega)
  rw [← hc'] at l1 l2 l3 l4 l5 l6 l7
  simp only [toC, List.length_map] at l1 l2 l3 l4 l5 l6 l7
  rw [← hc']
  -- p_n(tau)
  apply WP.spec_bind (p_n_spec hs c' p.nm.val (by rw [← hpnm]; exact l5) (by rw [← hpnm]; exact l3)
    (by rw [← hpnm]; exact l2) (by rw [← hpnm]; exact l4))
  rintro pn ⟨hpw, hph, hpe⟩
  rw [← hpe]
  apply WP.spec_bind (eval_spec hs (vec_coeff_model hs p.nm.val) pn hpw tau)
  intro r2 hr2
  split at hr2
  rotate_left
  · rename_i e he
    subst hr2
    rw [he, except_error_bind]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i pnt hpnt
  obtain ⟨pnt', rfl, hpntl, hpnt'⟩ := hr2
  rw [hpnt, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
  apply WP.spec_bind (weighted_norm_spec hs (alloc.vec.Vec.deref pnt') (hs.mulF rho rho))
  intro wn hwn
  simp only [hs.from_u64_eq, hs.add_eq, hs.mul_eq, bind_ok]
  -- tau^3
  apply WP.spec_bind (tau_pow_spec hs tau 3#i32 (by decide))
  intro r3 hr3
  have h3 : ((3#i32 : I32).val) = 3 := rfl
  rw [h3] at hr3
  split at hr3
  rotate_left
  · rename_i e he
    subst hr3
    rw [he, except_error_bind]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i t3v ht3v
  obtain ⟨t3', rfl, ht3'⟩ := hr3
  rw [ht3v, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.mul_eq, hs.add_eq]
  -- c(tau)
  apply WP.spec_bind (c_spec hs c' l6 beta)
  rintro cc ⟨hcw, hch, -, hce⟩
  rw [← hce]
  apply WP.spec_bind (eval_spec hs (vec_coeff_model hs 8) cc hcw tau)
  intro r4 hr4
  split at hr4
  rotate_left
  · rename_i e he
    subst hr4
    rw [he, except_error_bind]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i ctv hctv
  obtain ⟨ct', rfl, hctl, hct'⟩ := hr4
  rw [hctv, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
  have hmnd : p.m.val ≤ p.n_d.val := by rw [hnde]; exact Nat.le_mul_of_pos_right _ hd0
  have hm4 : vcs.val.length + 4 ≤ Usize.max := by omega
  step
  have hw0 : (alloc.vec.Vec.with_capacity (S × P) i3).val.length = 0 := rfl
  have hv5 : (bulletproofspp.circuit.C_S_POWER).val = -1 := by
    unfold bulletproofspp.circuit.C_S_POWER; rfl
  rw [show Bppp.Circuit.C_S_POWER = -1 from rfl]
  apply WP.spec_bind (tau_pow_spec hs tau bulletproofspp.circuit.C_S_POWER (by rw [hv5]; norm_num))
  intro r5 hr5
  rw [hv5] at hr5
  split at hr5
  rotate_left
  · rename_i e he
    subst hr5
    rw [he, except_error_bind]
    simp only [bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i x1 hx1
  obtain ⟨x1', rfl, hx1'⟩ := hr5
  rw [hx1, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.mul_eq]
  step
  have hl1 : extra1.val.length = 1 := by simp [extra1_post, hw0]
  have hv6 : (bulletproofspp.circuit.C_O_POWER).val = 0 := by
    unfold bulletproofspp.circuit.C_O_POWER; rfl
  rw [show Bppp.Circuit.C_O_POWER = 0 from rfl]
  apply WP.spec_bind (tau_pow_spec hs tau bulletproofspp.circuit.C_O_POWER (by rw [hv6]; norm_num))
  intro r6 hr6
  rw [hv6] at hr6
  split at hr6
  rotate_left
  · rename_i e he
    subst hr6
    rw [he, except_error_bind]
    simp only [bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i x2 hx2
  obtain ⟨x2', rfl, hx2'⟩ := hr6
  rw [hx2, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.mul_eq]
  step
  have hl2 : extra2.val.length = 2 := by simp [extra2_post, hl1]
  have hv7 : (bulletproofspp.circuit.C_L_POWER).val = 1 := by
    unfold bulletproofspp.circuit.C_L_POWER; rfl
  rw [show Bppp.Circuit.C_L_POWER = 1 from rfl]
  apply WP.spec_bind (tau_pow_spec hs tau bulletproofspp.circuit.C_L_POWER (by rw [hv7]; norm_num))
  intro r7 hr7
  rw [hv7] at hr7
  split at hr7
  rotate_left
  · rename_i e he
    subst hr7
    rw [he, except_error_bind]
    simp only [bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i x3 hx3
  obtain ⟨x3', rfl, hx3'⟩ := hr7
  rw [hx3, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.mul_eq]
  step
  have hl3 : extra3.val.length = 3 := by simp [extra3_post, hl2]
  have hv8 : (bulletproofspp.circuit.C_R_POWER).val = 2 := by
    unfold bulletproofspp.circuit.C_R_POWER; rfl
  rw [show Bppp.Circuit.C_R_POWER = 2 from rfl]
  apply WP.spec_bind (tau_pow_spec hs tau bulletproofspp.circuit.C_R_POWER (by rw [hv8]; norm_num))
  intro r8 hr8
  rw [hv8] at hr8
  split at hr8
  rotate_left
  · rename_i e he
    subst hr8
    rw [he, except_error_bind]
    simp only [bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i x4 hx4
  obtain ⟨x4', rfl, hx4'⟩ := hr8
  rw [hx4, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.mul_eq]
  step
  have hl4 : extra4.val.length = 4 := by simp [extra4_post, hl3]
  have hv9 : (bulletproofspp.circuit.V_HAT_POWER).val = 3 := by
    unfold bulletproofspp.circuit.V_HAT_POWER; rfl
  rw [show Bppp.Circuit.V_HAT_POWER = 3 from rfl]
  apply WP.spec_bind (tau_pow_spec hs tau bulletproofspp.circuit.V_HAT_POWER (by rw [hv9]; norm_num))
  intro r9 hr9
  rw [hv9] at hr9
  split at hr9
  rotate_left
  · rename_i e he
    subst hr9
    rw [he, except_error_bind]
    simp only [bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact hres _ _ _ ⟨_, rfl⟩
  rename_i x5 hx5
  obtain ⟨x5', rfl, hx5'⟩ := hr9
  rw [hx5, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.mul_eq]
  have hlam : vcs.length ≤ c'.lambdas.length := by
    show vcs.val.length ≤ c'.lambdas.val.length; omega
  apply WP.spec_bind (extra_loop_spec (ψ := ψ) hs vcs c'.lambdas hlam _ extra4 hl4 (by omega))
  intro ex hex
  have hexl : ex.val.length = 4 + vcs.val.length := by
    have := congrArg List.length hex
    simp [hl4] at this; omega
  have hgl' : gens.h_vec.length = gens.h_vec.val.length := rfl
  have hgg' : gens.g_vec.length = gens.g_vec.val.length := rfl
  apply WP.spec_mono (verify_spec hs hp ht gens hg (by omega) (by omega) hR t12
    (alloc.vec.Vec.deref ct') _ (alloc.vec.Vec.deref pnt') (alloc.vec.Vec.deref ex)
    (by simp only [Slice.length, deref_val, hexl]; omega) rho proof.nl_proof)
  intro r hr
  have hv := vmatches_of_unit hr
  convert hv using 4
  · rw [deref_val, ← hct']; rfl
  · rw [← hpnt', ← ht3']; simp [hwn, toC, vecψ, deref_val]
  · rw [deref_val, ← hpnt']; rfl
  · rw [← hx1', ← hx2', ← hx3', ← hx4', ← hx5', deref_val, hex, extra4_post, extra3_post,
      extra2_post, extra1_post]
    simp [pairψ, toCP, toC, toPC, List.zipIdx_map, Function.comp_def]
  · rfl

end BpppProofs
