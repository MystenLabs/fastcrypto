-- THIS FILE IS AI-ONLY
import bulletproofspp.CircuitOpening
import bulletproofspp.Prove

/-!
`circuit::prove` computes `Bppp.Circuit.prove`, for some draws of the random number generator.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

lemma reciprocals_spec (hs : ScalarModel F φ) (pm : Bppp.CircuitParams)
    (p : bulletproofspp.circuit.CircuitParams) (hp : ParamsOK pm p) (hnd : p.n_d.val ≤ p.nm.val)
    (n_l : Slice S) (hnl : n_l.length = p.nm.val) (alpha : S) :
    bulletproofspp.circuit.reciprocals p n_l alpha ⦃ r =>
      match Bppp.Circuit.reciprocals pm (n_l.val.map φ) (φ alpha) with
      | .ok v => ∃ v', r = .Ok v' ∧ v'.val.map φ = v ∧ v'.length = p.nm.val
      | .error _ => r = .Err .InvalidInput ⦄ := by
  obtain ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ := hp
  unfold bulletproofspp.circuit.reciprocals bulletproofspp.circuit.reciprocals_loop
  have enl : n_l.length = n_l.val.length := rfl
  apply WP.spec_bind (push_loop_off
    (body := fun x => bulletproofspp.circuit.reciprocals_loop.body p.n_d n_l alpha x.1 x.2)
    0 0 p.n_d.val φ (fun k => φ alpha + φ (n_l.val.getD k hs.z))
    (fun v k hv hk => by
      dsimp only
      unfold bulletproofspp.circuit.reciprocals_loop.body
      simp only [hs.add_eq]
      step*
      refine ⟨_, _, rfl, ⟨_, denominators1_post, ?_⟩, k1_post⟩
      rw [hs.φ_addF, rs_post, List.getD_eq_getElem _ _ (by scalar_tac)])
    (fun v k hv hk => by
      dsimp only
      unfold bulletproofspp.circuit.reciprocals_loop.body
      step*)
    _ 0#usize (by simp) (by simp))
  intro den hden
  have h00 : ((0#usize : Usize).val) = 0 := rfl
  simp only [with_capacity_val, List.map_nil, List.nil_append, h00, Nat.sub_zero] at hden
  have hden' : (alloc.vec.Vec.deref den).val.map φ =
      ((n_l.val.map φ).take pm.n_d).map (φ alpha + ·) := by
    rw [deref_val, hden, hpnd]
    refine List.ext_getElem (by simp; omega) (fun k h1 h2 => ?_)
    simp only [List.length_map, List.length_range'] at h1
    simp [List.getElem?_eq_getElem (show k < n_l.val.length by omega)]
  apply WP.spec_bind (batch_invert_spec hs _)
  intro r hr
  simp only [Bppp.Circuit.reciprocals, hden'] at hr ⊢
  split at hr
  · rename_i l hl
    obtain ⟨out, rfl, hout⟩ := hr
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hl, except_ok_bind]
    have houtl : out.val.length = p.n_d.val := by
      have h1 := batch_invert_length _ _ hl
      have h2 := congrArg List.length hout
      simp only [List.length_map, List.length_take] at h1 h2
      omega
    apply WP.spec_bind (pad_to_spec hs _ p.nm (by
      simp only [Slice.length, deref_val, houtl]; exact hnd))
    intro v hv
    rw [WP.spec_ok]
    refine ⟨v, rfl, by rw [hv, deref_val, hout, hpnm], ?_⟩
    have := congrArg List.length hv
    simp only [List.length_map, Bppp.pad_to, List.length_take, List.length_append,
      List.length_replicate] at this
    show v.val.length = _
    omega
  · rename_i e he
    subst hr
    simp only [List.map_take, List.map_map] at he
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, he]

lemma input_commitments_spec (hs : ScalarModel F φ) {G H : E} (hped : PedersenModel φ ψ G H)
    (gens : bulletproofspp.crs.Generators)
    (hcomp : bulletproofspp.crs.compatible_with_pedersen_commitments gens = ok true)
    (w : bulletproofspp.circuit.Witness) (hop : w.off_plane.val = [])
    (hlen : w.values.length = w.blindings.length) :
    bulletproofspp.circuit.Witness.input_commitments w gens ⦃ r =>
      ∃ cs, r = .Ok cs ∧
        (toWit φ w).input_commitments G H (toGens ψ gens) = .ok (cs.val.map (toPC ψ)) ∧
        cs.length = w.values.length ⦄ := by
  unfold bulletproofspp.circuit.Witness.input_commitments
    bulletproofspp.circuit.Witness.input_commitments_loop
  simp only [hcomp, bind_ok, massert, if_true]
  have hop' : w.off_plane.len = 0#usize := by
    apply UScalar.eq_of_val_eq
    show w.off_plane.val.length = 0
    rw [hop]; rfl
  have ev : w.values.length = w.values.val.length := rfl
  have eb : w.blindings.length = w.blindings.val.length := rfl
  have hmodel : (toWit φ w).input_commitments G H (toGens ψ gens) =
      .ok ((List.zip (w.values.val.map φ) (w.blindings.val.map φ)).map
        fun q => Bppp.PedersenCommitment.new G H q.1 q.2) := by
    unfold Bppp.Circuit.Witness.input_commitments
    rw [mapM_ok _ (fun q => Bppp.PedersenCommitment.new G H q.1.1 q.1.2)]
    · have key : ∀ (l : List (F × F)), (l.zipIdx.map fun x =>
          Bppp.PedersenCommitment.new G H x.1.1 x.1.2) =
          l.map (fun q => Bppp.PedersenCommitment.new G H q.1 q.2) := by
        intro l
        refine List.ext_getElem (by simp) (fun k h1 h2 => ?_)
        simp [List.getElem_zipIdx]
      rw [key]; rfl
    · intro x _
      simp [toWit, hop]; rfl
  rw [hmodel]
  apply loop.spec_decr_nat (fun x => w.values.length - x.2.val)
    (fun x => x.2.val ≤ w.values.length ∧ x.1.val.length = x.2.val ∧
      x.1.val.map (toPC ψ) = ((List.zip (w.values.val.map φ) (w.blindings.val.map φ)).take x.2.val).map
        fun q => Bppp.PedersenCommitment.new G H q.1 q.2)
  · rintro ⟨cs, i⟩ ⟨hi, hcl, hcs⟩
    simp only at hi hcl hcs
    unfold bulletproofspp.circuit.Witness.input_commitments_loop.body
    have hcsl : cs.length = cs.val.length := rfl
    by_cases hlt : i.val < w.values.length
    · have h1 : i < w.values.len := by scalar_tac
      have h2 : i < w.blindings.len := by scalar_tac
      simp only [h1, h2, if_true]
      step*
      obtain ⟨c, hc, hcv⟩ := hped.new rs rs1
      simp only [hc, bind_ok, hop', show ¬ (i < 0#usize) by scalar_tac, if_false]
      step*
      refine ⟨by scalar_tac, by simp [commitments1_post, hcl, i5_post], ?_, by scalar_tac⟩
      rw [commitments1_post, i5_post, List.map_append, hcs,
        List.take_succ_eq_append_getElem (by simp; omega)]
      simp [toPC, hcv, rs_post, rs1_post]
      rfl
    · have h1 : ¬ i < w.values.len := by scalar_tac
      simp only [h1, if_false, WP.spec_ok]
      refine ⟨cs, rfl, ?_, by rw [hcsl, hcl]; omega⟩
      rw [hcs, show i.val = w.values.val.length by omega]
      congr 2
      rw [List.take_of_length_le (by simp <;> omega)]
  · exact ⟨by simp, by simp, by simp⟩

lemma loop_lengths (params : Bppp.CircuitParams) (alpha mu mu_inv : F) (lambdas shape : List F)
    (K : ℕ) :
    let st := (List.range K).foldl (Bppp.Constraints.loop_step params alpha mu mu_inv lambdas shape)
      ⟨[], [], [], [], 0, Bppp.one, Bppp.one, Bppp.one⟩
    st.norm_weights.length = K ∧ st.cn_l.length = K ∧ st.cn_r.length = K ∧ st.cn_v.length = K := by
  intro st
  induction K with
  | zero => simp [st]
  | succ K ih =>
    simp only [st, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil] at ih ⊢
    obtain ⟨h1, h2, h3, h4⟩ := ih
    simp only [Bppp.Constraints.loop_step]
    split_ifs <;> simp [h1, h2, h3, h4]

lemma power_vector_length (x : F) (n : ℕ) : (Bppp.power_vector x n).length = n := by
  have key : ∀ (k : ℕ) (acc : List F × F),
      ((List.range k).foldl (fun (v, cur) _ => (v ++ [cur], cur * x)) acc).1.length =
        acc.1.length + k := by
    intro k
    induction k with
    | zero => intro acc; simp
    | succ k ih => intro acc; simp only [List.range_succ, List.foldl_append, List.foldl_cons,
        List.foldl_nil, List.length_append, ih]; simp; omega
  simp [Bppp.power_vector, key]

lemma except_bind_ok_inv {ε α β : Type} {x : Except ε α} {f : α → Except ε β} {c : β}
    (h : (x >>= f) = .ok c) : ∃ a, x = .ok a ∧ f a = .ok c := by
  cases x with
  | error e => exact absurd h (by intro h'; cases h')
  | ok a => exact ⟨a, rfl, h⟩

lemma cons_new_len (params : Bppp.CircuitParams) (alpha mu lambda : F) (C : Bppp.Constraints F)
    (h : Bppp.Constraints.new params alpha mu lambda = .ok C) (hb : 15 ≤ params.nm) :
    C.norm_weights.length = params.nm ∧ C.cn_l.length = params.nm ∧
      C.cn_r.length = params.nm ∧ C.cn_o.length = params.nm ∧ C.cn_v.length = params.nm ∧
      C.cl_v.length = 8 ∧ C.lambdas.length = params.m + 1 := by
  unfold Bppp.Constraints.new at h
  obtain ⟨mi, -, h⟩ := except_bind_ok_inv h
  obtain ⟨inv, -, h⟩ := except_bind_ok_inv h
  obtain ⟨ai, -, h⟩ := except_bind_ok_inv h
  simp only [pure, Except.pure, Except.ok.injEq] at h
  subst h
  obtain ⟨h1, h2, h3, h4⟩ := loop_lengths params alpha mu mi
    (Bppp.power_vector lambda (params.m + 1))
    (List.iterate (· * (Bppp.power_vector lambda (params.m + 1)).getD params.m 0)
      (lambda * (Bppp.power_vector lambda (params.m + 1)).getD params.m 0)
      (params.nm + Bppp.H_LEN - 1)) params.nm
  refine ⟨h1, h2, h3, ?_, h4, ?_, power_vector_length _ _⟩
  · simp [Bppp.pad_to, Bppp.BASE]; omega
  · simp [Bppp.H_LEN]

/-- The model of a generated circuit proof. -/
def toCP (φ : S → F) (ψ : P → E) (cp : bulletproofspp.circuit.CircuitProof) :
    Bppp.Circuit.CircuitProof F E :=
  ⟨ψ cp.c_l, ψ cp.c_o, ψ cp.c_r, ψ cp.c_s, toProof φ ψ cp.nl_proof⟩

/-- The result of a generated circuit prover matches the model's run: the same proof and
commitments under the models, and the same transcript; or both fail. -/
def CPMatches (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (r : core.result.Result (bulletproofspp.circuit.CircuitProof ×
      alloc.vec.Vec pedersen.PedersenCommitment) error.FastCryptoError ×
      bulletproofspp.transcript.BpppTranscript)
    (m : Except Bppp.Error ((Bppp.Circuit.CircuitProof F E × List (Bppp.PedersenCommitment E)) ×
      Bppp.BpppTranscript F E)) : Prop :=
  match m with
  | .ok ((cp, vs), T) => ∃ cp' vs', r.1 = .Ok (cp', vs') ∧ toCP φ ψ cp' = cp ∧
      vs'.val.map (toPC ψ) = vs ∧ τ r.2 = T
  | .error _ => ∃ e, r.1 = .Err e

set_option maxHeartbeats 4000000 in
lemma prove_witness_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) {G H : E} (hped : PedersenModel φ ψ G H)
    (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (hcomp : bulletproofspp.crs.compatible_with_pedersen_commitments gens = ok true)
    (pm : Bppp.CircuitParams) (p : bulletproofspp.circuit.CircuitParams) (hpo : ParamsOK pm p)
    (hnd : p.n_d.val ≤ p.nm.val) (hgh : gens.h_vec.length = 8) (hgg : gens.g_vec.length = p.nm.val)
    (hgB : 4 * (gens.h_vec.length + gens.g_vec.length) + 8 ≤ Usize.max)
    (w : bulletproofspp.circuit.Witness) (hw : WitLen p.m.val p.nm.val w)
    (t : bulletproofspp.transcript.BpppTranscript) :
    bulletproofspp.circuit.prove_witness
      bulletproofspp.circuit.HonestReciprocals.Insts.FastcryptoBulletproofsppCircuitReciprocalsOf
      t gens p w () ⦃ r =>
      CPMatches φ ψ τ r ((Bppp.Circuit.prove_witness G H (toGens ψ gens) pm (toWit φ w)
        (fun alpha => Bppp.Circuit.reciprocals pm (toWit φ w).n_l alpha)).run (τ t)) ⦄ := by
  unfold bulletproofspp.circuit.prove_witness
  apply WP.spec_bind (input_commitments_spec hs hped gens hcomp w hw.off_plane
    (hw.values.trans hw.blindings.symm))
  rintro r ⟨cs, rfl, hic, hcsl⟩
  simp only [Bppp.Circuit.prove_witness, StateT.run_bind, hic, liftM_ok_run, except_ok_bind,
    core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
  obtain ⟨t1, h1, m1⟩ := ht.domain_sep t .Circuit
  obtain ⟨t2, h2, m2⟩ := ht.append_commits t1 .V (alloc.vec.Vec.deref cs)
  simp only [labelStr] at m1 m2
  simp only [h1, h2, bind_ok, m1, except_ok_bind, deref_val] at m2 ⊢
  have m2' : StateT.run (Bppp.BpppTranscript.append_commits "V" (cs.val.map (toPC ψ))) (τ t1) =
      .ok ((), τ t2) := m2
  have hlen : 1 + gens.h_vec.length + gens.g_vec.length ≤ Usize.max := by omega
  have hrl : (alloc.vec.Vec.deref w.r_l).length = 8 := by
    simp only [Slice.length, deref_val]; exact hw.r_l
  have hro : (alloc.vec.Vec.deref w.r_o).length = 8 := by
    simp only [Slice.length, deref_val]; exact hw.r_o
  have hrr : (alloc.vec.Vec.deref w.r_r).length = 8 := by
    simp only [Slice.length, deref_val]; exact hw.r_r
  simp only [m2', except_ok_bind, vec_clone_eq hs, bind_ok]
  -- C_L
  apply WP.spec_bind (message_opening_spec hs _ w.n_l (by rw [hrl]; norm_num))
  rintro o ⟨ho, hol, hon⟩
  simp only [deref_val] at ho
  apply WP.spec_bind (commit_spec (ψ := ψ) hs gens hg o (by rw [hol, hrl, hgh])
    (by rw [hon, hgg]; exact hw.n_l) hlen)
  intro r1 hr1
  rw [show Bppp.Circuit.message_opening (toWit φ w).r_l (toWit φ w).n_l = toO φ o from ho.symm]
  rcases hc1 : (toGens ψ gens).commit (toO φ o) with e | e1
  · rw [hc1] at hr1
    simp only [MsmMatches] at hr1
    subst hr1
    simp [CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rw [hc1] at hr1
  obtain ⟨c_l, rfl, hcl⟩ := hr1
  simp only [liftM_ok_run, except_ok_bind, bind_ok]
  -- C_O
  apply WP.spec_bind (message_opening_spec hs _ w.n_o (by rw [hro]; norm_num))
  rintro o1 ⟨ho1, hol1, hon1⟩
  simp only [deref_val] at ho1
  apply WP.spec_bind (commit_spec (ψ := ψ) hs gens hg o1 (by rw [hol1, hro, hgh])
    (by rw [hon1, hgg]; exact hw.n_o) hlen)
  intro r2 hr2
  rw [show Bppp.Circuit.message_opening (toWit φ w).r_o (toWit φ w).n_o = toO φ o1 from ho1.symm]
  rcases hc2 : (toGens ψ gens).commit (toO φ o1) with e | e2
  · rw [hc2] at hr2
    simp only [MsmMatches] at hr2
    subst hr2
    simp [CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rw [hc2] at hr2
  obtain ⟨c_o, rfl, hco⟩ := hr2
  simp only [liftM_ok_run, except_ok_bind, bind_ok]
  obtain ⟨t3, h3, m3⟩ := ht.append_point t2 .CL c_l
  obtain ⟨t4, h4, m4⟩ := ht.append_point t3 .CO c_o
  obtain ⟨alpha, t5, h5, m5⟩ := ht.challenge_scalar t4 .Alpha
  simp only [labelStr] at m3 m4 m5
  rw [← hcl, ← hco]
  simp only [h3, h4, h5, bind_ok, m3, m4, m5, except_ok_bind, Std.uncurry_apply_pair]
  -- reciprocals
  simp only [bulletproofspp.circuit.HonestReciprocals.Insts.FastcryptoBulletproofsppCircuitReciprocalsOf.reciprocals_of]
  apply WP.spec_bind (reciprocals_spec hs pm p hpo hnd (alloc.vec.Vec.deref w.n_l)
    (by simp only [Slice.length, deref_val]; exact hw.n_l) alpha)
  intro r3 hr3
  simp only [deref_val] at hr3
  have htn : (toWit φ w).n_l = w.n_l.val.map φ := rfl
  rw [htn]
  split at hr3
  rotate_left
  · rename_i e he
    subst hr3
    simp [he, CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rename_i nr hnr
  obtain ⟨n_r, rfl, hnrv, hnrl⟩ := hr3
  simp only [hnr, liftM_ok_run, except_ok_bind, bind_ok, vec_clone_eq hs]
  -- C_R
  apply WP.spec_bind (message_opening_spec hs _ n_r (by rw [hrr]; norm_num))
  rintro o2 ⟨ho2, hol2, hon2⟩
  simp only [deref_val] at ho2
  rw [← hnrv, show Bppp.Circuit.message_opening (toWit φ w).r_r (n_r.val.map φ) = toO φ o2
    from ho2.symm]
  apply WP.spec_bind (commit_spec (ψ := ψ) hs gens hg o2 (by rw [hol2, hrr, hgh])
    (by rw [hon2, hgg]; exact hnrl) hlen)
  intro r4 hr4
  rcases hc4 : (toGens ψ gens).commit (toO φ o2) with e | e4
  · rw [hc4] at hr4
    simp only [MsmMatches] at hr4
    subst hr4
    simp [CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rw [hc4] at hr4
  obtain ⟨c_r, rfl, hcr⟩ := hr4
  simp only [liftM_ok_run, except_ok_bind, bind_ok]
  rw [← hcr]
  obtain ⟨t6, h6, m6⟩ := ht.append_point t5 .CR c_r
  obtain ⟨rho, t7, h7, m7⟩ := ht.challenge_scalar t6 .Rho
  obtain ⟨lambda, t8, h8, m8⟩ := ht.challenge_scalar t7 .Lambda
  obtain ⟨beta, t9, h9, m9⟩ := ht.challenge_scalar t8 .Beta
  obtain ⟨delta, t10, h10, m10⟩ := ht.challenge_scalar t9 .Delta
  simp only [labelStr] at m6 m7 m8 m9 m10
  simp only [h6, h7, h8, h9, h10, bind_ok, m6, m7, m8, m9, m10, except_ok_bind,
    Std.uncurry_apply_pair, hs.mul_eq]
  -- delta inverse
  apply WP.spec_bind (inverse_spec' hs delta)
  intro r5 hr5
  split at hr5
  rotate_left
  · rename_i e he
    subst hr5
    simp [he, CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rename_i dinv hdinv
  obtain ⟨dinv', rfl, hdinv'⟩ := hr5
  simp only [hdinv, liftM_ok_run, except_ok_bind, bind_ok, core.result.Result.Insts.CoreOpsTry.branch]
  -- constraints
  apply WP.spec_bind (constraints_new_spec hs pm p hpo alpha (hs.mulF rho rho) lambda)
  intro r6 hr6
  simp only [ScalarModel.φ_mulF] at hr6
  split at hr6
  rotate_left
  · rename_i e he
    subst hr6
    simp [he, CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rename_i C hC
  obtain ⟨c', rfl, hc'⟩ := hr6
  simp only [hC, liftM_ok_run, except_ok_bind, bind_ok]
  obtain ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ := hpo
  obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := cons_new_len pm _ _ _ C hC (by omega)
  rw [← hc'] at l1 l2 l3 l4 l5 l6 l7
  simp only [toC, List.length_map] at l1 l2 l3 l4 l5 l6 l7
  have hcons : ConsLen p.m.val p.nm.val c' :=
    ⟨by show p.m.val ≤ c'.lambdas.val.length; omega, by rw [← hpnm]; exact l1,
      by rw [← hpnm]; exact l2, by rw [← hpnm]; exact l3, by rw [← hpnm]; exact l4,
      by rw [← hpnm]; exact l5, l6⟩
  rw [← hc']
  -- c
  apply WP.spec_bind (c_spec hs c' l6 beta)
  rintro cc ⟨hcw, hch, -, hce⟩
  rw [← hce]
  -- C_S
  apply WP.spec_bind (commit_c_s_spec (ψ := ψ) hs gens hg pm p
    ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ hgh hgg hlen c' hcons w hw n_r hnrl cc hcw hch
    beta delta dinv')
  intro r7 hr7
  rw [← hdinv']
  split at hr7
  rotate_left
  · rename_i e he
    subst hr7
    simp [he, CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rename_i csm com hcsm
  obtain ⟨c_s, co, rfl, hcs, hcoe, hcok⟩ := hr7
  simp only [hcsm, liftM_ok_run, except_ok_bind, bind_ok]
  rw [← hcs, ← hcoe]
  obtain ⟨t11, h11, m11⟩ := ht.append_point t10 .CS c_s
  obtain ⟨tau, t12, h12, m12⟩ := ht.challenge_scalar t11 .Tau
  simp only [labelStr] at m11 m12
  simp only [h11, h12, bind_ok, m11, m12, except_ok_bind, Std.uncurry_apply_pair]
  -- evaluations
  apply WP.spec_bind (eval_spec hs (vec_coeff_model hs 8) cc hcw tau)
  intro r8 hr8
  split at hr8
  rotate_left
  · rename_i e he
    subst hr8
    simp [he, CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rename_i cv hcv
  obtain ⟨cv', rfl, hcv'l, hcv'⟩ := hr8
  simp only [hcv, liftM_ok_run, except_ok_bind, bind_ok]
  apply WP.spec_bind (co_eval_spec hs p.nm.val co (-1) 7 hcok tau)
  intro r9 hr9
  split at hr9
  rotate_left
  · rename_i e he
    subst hr9
    simp [he, CPMatches, liftM_error_run, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rename_i ov hov
  obtain ⟨o', rfl, ho', ho'l, ho'n⟩ := hr9
  simp only [hov, liftM_ok_run, except_ok_bind, bind_ok]
  rw [← hcv', ← ho']
  -- norm-linear argument
  apply WP.spec_bind (prove_spec hs hp ht gens hg (by omega) hgB t12 (alloc.vec.Vec.deref cv') rho o'
    (by rw [ho'l, hgh]) (by simp only [Slice.length, deref_val]; rw [hgh]; exact hcv'l)
    (by rw [ho'n, hgg]) (by rw [hgh]; norm_num))
  rintro ⟨r10, t13⟩ hr10
  simp only [deref_val] at hr10
  have hvc : vecψ φ cv' = cv'.val.map φ := rfl
  rw [hvc]
  rcases hpr : (Bppp.NormLinear.prove (toGens ψ gens) (cv'.val.map φ) (φ rho) (toO φ o')).run
    (τ t12) with e | ⟨pf, T⟩
  · rw [hpr] at hr10
    simp only [ProveMatches] at hr10
    subst hr10
    simp [CPMatches, except_error_bind,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  rw [hpr] at hr10
  obtain ⟨pr, hpr1, hpr2, hpr3⟩ := hr10
  simp only at hpr1 hpr2
  subst hpr1
  simp only [except_ok_bind, StateT.run_pure, core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
    WP.spec_ok, CPMatches]
  simp only [Std.uncurry_apply_pair, bind_ok, WP.spec_ok, Pure.pure, Except.pure]
  refine ⟨_, _, rfl, ?_, rfl, hpr2⟩
  simp only [toCP, hpr3, List.nil_append]

@[simp] lemma except_throw' {ε α : Type} (e : ε) : (throw e : Except ε α) = .error e := rfl

/-- The model of a generated range. -/
def toRange : pedersen.Range → Bppp.Range
  | .Bits8 => .Bits8
  | .Bits16 => .Bits16
  | .Bits32 => .Bits32
  | .Bits64 => .Bits64

lemma is_in_range_eq (r : pedersen.Range) (v : U64) :
    pedersen.Range.is_in_range r v = ok ((toRange r).is_in_range v.val) := by
  cases r <;> simp [pedersen.Range.is_in_range, pedersen.Range.bits, toRange,
    Bppp.Range.is_in_range, Bppp.Range.bits] <;> exact decide_eq_decide.mpr Iff.rfl

lemma all_in_range_spec (range : pedersen.Range) (values : Slice U64) :
    bulletproofspp.circuit.all_in_range range values ⦃ b =>
      b = !((values.val.map (·.val)).any fun v => !(toRange range).is_in_range v) ⦄ := by
  unfold bulletproofspp.circuit.all_in_range bulletproofspp.circuit.all_in_range_loop
  have ev : values.len.val = values.val.length := rfl
  apply loop.spec_decr_nat (fun x => values.val.length - x.2.val)
    (fun x => x.2.val ≤ values.val.length ∧
      x.1 = !(((values.val.take x.2.val).map (·.val)).any fun v => !(toRange range).is_in_range v))
  · rintro ⟨b, i⟩ ⟨hi, hb⟩
    simp only at hi hb
    unfold bulletproofspp.circuit.all_in_range_loop.body
    simp only [is_in_range_eq]
    step*
    · have hlt : i.val < values.val.length := by scalar_tac
      have htk := List.take_succ_eq_append_getElem hlt
      split <;> step* <;> refine ⟨by scalar_tac, ?_, by scalar_tac⟩ <;>
        simp only [i3_post, htk, List.map_append, List.any_append, List.map_cons, List.map_nil,
          List.any_cons, List.any_nil] <;> simp_all
    · have : i.val = values.val.length := by scalar_tac
      rw [hb, this, List.take_length]
  · simp

lemma circuit_prove_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) {G H : E} (hped : PedersenModel φ ψ G H) (hr : RandOK)
    {R : Type} (inst : traits.AllowedRng R)
    (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (hcomp : bulletproofspp.crs.compatible_with_pedersen_commitments gens = ok true)
    (pm : Bppp.CircuitParams) (p : bulletproofspp.circuit.CircuitParams) (hpo : ParamsOK pm p)
    (hrange : pm.range = toRange p.range) (hd : p.d.val ≤ 16)
    (hnd : p.n_d.val ≤ p.nm.val) (hgh : gens.h_vec.length = 8)
    (hgB : 4 * (gens.h_vec.length + gens.g_vec.length) + 8 ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (rng : R) (values : Slice U64)
    (blindings : Slice S) :
    bulletproofspp.circuit.prove inst t gens p rng values blindings ⦃ r =>
      CPMatches φ ψ τ (r.1, r.2.1)
        ((Bppp.Circuit.prove G H (toGens ψ gens) pm (rngD φ hr inst rng p.nm.val)
          (values.val.map (·.val))
          (blindings.val.map φ)).run (τ t)) ⦄ := by
  have hpo' := hpo
  obtain ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ := hpo'
  have ev : values.len.val = values.val.length := rfl
  have eb : blindings.len.val = blindings.val.length := rfl
  have eg : gens.g_vec.len.val = gens.g_vec.val.length := rfl
  unfold bulletproofspp.circuit.prove
  unfold Bppp.Circuit.prove
  by_cases h1 : values.val.length = p.m.val
  swap
  · have : (values.len != p.m) = true := by
      simp only [bne_iff_ne, ne_eq]; intro h; apply h1; rw [← ev, h]
    rw [if_pos this, WP.spec_ok]
    exact (by simp [CPMatches, hm, h1, except_throw'])
  have : (values.len != p.m) = false := by
    simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [ev, h1]
  rw [if_neg (by simp [this])]
  by_cases h2 : blindings.val.length = p.m.val
  swap
  · have : (blindings.len != p.m) = true := by
      simp only [bne_iff_ne, ne_eq]; intro h; apply h2; rw [← eb, h]
    rw [if_pos this, WP.spec_ok]
    exact (by simp [CPMatches, hm, h2, except_throw'])
  have : (blindings.len != p.m) = false := by
    simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [eb, h2]
  rw [if_neg (by simp [this])]
  by_cases h3 : gens.g_vec.val.length = p.nm.val
  swap
  · have : (gens.g_vec.len != p.nm) = true := by
      simp only [bne_iff_ne, ne_eq]; intro h; apply h3; rw [← eg, h]
    rw [if_pos this, WP.spec_ok]
    exact (by simp [CPMatches, hpnm, h3, toGens, except_throw'])
  have : (gens.g_vec.len != p.nm) = false := by
    simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [eg, h3]
  rw [if_neg (by simp [this])]
  apply WP.spec_bind (all_in_range_spec p.range values)
  intro b hb
  subst hb
  split
  swap
  · rename_i hnall
    rw [WP.spec_ok]
    simp only [Bool.not_eq_true', Bool.not_eq_false'] at hnall
    simp [CPMatches, hrange, hnall, except_throw']
  rename_i hall
  apply WP.spec_bind (witness_new_spec hs hr inst pm p hpo hd hnd rng values blindings
    (by show values.val.length = _; exact h1))
  rintro ⟨w, rng1⟩ ⟨hwit, hop, hnl, hno, hns, hro, hrl, hrr, hvl, hbl⟩
  simp only [Std.uncurry_apply_pair]
  apply WP.spec_bind (prove_witness_spec (G := G) (H := H) hs hp ht hped gens hg hcomp pm p hpo hnd
    hgh h3 hgB w ⟨hvl, by rw [hbl]; exact h2, hop, hnl, hno, hns, hro, hrl, hrr⟩ t)
  rintro ⟨r, t'⟩ hr'
  simp only [Std.uncurry_apply_pair, WP.spec_ok]
  have hcond : ¬ ((values.val.map (·.val)).length ≠ pm.m ∨ (blindings.val.map φ).length ≠ pm.m ∨
      (toGens ψ gens).g_vec.length ≠ pm.nm ∨
      ((values.val.map (·.val)).any fun v => !pm.range.is_in_range v) = true) := by
    simp only [Bool.not_eq_true'] at hall
    simp [toGens, hm, hpnm, h1, h2, h3, hrange, hall]
  simp only [hcond, if_false]
  rw [← hwit]
  exact hr'

end BpppProofs
