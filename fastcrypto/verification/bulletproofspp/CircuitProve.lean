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

end BpppProofs
