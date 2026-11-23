-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Circuit
import bulletproofspp.Proofs.Constraints
import bulletproofspp.Spec.Honest
import bulletproofspp.Proofs.Weights

/-!
# The witness of `circuit.rs`

`Witness::new` builds the honest witness of `Spec.Honest`: its digits are the base-16 digits of
the values, its multiplicities count them, and the reciprocals invert `α + d_k`.
-/

open Finset

namespace Bppp

variable {F : Type} [Field F] [DecidableEq F]

set_option linter.unusedSectionVars false

/-! ## Digits -/

/-- A value below `16^D` is the sum of its `D` base-16 digits. -/
lemma sum_digits (D v : ℕ) (hv : v < 16 ^ D) : ∑ t ∈ range D, 16 ^ t * (v / 16 ^ t % 16) = v := by
  induction D generalizing v with
  | zero => simp at hv; simp [hv]
  | succ D ih =>
    rw [sum_range_succ', pow_zero, one_mul, Nat.div_one]
    have h16 : v / 16 < 16 ^ D := by rw [pow_succ] at hv; omega
    have key : ∑ t ∈ range D, 16 ^ (t + 1) * (v / 16 ^ (t + 1) % 16) =
        16 * ∑ t ∈ range D, 16 ^ t * (v / 16 / 16 ^ t % 16) := by
      rw [mul_sum]; refine sum_congr rfl fun t _ => ?_
      rw [Nat.div_div_eq_div_mul, pow_succ']; ring
    rw [key, ih _ h16]; omega

lemma getD_flatMap_uniform (vs : List ℕ) (f : ℕ → List ℕ) (d : ℕ) (hf : ∀ v, (f v).length = d)
    (k : ℕ) : (vs.flatMap f).getD k 0 =
      if k < vs.length * d then (f (vs.getD (k / d) 0)).getD (k % d) 0 else 0 := by
  rcases Nat.eq_zero_or_pos d with rfl | hd
  · have : vs.flatMap f = [] := by
      simp only [List.flatMap_eq_nil_iff]; intro v _; exact List.length_eq_zero_iff.1 (hf v)
    simp [this]
  induction vs generalizing k with
  | nil => simp
  | cons v vs ih =>
    rw [List.flatMap_cons]
    rcases lt_or_ge k d with hk | hk
    · rw [NormLinear.getD_append_lt _ _ (by rw [hf]; exact hk),
        if_pos (Nat.lt_of_lt_of_le hk (Nat.le_mul_of_pos_left _ (by simp))),
        Nat.div_eq_of_lt hk, Nat.mod_eq_of_lt hk]
      rfl
    · rw [NormLinear.getD_append_ge _ _ (by rw [hf]; exact hk), hf, ih]
      rw [show k / d = (k - d) / d + 1 by
          rw [← Nat.add_div_right _ hd, Nat.sub_add_cancel hk],
        show k % d = (k - d) % d by
          conv_lhs => rw [← Nat.sub_add_cancel hk]
          exact Nat.add_mod_right _ _]
      simp only [List.length_cons, List.getD_cons_succ, add_mul, one_mul]
      generalize vs.length * d = X
      split_ifs <;> first | rfl | omega

lemma count_eq_card (a : ℕ) (l : List ℕ) :
    l.count a = ((range l.length).filter fun k => l.getD k 0 = a).card := by
  induction l with
  | nil => simp
  | cons x l ih =>
    rw [List.count_cons, ih, List.length_cons, card_filter, card_filter, sum_range_succ']
    simp only [List.getD_cons_zero, List.getD_cons_succ, beq_iff_eq]

namespace Circuit

/-- The vector of length `H_LEN` with `rng j` in slot `j`, except zeros at `zeros`. -/
def masked (rng : ℕ → F) (zeros : List ℕ) : List F :=
  (List.range H_LEN).map fun i => if i ∈ zeros then 0 else rng i

/-- `blinding_vector` for `C_O`, `C_L` and `C_R`: the zero patterns of (22). -/
lemma blinding_vector_O (rng : ℕ → F) : blinding_vector rng C_O_POWER = masked rng [4, 7] := by
  simp [blinding_vector, masked, CR_POWERS, C_O_POWER, H_LEN, List.range_succ, List.zipIdx]

lemma blinding_vector_L (rng : ℕ → F) : blinding_vector rng C_L_POWER = masked rng [3, 6, 7] := by
  simp [blinding_vector, masked, CR_POWERS, C_L_POWER, H_LEN, List.range_succ, List.zipIdx]

lemma blinding_vector_R (rng : ℕ → F) :
    blinding_vector rng C_R_POWER = masked rng [2, 5, 6, 7] := by
  simp [blinding_vector, masked, CR_POWERS, C_R_POWER, H_LEN, List.range_succ, List.zipIdx]

/-- The honest prover of `Spec` for the inputs and draws of `Witness::new`. -/
def specHonest (rng : Randomness F) (values : List ℕ) (blindings : List F) : Spec.Honest F where
  d i t := values.getD i 0 / 16 ^ t % 16
  s i := blindings.getD i 0
  nS := rng.n_s
  ℓS := rng.l_s
  rO j := (masked rng.r_o [4, 7]).getD j 0
  rL j := (masked rng.r_l [3, 6, 7]).getD j 0
  rR j := (masked rng.r_r [2, 5, 6, 7]).getD j 0

variable (params : CircuitParams) (hv : params.Valid) (rng : Randomness F) (values : List ℕ)
  (blindings : List F)

lemma getD_masked (rng' : ℕ → F) (zeros : List ℕ) (j : ℕ) :
    (masked rng' zeros).getD j 0 = if j < H_LEN ∧ j ∉ zeros then rng' j else 0 := by
  unfold masked
  rw [List.getD_eq_getElem?_getD, List.getElem?_map]
  by_cases hj : j < H_LEN
  · rw [List.getElem?_range hj]; by_cases hz : j ∈ zeros <;> simp [hz, hj]
  · rw [List.getElem?_eq_none (by simpa using hj)]; simp [hj]

lemma zero_pattern : (specHonest rng values blindings).ZeroPattern := by
  constructor <;> (simp only [specHonest]; rw [getD_masked]; simp [H_LEN])

lemma digits_lt : ∀ i < params.m, ∀ t < params.d,
    (specHonest rng values blindings).d i t < 16 := fun _ _ _ _ => Nat.mod_lt _ (by norm_num)

/-- The digits of `Witness::new`. -/
lemma getD_digits (k : ℕ) (hlen : values.length = params.m) :
    (values.flatMap fun v => to_digits v params.d).getD k 0 =
      (specHonest rng values blindings).dig (params.toSpec hv) k := by
  rw [getD_flatMap_uniform _ _ params.d (fun v => by simp [to_digits_eq]), hlen, Spec.Honest.dig,
    CircuitParams.Nd_toSpec, hv.n_d]
  split_ifs with hk
  · have hd : 0 < params.d := by
      rcases Nat.eq_zero_or_pos params.d with h | h
      · rw [h, mul_zero] at hk; omega
      · exact h
    rw [to_digits_eq, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range (Nat.mod_lt _ hd)]
    rfl
  · rfl

lemma length_digits (hlen : values.length = params.m) :
    (values.flatMap fun v => to_digits v params.d).length = params.m * params.d := by
  rw [List.length_flatMap]
  simp only [to_digits_eq, List.length_map, List.length_range, List.map_const', List.sum_replicate,
    smul_eq_mul, hlen]

lemma getD_n_l (hlen : values.length = params.m) (k : ℕ) :
    (Witness.new params rng values blindings : Witness F).n_l.getD k 0 =
      ((specHonest rng values blindings).dig (params.toSpec hv) k : F) := by
  simp only [Witness.new]
  rw [getD_pad_to, getD_to_scalars, getD_digits params hv rng values blindings k hlen]
  split_ifs with hk
  · rfl
  · rw [Spec.Honest.dig, if_neg (by rw [CircuitParams.Nd_toSpec]; have := hv.le; omega)]; simp

lemma getD_n_o (hlen : values.length = params.m) (k : ℕ) :
    (Witness.new params rng values blindings : Witness F).n_o.getD k 0 =
      if k < 15 then ((specHonest rng values blindings).mult (params.toSpec hv) (k + 1) : F)
      else 0 := by
  simp only [Witness.new]
  have hlt : ∀ d ∈ values.flatMap fun v => to_digits v params.d, d < 16 := by
    intro d hd
    simp only [List.mem_flatMap, to_digits_eq, List.mem_map] at hd
    obtain ⟨_, _, t, _, rfl⟩ := hd
    exact Nat.mod_lt _ (by norm_num)
  rw [getD_pad_to, getD_to_scalars, multiplicities_eq _ hlt]
  have hnm := hv.base
  split_ifs with hk hk15 hk15
  · rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hk15, Option.map_some,
      Option.getD_some, count_eq_card, length_digits params values hlen, ← hv.n_d,
      Spec.Honest.mult, CircuitParams.Nd_toSpec]
    congr 2
    exact filter_congr fun j hj => by
      rw [getD_digits params hv rng values blindings j hlen]
  · rw [getD_eq_zero_of_le (by simp; omega)]; simp
  · omega
  · rfl

end Circuit

end Bppp
