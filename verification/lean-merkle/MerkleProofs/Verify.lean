-- THIS FILE IS AI-ONLY
import MerkleProofs.Model

/-!
What the generated `MerkleProof::verify` and `MerkleProof::verify_for_trusted_tree` compute, and
the functions they call.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

theorem hash_along_path_loop_spec (hm : HashModel inst H) (v : alloc.vec.Vec Node) (c : Node)
    (li lvl : Usize) (hl : lvl.val ≤ v.length) :
    merkle.MerkleProof.hash_along_path_loop inst v c li lvl ⦃ r =>
      r = fold H c (v.val.drop lvl.val) li.val ⦄ := by
  unfold merkle.MerkleProof.hash_along_path_loop
  apply loop.spec_decr_nat (fun p => v.length - p.2.2.val)
    (fun p => p.2.2.val ≤ v.length ∧
      fold H p.1 (v.val.drop p.2.2.val) p.2.1.val = fold H c (v.val.drop lvl.val) li.val)
  · rintro ⟨c', li', lvl'⟩ ⟨hl', heq⟩
    dsimp only at hl' heq ⊢
    unfold merkle.MerkleProof.hash_along_path_loop.body
    simp only [inner_hash_eq hm]
    step*
    · split <;> step* <;>
      · have hlt : lvl'.val < v.length := by scalar_tac
        rw [List.drop_eq_getElem_cons hlt] at heq
        simp only [fold, step] at heq
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← heq, level1_post, level_index1_post, sibling_post]
        simp_all
    · rw [← heq, List.drop_of_length_le (by scalar_tac)]
      rfl
  · exact ⟨hl, rfl⟩

/-- `hash_along_path` returns `none` for proofs of `usize::BITS` or more levels and for indices not
below `2 ^ path.len()`, and otherwise the hash of the leaf up the path. -/
theorem hash_along_path_spec (hm : HashModel inst H) (p : merkle.MerkleProof T) (leaf : Slice U8)
    (i : Usize) :
    merkle.MerkleProof.hash_along_path inst p leaf i ⦃ r =>
      r = if p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length
        then some (fold H (leafN H leaf.val) p.path.val i.val) else none ⦄ := by
  unfold merkle.MerkleProof.hash_along_path
  simp only [leaf_hash_eq hm]
  have hbits : (UScalar.cast UScalarTy.Usize core.num.Usize.BITS).val = System.Platform.numBits := by
    simp [UScalar.cast_val_eq, core.num.Usize.BITS]
  have hshr : ∀ k : Nat, i.val >>> k = 0 ↔ i.val < 2 ^ k := fun k => by
    rw [Nat.shiftRight_eq_div_pow, Nat.div_eq_zero_iff_lt (by positivity)]
  step*
  · rename_i hlen hne
    have h3 : i3.val = 0 := by
      simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hne; scalar_tac
    rw [i3_post, alloc.vec.Vec.len_val, hshr] at h3
    rw [ite_eq_left ⟨by scalar_tac, h3⟩]
    apply WP.spec_bind (hash_along_path_loop_spec hm _ _ _ _ (by simp))
    intro r hr
    simp [hr]

theorem allM_eq : ∀ l l' : List U8, l.length = l'.length →
    List.allM (fun p : U8 × U8 => (ok (decide (p.1.val = p.2.val)) : Result Bool)) (l.zip l') =
      ok (decide (l = l')) := by
  intro l
  induction l with
  | nil => intro l' h; cases l' <;> simp_all; rfl
  | cons x l ih =>
    intro l' h
    cases l' with
    | nil => simp at h
    | cons y l' =>
      simp only [List.zip_cons_cons, List.allM_cons]
      by_cases hxy : x = y
      · subst hxy; simp [ih l' (by simpa using h)]
      · have : x.val ≠ y.val := fun e => hxy (UScalar.eq_of_val_eq e)
        simp [this, hxy]; rfl

theorem arr_eq (x y : Array U8 32#usize) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 x y = ok (decide (x = y)) := by
  unfold core.array.equality.PartialEqArray.eq
  simp [liftFun2]
  rw [allM_eq _ _ (by simp)]
  simp [Aeneas.Std.Array.eq_iff]

/-- `PartialEq` for nodes is equality. -/
theorem node_eq_spec (a b : merkle.Node) :
    ∃ r, merkle.Node.Insts.CoreCmpPartialEqNode.eq a b = ok r ∧ (r = true ↔ a = b) := by
  cases a <;> cases b <;>
    simp [merkle.Node.Insts.CoreCmpPartialEqNode.eq, merkle.Node.read_discriminant, arr_eq]

/-- `verify_for_trusted_tree` accepts exactly when `hash_along_path` returns `root`. -/
theorem verify_for_trusted_tree_spec (hm : HashModel inst H) (p : merkle.MerkleProof T) (root : Node)
    (leaf : Slice U8) (i : Usize) :
    merkle.MerkleProof.verify_for_trusted_tree inst p root leaf i ⦃ r =>
      (r = .Ok ()) ↔ (p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length ∧
        fold H (leafN H leaf.val) p.path.val i.val = root) ⦄ := by
  unfold merkle.MerkleProof.verify_for_trusted_tree
  apply WP.spec_bind (hash_along_path_spec hm p leaf i)
  intro o ho
  subst ho
  split
  · rename_i h
    split at h
    · simp at h
    · simp only [WP.spec_ok]; simp_all
  · rename_i r h
    split at h
    · rename_i hc
      simp only [Option.some.injEq] at h
      subst h
      obtain ⟨b, hb, hbi⟩ := node_eq_spec (fold H (leafN H leaf.val) p.path.val i.val) root
      simp only [hb, bind_ok]
      split <;> simp_all
    · simp at h

/-- For `n ≥ 2`, `depth(n)` is `⌈log₂ n⌉ = ⌊log₂ (n - 1)⌋ + 1`. -/
theorem depth_eq_log (n : Nat) (h : 2 ≤ n) : depth n = Nat.log 2 (n - 1) + 1 := by
  rw [depth, ite_eq_right (by omega)]
  by_cases h2 : n = 2
  · subst h2; simp [depth]
  · rw [depth_eq_log ((n + n % 2) / 2) (by omega)]
    have : Nat.log 2 (n - 1) = Nat.log 2 ((n - 1) / 2) + 1 := Nat.log_of_one_lt_of_le (by norm_num) (by omega)
    have e : (n + n % 2) / 2 - 1 = (n - 1) / 2 := by omega
    rw [this, e]
termination_by n
decreasing_by omega

/-- `(n.saturating_sub(1)).leading_zeros()`. -/
theorem lz_spec (n : Usize) :
    BitVec.leadingZeros (core.num.Usize.saturating_sub n 1#usize).bv =
      if n.val ≤ 1 then UScalarTy.Usize.numBits
      else UScalarTy.Usize.numBits - Nat.log 2 (n.val - 1) - 1 := by
  have hx : (core.num.Usize.saturating_sub n 1#usize).bv.toNat = n.val - 1 := by
    have hn := n.hBounds
    simp only [core.num.Usize.saturating_sub, UScalar.saturating_sub]
    show (BitVec.ofNat _ _).toNat = _
    rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt]
    · simp
    · simp [UScalarTy.numBits] at hn ⊢; omega
  unfold BitVec.leadingZeros
  have h0 : (core.num.Usize.saturating_sub n 1#usize).bv = 0 ↔ n.val ≤ 1 := by
    rw [← BitVec.toNat_inj, hx]; simp; omega
  by_cases h1 : n.val ≤ 1
  · rw [ite_eq_left (h0.mpr h1), ite_eq_left h1]
  · rw [ite_eq_right (mt h0.mp h1), ite_eq_right h1, hx]

/-- `expected_proof_length(n)` is `depth(n)`. -/
theorem expected_proof_length_spec (n : Usize) :
    merkle.MerkleProof.expected_proof_length inst n ⦃ r => r.val = depth n.val ⦄ := by
  unfold merkle.MerkleProof.expected_proof_length
  simp only [lift, bind_ok, core.num.Usize.leading_zeros]
  have hl := lz_spec n
  have hb : UScalarTy.Usize.numBits ≤ 64 := by
    simp [UScalarTy.numBits]
  have hbits : core.num.Usize.BITS.val = UScalarTy.Usize.numBits := by simp [core.num.Usize.BITS]
  have hle : BitVec.leadingZeros (core.num.Usize.saturating_sub n 1#usize).bv ≤ UScalarTy.Usize.numBits := by
    rw [hl]; split <;> omega
  have hv : (⟨BitVec.leadingZeros (core.num.Usize.saturating_sub n 1#usize).bv⟩ : U32).val =
      BitVec.leadingZeros (core.num.Usize.saturating_sub n 1#usize).bv := by
    show (BitVec.ofNat 32 _).toNat = _
    rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt]
    have : UScalarTy.Usize.numBits < 2 ^ 32 := by
      simp [UScalarTy.numBits]; rcases System.Platform.numBits_eq with h | h <;> omega
    omega
  step*
  simp only [Usize.bv] at *
  simp only [hl] at i2_post
  rw [UScalar.cast_val_eq, i2_post]
  have hlog : ∀ m, m < 2 ^ UScalarTy.Usize.numBits → Nat.log 2 m < UScalarTy.Usize.numBits :=
    fun m hm => Nat.log_lt_of_lt_pow' (by simp [UScalarTy.numBits]; rcases System.Platform.numBits_eq with h | h <;> omega) hm
  by_cases h1 : n.val ≤ 1
  · simp [h1]
    rw [depth, ite_eq_left h1]
    rcases System.Platform.numBits_eq with h | h <;> simp [h, UScalar.val]
  · simp [h1]
    have hn := n.hBounds
    have hlt := hlog (n.val - 1) (by simp [UScalarTy.numBits] at hn ⊢; omega)
    rw [depth_eq_log n.val (by omega)]
    simp [UScalarTy.numBits] at hlt
    have hlz : ∀ x, x ≤ 64 → (⟨BitVec.ofNat 32 x⟩ : U32).val = x := fun x hx => by
      show (BitVec.ofNat 32 x).toNat = x
      rw [BitVec.toNat_ofNat]; omega
    have hb64 : System.Platform.numBits ≤ 64 := by
      rcases System.Platform.numBits_eq with h | h <;> omega
    rw [hlz _ (by omega), Nat.mod_eq_of_lt]
    · omega
    · have : System.Platform.numBits < 2 ^ System.Platform.numBits := Nat.lt_two_pow_self
      omega

/-- `compute_root` returns `none` unless the index is below `n_leaves` and the proof has
`depth(n_leaves)` siblings, and otherwise what `hash_along_path` returns. -/
theorem compute_root_spec (hm : HashModel inst H) (p : merkle.MerkleProof T) (leaf : Slice U8)
    (i n : Usize) :
    merkle.MerkleProof.compute_root inst p leaf i n ⦃ r =>
      r = if i.val < n.val ∧ p.path.length = depth n.val ∧
          p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length
        then some (fold H (leafN H leaf.val) p.path.val i.val) else none ⦄ := by
  unfold merkle.MerkleProof.compute_root
  by_cases hi : i.val < n.val
  · have : ¬ (i ≥ n) := by scalar_tac
    simp only [this, merkle.MerkleProof.len, bind_ok]
    apply WP.spec_bind (expected_proof_length_spec (inst := inst) n)
    intro e he
    by_cases hl : p.path.length = depth n.val
    · have : ¬ ((alloc.vec.Vec.len p.path) != e) = true := by
        simp only [bne_iff_ne, ne_eq, Decidable.not_not]; scalar_tac
      simp only [this]
      apply WP.spec_mono (hash_along_path_spec hm p leaf i)
      intro r hr
      rw [hr]
      by_cases hc : p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length
      · rw [ite_eq_left hc, ite_eq_left ⟨hi, hl, hc⟩]
      · rw [ite_eq_right hc, ite_eq_right (by tauto)]
    · have : ((alloc.vec.Vec.len p.path) != e) = true := by
        simp only [bne_iff_ne, ne_eq]; intro h; apply hl; scalar_tac
      simp only [this, ↓reduceIte, WP.spec_ok]
      rw [ite_eq_right (by tauto)]
  · have : i ≥ n := by scalar_tac
    simp only [this, ↓reduceIte, WP.spec_ok]
    rw [ite_eq_right (by tauto)]

/-- `verify(root, leaf, i, n_leaves)` accepts exactly when the index is below `n_leaves`, the
proof has `depth(n_leaves)` siblings, and the leaf hashed up the path is `root`. -/
theorem verify_spec (hm : HashModel inst H) (p : merkle.MerkleProof T) (root : Node)
    (leaf : Slice U8) (i n : Usize) :
    merkle.MerkleProof.verify inst p root leaf i n ⦃ r =>
      (r = .Ok ()) ↔ (i.val < n.val ∧ p.path.length = depth n.val ∧
        p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length ∧
        fold H (leafN H leaf.val) p.path.val i.val = root) ⦄ := by
  unfold merkle.MerkleProof.verify
  apply WP.spec_bind (compute_root_spec hm p leaf i n)
  intro o ho
  subst ho
  split
  · rename_i h
    split at h
    · simp at h
    · simp only [WP.spec_ok]; simp_all
  · rename_i r h
    split at h
    · rename_i hc
      simp only [Option.some.injEq] at h
      subst h
      obtain ⟨b, hb, hbi⟩ := node_eq_spec (fold H (leafN H leaf.val) p.path.val i.val) root
      simp only [hb, bind_ok]
      split
      · rename_i hbt
        simp only [WP.spec_ok, true_iff]
        exact ⟨hc.1, hc.2.1, hc.2.2.1, hc.2.2.2, hbi.mp hbt⟩
      · rename_i hbf
        simp only [WP.spec_ok, reduceCtorEq, false_iff]
        intro ⟨_, _, _, _, he⟩
        exact hbf (hbi.mpr he)
    · simp at h

end MerkleProofs
