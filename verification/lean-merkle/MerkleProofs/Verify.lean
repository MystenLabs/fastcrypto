-- THIS FILE IS AI-ONLY
import MerkleProofs.Model

/-!
What the generated `MerkleProof::compute_root` and `MerkleProof::verify_proof` compute.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

theorem compute_root_loop_spec (hm : HashModel inst H) (v : alloc.vec.Vec Node) (c : Node)
    (li lvl : Usize) (hl : lvl.val ≤ v.length) :
    merkle.MerkleProof.compute_root_loop inst v c li lvl ⦃ r =>
      r = fold H c (v.val.drop lvl.val) li.val ⦄ := by
  unfold merkle.MerkleProof.compute_root_loop
  apply loop.spec_decr_nat (fun p => v.length - p.2.2.val)
    (fun p => p.2.2.val ≤ v.length ∧
      fold H p.1 (v.val.drop p.2.2.val) p.2.1.val = fold H c (v.val.drop lvl.val) li.val)
  · rintro ⟨c', li', lvl'⟩ ⟨hl', heq⟩
    dsimp only at hl' heq ⊢
    unfold merkle.MerkleProof.compute_root_loop.body
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

/-- `compute_root` returns `none` for proofs of `usize::BITS` or more levels and for indices not
below `2 ^ path.len()`, and otherwise the hash of the leaf up the path. -/
theorem compute_root_spec (hm : HashModel inst H) (p : merkle.MerkleProof T) (leaf : Slice U8)
    (i : Usize) :
    merkle.MerkleProof.compute_root inst p leaf i ⦃ r =>
      r = if p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length
        then some (fold H (leafN H leaf.val) p.path.val i.val) else none ⦄ := by
  unfold merkle.MerkleProof.compute_root
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
    apply WP.spec_bind (compute_root_loop_spec hm _ _ _ _ (by simp))
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

/-- `verify_proof` accepts exactly when `compute_root` returns `root`. -/
theorem verify_proof_spec (hm : HashModel inst H) (p : merkle.MerkleProof T) (root : Node)
    (leaf : Slice U8) (i : Usize) :
    merkle.MerkleProof.verify_proof inst p root leaf i ⦃ r =>
      (r = .Ok ()) ↔ (p.path.length < System.Platform.numBits ∧ i.val < 2 ^ p.path.length ∧
        fold H (leafN H leaf.val) p.path.val i.val = root) ⦄ := by
  unfold merkle.MerkleProof.verify_proof
  apply WP.spec_bind (compute_root_spec hm p leaf i)
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

end MerkleProofs
