-- THIS FILE IS AI-ONLY
import merkle.Proofs.Build

/-!
What the generated `MerkleTree::get_proof` returns: the path `pathOf` of the leaf.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

lemma depth_lt (n : Nat) (h : 1 ≤ n) : depth n < n := by
  have := depth_le n (n - 1) (by
    obtain ⟨k, rfl⟩ : ∃ k, n = k + 1 := ⟨n - 1, by omega⟩
    simpa using Nat.lt_two_pow_self (n := k))
  omega

lemma get_proof_loop_spec (P : List Node) (v : alloc.vec.Vec Node)
    (pre l : List Node) (hv : v.val = pre ++ (levels H l).flatten)
    (path : alloc.vec.Vec Node) (li nl base : Usize) (hP : path.val ++ pathOf H l li.val = P)
    (hPl : P.length < Usize.max) (hli : li.val < l.length) (hnl : nl.val = l.length)
    (hbase : base.val = pre.length) :
    merkle.MerkleTree.get_proof_loop v path li nl base ⦃ r => r.val = P ⦄ := by
  unfold merkle.MerkleTree.get_proof_loop
  apply loop.spec_decr_nat (fun p => p.2.2.1.val)
    (fun p => ∃ pre l, v.val = pre ++ (levels H l).flatten ∧ p.1.val ++ pathOf H l p.2.1.val = P ∧
      p.2.1.val < l.length ∧ p.2.2.1.val = l.length ∧ p.2.2.2.val = pre.length)
  · rintro ⟨path', li', nl', base'⟩ ⟨pre', l', hv', hP', hli', hnl', hbase'⟩
    dsimp only at hv' hP' hli' hnl' hbase' ⊢
    unfold merkle.MerkleTree.get_proof_loop.body
    by_cases h1 : l'.length ≤ 1
    · have : ¬ (nl' > 1#usize) := by scalar_tac
      simp only [this, ↓reduceIte, WP.spec_ok]
      rw [pathOf, dite_eq_left h1] at hP'
      simpa using hP'
    · have hgt : nl' > 1#usize := by scalar_tac
      simp only [hgt, ↓reduceIte]
      have hlev : levels H l' = pad l' :: levels H (up H l') := by rw [levels, dite_eq_right h1]
      rw [hlev, List.flatten_cons] at hv'
      have hpad := length_pad l'
      have hvl : v.length = pre'.length + (pad l').length + (levels H (up H l')).flatten.length := by
        simp [alloc.vec.Vec.length, hv']; omega
      have hvmax : v.length ≤ Usize.max := by scalar_tac
      have hget : ∀ j (hj : pre'.length + j < v.length), j < (pad l').length →
          v.val[pre'.length + j]'(by simpa using hj) = (pad l')[j]! := by
        intro j hj hj'
        simp only [hv']
        rw [List.getElem_append_right (by simp)]
        simp only [Nat.add_sub_cancel_left]
        rw [List.getElem_append_left (by omega)]
        simp [hj']
      have hPstep : pathOf H l' li'.val = (pad l').getD (if li'.val % 2 = 0 then li'.val + 1
          else li'.val - 1) .Empty :: pathOf H (up H l') (li'.val / 2) := by
        rw [pathOf, dite_eq_right h1]
      have hplen : path'.length < P.length := by
        rw [← hP', hPstep]; simp
      step*
      have hsib : (if b = true then do
            let i1 ← base' + li'
            i1 + 1#usize
          else do
            let i1 ← base' + li'
            i1 - 1#usize) ⦃ s =>
          s.val = pre'.length + (if li'.val % 2 = 0 then li'.val + 1 else li'.val - 1) ⦄ := by
        split
        · rename_i hb
          have he : li'.val % 2 = 0 := by simpa [hb] using b_post
          step*
        · rename_i hb
          have he : li'.val % 2 ≠ 0 := by simpa [hb] using b_post
          step*
          simp [he]; scalar_tac
      apply WP.spec_bind hsib
      intro sib hsib'
      have hsl : (if li'.val % 2 = 0 then li'.val + 1 else li'.val - 1) < (pad l').length := by
        split <;> omega
      step*
      apply WP.spec_bind (node_clone_spec _)
      intro n1 hn1
      step*
      refine ⟨⟨pre' ++ pad l', up H l', ?_, ?_, ?_, ?_, ?_⟩, ?_⟩
      · rw [hv']; simp
      · rw [path1_post, ← hP', hPstep, hn1, n_post, level_index1_post]
        simp only [List.append_assoc, List.cons_append, List.nil_append]
        congr 2
        rw [← List.getD_eq_getElem _ merkle.Node.Empty]
        simp only [hv', hsib', List.getD_eq_getElem?_getD]
        rw [List.getElem?_append_right (by simp), Nat.add_sub_cancel_left,
          List.getElem?_append_left hsl]
      · rw [level_index1_post, length_up]; omega
      · rw [n_level2_post, n_level1_post, length_up]; scalar_tac
      · rw [level_base_index1_post, n_level1_post]; simp; scalar_tac
      · rw [n_level2_post, n_level1_post]; scalar_tac
  · exact ⟨pre, l, hv, hP, hli, hnl, hbase⟩

/-- For a tree built from `hs` and `i < hs.len()`, `get_proof(i)` returns the path `pathOf`. -/
lemma get_proof_spec (hs : List Node) (t : merkle.MerkleTree T)
    (ht : t.nodes.val = (levels H hs).flatten) (hn : t.n_leaves.val = hs.length)
    (i : Usize) (hi : i.val < hs.length) :
    merkle.MerkleTree.get_proof inst t i ⦃ r =>
      ∃ p, r = .Ok p ∧ p.path.val = pathOf H hs i.val ⦄ := by
  unfold merkle.MerkleTree.get_proof
  have hge : ¬ (i ≥ t.n_leaves) := by scalar_tac
  simp only [hge, ↓reduceIte]
  have hd := depth_lt hs.length (by omega)
  have hP : (pathOf H hs i.val).length < Usize.max := by
    rw [length_pathOf]
    have := length_le_flatten_levels (H := H) hs
    have : t.nodes.length ≤ Usize.max := by scalar_tac
    simp only [alloc.vec.Vec.length, ht] at this
    omega
  apply WP.spec_bind (get_proof_loop_spec (H := H) (pathOf H hs i.val) t.nodes [] hs (by simp [ht])
    (alloc.vec.Vec.new Node) i t.n_leaves 0#usize (by simp) hP hi hn (by simp))
  intro r hr
  simp [WP.spec_ok, hr]

end MerkleProofs
