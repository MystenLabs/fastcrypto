-- THIS FILE IS AI-ONLY
import merkle.Proofs.Model

/-!
What the generated `MerkleTree::build_from_leaf_hashes` and `MerkleTree::root` compute: the
nodes are the concatenation of `levels` of the leaf hashes, and the root is `rootOf` them.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

lemma length_pad_even (l : List Node) : (pad l).length % 2 = 0 := by
  rw [length_pad]; omega

lemma length_le_flatten_levels (l : List Node) : l.length ≤ (levels H l).flatten.length := by
  rw [levels]; split
  · simp
  · simp [length_pad]; omega

/-- The inner loop appends the parents of the padded level `pl` that starts at `pre.length`, iterating
`(pre.length..pre.length + pl.length).step_by(2)`. -/
lemma build_inner_spec (hm : HashModel inst H) (pre pl : List Node) (hpl : pl.length % 2 = 0)
    (hb : pre.length + pl.length + pl.length / 2 ≤ Usize.max)
    (nodes : alloc.vec.Vec Node) (hn : nodes.val = pre ++ pl)
    (it : core.iter.adapters.step_by.StepBy (core.ops.range.Range Usize))
    (hend : it.iter.end.val = pre.length + pl.length) (hstep : it.step_by.val = 2)
    (hstart : it.iter.start.val = pre.length) :
    merkle.MerkleTree.build_from_leaf_hashes_loop0_loop0 inst it nodes ⦃ r =>
      r.val = pre ++ pl ++ parents H pl ⦄ := by
  unfold merkle.MerkleTree.build_from_leaf_hashes_loop0_loop0
  apply loop.spec_decr_nat
    (fun p : core.iter.adapters.step_by.StepBy (core.ops.range.Range Usize) × alloc.vec.Vec Node =>
      pre.length + pl.length - p.1.iter.start.val)
    (fun p => p.1.iter.end.val = pre.length + pl.length ∧ p.1.step_by.val = 2 ∧
      ∃ k, k ≤ pl.length / 2 ∧ p.1.iter.start.val = pre.length + 2 * k ∧
        p.2.val = pre ++ pl ++ (parents H pl).take k)
  · rintro ⟨it', nodes'⟩ ⟨hend', hstep', k, hk, hi, hv⟩
    dsimp only at hend' hstep' hk hi hv ⊢
    unfold merkle.MerkleTree.build_from_leaf_hashes_loop0_loop0.body
    simp only [inner_hash_eq hm]
    have hlen : nodes'.length = pre.length + pl.length + k := by
      simp [hv, length_parents]; omega
    let* ⟨ o, it1, ho, hend1, hstep1 ⟩ ←
      core.iter.adapters.step_by.IteratorStepBy.next_Range_Usize_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hstart1⟩ := ho
      have hk' : k < pl.length / 2 := by omega
      simp only
      step*
      rw [hi, hstep', hend'] at hstart1
      refine ⟨by rw [hend1]; exact hend', by rw [hstep1]; exact hstep',
        ⟨k + 1, by omega, by omega, ?_⟩, by omega⟩
      have hget : ∀ j (hj : pre.length + j < nodes'.length), j < pl.length →
          nodes'.val[pre.length + j]'(by simpa using hj) = pl[j]! := by
        intro j hj hj'
        simp only [hv, List.append_assoc]
        rw [List.getElem_append_right (by simp)]
        simp only [Nat.add_sub_cancel_left]
        rw [List.getElem_append_left (by omega)]
        simp [hj']
      have e1 : n = pl[2 * k]! := by
        rw [n_post, ← hget (2 * k) (by scalar_tac) (by omega)]; simp only [hi]
      have e2 : n1 = pl[2 * k + 1]! := by
        rw [n1_post, ← hget (2 * k + 1) (by scalar_tac) (by omega)]; simp only [i_post, hi]; rfl
      have hpar : (parents H pl).length = pl.length / 2 := length_parents H pl
      rw [nodes1_post, hv, List.take_succ_eq_append_getElem (by omega), getElem_parents H pl k hk',
        e1, e2]
      simp only [List.append_assoc]
      simp [show 2 * k < pl.length by omega, show 2 * k + 1 < pl.length by omega]
    · obtain ⟨rfl, hstart1⟩ := ho
      simp only [WP.spec_ok]
      have : k = pl.length / 2 := by omega
      rw [hv, this, List.take_of_length_le (by rw [length_parents])]
  · exact ⟨hend, hstep, 0, by omega, by simp [hstart], by simp [hn]⟩

/-- The padding step of the outer loop. -/
lemma pad_step_spec (pre l : List Node) (nodes : alloc.vec.Vec Node) (hn : nodes.val = pre ++ l)
    (ln i : Usize) (hln : ln.val = l.length) (hi : i.val = ln.val % 2)
    (hb : pre.length + (pad l).length ≤ Usize.max) :
    (if i = 1#usize then do
        let nodes2 ← alloc.vec.Vec.push nodes merkle.Node.Empty
        let level_nodes2 ← ln + 1#usize
        ok (nodes2, level_nodes2)
      else ok (nodes, ln)) ⦃ p => p.1.val = pre ++ pad l ∧ p.2.val = (pad l).length ⦄ := by
  have hp := length_pad l
  by_cases hodd : l.length % 2 = 1
  · have : i = 1#usize := by scalar_tac
    rw [ite_eq_left this]
    step*
    simp [nodes2_post, hn, pad, hodd]; scalar_tac
  · have : i ≠ 1#usize := by scalar_tac
    rw [ite_eq_right this, WP.spec_ok]
    simp [hn, pad, hodd]; scalar_tac

/-- The outer loop: from `pre ++ l`, where `l` is the current level, it appends the levels above
`l`. -/
lemma build_outer_spec (hm : HashModel inst H) (F : List Node) (hF : F.length ≤ Usize.max)
    (pre l : List Node) (hpre : pre ++ (levels H l).flatten = F)
    (nodes : alloc.vec.Vec Node) (hn : nodes.val = pre ++ l)
    (level_nodes prev : Usize) (hln : level_nodes.val = l.length) (hprev : prev.val = pre.length) :
    merkle.MerkleTree.build_from_leaf_hashes_loop0 inst nodes level_nodes prev ⦃ r =>
      r.val = F ⦄ := by
  unfold merkle.MerkleTree.build_from_leaf_hashes_loop0
  apply loop.spec_decr_nat (fun p => p.2.1.val)
    (fun p => ∃ pre l, pre ++ (levels H l).flatten = F ∧ p.1.val = pre ++ l ∧
      p.2.1.val = l.length ∧ p.2.2.val = pre.length)
  · rintro ⟨nodes', ln', prev'⟩ ⟨pre', l', hpre', hn', hln', hprev'⟩
    dsimp only at hpre' hn' hln' hprev' ⊢
    unfold merkle.MerkleTree.build_from_leaf_hashes_loop0.body
    by_cases h1 : l'.length ≤ 1
    · have : ¬ (ln' > 1#usize) := by scalar_tac
      simp only [this, ↓reduceIte, WP.spec_ok]
      rw [levels, dite_eq_left h1] at hpre'
      simp [hn', ← hpre']
    · have hgt : ln' > 1#usize := by scalar_tac
      have hlev : levels H l' = pad l' :: levels H (up H l') := by rw [levels, dite_eq_right h1]
      rw [hlev, List.flatten_cons] at hpre'
      have hFl := congrArg List.length hpre'
      simp only [List.length_append] at hFl
      have hup := length_le_flatten_levels (H := H) (up H l')
      rw [length_up] at hup
      have hpad := length_pad l'
      simp only [hgt, ↓reduceIte]
      step*
      apply WP.spec_bind (pad_step_spec pre' l' nodes' hn' ln' i hln' i_post (by omega))
      rintro ⟨nodes1, ln1⟩ ⟨hn1, hln1⟩
      dsimp only at hn1 hln1 ⊢
      step*
      apply WP.spec_bind (build_inner_spec hm pre' (pad l') (length_pad_even l') (by omega) nodes1
        hn1 iter (by rw [iter_post]; scalar_tac) (by rw [iter_post1]; rfl)
        (by rw [iter_post]; scalar_tac))
      intro nodes2 hn2
      step*
      refine ⟨⟨pre' ++ pad l', up H l', ?_, ?_, ?_, ?_⟩, ?_⟩
      · rw [← hpre']; simp
      · rw [hn2]; rfl
      · rw [level_nodes2_post, hln1, length_up, hpad]
      · scalar_tac
      · rw [level_nodes2_post, hln1, hpad]; scalar_tac
  · exact ⟨pre, l, hpre, hn, hln, hprev⟩

/-- `build_from_leaf_hashes` returns the tree whose nodes are the levels over the leaf hashes,
for at most `usize::MAX / 4` leaves. -/
lemma build_spec (hm : HashModel inst H) (hs : alloc.vec.Vec Node)
    (hn : 4 * hs.length ≤ Usize.max) :
    merkle.MerkleTree.build_from_leaf_hashes inst hs ⦃ t =>
      t.nodes.val = (levels H hs.val).flatten ∧ t.n_leaves.val = hs.length ⦄ := by
  unfold merkle.MerkleTree.build_from_leaf_hashes
  have hF := length_flatten_levels H hs.val
  apply WP.spec_bind (build_outer_spec hm (levels H hs.val).flatten
    (by have : hs.length = hs.val.length := rfl; omega) []
    hs.val (by simp) hs
    (by simp) _ 0#usize (by simp) (by simp))
  intro r hr
  simp [hr]

lemma node_clone_spec (n : Node) : merkle.Node.Insts.CoreCloneClone.clone n ⦃ r => r = n ⦄ := by
  cases n with
  | Empty => simp [merkle.Node.Insts.CoreCloneClone.clone, WP.spec_ok]
  | Digest v =>
    simp only [merkle.Node.Insts.CoreCloneClone.clone, core.array.CloneArray.clone]
    apply WP.spec_bind (Array.clone_spec (by simp [liftFun1]))
    intro a ha
    simp [ha, WP.spec_ok]

/-- `root` returns `rootOf` the leaf hashes. -/
lemma root_spec (hs : List Node) (t : merkle.MerkleTree T)
    (ht : t.nodes.val = (levels H hs).flatten) :
    merkle.MerkleTree.root inst t ⦃ r => r = rootOf H hs ⦄ := by
  unfold merkle.MerkleTree.root
  have hle := length_le_flatten_levels (H := H) hs
  step*
  · rename_i hb
    have h0 : t.nodes.length = 0 := by simpa [b_post] using hb
    have : hs = [] := List.eq_nil_of_length_eq_zero (by simp [← ht] at hle; scalar_tac)
    subst this
    rw [rootOf]; simp
  · rename_i hb
    apply WP.spec_mono (node_clone_spec n)
    intro r hr
    rw [hr, n_post]
    have hne : hs ≠ [] := by
      rintro rfl
      have : (levels H []).flatten = [] := by rw [levels]; simp
      rw [this] at ht
      have : t.nodes.length = 0 := by simp [alloc.vec.Vec.length, ht]
      scalar_tac
    obtain ⟨h', e⟩ := getLast_flatten_levels H hs hne
    rw [← e, List.getLast_eq_getElem]
    have hl : t.nodes.len.val = (levels H hs).flatten.length := by simp [← ht]
    simp only [ht, i1_post, hl]

end MerkleProofs
