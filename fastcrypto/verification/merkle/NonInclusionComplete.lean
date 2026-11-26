-- THIS FILE IS AI-ONLY
import merkle.NonInclusion
import merkle.GetProof

/-!
Completeness of non-inclusion proofs: `MerkleTree::compute_non_inclusion_proof` returns a proof that
`MerkleNonInclusionProof::verify_for_trusted_tree` accepts. The assumptions it needs about code
that Lean sees as opaque: `PartitionPointSpec`, `LinearOrd`, `EqModel` and `CloneIsId`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

/-! ## Assumptions -/

/-! ## Lemmas -/

lemma sortedLe_tail {L : Type} {o : core.cmp.PartialOrd L L} {x : L} {ls : List L}
    (h : SortedLe o (x :: ls)) : SortedLe o ls := fun j k hjk hk => by
  have := h (j + 1) (k + 1) (by omega) (by simpa using hk)
  simp only [List.getElem_cons_succ] at this
  exact this

/-- In a list sorted by `<=`, the elements `<= t` are a prefix. -/
lemma partition_index {L : Type} {o : core.cmp.PartialOrd L L} (hl : LinearOrd o) (t : L) :
    ∀ ls : List L, SortedLe o ls →
    ∃ p ≤ ls.length, ∀ k (hk : k < ls.length), o.le ls[k] t = ok (decide (k < p))
  | [], _ => ⟨0, le_rfl, fun k hk => by simp at hk⟩
  | x :: ls, hs => by
    rcases hl.le_ok x t with hx | hx
    · obtain ⟨p, hp, hk⟩ := partition_index hl t ls (sortedLe_tail hs)
      refine ⟨p + 1, by simp; omega, fun k hk' => ?_⟩
      cases k with
      | zero => simpa using hx
      | succ k => simpa using hk k (by simpa using hk')
    · refine ⟨0, by simp, fun k hk' => ?_⟩
      cases k with
      | zero => simpa using hx
      | succ k =>
        have hk : k < ls.length := by simpa using hk'
        simp only [List.getElem_cons_succ, Nat.not_lt_zero, decide_false]
        rcases hl.le_ok ls[k] t with h | h
        · have := hl.trans _ _ _ (by simpa using hs 0 (k + 1) (by omega) hk') h
          rw [hx] at this; simp at this
        · exact h

/-- The honest path of the last leaf passes `is_right_most`. -/
lemma rightMost_last (l : List Node) : RightMost (pathOf H l (l.length - 1)) (l.length - 1) := by
  by_cases h1 : l.length ≤ 1
  · rw [pathOf, dite_eq_left h1]; trivial
  rw [pathOf_up H l _ h1]
  have hlu := length_up H l
  refine ⟨fun he => ?_, ?_⟩
  · simp only [he, ite_true]
    rw [List.getD_eq_default _ _ (by omega)]
  · have : (l.length - 1) / 2 = (up H l).length - 1 := by rw [hlu]; omega
    rw [this]
    exact rightMost_last (up H l)
termination_by l.length
decreasing_by exact length_up_lt H l h1

/-- `verify_for_trusted_tree` accepts the honest path of leaf `j` against the root. -/
lemma trusted_complete_at (hm : HashModel inst H) (hs : List Node) (hn : 4 * hs.length ≤ Usize.max)
    (j : Usize) (hj : j.val < hs.length) (leaf : Slice U8)
    (hleaf : merkle.leaf_hash inst leaf = ok hs[j.val]) (p : merkle.MerkleProof T)
    (hp : p.path.val = pathOf H hs j.val) :
    merkle.MerkleProof.verify_for_trusted_tree inst p (rootOf H hs) leaf j = ok (.Ok ()) := by
  obtain ⟨v, hv, hvi⟩ := spec_eq_ok (verify_for_trusted_tree_spec hm p (rootOf H hs) leaf j)
  rw [hv, hvi.mpr]
  have hlen : p.path.length = depth hs.length := by
    simp only [alloc.vec.Vec.length, hp, length_pathOf]
  have hl : leafN H leaf.val = hs[j.val] := by
    rw [leaf_hash_eq hm] at hleaf; exact Result.ok_injective hleaf
  refine ⟨by rw [hlen]; exact depth_lt_numBits _ hn, by rw [hlen]; exact lt_of_lt_of_le hj (lt_two_pow_depth _), ?_⟩
  rw [hp, hl, fold_pathOf H hs j.val hj]

lemma unserialized_of {L : Type} (ser : serde_core.ser.Serialize L) (p : merkle.MerkleProof T)
    (root : Node) (l : L) (i : Usize) (v : alloc.vec.Vec U8)
    (hv : bcs.ser.to_bytes ser l = ok (.Ok v))
    (h : merkle.MerkleProof.verify_for_trusted_tree inst p root (alloc.vec.Vec.deref v) i =
      ok (.Ok ())) :
    merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser p root l i =
      ok (.Ok ()) := by
  unfold merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf
  simp [hv, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, h]

/-- `MerkleNonInclusionProof::verify_for_trusted_tree` accepts a proof with a left neighbor at
`index - 1` that verifies and is less than `t`, and either no right neighbor and a left proof that
passes `is_right_most`, or a right neighbor at `index` that verifies and is greater than `t`. -/
lemma ni_of_left {L : Type} (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L)
    (pr : merkle.MerkleNonInclusionProof L T) (root : Node) (t : L) (l : L)
    (lp : merkle.MerkleProof T) (j : Usize) (hl : pr.left_leaf = some (l, lp))
    (hj : Usize.checked_sub pr.index 1#usize = some j)
    (hvl : merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser lp root l j =
      ok (.Ok ()))
    (hge : ord.partialOrdInst.ge l t = ok false)
    (hright : (pr.right_leaf = none ∧ merkle.MerkleProof.is_right_most inst lp j = ok true) ∨
      (∃ r rp, pr.right_leaf = some (r, rp) ∧
        merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser rp root r
          pr.index = ok (.Ok ()) ∧
        ord.partialOrdInst.le r t = ok false)) :
    merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root t = ok (.Ok ()) := by
  obtain ⟨s, hs, s1, hs1, heq⟩ := root_check root
  unfold merkle.MerkleNonInclusionProof.verify_for_trusted_tree
  simp only [hs, hs1, heq, bind_ok, merkle.MerkleNonInclusionProof.is_valid_neighbor,
    core.cmp.impls.PartialOrdShared.ge, core.cmp.impls.PartialOrdShared.le, lift]
  by_cases hr : bytesOf root = bytesOf .Empty
  · simp [hr]
  simp only [hr, decide_false, Bool.false_eq_true, ite_false, hj, hl, bind_ok]
  rcases hright with ⟨hn, hrm⟩ | ⟨r, rp, hrr, hvr, hle⟩
  · simp [hn, hrm, hvl, hge, core.result.Result.Insts.CoreOpsTry.branch]
  · simp [hrr, hvr, hle, hvl, hge, core.result.Result.Insts.CoreOpsTry.branch]

/-- `MerkleNonInclusionProof::verify_for_trusted_tree` accepts a proof with index `0`, no left
neighbor, and a right neighbor at `0` that verifies and is greater than `t`. -/
lemma ni_of_zero {L : Type} (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L)
    (pr : merkle.MerkleNonInclusionProof L T) (root : Node) (t : L) (r : L)
    (rp : merkle.MerkleProof T) (h0 : pr.index.val = 0) (hl : pr.left_leaf = none)
    (hrr : pr.right_leaf = some (r, rp))
    (hvr : merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser rp root r
      pr.index = ok (.Ok ()))
    (hle : ord.partialOrdInst.le r t = ok false) :
    merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root t = ok (.Ok ()) := by
  obtain ⟨s, hs, s1, hs1, heq⟩ := root_check root
  unfold merkle.MerkleNonInclusionProof.verify_for_trusted_tree
  simp only [hs, hs1, heq, bind_ok, merkle.MerkleNonInclusionProof.is_valid_neighbor,
    core.cmp.impls.PartialOrdShared.ge, core.cmp.impls.PartialOrdShared.le, lift]
  by_cases hr : bytesOf root = bytesOf .Empty
  · simp [hr]
  have hi : pr.index = 0#usize := by scalar_tac
  rw [hi] at hvr
  simp only [hr, decide_false, Bool.false_eq_true, ite_false, hl, bind_ok]
  simp [hi, hrr, core.option.Option.is_none, hvr, hle, core.result.Result.Insts.CoreOpsTry.branch]

lemma get_proof_ok (hs : List Node) (t : merkle.MerkleTree T)
    (ht : t.nodes.val = (levels H hs).flatten) (hn : t.n_leaves.val = hs.length) (i : Usize)
    (hi : i.val < hs.length) :
    ∃ P, merkle.MerkleTree.get_proof inst t i = ok (.Ok P) ∧ P.path.val = pathOf H hs i.val := by
  obtain ⟨r, hr, P, rfl, hP⟩ := spec_eq_ok (get_proof_spec (inst := inst) hs t ht hn i hi)
  exact ⟨P, hr, hP⟩

/-- What `compute_non_inclusion_proof(leaves, target)` returns for a target that is not a leaf,
where `leaves[k] <= target` exactly for `k < p`: a proof with index `p`, the left neighbor
`leaves[p - 1]` with its honest path if `p > 0`, and the right neighbor `leaves[p]` with its honest
path if `p < leaves.len()`. -/
lemma compute_spec (hpp : PartitionPointSpec) {L : Type} (ord : core.cmp.Ord L)
    (ser : serde_core.ser.Serialize L) (cl : core.clone.Clone L) (hcl : CloneIsId cl)
    (heqm : EqModel ord.eqInst.partialEqInst) (hs : List Node) (t : merkle.MerkleTree T)
    (ht : t.nodes.val = (levels H hs).flatten) (hnl : t.n_leaves.val = hs.length)
    (leaves : Slice L) (hlen : hs.length = leaves.val.length) (target : L)
    (hnot : target ∉ leaves.val) (p : Nat) (hp : p ≤ leaves.val.length)
    (hpk : ∀ k (hk : k < leaves.val.length),
      ord.partialOrdInst.le leaves.val[k] target = ok (decide (k < p))) :
    ∃ pr, merkle.MerkleTree.compute_non_inclusion_proof inst ord ser cl t leaves target =
      ok (.Ok pr) ∧ pr.index.val = p ∧
    (∀ h : 0 < p, ∃ P : merkle.MerkleProof T,
      pr.left_leaf = some (leaves.val[p - 1]'(by omega), P) ∧ P.path.val = pathOf H hs (p - 1)) ∧
    (p = 0 → pr.left_leaf = none) ∧
    (∀ h : p < leaves.val.length, ∃ P : merkle.MerkleProof T,
      pr.right_leaf = some (leaves.val[p], P) ∧ P.path.val = pathOf H hs p) ∧
    (p = leaves.val.length → pr.right_leaf = none) := by
  unfold CloneIsId at hcl
  unfold merkle.MerkleTree.compute_non_inclusion_proof
  obtain ⟨pos, hpos, hposv⟩ := hpp
    (merkle.MerkleTree.compute_non_inclusion_proof.closure.Insts.CoreOpsFunctionFnMutTupleShared1LBool
      inst ord ser cl) leaves target p hp (fun k hk => by
        simp [merkle.MerkleTree.compute_non_inclusion_proof.closure.Insts.CoreOpsFunctionFnMutTupleShared1LBool.call_mut,
          hpk k hk])
  simp only [hpos, bind_ok, merkle.MerkleNonInclusionProof.new]
  have hidx : ∀ (i : Usize) (hi : i.val < leaves.val.length),
      Slice.index_usize leaves i = ok (leaves.val[i.val]) := fun i hi => by
    obtain ⟨x, hx, rfl⟩ := spec_eq_ok (Slice.index_usize_spec leaves i hi); exact hx
  have hlenS : (Slice.len leaves).val = leaves.val.length := by simp
  by_cases h0 : 0 < p
  · have hgt : pos > 0#usize := by scalar_tac
    obtain ⟨j, hj, hjv⟩ := spec_eq_ok (Usize.sub_spec (x := pos) (y := 1#usize) (by scalar_tac))
    have hjl : j.val < leaves.val.length := by scalar_tac
    have hne : leaves.val[j.val] ≠ target := fun e => hnot (e ▸ List.getElem_mem hjl)
    obtain ⟨P, hP, hPp⟩ := get_proof_ok (inst := inst) hs t ht hnl j (by omega)
    simp only [hgt, ite_true, hj, bind_ok, hidx j hjl, heqm _ _ hne, Bool.false_eq_true,
      ite_false, hcl, hP, core.result.Result.Insts.CoreOpsTry.branch]
    have hjp : j.val = p - 1 := by scalar_tac
    by_cases hr : p < leaves.val.length
    · have hlt : pos < Slice.len leaves := by scalar_tac
      obtain ⟨Q, hQ, hQp⟩ := get_proof_ok (inst := inst) hs t ht hnl pos (by omega)
      simp only [hlt, ite_true, hidx pos (by omega), hQ, bind_ok]
      refine ⟨_, rfl, hposv, fun _ => ⟨P, by simp [hjp], by rw [hPp, hjp]⟩, fun h => by omega,
        fun _ => ⟨Q, by simp [hposv], by rw [hQp, hposv]⟩, fun h => by omega⟩
    · have hlt : ¬ pos < Slice.len leaves := by scalar_tac
      simp only [hlt, ite_false]
      refine ⟨_, rfl, hposv, fun _ => ⟨P, by simp [hjp], by rw [hPp, hjp]⟩, fun h => by omega,
        fun h => by omega, fun _ => rfl⟩
  · have hgt : ¬ pos > 0#usize := by scalar_tac
    simp only [hgt, ite_false]
    by_cases hr : p < leaves.val.length
    · have hlt : pos < Slice.len leaves := by scalar_tac
      obtain ⟨Q, hQ, hQp⟩ := get_proof_ok (inst := inst) hs t ht hnl pos (by omega)
      simp only [hlt, ite_true, hidx pos (by omega), hcl, hQ, bind_ok,
        core.result.Result.Insts.CoreOpsTry.branch]
      refine ⟨_, rfl, hposv, fun h => by omega, fun _ => rfl,
        fun _ => ⟨Q, by simp [hposv], by rw [hQp, hposv]⟩, fun h => by omega⟩
    · have hlt : ¬ pos < Slice.len leaves := by scalar_tac
      simp only [hlt, ite_false]
      refine ⟨_, rfl, hposv, fun h => by omega, fun _ => rfl, fun h => by omega, fun _ => rfl⟩

/-- `MerkleNonInclusionProof::verify_for_trusted_tree` accepts every proof against a root with the
bytes of `Empty`. -/
lemma ni_of_empty {L : Type} (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L)
    (pr : merkle.MerkleNonInclusionProof L T) (root : Node) (t : L)
    (hr : bytesOf root = bytesOf .Empty) :
    merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root t = ok (.Ok ()) := by
  obtain ⟨s, hs, s1, hs1, heq⟩ := root_check root
  unfold merkle.MerkleNonInclusionProof.verify_for_trusted_tree
  simp [hs, hs1, heq, hr]

/-- Completeness of non-inclusion proofs against the model root: for `ls` sorted, serialized to
`ys`, and a target not in `ls`, `compute_non_inclusion_proof` returns a proof that
`verify_for_trusted_tree` accepts against the root of the tree over the leaf hashes of `ys`. -/
lemma ni_complete (hm : HashModel inst H) (hpp : PartitionPointSpec) {L : Type}
    (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L) (cl : core.clone.Clone L)
    (ho : OrdModel ord.partialOrdInst) (hlin : LinearOrd ord.partialOrdInst)
    (heqm : EqModel ord.eqInst.partialEqInst) (hcl : CloneIsId cl) (leaves : Slice L)
    (hsort : SortedLe ord.partialOrdInst leaves.val) (ys : List (List U8))
    (hser : Serializes ser leaves.val ys) (hn : 4 * ys.length ≤ Usize.max)
    (t : merkle.MerkleTree T) (ht : t.nodes.val = (levels H (ys.map (leafN H))).flatten)
    (hnl : t.n_leaves.val = ys.length) (target : L) (hnot : target ∉ leaves.val) :
    ∃ pr, merkle.MerkleTree.compute_non_inclusion_proof inst ord ser cl t leaves target =
      ok (.Ok pr) ∧
    merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr
      (rootOf H (ys.map (leafN H))) target = ok (.Ok ()) := by
  set hsl := ys.map (leafN H) with hhsl
  have hlen : hsl.length = leaves.val.length := by simp [hhsl, hser.1]
  obtain ⟨p, hp, hpk⟩ := partition_index hlin target leaves.val hsort
  obtain ⟨pr, hc, hidx, hleft, hleft0, hright, hrightn⟩ :=
    compute_spec (inst := inst) hpp ord ser cl hcl heqm hsl t ht (by simp [hnl, hhsl]) leaves
      hlen target hnot p hp hpk
  refine ⟨pr, hc, ?_⟩
  by_cases hy : leaves.val = []
  · apply ni_of_empty
    have : ys = [] := List.eq_nil_of_length_eq_zero (by rw [hser.1, hy]; rfl)
    simp [hhsl, this, rootOf]
  have hn' : 4 * hsl.length ≤ Usize.max := by simpa [hhsl] using hn
  -- The neighbor at `j` verifies with its honest path.
  have hnb : ∀ (j : Usize) (hj : j.val < leaves.val.length) (P : merkle.MerkleProof T),
      P.path.val = pathOf H hsl j.val →
      merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser P
        (rootOf H hsl) (leaves.val[j.val]) j = ok (.Ok ()) := by
    intro j hj P hP
    obtain ⟨v, hv, hvv⟩ := hser.2 j.val hj
    refine unserialized_of ser P _ _ j v hv (trusted_complete_at hm hsl hn' j (by omega) _ ?_ P hP)
    rw [leaf_hash_eq hm]
    simp only [hhsl, List.getElem_map, alloc.vec.Vec.deref]
    congr 2
    simp [hvv, List.getElem?_eq_getElem (show j.val < ys.length by rw [hser.1]; exact hj)]
  by_cases h0 : 0 < p
  · obtain ⟨P, hPl, hPp⟩ := hleft h0
    rcases checked_sub_one pr.index with ⟨j, hj, hjv⟩ | ⟨-, hz⟩
    swap; · omega
    have hjp : j.val = p - 1 := by omega
    have hjl : j.val < leaves.val.length := by omega
    have hget : leaves.val[p - 1]'(by omega) = leaves.val[j.val] := by simp [hjp]
    rw [hget] at hPl
    have hle1 : ord.partialOrdInst.le leaves.val[j.val] target = ok true := by
      rw [hpk j.val hjl]; simp; omega
    have hge : ord.partialOrdInst.ge leaves.val[j.val] target = ok false := by
      rw [ho.ge_eq_le]
      rcases hlin.le_ok target leaves.val[j.val] with h | h
      · exact absurd (hlin.antisymm _ _ hle1 h ▸ List.getElem_mem hjl) hnot
      · exact h
    apply ni_of_left ord ser pr _ target _ P j hPl hj (hnb j hjl P (by rw [hPp, hjp])) hge
    by_cases hr : p < leaves.val.length
    · obtain ⟨Q, hQr, hQp⟩ := hright hr
      right
      have hil : pr.index.val < leaves.val.length := by omega
      have hget' : leaves.val[p] = leaves.val[pr.index.val] := by simp [hidx]
      refine ⟨_, Q, hQr, ?_, ?_⟩
      · rw [hget']; exact hnb pr.index hil Q (by rw [hQp, hidx])
      · rw [hpk p hr]; simp
    · left
      refine ⟨hrightn (by omega), ?_⟩
      obtain ⟨b, hb, hbi⟩ := spec_eq_ok (is_right_most_spec (inst := inst) P j)
      rw [hb, hbi.mpr]
      rw [hPp, hjp]
      have : p - 1 = hsl.length - 1 := by omega
      rw [this]
      exact rightMost_last hsl
  · have hp0 : p = 0 := by omega
    have hr : 0 < leaves.val.length := List.length_pos_of_ne_nil hy
    obtain ⟨Q, hQr, hQp⟩ := hright (by omega)
    have hil : pr.index.val < leaves.val.length := by omega
    have hget' : leaves.val[p] = leaves.val[pr.index.val] := by simp [hidx]
    apply ni_of_zero ord ser pr _ target _ Q (by omega) (hleft0 hp0) hQr
    · rw [hget']; exact hnb pr.index hil Q (by rw [hQp, hidx])
    · rw [hpk p (by omega)]; simp [hp0]

end MerkleProofs
