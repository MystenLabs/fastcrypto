/-
Copyright (c) 2022, Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0

Definitions used to state the properties of `Party::merge`, and the pure lemmas about them. Nothing
here depends on the translated functions, only on the translated types. See README.md for what is
proved.
-/
import DkgMerge.Types
import Mathlib.Data.Finset.Card

open Aeneas Std

namespace DkgMerge

variable {G EG : Type _}

/-! ## Definitions -/

/-- The senders of `msgs`, in order. -/
def senders (msgs : List (ProcessedMessage G EG)) : List U16 :=
  msgs.map (·.message.sender)

/-- `kept` with `m` appended, unless `kept` already has a message from the sender of `m`. -/
def keepFirst (kept : List (ProcessedMessage G EG)) (m : ProcessedMessage G EG) :
    List (ProcessedMessage G EG) :=
  if m.message.sender ∈ senders kept then kept else kept ++ [m]

/-- `msgs` keeping only the first message of each sender, in order. The lemmas below show that its
senders are distinct, that they are the senders of `msgs`, and that it is a sublist of `msgs`. -/
def firstBySender (msgs : List (ProcessedMessage G EG)) : List (ProcessedMessage G EG) :=
  msgs.foldl keepFirst []

/-- The total weight of the senders of `msgs`, where the node with id `i` is `nodes[i]`. -/
def weightOf (nodes : List (Node EG)) (msgs : List (ProcessedMessage G EG)) : ℕ :=
  (msgs.map fun m => (nodes[m.message.sender.val]?.map (·.weight.val)).getD 0).sum

/-- The complaints in `msgs`, in order. -/
def complaints (msgs : List (ProcessedMessage G EG)) : List (Complaint EG) :=
  msgs.filterMap (·.complaint)

/-! ## `firstBySender` -/

theorem firstBySender_append_singleton (msgs : List (ProcessedMessage G EG))
    (m : ProcessedMessage G EG) :
    firstBySender (msgs ++ [m]) = keepFirst (firstBySender msgs) m := by
  simp [firstBySender, List.foldl_append]

theorem senders_foldl_nodup (msgs kept : List (ProcessedMessage G EG))
    (h : (senders kept).Nodup) : (senders (msgs.foldl keepFirst kept)).Nodup := by
  induction msgs generalizing kept with
  | nil => exact h
  | cons m msgs ih =>
    apply ih
    unfold keepFirst
    split
    · exact h
    · simp only [senders, List.map_append, List.map_cons, List.map_nil] at h ⊢
      exact List.nodup_append.mpr ⟨h, List.nodup_singleton _, by
        intro a ha b hb; simp at hb; subst hb; rintro rfl; contradiction⟩

/-- The senders of `firstBySender msgs` are distinct. -/
theorem firstBySender_nodup (msgs : List (ProcessedMessage G EG)) :
    (senders (firstBySender msgs)).Nodup :=
  senders_foldl_nodup msgs [] List.nodup_nil

theorem mem_senders_foldl (msgs kept : List (ProcessedMessage G EG)) (s : U16) :
    s ∈ senders (msgs.foldl keepFirst kept) ↔ s ∈ senders kept ∨ s ∈ senders msgs := by
  induction msgs generalizing kept with
  | nil => simp [senders]
  | cons m msgs ih =>
    rw [List.foldl_cons, ih]
    unfold keepFirst
    split <;> simp only [senders, List.map_append, List.map_cons, List.map_nil, List.mem_append,
      List.mem_cons, List.not_mem_nil, or_false] at * <;> grind

/-- `firstBySender msgs` has the same senders as `msgs`. -/
theorem mem_senders_firstBySender (msgs : List (ProcessedMessage G EG)) (s : U16) :
    s ∈ senders (firstBySender msgs) ↔ s ∈ senders msgs := by
  rw [firstBySender, mem_senders_foldl]
  simp [senders]

theorem foldl_sublist (msgs kept pre : List (ProcessedMessage G EG)) (h : kept.Sublist pre) :
    (msgs.foldl keepFirst kept).Sublist (pre ++ msgs) := by
  induction msgs generalizing kept pre with
  | nil => simpa using h
  | cons m msgs ih =>
    rw [List.foldl_cons, show pre ++ m :: msgs = (pre ++ [m]) ++ msgs by simp]
    apply ih
    unfold keepFirst
    split
    · exact h.trans (List.sublist_append_left _ _)
    · exact h.append (List.Sublist.refl _)

/-- `firstBySender msgs` is a sublist of `msgs`. -/
theorem firstBySender_sublist (msgs : List (ProcessedMessage G EG)) :
    (firstBySender msgs).Sublist msgs := by
  simpa [firstBySender] using foldl_sublist msgs [] [] (List.Sublist.refl _)

/-! ## Bounds -/

/-- At most `2^16` messages have distinct senders, since senders are `u16`s. -/
theorem length_le_of_senders_nodup (msgs : List (ProcessedMessage G EG))
    (h : (senders msgs).Nodup) : msgs.length ≤ 65536 := by
  have hinj : Function.Injective (fun x : U16 => x.val) := fun a b hab => by
    simpa [UScalar.eq_equiv] using hab
  have hnodup : ((senders msgs).map (·.val)).Nodup := h.map hinj
  have hsub : ((senders msgs).map (·.val)).toFinset ⊆ Finset.range 65536 := by
    intro x hx
    simp only [List.mem_toFinset, List.mem_map] at hx
    obtain ⟨a, _, rfl⟩ := hx
    simp only [Finset.mem_range]
    scalar_tac
  calc msgs.length = ((senders msgs).map (·.val)).toFinset.card := by
        rw [List.toFinset_card_of_nodup hnodup]; simp [senders]
    _ ≤ (Finset.range 65536).card := Finset.card_le_card hsub
    _ = 65536 := by simp

/-- Each sender weighs at most `2^16 - 1`. -/
theorem weightOf_le (nodes : List (Node EG)) (msgs : List (ProcessedMessage G EG)) :
    weightOf nodes msgs ≤ 65535 * msgs.length := by
  induction msgs with
  | nil => simp [weightOf]
  | cons m msgs ih =>
    simp only [weightOf, List.map_cons, List.sum_cons, List.length_cons] at ih ⊢
    have : (nodes[m.message.sender.val]?.map (·.weight.val)).getD 0 ≤ 65535 := by
      cases nodes[m.message.sender.val]? with
      | none => simp
      | some n => simp; scalar_tac
    omega

theorem weightOf_append_singleton (nodes : List (Node EG)) (msgs : List (ProcessedMessage G EG))
    (m : ProcessedMessage G EG) :
    weightOf nodes (msgs ++ [m]) =
      weightOf nodes msgs + (nodes[m.message.sender.val]?.map (·.weight.val)).getD 0 := by
  simp [weightOf]

theorem complaints_append_singleton (msgs : List (ProcessedMessage G EG))
    (m : ProcessedMessage G EG) :
    complaints (msgs ++ [m]) = complaints msgs ++ m.complaint.toList := by
  cases h : m.complaint <;> simp [complaints, h]

end DkgMerge
