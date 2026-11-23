import Avss.Protocol.Steps
import Avss.Protocol.Agreement
import Avss.Protocol.HonestDealer
import Avss.VerifyBinds
import Avss.RecoverSound
import Avss.ProcessValid
import Avss.ResponseVerifies
import Avss.ProcessInvalidIff
import Avss.HandleAccepts
import Avss.RecoverComplete
import Avss.FeldmanBinding

/-!
The lemmas of `Protocol.Avss.Contracts`, proved for the generated code.

`api` builds the spec's `Api` from the generated functions, for receivers `recv j` configured
alike, and `contracts` proves `Contracts` for it from the theorems in this directory.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs.Link

/-- The value a call returns, if it returns. -/
noncomputable def okVal {α : Type _} (x : Result α) : Option α :=
  open Classical in if h : ∃ a, x = ok a then some h.choose else none

theorem okVal_eq_some {α : Type _} {x : Result α} {a : α} : okVal x = some a ↔ x = ok a := by
  unfold okVal
  split
  · rename_i h
    constructor
    · intro ha
      simp only [Option.some.injEq] at ha
      rw [← ha]; exact h.choose_spec
    · intro hx
      have := h.choose_spec
      have h2 : ok a = ok h.choose := hx.symm.trans this
      rw [Result.ok_injective.eq_iff] at h2
      rw [h2]
  · rename_i h
    simp only [reduceCtorEq, false_iff]
    exact fun hx => h ⟨a, hx⟩

/-- A call's Rust result as an `Option`: `none` for an `Err`, a panic or no return. -/
noncomputable def toOption {T E : Type _} (x : Result (core.result.Result T E)) : Option T :=
  (okVal x).bind fun
    | .Ok v => some v
    | .Err _ => none

theorem toOption_eq_some {T E : Type _} {x : Result (core.result.Result T E)} {v : T} :
    toOption x = some v ↔ x = ok (core.result.Result.Ok v) := by
  unfold toOption
  rw [← okVal_eq_some]
  cases okVal x with
  | none => simp
  | some r => cases r <;> simp

/-- `process_message`'s result as the spec's `Processed`. -/
noncomputable def toProcessed {R E : Type _}
    (x : Result (core.result.Result threshold_schnorr.avss.ProcessedMessage E × R)) :
    Protocol.Avss.Processed threshold_schnorr.avss.AvssOutput
      threshold_schnorr.avss.Complaint :=
  match okVal x with
  | some (.Ok (.Valid o), _) => .valid o
  | some (.Ok (.Complaint c), _) => .complaint c
  | _ => .invalid

theorem toProcessed_valid {R E : Type _}
    {x : Result (core.result.Result threshold_schnorr.avss.ProcessedMessage E × R)} {o} :
    toProcessed x = .valid o ↔ ∃ g, x = ok (core.result.Result.Ok (.Valid o), g) := by
  unfold toProcessed
  simp only [← okVal_eq_some]
  split <;> simp_all

theorem toProcessed_complaint {R E : Type _}
    {x : Result (core.result.Result threshold_schnorr.avss.ProcessedMessage E × R)} {c} :
    toProcessed x = .complaint c ↔ ∃ g, x = ok (core.result.Result.Ok (.Complaint c), g) := by
  unfold toProcessed
  simp only [← okVal_eq_some]
  split <;> simp_all

theorem toProcessed_invalid {R E : Type _}
    {x : Result (core.result.Result threshold_schnorr.avss.ProcessedMessage E × R)} :
    toProcessed x = .invalid ↔ ∀ y, x = ok y → IsErr y.1 := by
  unfold toProcessed
  constructor
  · intro h y hy
    rw [← okVal_eq_some] at hy
    rw [hy] at h
    obtain ⟨r, g⟩ := y
    cases r with
    | Ok pm => cases pm <;> simp at h
    | Err e => exact ⟨e, rfl⟩
  · intro h
    split
    · rename_i o g hx
      obtain ⟨e, he⟩ := h _ (okVal_eq_some.mp hx)
      simp at he
    · rename_i c g hx
      obtain ⟨e, he⟩ := h _ (okVal_eq_some.mp hx)
      simp at he
    · rfl

abbrev Nodes := nodes.Nodes fastcrypto.groups.ristretto255.RistrettoPoint
  fastcrypto.groups.ristretto255.RistrettoScalar

/-- `nodes.share_ids_of(j)`. -/
noncomputable abbrev shareIdsOf (ns : Nodes) (j : Std.U16) :=
  nodes.Nodes.share_ids_of
    fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
    fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize ns j

/-- The parties: the ids that `nodes.weight_of` accepts. -/
abbrev Party (ns : Nodes) := {j : Std.U16 // ∃ w, weightOf ns j = ok (core.result.Result.Ok w)}

/-- There are finitely many parties: at most one per `u16`. -/
noncomputable instance (ns : Nodes) : Fintype (Party ns) :=
  have : Finite (Party ns) := Finite.of_injective
    (fun j : Party ns => (⟨j.val.val, by have := j.val.hBounds; simp at this ⊢; omega⟩ : Fin 65536))
    (fun a b h => Subtype.ext (UScalar.eq_of_val_eq (by simpa using h)))
  Fintype.ofFinite _

/-- `nodes.weight_of(j)`. -/
noncomputable def Party.weight {ns : Nodes} (j : Party ns) : Std.U16 := j.2.choose

theorem Party.weight_spec {ns : Nodes} (j : Party ns) :
    weightOf ns j.val = ok (core.result.Result.Ok j.weight) := j.2.choose_spec

/-- One receiver per party, `recv j` with id `j`, all with the same `nodes`, `params`, `sid` and
`commitment`, and the randomness `rng j` that each passes to `process_message`. -/
structure Receivers where
  ns : Nodes
  recv : Std.U16 → threshold_schnorr.avss.Receiver
  R : Type
  rngInst : fastcrypto.traits.AllowedRng R
  rng : Std.U16 → R
  id_eq : ∀ j, (recv j).id = j
  nodes_eq : ∀ j, (recv j).nodes = ns
  params_eq : ∀ i j, (recv i).params = (recv j).params
  sid_eq : ∀ i j, (recv i).sid = (recv j).sid
  commitment_eq : ∀ i j, (recv i).commitment = (recv j).commitment

/-- What the spec needs about scalars and share indices that the generated code does not give: the
scalar field `F` and how secp256k1 scalars map to it, how a share index is made into a
`NonZeroU16` (`ofIndex`), and the scalar-polynomial functions that AVSS does not call (`add`,
`mul`, `rand_fixed_c0`, `recover_c0`). -/
structure Scalars where
  F : Type
  [field : Field F]
  [fintype : Fintype F]
  toF : fastcrypto.groups.secp256k1.Scalar → F
  ofIndex : Protocol.Shamir.ShareIndex →
    core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner
  randFixedC0 : ℕ → F → PMF (polynomial.Poly fastcrypto.groups.secp256k1.Scalar)
  add : polynomial.Poly fastcrypto.groups.secp256k1.Scalar →
    polynomial.Poly fastcrypto.groups.secp256k1.Scalar →
    polynomial.Poly fastcrypto.groups.secp256k1.Scalar
  mul : polynomial.Poly fastcrypto.groups.secp256k1.Scalar → F →
    polynomial.Poly fastcrypto.groups.secp256k1.Scalar
  recoverC0 : ℕ → List (Protocol.Shamir.Eval F) →
    Except Protocol.Shamir.Error F
  /-- `G::generator() * x` for `x` in `F`. -/
  gen : F → fastcrypto.groups.secp256k1.ProjectivePoint

attribute [instance] Scalars.field Scalars.fintype

/-- `o.feldman_commitment.eval(k)` as an element of `F`: the `x` with
`o.feldman_commitment.eval(k) = G::generator() * x`, or `0` if there is none. -/
noncomputable def committedOf (Z : Scalars) (o : threshold_schnorr.avss.AvssOutput)
    (k : Protocol.Shamir.ShareIndex) : Z.F :=
  open Classical in
  if h : ∃ x iv, polynomial.Poly.eval
      fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
      fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
      fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsModuleScalar
      o.feldman_commitment (Z.ofIndex k) = ok iv ∧ iv.value = Z.gen x then h.choose
  else 0

/-- A `NonZeroU16` as the spec's share index. -/
noncomputable def idx (k : core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner) :
    Protocol.Shamir.ShareIndex :=
  open Classical in
  if h : ∃ u : Std.U16, nzGet k = ok u ∧ 0 < u.val then ⟨h.choose.val, h.choose_spec.2, by
    have := h.choose.hBounds; simp at this ⊢; omega⟩
  else ⟨1, by norm_num⟩

/-- `Poly::eval` and `Poly::degree` for scalar polynomials, as total functions. -/
noncomputable def evalAt (Z : Scalars) (p : polynomial.Poly fastcrypto.groups.secp256k1.Scalar)
    (k : Protocol.Shamir.ShareIndex) : Protocol.Shamir.Eval Z.F :=
  ⟨k, ((okVal (evalS p (Z.ofIndex k))).map fun iv => Z.toF iv.value).getD 0⟩

noncomputable def degreeBound (p : polynomial.Poly fastcrypto.groups.secp256k1.Scalar) : ℕ :=
  ((okVal (degreeS p)).map (·.val)).getD 0

/-- `Rᵢ.verify_complaint_response`, whose result's responder is the party `j`. -/
noncomputable def verifyResponse (C : Receivers) (i : Party C.ns) (m : threshold_schnorr.avss.Message)
    (j : Party C.ns) (r : threshold_schnorr.avss.ComplaintResponse) :
    Option {v : threshold_schnorr.avss.VerifiedComplaintResponse //
      ∃ w, weightOf C.ns v.responder_id = ok (core.result.Result.Ok w)} :=
  match h : toOption (threshold_schnorr.avss.Receiver.verify_complaint_response (C.recv i.val) m
      j.val r) with
  | some v => some ⟨v, by rw [verify_binds _ _ _ _ _ (toOption_eq_some.mp h)]; exact j.2⟩
  | none => none

theorem verifyResponse_eq_some (C : Receivers) (i : Party C.ns) m (j : Party C.ns) r v :
    verifyResponse C i m j r = some v ↔
      threshold_schnorr.avss.Receiver.verify_complaint_response (C.recv i.val) m j.val r =
        ok (core.result.Result.Ok v.val) := by
  unfold verifyResponse
  rw [← toOption_eq_some]
  split
  · rename_i w hw
    simp only [hw, Option.some.injEq]
    constructor
    · rintro rfl; rfl
    · intro h; exact Subtype.ext h
  · rename_i hw
    simp [hw]

/-- The spec's `Setup`: weights from `nodes.weight_of`, `t` and `f` from `params`. -/
noncomputable def setup (C : Receivers) : Protocol.Avss.Setup (Party C.ns) where
  weight j := j.weight.val
  t := (C.recv 0#u16).params.t.val
  f := (C.recv 0#u16).params.f.val

/-- The dealers, which stay abstract: the generated code does not include `Dealer`. `secret d` is
the secret `d` shares. -/
structure Dealers (Z : Scalars) where
  Dealer : Type
  createMessage : Dealer → PMF threshold_schnorr.avss.Message
  secret : Dealer → Z.F

/-- `Poly::c0` for scalar polynomials, as a total function into `F`. -/
noncomputable def c0Of (Z : Scalars) (p : polynomial.Poly fastcrypto.groups.secp256k1.Scalar) : Z.F :=
  ((okVal (@polynomial.Poly.c0 _
    fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst.AdditiveGroupInst
    p)).map Z.toF).getD 0

/-- The spec's `Api` for the generated code. -/
noncomputable def api (C : Receivers) (Z : Scalars) (D : Dealers Z) :
    Protocol.Avss.Api (Party C.ns) where
  Message := threshold_schnorr.avss.Message
  Complaint := threshold_schnorr.avss.Complaint
  Response := threshold_schnorr.avss.ComplaintResponse
  Verified := {v : threshold_schnorr.avss.VerifiedComplaintResponse //
    ∃ w, weightOf C.ns v.responder_id = ok (core.result.Result.Ok w)}
  Output := threshold_schnorr.avss.AvssOutput
  Shares := threshold_schnorr.avss.SharesForNode
  processMessage i m :=
    toProcessed (threshold_schnorr.avss.Receiver.process_message C.rngInst (C.recv i.val) m
      (C.rng i.val))
  handleComplaint j m a c o :=
    toOption (threshold_schnorr.avss.Receiver.handle_complaint (C.recv j.val) m a.val c o)
  verifyComplaintResponse := verifyResponse C
  responderId v := ⟨v.val.responder_id, v.2⟩
  recover i m vs :=
    if h : (vs.map Subtype.val).length ≤ Usize.max then
      toOption (threshold_schnorr.avss.Receiver.recover (C.recv i.val) m
        (alloc.vec.Vec.from (vs.map Subtype.val) h))
    else none
  shares o := o.my_shares
  verifyShares m i sh := open Classical in decide (ValidShares C.ns m i.val sh)
  Dealer := D.Dealer
  createMessage := D.createMessage
  secret := D.secret
  committed := committedOf Z
  F := Z.F
  Sh := {
    Poly := polynomial.Poly fastcrypto.groups.secp256k1.Scalar
    c0 := c0Of Z
    degreeBound := degreeBound
    randFixedC0 := Z.randFixedC0
    eval := evalAt Z
    add := Z.add
    mul := Z.mul
    recoverC0 := Z.recoverC0 }
  shareIds j := ((toOption (shareIdsOf C.ns j.val)).map fun ids => ids.val.map idx).getD []
  shareList sh := sh.shares.val.map fun s => ⟨idx s.index, Z.toF s.value⟩

open scoped ENNReal in
/-- `create_valid` for the dealers `D`: a message from `create_message` is valid for all receivers
except with probability `≤ 1/|F|`. -/
def CreateValid (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop :=
  ∀ d, ((api C Z D).createMessage d).toOuterMeasure {m | ¬ (api C Z D).AllValid m} ≤
    (Fintype.card Z.F : ℝ≥0∞)⁻¹

/-- `create_secret` for the dealers `D`: every polynomial a message from `create_message` binds to
has the dealer's `secret` as constant term. -/
def CreateSecret (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop :=
  ∀ d m, m ∈ ((api C Z D).createMessage d).support →
    ∀ p, (api C Z D).Sh.degreeBound p < (setup C).t →
      (∀ j sh, (api C Z D).verifyShares m j sh = true →
        (api C Z D).shareList sh = ((api C Z D).shareIds j).map ((api C Z D).Sh.eval p)) →
      (api C Z D).Sh.c0 p = (api C Z D).secret d

/-- `output_commitment`: an output `o` of an accepted message `m` commits to every polynomial `m`
binds to, `o.feldman_commitment.eval(k) = G::generator() * p.eval(k)`. -/
def OutputCommitment (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop :=
  ∀ i m o, (api C Z D).processMessage i m ≠ .invalid →
    ((api C Z D).processMessage i m = .valid o ∨ ∃ vs, (api C Z D).recover i m vs = some o) →
    ∀ p, (api C Z D).Sh.degreeBound p < (setup C).t →
      (∀ j sh, (api C Z D).verifyShares m j sh = true →
        (api C Z D).shareList sh = ((api C Z D).shareIds j).map ((api C Z D).Sh.eval p)) →
      ∀ k, (api C Z D).committed o k = ((api C Z D).Sh.eval p k).value

/-- `NonZeroU16::get` returns a positive value that determines the `NonZeroU16`, and `ofIndex k`
is the `NonZeroU16` with value `k`. -/
def NonZeroModel (Z : Scalars) : Prop :=
  (∀ k, ∃ u : Std.U16, nzGet k = ok u ∧ 0 < u.val) ∧ NonZeroGetInj ∧
    ∀ k : Protocol.Shamir.ShareIndex, ∃ u : Std.U16,
      nzGet (Z.ofIndex k) = ok u ∧ u.val = k.val

/-- Distinct `u16`s number at most `2^16`. -/
theorem nodup_u16_length {l : List Std.U16} (h : l.Nodup) : l.length ≤ 65536 := by
  have hinj : Function.Injective (fun x : Std.U16 => x.val) := fun a b hab => UScalar.eq_of_val_eq hab
  have hnd : (l.map fun x => x.val).Nodup := h.map hinj
  have hsub : (l.map fun x => x.val).toFinset ⊆ Finset.range 65536 := by
    intro n hn
    simp only [List.mem_toFinset, List.mem_map] at hn
    obtain ⟨x, -, rfl⟩ := hn
    have := x.hBounds
    simp at this ⊢; omega
  have := Finset.card_le_card hsub
  rw [List.toFinset_card_of_nodup hnd, List.length_map] at this
  simpa using this

theorem forall₂_and {α β : Type _} {R S : α → β → Prop} :
    ∀ {l₁ : List α} {l₂ : List β}, List.Forall₂ R l₁ l₂ → List.Forall₂ S l₁ l₂ →
      List.Forall₂ (fun a b => R a b ∧ S a b) l₁ l₂
  | _, _, .nil, .nil => .nil
  | _, _, .cons h t, .cons h' t' => .cons ⟨h, h'⟩ (forall₂_and t t')

theorem forall₂_map_eq {α β γ : Type _} {R : α → β → Prop} {f : α → γ} {g : β → γ}
    (H : ∀ a b, R a b → f a = g b) :
    ∀ {l₁ : List α} {l₂ : List β}, List.Forall₂ R l₁ l₂ → l₁.map f = l₂.map g
  | _, _, .nil => rfl
  | _, _, .cons h t => by simp [H _ _ h, forall₂_map_eq H t]

/-- `idx` undoes `ofIndex`. -/
theorem ofIndex_idx (Z : Scalars) (hnz : NonZeroModel Z) k : Z.ofIndex (idx k) = k := by
  obtain ⟨hpos, hinj, hof⟩ := hnz
  have hk : ∃ u : Std.U16, nzGet k = ok u ∧ 0 < u.val := hpos k
  obtain ⟨v, hv, hvv⟩ := hof (idx k)
  apply hinj _ _ v hv
  rw [hk.choose_spec.1]
  congr 1
  apply UScalar.eq_of_val_eq
  rw [hvv]
  simp [idx, hk]

/-- A process_message call that is not `invalid` returned a result that is not an `Err`. -/
theorem not_invalid {R E : Type _}
    {x : Result (core.result.Result threshold_schnorr.avss.ProcessedMessage E × R)}
    (h : toProcessed x ≠ .invalid) (hx : ∃ y, x = ok y) : ∃ y, x = ok y ∧ ¬ IsErr y.1 := by
  obtain ⟨y, hy⟩ := hx
  refine ⟨y, hy, fun he => h (toProcessed_invalid.mpr fun y' hy' => ?_)⟩
  rw [hy, Result.ok_injective.eq_iff] at hy'
  subst hy'; exact he

open scoped ENNReal in
/-- `Contracts` holds for the generated code, assuming `CreateValid`, `CreateSecret`,
`OutputCommitment` and the hypotheses of the lemmas in `Avss`. -/
theorem contracts (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (hclone : CloneIsId) (hpclone : PolyCloneIsId) (hpeq : PolyEqRefl) (hrec : RecoveryComplete)
    (hinterp : ∀ j, InterpolationComplete (C.recv j)) (hbind : CommitmentBinding)
    (hnz : NonZeroModel Z)
    (hids : ∀ j : Party C.ns, ∃ ids, shareIdsOf C.ns j.val = ok (core.result.Result.Ok ids))
    (hfits : ∀ A : Finset (Party C.ns), (setup C).weightOf A ≤ U16.max)
    (hret : ∀ (j : Party C.ns) m, ∃ y,
      threshold_schnorr.avss.Receiver.process_message C.rngInst (C.recv j.val) m (C.rng j.val) =
        ok y)
    (hcreate : CreateValid C Z D) (hsecret : CreateSecret C Z D)
    (hcomm : OutputCommitment C Z D) :
    Protocol.Avss.Contracts (setup C) (api C Z D) where
  process_valid := by
    intro i m o h
    obtain ⟨g, hg⟩ := toProcessed_valid.mp h
    have := process_valid C.rngInst _ m _ g o hg
    rw [C.nodes_eq, C.id_eq] at this
    simpa [Protocol.Avss.Api.ValidOutput, api] using this
  process_invalid_iff := by
    intro i j m
    obtain ⟨⟨xi, gi⟩, hxi⟩ := hret i m
    obtain ⟨⟨xj, gj⟩, hxj⟩ := hret j m
    have key := process_invalid_iff C.rngInst (C.recv i.val) (C.recv j.val)
      (by rw [C.nodes_eq, C.nodes_eq]) (C.params_eq _ _) (C.sid_eq _ _) (C.commitment_eq _ _) m
      _ _ gi gj xi xj hxi hxj
    show toProcessed _ = _ ↔ toProcessed _ = _
    refine (toProcessed_invalid).trans (Iff.trans ?_ (toProcessed_invalid).symm)
    constructor
    · intro h y hy
      rw [hxj, Result.ok_injective.eq_iff] at hy
      subst hy
      exact key.mp (h _ hxi)
    · intro h y hy
      rw [hxi, Result.ok_injective.eq_iff] at hy
      subst hy
      exact key.mpr (h _ hxj)
  handle_accepts := by
    intro i j m c o hi hj
    obtain ⟨gi, hgi⟩ := toProcessed_complaint.mp hi
    obtain ⟨gj, hgj⟩ := toProcessed_valid.mp hj
    obtain ⟨ids, hids'⟩ := hids i
    obtain ⟨r, hr⟩ := handle_accepts hclone hpclone hpeq hrec C.rngInst (C.recv i.val)
      (C.recv j.val) (by rw [C.nodes_eq, C.nodes_eq]) (C.params_eq _ _) (C.sid_eq _ _)
      (C.commitment_eq _ _) ids (by rw [C.nodes_eq, C.id_eq]; exact hids') m c o _ gi _ gj hgi hgj
    rw [C.id_eq] at hr
    exact ⟨r, toOption_eq_some.mpr hr⟩
  response_verifies := by
    intro i j m c o r hp hh
    obtain ⟨g, hg⟩ := toProcessed_valid.mp hp
    have hh' := toOption_eq_some.mp hh
    rw [← C.id_eq i.val] at hh'
    obtain ⟨v, hv⟩ := response_verifies hclone C.rngInst (C.recv i.val) (C.recv j.val)
      (by rw [C.nodes_eq, C.nodes_eq]) m c o r _ g hg hh'
    rw [C.id_eq] at hv
    have hb := verify_binds _ _ _ _ _ hv
    exact ⟨⟨v, by rw [hb]; exact j.2⟩, (verifyResponse_eq_some C i m j r _).mpr hv⟩
  verify_binds := by
    intro i m j r v h
    apply Subtype.ext
    have := verify_binds _ _ _ _ _ ((verifyResponse_eq_some C i m j r v).mp h)
    exact this
  recover_complete := by
    intro i m vs hpm hv hnd ht
    obtain ⟨⟨x, g⟩, hx, hnx⟩ := not_invalid hpm (hret i m)
    have hnd' : ((vs.map Subtype.val).map (·.responder_id)).Nodup := by
      have := hnd.map (f := Subtype.val) Subtype.val_injective
      rw [List.map_map] at this
      erw [List.map_map]
      exact this
    have hlen : (vs.map Subtype.val).length ≤ Usize.max := by
      have := nodup_u16_length hnd'
      rw [List.length_map] at this
      have : (65536 : ℕ) ≤ Usize.max := by scalar_tac
      omega
    let W : Std.U16 → Std.U16 := fun j => open Classical in
      if h : ∃ w, weightOf C.ns j = ok (core.result.Result.Ok w) then h.choose else 0#u16
    have hWp : ∀ j : Party C.ns, W j.val = j.weight := fun j => by simp [W, j.2, Party.weight]
    have hW : ∀ v ∈ (alloc.vec.Vec.from (vs.map Subtype.val) hlen).val, weightOf (C.recv i.val).nodes v.responder_id =
        ok (core.result.Result.Ok (W v.responder_id)) := by
      intro v hv'
      rw [alloc.vec.Vec.from_val] at hv'
      obtain ⟨w, -, rfl⟩ := List.mem_map.mp hv'
      rw [C.nodes_eq, hWp ⟨w.val.responder_id, w.2⟩]
      exact Party.weight_spec ⟨w.val.responder_id, w.2⟩
    have hsumeq : (setup C).weightOf ((vs.map (api C Z D).responderId).toFinset) =
        ((vs.map Subtype.val).map fun v => (W v.responder_id).val).sum := by
      unfold Protocol.Avss.Setup.weightOf
      erw [List.sum_toFinset _ hnd, List.map_map, List.map_map]
      congr 1
      apply List.map_congr_left
      intro w _
      exact congrArg UScalar.val (hWp ⟨w.val.responder_id, w.2⟩).symm
    obtain ⟨ids, hids'⟩ := hids i
    have htri := recover_complete hpclone C.rngInst (C.recv i.val) (hinterp _) m (C.rng i.val) g x
      hx hnx (alloc.vec.Vec.from (vs.map Subtype.val) hlen)
      (by
        intro v hv'
        rw [alloc.vec.Vec.from_val] at hv'
        obtain ⟨w, hw, rfl⟩ := List.mem_map.mp hv'
        obtain ⟨j, r, hjr⟩ := hv w hw
        exact ⟨j.val, r, (verifyResponse_eq_some C i m j r w).mp hjr⟩)
      (by rw [alloc.vec.Vec.from_val]; exact hnd') W hW
      (by rw [alloc.vec.Vec.from_val, ← hsumeq]; exact hfits _)
      (by rw [alloc.vec.Vec.from_val, ← hsumeq, C.params_eq _ 0#u16]; exact ht)
      ids (by rw [C.nodes_eq, C.id_eq]; exact hids')
    obtain ⟨y, hy, o, rfl⟩ := spec_eq_ok htri
    refine ⟨o, ?_⟩
    show (if h : _ then _ else none) = _
    rw [dite_eq_left_of_eq_true (eq_true hlen)]
    exact toOption_eq_some.mpr hy
  recover_sound := by
    intro i m vs o h
    simp only [api] at h
    split at h
    · have := recover_sound _ m _ o (toOption_eq_some.mp h)
      rw [C.nodes_eq, C.id_eq] at this
      simpa [Protocol.Avss.Api.ValidOutput, api] using this
    · simp at h
  create_valid := hcreate
  create_secret := hsecret
  output_commitment := hcomm
  feldman_binding := by
    intro i m hpm
    obtain ⟨⟨x, g⟩, hx, hnx⟩ := not_invalid hpm (hret i m)
    obtain ⟨p, e, he, het, hall⟩ := feldman_binding hbind hnz.2.1 C.rngInst (C.recv i.val) m _ g x
      hx hnx
    refine ⟨p, ?_, ?_⟩
    · show degreeBound p < (C.recv 0#u16).params.t.val
      simp only [degreeBound, okVal_eq_some.mpr he, Option.map_some, Option.getD_some]
      rw [C.params_eq 0#u16 i.val]; exact het
    · intro j sh hsh
      have hvs : ValidShares C.ns m j.val sh := by simpa [api] using hsh
      obtain ⟨ids, hids', hver⟩ := hvs
      have hev := hall sh _ _ hver
      have hix := (verify_ok sh m _ _ hver).1
      show sh.shares.val.map _ = (((toOption (shareIdsOf C.ns j.val)).map _).getD []).map _
      rw [toOption_eq_some.mpr hids']
      simp only [Option.map_some, Option.getD_some]
      erw [List.map_map]
      rw [vec_deref_val] at hev hix
      refine forall₂_map_eq ?_ (forall₂_and hix (List.Forall₂.flip (R := fun s k => _) hev))
      rintro s k ⟨⟨u, hu1, hu2⟩, iv, hiv, hval⟩
      have hsk : s.index = k := hnz.2.1 _ _ u hu1 hu2
      subst hsk
      show _ = evalAt Z p (idx s.index)
      simp only [evalAt, ofIndex_idx Z hnz, okVal_eq_some.mpr hiv, Option.map_some,
        Option.getD_some, hval]

open scoped ENNReal in
/-- The hypotheses of `contracts`, together. -/
structure Assumptions (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop where
  clone : CloneIsId
  polyClone : PolyCloneIsId
  polyEq : PolyEqRefl
  recovery : RecoveryComplete
  interpolation : ∀ j, InterpolationComplete (C.recv j)
  binding : CommitmentBinding
  nonZero : NonZeroModel Z
  shareIds : ∀ j : Party C.ns, ∃ ids, shareIdsOf C.ns j.val = ok (core.result.Result.Ok ids)
  weightsFit : ∀ A : Finset (Party C.ns), (setup C).weightOf A ≤ U16.max
  processReturns : ∀ (j : Party C.ns) m, ∃ y,
    threshold_schnorr.avss.Receiver.process_message C.rngInst (C.recv j.val) m (C.rng j.val) =
      ok y
  createValid : CreateValid C Z D
  createSecret : CreateSecret C Z D
  outputCommitment : OutputCommitment C Z D

variable {C : Receivers} {Z : Scalars} {D : Dealers Z}

theorem Assumptions.contracts (h : Assumptions C Z D) :
    Protocol.Avss.Contracts (setup C) (api C Z D) :=
  AvssProofs.Link.contracts C Z D h.clone h.polyClone h.polyEq h.recovery
    h.interpolation h.binding h.nonZero h.shareIds h.weightsFit h.processReturns h.createValid h.createSecret
    h.outputCommitment

/-! The protocol theorems that follow from `Contracts`, for the generated code. -/

open Protocol.Avss in
/-- **Liveness of AVSS.** For a certified message, every honest party eventually holds an output
whose shares pass `SharesForNode::verify(m, share_ids_of(i), i)`. -/
theorem every_honest_party_gets_valid_shares (h : Assumptions C Z D)
    (hS : (setup C).Valid) {corrupt : Finset (Party C.ns)} (hcorrupt : (setup C).Tolerates corrupt)
    {m : threshold_schnorr.avss.Message} {signers : Finset (Party C.ns)}
    (hcert : Certificate (setup C) (api C Z D) corrupt m signers)
    {σ : ℕ → State (api C Z D)}
    (hrun : Run (api C Z D) m corrupt signers σ) (i : Party C.ns) (hi : i ∉ corrupt) :
    ∃ n o, (σ n).output i = some o ∧ (api C Z D).ValidOutput m i o :=
  Protocol.Avss.every_honest_party_gets_valid_shares hS h.contracts hcorrupt hcert hrun i hi

open Protocol.Avss in
/-- **Agreement.** All outputs honest parties hold for a certified message fit one polynomial of
degree `< t`, in their shares and their Feldman commitments. -/
theorem honest_outputs_agree (h : Assumptions C Z D) (hS : (setup C).Valid)
    {corrupt : Finset (Party C.ns)} (hcorrupt : (setup C).Tolerates corrupt)
    {m : threshold_schnorr.avss.Message} {signers : Finset (Party C.ns)}
    (hcert : Certificate (setup C) (api C Z D) corrupt m signers)
    {σ : ℕ → State (api C Z D)}
    (hrun : BasicRun (api C Z D) m corrupt σ) (i₀ : Party C.ns) :
    ∃ p, (api C Z D).Sh.degreeBound p < (setup C).t ∧
      ∀ i n o, i ∉ corrupt → (σ n).output i = some o →
        (api C Z D).shareList ((api C Z D).shares o) =
          ((api C Z D).shareIds i).map ((api C Z D).Sh.eval p) ∧
        ∀ k, (api C Z D).committed o k = ((api C Z D).Sh.eval p k).value :=
  Protocol.Avss.honest_outputs_agree hS h.contracts hcorrupt hcert hrun i₀

open Protocol.Avss in
/-- **Honest dealer: no complaints.** If every receiver finds `m` valid, every honest party
eventually holds an output from `process_message` whose shares verify, and never complains. -/
theorem honest_dealer_no_complaints (h : Assumptions C Z D)
    {m : threshold_schnorr.avss.Message} (hm : (api C Z D).AllValid m)
    {corrupt : Finset (Party C.ns)} {σ : ℕ → State (api C Z D)}
    (hrun : BasicRun (api C Z D) m corrupt σ) (i : Party C.ns)
    (hi : i ∉ corrupt) :
    (∃ n o, (σ n).output i = some o ∧ (api C Z D).ValidOutput m i o) ∧
      ∀ n c, (σ n).processed i ≠ some (.complaint c) :=
  Protocol.Avss.honest_dealer_no_complaints h.contracts hm hrun i hi

end AvssProofs.Link
