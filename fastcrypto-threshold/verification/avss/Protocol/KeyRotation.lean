-- THIS FILE IS AI-ONLY
/-
Key rotation, as in the module docs of avss.rs: each old share `s_u` is reshared by its own AVSS
instance, whose receivers check the dealing against the public commitment to `s_u`, and every
party combines `t_old` of the outputs with `DkOutput::complete_key_rotation`. The new shares are
shares of the old secret.
-/
import avss.Protocol.Dkg

namespace Protocol.Avss

open Shamir (ShareIndex Eval)

variable {Party : Type} [DecidableEq Party]

/-- The key-rotation functions of `avss.rs` as black boxes, with the idealizations of `Api`.

`…With s` is the receiver function of a `Receiver` created with
`commitment = Some(G::generator() * s)`. Receivers know only the commitment; indexing by `s` uses
that `s ↦ G::generator() * s` is injective. -/
structure RotationApi (Party : Type) (A : Api Party) (D : DkgApi Party A) where
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::process_message`, with a
  commitment. -/
  processMessageWith : A.F → (i : Party) → A.Message → Processed A.Output A.Complaint
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::handle_complaint`, with a
  commitment. -/
  handleComplaintWith : A.F → (j : Party) → A.Message → (accuser : Party) → A.Complaint →
    A.Output → Option A.Response
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::verify_complaint_response`, with a
  commitment. -/
  verifyComplaintResponseWith : A.F → (i : Party) → A.Message → (responder : Party) →
    A.Response → Option A.Verified
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::recover`, with a commitment. -/
  recoverWith : A.F → (i : Party) → A.Message → List A.Verified → Option A.Output
  /-- `fastcrypto_threshold::threshold_schnorr::avss::DkOutput::complete_key_rotation(t, i, nodes,
  outputs)`, with `outputs` given as a list of (share index, output) pairs. `none` is an `Err`. -/
  completeKeyRotation : (t : ℕ) → (i : Party) → List (ShareIndex × A.Output) →
    Option D.DkOutput

/-- The AVSS instance that reshares `s`: receivers created with
`commitment = Some(G::generator() * s)`, and dealers whose `secret` is `s`. -/
abbrev RotationApi.at {A : Api Party} {D : DkgApi Party A} (R : RotationApi Party A D)
    (s : A.F) : Api Party :=
  { A with
    processMessage := R.processMessageWith s
    handleComplaint := R.handleComplaintWith s
    verifyComplaintResponse := R.verifyComplaintResponseWith s
    recover := R.recoverWith s
    Dealer := { d : A.Dealer // A.secret d = s }
    createMessage := fun d => A.createMessage d.1
    secret := fun d => A.secret d.1 }

/-- What we expect from the key-rotation functions, beyond `Contracts S (R.at s)` for each
instance. `Rᵢ` is party `i`'s `Receiver` with `commitment = Some(G::generator() * s)`. -/
structure RotationContracts (S : Setup Party) (A : Api Party) (D : DkgApi Party A)
    (R : RotationApi Party A D) : Prop where
  /-- `Rᵢ.process_message(m) ≠ Err` ⇒ every `p` with `p.degree_bound() < t` such that, for all
  `j` and `sh`, `sh.verify(m, share_ids_of(j), j)` is `Ok` ⇒
  `sh.shares = [p.eval(k) for k in share_ids_of(j)]`, has `p.c0() = s`. -/
  process_matches_commitment : ∀ s i m, R.processMessageWith s i m ≠ .invalid →
    ∀ p, A.Sh.degreeBound p < S.t →
      (∀ j sh, A.verifyShares m j sh = true → A.shareList sh = (A.shareIds j).map (A.Sh.eval p)) →
      A.Sh.c0 p = s
  /-- `complete_key_rotation(t, i, os) = Ok(dk)` and each `o = (u, out) ∈ os` holds the shares
  `[(k, v_o(k)) for k in share_ids_of(i)]` ⇒ `dk.my_shares = [(k, w(k)) for k in share_ids_of(i)]`
  with `recover_c0(t, [(u, v_o(k)) for o = (u, out) in os]) = Ok(w(k))`. -/
  rotation_interpolates : ∀ t i os dk (v : ShareIndex × A.Output → ShareIndex → A.F),
    R.completeKeyRotation t i os = some dk →
    (∀ o ∈ os, A.shareList (A.shares o.2) = (A.shareIds i).map fun k => ⟨k, v o k⟩) →
    ∃ w : ShareIndex → A.F,
      A.shareList (D.shares dk) = (A.shareIds i).map (fun k => ⟨k, w k⟩) ∧
      ∀ k ∈ A.shareIds i, A.Sh.recoverC0 t (os.map fun o => ⟨o.1, v o k⟩) = .ok (w k)
  /-- `complete_key_rotation(t, i, os) = Ok(dk)` and
  `dk.commitment_for_index(k) = Some(G::generator() * x)` ⇒ `G::generator() * x` is the Lagrange
  combination at 0 of the `(u, out.feldman_commitment.eval(k))` for `(u, out) ∈ os`, i.e.
  `recover_c0(t, [(u, y_u)]) = Ok(x)` where `out.feldman_commitment.eval(k) = G::generator() * y_u`. -/
  rotation_commitments : ∀ t i os dk k x, R.completeKeyRotation t i os = some dk →
    D.commitmentForIndex dk k = some x →
    A.Sh.recoverC0 t (os.map fun o => ⟨o.1, A.committed o.2 k⟩) = .ok x

section Lemmas

lemma zipWith_congr_left {α β γ : Type} {f g : α → β → γ} :
    ∀ (l : List α) (l' : List β), (∀ a ∈ l, ∀ b, f a b = g a b) →
      List.zipWith f l l' = List.zipWith g l l'
  | [], _, _ => rfl
  | _ :: _, [], _ => rfl
  | a :: l, b :: l', h => by
    rw [List.zipWith_cons_cons, List.zipWith_cons_cons, h a (List.mem_cons_self ..) b,
      zipWith_congr_left l l' fun a' ha' => h a' (List.mem_cons_of_mem _ ha')]

lemma zipWith_mk_map {F : Type} (g : ShareIndex → F) :
    ∀ l : List ShareIndex, List.zipWith Eval.mk l (l.map g) = l.map fun u => ⟨u, g u⟩
  | [] => rfl
  | u :: l => by rw [List.map_cons, List.zipWith_cons_cons, zipWith_mk_map g l, List.map_cons]

variable {F : Type} [Field F] {Sh : Shamir.Api F}

lemma map_eval_eq_mk (hSh : Shamir.Contracts Sh) (q : Sh.Poly) (l : List ShareIndex) :
    l.map (Sh.eval q) = l.map fun k => ⟨k, (Sh.eval q k).value⟩ :=
  List.map_congr_left fun k _ => by ext <;> simp [hSh.eval_index]

/-- A linear combination `Σⱼ qⱼ·cⱼ` of polynomials with `degree_bound() < t`, built with `mul` and
`add`, has `degree_bound() < t` and its constant term and evaluations are the same combinations. -/
lemma exists_lincomb (hSh : Shamir.Contracts Sh) {t : ℕ} :
    ∀ (qs : List Sh.Poly) (cs : List F), qs ≠ [] → (∀ q ∈ qs, Sh.degreeBound q < t) →
      ∃ Q, Sh.degreeBound Q < t ∧
        Sh.c0 Q = (List.zipWith (fun q c => Sh.c0 q * c) qs cs).sum ∧
        ∀ k, (Sh.eval Q k).value = (List.zipWith (fun q c => (Sh.eval q k).value * c) qs cs).sum
  | [], _, h, _ => absurd rfl h
  | q :: _, [], _, hdeg =>
    ⟨Sh.mul q 0, lt_of_le_of_lt (hSh.mul_degree q 0) (hdeg q (List.mem_cons_self ..)),
      by simp [hSh.mul_c0], fun k => by simp [hSh.mul_eval]⟩
  | [q], c :: _, _, hdeg =>
    ⟨Sh.mul q c, lt_of_le_of_lt (hSh.mul_degree q c) (hdeg q (List.mem_cons_self ..)),
      by simp [hSh.mul_c0], fun k => by simp [hSh.mul_eval]⟩
  | q :: q' :: qs, c :: cs, _, hdeg => by
    obtain ⟨Q, hQd, hQc, hQe⟩ := exists_lincomb hSh (q' :: qs) cs (List.cons_ne_nil _ _)
      fun r hr => hdeg r (List.mem_cons_of_mem _ hr)
    refine ⟨Sh.add (Sh.mul q c) Q, ?_, ?_, fun k => ?_⟩
    · rw [hSh.add_degree]
      exact max_lt (lt_of_le_of_lt (hSh.mul_degree q c) (hdeg q (List.mem_cons_self ..))) hQd
    · rw [hSh.add_c0, hSh.mul_c0, hQc, List.zipWith_cons_cons, List.sum_cons]
    · rw [hSh.add_eval, hSh.mul_eval, hQe, List.zipWith_cons_cons, List.sum_cons]

end Lemmas

variable [Fintype Party] {S : Setup Party} {A : Api Party} {D : DkgApi Party A}
  {R : RotationApi Party A D}

/-- Per reshared index `u`, a polynomial with `degree_bound() < t` and constant term `s u` that
every honest output of `u`'s instance fits, in its shares and its commitments. -/
lemma rotation_polys (hS : S.Valid) (hR : ∀ s, Contracts S (R.at s))
    (hRot : RotationContracts S A D R) {corrupt : Finset Party} (hcorrupt : S.Tolerates corrupt)
    {us : List ShareIndex} (hne : us ≠ []) {s : ShareIndex → A.F} {m : ShareIndex → A.Message}
    {signers : ShareIndex → Finset Party}
    (hcert : ∀ u ∈ us, Certificate S (R.at (s u)) corrupt (m u) (signers u))
    {σ : (u : ShareIndex) → ℕ → State (R.at (s u))}
    (hrun : ∀ u ∈ us, BasicRun (R.at (s u)) (m u) corrupt (σ u))
    (i₀ : Party) :
    ∃ p : ShareIndex → A.Sh.Poly, ∀ u ∈ us, A.Sh.degreeBound (p u) < S.t ∧ A.Sh.c0 (p u) = s u ∧
      ∀ i n o, i ∉ corrupt → (σ u n).output i = some o →
        A.shareList (A.shares o) = (A.shareIds i).map (A.Sh.eval (p u)) ∧
          ∀ k, A.committed o k = (A.Sh.eval (p u) k).value := by
  have h : ∀ u ∈ us, ∃ p : A.Sh.Poly, A.Sh.degreeBound p < S.t ∧ A.Sh.c0 p = s u ∧
      ∀ i n o, i ∉ corrupt → (σ u n).output i = some o →
        A.shareList (A.shares o) = (A.shareIds i).map (A.Sh.eval p) ∧
          ∀ k, A.committed o k = (A.Sh.eval p k).value := by
    intro u hu
    have hnot := certified_not_invalid hS (hR (s u)) hcorrupt (hcert u hu)
    obtain ⟨p, hdeg, hbind⟩ := (hR (s u)).feldman_binding i₀ (m u) (hnot i₀)
    exact ⟨p, hdeg, hRot.process_matches_commitment (s u) i₀ (m u) (hnot i₀) p hdeg hbind,
      fun i n o hi ho => ⟨hbind i _ (output_valid (hR (s u)) ((hrun u hu).honest n) hi ho),
        (hR (s u)).output_commitment i (m u) o (hnot i)
          (output_source ((hrun u hu).honest n) hi ho) p hdeg hbind⟩⟩
  obtain ⟨u₀, hu₀⟩ := List.exists_mem_of_ne_nil us hne
  haveI : Nonempty A.Sh.Poly := ⟨(h u₀ hu₀).choose⟩
  choose! p hp using h
  exact ⟨p, hp⟩

/-- **Key rotation keeps the secret.** Let the old shares be evaluations of a polynomial `P` with
`degree_bound() < t_old`, and let `us` be `t_old` distinct share indices. Suppose each `u ∈ us` is
reshared by an AVSS instance whose receivers use `commitment = Some(G::generator() * P.eval(u))`
(as `old.commitment_for_index(u)` is, for the output `old` of `complete_dkg` or of an earlier
rotation, by `dkg_outputs_agree` and this theorem), and that every honest party `i` holds the
output `out i u` of each of these instances (caller obligations). Then there is a polynomial `Q` with `degree_bound() < t` and `Q.c0() = P.c0()` such
that whenever `complete_key_rotation(t_old, i, [(u, out i u) for u in us])` returns `Ok(dk)` for an
honest party `i`, `dk.my_shares = [Q.eval(k) for k in share_ids_of(i)]`, and
`dk.commitment_for_index(k) = Some(c)` ⇒ `c = G::generator() * Q.eval(k)`.

All honest parties pass the same `us`: this is the caller obligation that all parties use the
outputs of the same certified instances. (`i₀` is any party.) -/
theorem key_rotation_keeps_secret (hS : S.Valid) (hR : ∀ s, Contracts S (R.at s))
    (hRot : RotationContracts S A D R) (hSh : Shamir.Contracts A.Sh) {corrupt : Finset Party}
    (hcorrupt : S.Tolerates corrupt) {told : ℕ} {P : A.Sh.Poly} (hP : A.Sh.degreeBound P < told)
    {us : List ShareIndex} (hnodup : us.Nodup) (hlen : us.length = told)
    {m : ShareIndex → A.Message} {signers : ShareIndex → Finset Party}
    (hcert : ∀ u ∈ us, Certificate S (R.at (A.Sh.eval P u).value) corrupt (m u) (signers u))
    {σ : (u : ShareIndex) → ℕ → State (R.at (A.Sh.eval P u).value)}
    (hrun : ∀ u ∈ us, BasicRun (R.at (A.Sh.eval P u).value) (m u) corrupt (σ u))
    {out : Party → ShareIndex → A.Output}
    (hout : ∀ i, i ∉ corrupt → ∀ u ∈ us, ∃ n, (σ u n).output i = some (out i u)) (i₀ : Party) :
    ∃ Q, A.Sh.degreeBound Q < S.t ∧ A.Sh.c0 Q = A.Sh.c0 P ∧
      (∀ i dk, i ∉ corrupt → R.completeKeyRotation told i (us.map fun u => (u, out i u)) = some dk →
        A.shareList (D.shares dk) = (A.shareIds i).map (A.Sh.eval Q)) ∧
      ∀ i dk k x, i ∉ corrupt →
        R.completeKeyRotation told i (us.map fun u => (u, out i u)) = some dk →
        D.commitmentForIndex dk k = some x → x = (A.Sh.eval Q k).value := by
  have hne : us ≠ [] := by
    rintro rfl
    simp at hlen
    omega
  obtain ⟨p, hp⟩ := rotation_polys (s := fun u => (A.Sh.eval P u).value) hS hR hRot hcorrupt hne
    hcert hrun i₀
  -- `recover_c0(t_old, ·)` on the indices `us` is the linear combination with `coeffs`.
  obtain ⟨coeffs, hcoeffs⟩ := hSh.recover_c0_linear told us hnodup hlen
  have hlin : ∀ g : ShareIndex → A.F,
      A.Sh.recoverC0 told (us.map fun u => ⟨u, g u⟩) =
        .ok (List.zipWith (fun u c => g u * c) us coeffs).sum := fun g => by
    rw [← zipWith_mk_map, hcoeffs _ (by rw [List.length_map, hlen]), List.zipWith_map_left]
  -- `Q = Σ_u p_u · coeffs_u`.
  obtain ⟨Q, hQd, hQc, hQe⟩ := exists_lincomb hSh (us.map p) coeffs
    (by simpa using hne) fun q hq => by
      obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hq
      exact (hp u hu).1
  rw [List.zipWith_map_left] at hQc
  refine ⟨Q, hQd, ?_, fun i dk hi hdk => ?_, fun i dk k x hi hdk hx => ?_⟩
  · -- `Q.c0() = Σ_u P.eval(u) · coeffs_u = P.c0()`.
    have hrec := hSh.recover_c0 told P us hP hnodup hlen
    rw [map_eval_eq_mk hSh, hlin] at hrec
    rw [hQc, ← Except.ok.inj hrec]
    congr 1
    exact zipWith_congr_left us coeffs fun u hu c => by rw [(hp u hu).2.1]
  · -- Each new share is `Σ_u p_u.eval(k) · coeffs_u = Q.eval(k)`.
    obtain ⟨w, hw, hwk⟩ := hRot.rotation_interpolates told i _ dk
      (fun o k => (A.Sh.eval (p o.1) k).value) hdk fun o ho => by
        obtain ⟨u, hu, rfl⟩ := List.mem_map.mp ho
        obtain ⟨n, hn⟩ := hout i hi u hu
        rw [((hp u hu).2.2 i n _ hi hn).1, map_eval_eq_mk hSh]
    rw [hw, map_eval_eq_mk hSh Q]
    refine List.map_congr_left fun k hk => ?_
    have hk' := hwk k hk
    rw [List.map_map, Function.comp_def, hlin] at hk'
    rw [hQe k, List.zipWith_map_left, ← Except.ok.inj hk']
  · -- Each new commitment is `Σ_u p_u.eval(k) · coeffs_u = Q.eval(k)`, in the exponent.
    have hl : (us.map fun u => (u, out i u)).map
        (fun o => (⟨o.1, A.committed o.2 k⟩ : Eval A.F)) =
        us.map fun u => ⟨u, (A.Sh.eval (p u) k).value⟩ := by
      rw [List.map_map]
      refine List.map_congr_left fun u hu => ?_
      obtain ⟨n, hn⟩ := hout i hi u hu
      simp only [Function.comp_apply]
      rw [((hp u hu).2.2 i n _ hi hn).2 k]
    have hx' := hRot.rotation_commitments told i _ dk k x hdk hx
    rw [hl, hlin] at hx'
    rw [hQe k, List.zipWith_map_left]
    exact (Except.ok.inj hx').symm
