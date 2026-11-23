-- THIS FILE IS AI-ONLY
/-
Liveness of DKG over the total-order broadcast (TOB): every honest party is eventually done,
holds an output of the instance of each dealer it accepted, and gets `Ok` from `complete_dkg` on
those outputs.
-/
import avss.Protocol.Tob

namespace Protocol.Avss

variable {Party : Type} [Fintype Party] [DecidableEq Party] {A : Api Party}

/-- The honest parties' views of the TOB over time, and the AVSS instances of the dealers they
accept. `view n i` is what party `i` has read from the TOB at time `n`, and `σ d` is the execution
of dealer `d`'s instance. -/
structure TobLive (S : Setup Party) (A : Api Party) (corrupt : Finset Party)
    (valid : Cert A → Bool) (view : ℕ → Party → List (Cert A)) (σ : Party → ℕ → State A) :
    Prop where
  /-- At every time, the views are as in `Tob`. -/
  tob : ∀ n, Tob S A corrupt valid (view n)
  /-- An honest party's view only grows. Network assumption. -/
  grows : ∀ n i, i ∉ corrupt → view n i <+: view (n + 1) i
  /-- For every honest dealer `d`, a valid certificate of `d` eventually appears in every honest
  party's view. Caller obligation (`d` gets a certificate and posts it, which needs honest signers
  of weight at least `t + f`; see `corrupt_can_block_certificate`) and network assumption (the TOB
  delivers it). -/
  honest_dealer_posts : ∀ d, d ∉ corrupt → ∃ c : Cert A, c.dealer = d ∧ valid c = true ∧
    ∀ i, i ∉ corrupt → ∃ n, c ∈ view n i
  /-- The instance of each dealer an honest party has accepted runs on the accepted message,
  including the complaint path in which the certificate's signers answer complaints. Caller
  obligation. -/
  runs : ∀ n i, i ∉ corrupt → ∀ c ∈ accepted S valid (view n i),
    Run A c.msg corrupt c.signers (σ c.dealer)

section Lemmas

variable {S : Setup Party} {corrupt : Finset Party} {valid : Cert A → Bool}

omit [Fintype Party] in
/-- A valid certificate in the input gets its dealer accepted, unless the accepted dealers already
have weight at least `t`. -/
lemma foldl_accepts (l acc : List (Cert A)) {c : Cert A} (hc : c ∈ l) (hv : valid c = true) :
    S.t ≤ S.weightOf ((l.foldl (acceptStep S valid) acc).map Cert.dealer).toFinset ∨
      c.dealer ∈ (l.foldl (acceptStep S valid) acc).map Cert.dealer := by
  induction l generalizing acc with
  | nil => cases hc
  | cons c' l ih =>
    rw [List.foldl_cons]
    rcases List.mem_cons.mp hc with rfl | hc
    · by_cases hdone : S.t ≤ S.weightOf (acc.map Cert.dealer).toFinset
      · left
        have hstep : acceptStep S valid acc c = acc := by simp [acceptStep, hdone]
        rw [hstep, foldl_done l acc hdone]
        exact hdone
      · right
        have hmem : c.dealer ∈ (acceptStep S valid acc c).map Cert.dealer := by
          by_cases hin : c.dealer ∈ acc.map Cert.dealer
          · have hstep : acceptStep S valid acc c = acc := by simp [acceptStep, hdone, hin]
            rw [hstep]
            exact hin
          · have hstep : acceptStep S valid acc c = acc ++ [c] := by
              simp [acceptStep, hdone, hin, hv]
            rw [hstep]
            simp
        exact ((foldl_extends l _).map Cert.dealer).subset hmem
    · exact ih _ hc

omit [Fintype Party] in
/-- A party whose view holds valid certificates of dealers `T` of weight at least `t` is done. -/
lemma done_of_valid_dealers {v : List (Cert A)} {T : Finset Party} (hT : S.t ≤ S.weightOf T)
    (h : ∀ d ∈ T, ∃ c ∈ v, c.dealer = d ∧ valid c = true) : Done S valid v := by
  by_contra hnd
  apply hnd
  refine le_trans hT (S.weightOf_mono fun d hd => ?_)
  obtain ⟨c, hc, rfl, hv⟩ := h d hd
  rcases foldl_accepts (S := S) v [] hc hv with h' | h'
  · exact absurd h' hnd
  · exact List.mem_toFinset.mpr h'

omit [Fintype Party] in
lemma TobLive.view_mono {view : ℕ → Party → List (Cert A)} {σ : Party → ℕ → State A}
    (h : TobLive S A corrupt valid view σ) {i : Party} (hi : i ∉ corrupt) {n n' : ℕ}
    (hle : n ≤ n') : view n i <+: view n' i := by
  induction n', hle using Nat.le_induction with
  | base => exact List.prefix_refl _
  | succ k _ ih => exact ih.trans (h.grows k i hi)

/-- Every honest party is eventually done. -/
lemma TobLive.eventually_done {view : ℕ → Party → List (Cert A)} {σ : Party → ℕ → State A}
    (hS : S.Valid) (hcorrupt : S.Tolerates corrupt) (h : TobLive S A corrupt valid view σ)
    {i : Party} (hi : i ∉ corrupt) : ∃ n, Done S valid (view n i) := by
  -- The honest dealers have weight at least `t`.
  have hT : S.t ≤ S.weightOf corruptᶜ := by
    have := S.weightOf_add_compl corrupt
    have := hS.t_add_f_le_W
    unfold Setup.Tolerates at hcorrupt
    omega
  have hall : ∀ d ∈ corruptᶜ, ∃ n, ∃ c ∈ view n i, c.dealer = d ∧ valid c = true := by
    intro d hd
    obtain ⟨c, hcd, hv, hdel⟩ := h.honest_dealer_posts d (Finset.mem_compl.mp hd)
    obtain ⟨n, hn⟩ := hdel i hi
    exact ⟨n, c, hn, hcd, hv⟩
  obtain ⟨N, hN⟩ := eventually_all corruptᶜ
    (fun d n => ∃ c ∈ view n i, c.dealer = d ∧ valid c = true)
    (fun _ _ _ hle ⟨c, hc, hcd, hv⟩ => ⟨c, (h.view_mono hi hle).subset hc, hcd, hv⟩) hall
  exact ⟨N, done_of_valid_dealers hT hN⟩

end Lemmas

variable {S : Setup Party} {corrupt : Finset Party} {valid : Cert A → Bool}
  {view : ℕ → Party → List (Cert A)} {σ : Party → ℕ → State A}

/-- **DKG liveness.** Every honest party `i` is eventually done, holds an output `out i d` of the
instance of each dealer `d` it has accepted, and `complete_dkg` returns `Ok` on these outputs. -/
theorem every_honest_party_completes_dkg (hS : S.Valid) (hA : Contracts S A)
    (hSh : Shamir.Contracts A.Sh) {D : DkgApi Party A} (hD : DkgContracts S A D)
    (hcorrupt : S.Tolerates corrupt) (h : TobLive S A corrupt valid view σ) (i : Party)
    (hi : i ∉ corrupt) :
    ∃ n, ∃ out : Party → Party → A.Output, Done S valid (view n i) ∧
      (∀ c ∈ accepted S valid (view n i), ∃ n', (σ c.dealer n').output i = some (out i c.dealer)) ∧
      ∃ dk, D.completeDkg (dkgInput ((accepted S valid (view n i)).map Cert.dealer) out i) =
        some dk := by
  obtain ⟨n, hd⟩ := h.eventually_done hS hcorrupt hi
  have hne : (accepted S valid (view n i)).map Cert.dealer ≠ [] := by
    intro hnil
    have h0 := hd
    rw [Done, hnil] at h0
    simp [Setup.weightOf] at h0
    have := hS.f_lt_t
    omega
  -- The certificates `i` accepted, one per dealer.
  obtain ⟨d₀, hd₀⟩ := List.exists_mem_of_ne_nil _ hne
  obtain ⟨c₀, -, -⟩ := List.mem_map.mp hd₀
  haveI : Nonempty (Cert A) := ⟨c₀⟩
  have hex : ∀ d ∈ (accepted S valid (view n i)).map Cert.dealer,
      ∃ c ∈ accepted S valid (view n i), c.dealer = d := fun d hd => List.mem_map.mp hd
  choose! cf hcfL hcfd using hex
  have hcert : ∀ d ∈ (accepted S valid (view n i)).map Cert.dealer,
      Certificate S A corrupt (cf d).msg (cf d).signers :=
    fun d hd => (h.tob n).valid_cert _ ((accepted_inv _).2 _ (hcfL d hd))
  have hrun : ∀ d ∈ (accepted S valid (view n i)).map Cert.dealer,
      Run A (cf d).msg corrupt (cf d).signers (σ d) := fun d hd => by
    have := h.runs n i hi _ (hcfL d hd)
    rwa [hcfd d hd] at this
  -- Every honest party eventually gets an output from each accepted dealer's instance.
  have hget : ∀ j, j ∉ corrupt → ∀ d ∈ (accepted S valid (view n i)).map Cert.dealer,
      ∃ o, ∃ n', (σ d n').output j = some o := by
    intro j hj d hd
    obtain ⟨n', o, ho, -⟩ :=
      every_honest_party_gets_valid_shares hS hA hcorrupt (hcert d hd) (hrun d hd) j hj
    exact ⟨o, n', ho⟩
  obtain ⟨o₀, -⟩ := hget i hi d₀ hd₀
  haveI : Nonempty A.Output := ⟨o₀⟩
  choose! out hout using hget
  obtain ⟨dk, hdk⟩ := dkg_completes hS hA hSh hD hcorrupt hcert
    (fun d hd => (hrun d hd).toBasicRun) hout hne (accepted_inv _).1 hd i hi
  exact ⟨n, out, hd, fun c hc => hout i hi c.dealer (List.mem_map_of_mem hc), dk, hdk⟩

end Protocol.Avss
