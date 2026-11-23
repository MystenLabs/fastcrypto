-- THIS FILE IS AI-ONLY
/-
Total-order broadcast (TOB) for DKG: every party reads dealer certificates from one log and
accepts, in log order, the first valid certificate of each dealer until the accepted dealers have
weight at least `t`. From this, honest parties accept the same message per dealer and end up with
the same dealers, which `Dkg.lean` takes as given.
-/
import avss.Protocol.Dkg

namespace Protocol.Avss

variable {Party : Type} [DecidableEq Party] {A : Api Party}

/-- A dealer certificate on the TOB. It holds the dealer's message itself; in Rust it holds the
message's hash, so this assumes that the hash is collision resistant. -/
structure Cert (A : Api Party) where
  dealer : Party
  msg : A.Message
  signers : Finset Party

section Accept

variable (S : Setup Party) (valid : Cert A → Bool)

/-- One step of the caller's rule: stop once the accepted dealers have weight at least `t`;
otherwise accept `c` if it is valid and its dealer has not been accepted yet. -/
def acceptStep (acc : List (Cert A)) (c : Cert A) : List (Cert A) :=
  if S.t ≤ S.weightOf (acc.map Cert.dealer).toFinset then acc
  else if valid c ∧ c.dealer ∉ acc.map Cert.dealer then acc ++ [c] else acc

/-- The certificates a party accepts after reading `view`, in log order. `valid` is the caller's
check of a certificate. Caller obligation: an honest party processes the message of each accepted
certificate and passes the accepted dealers to `complete_dkg`. -/
def accepted (view : List (Cert A)) : List (Cert A) := view.foldl (acceptStep S valid) []

/-- The accepted dealers have weight at least `t`, so the party calls `complete_dkg`. -/
def Done (view : List (Cert A)) : Prop :=
  S.t ≤ S.weightOf ((accepted S valid view).map Cert.dealer).toFinset

end Accept

/-- How the honest parties read the TOB. `view i` is what party `i` has read from it. -/
structure Tob (S : Setup Party) (A : Api Party) (corrupt : Finset Party) (valid : Cert A → Bool)
    (view : Party → List (Cert A)) : Prop where
  /-- The honest parties read prefixes of one log. Network assumption. -/
  same_log : ∃ log, ∀ i, i ∉ corrupt → view i <+: log
  /-- A valid certificate is a `Certificate` for its message and signers. Caller obligation (the
  check covers the signers' weight and signatures), and signatures cannot be forged. -/
  valid_cert : ∀ c, valid c = true → Certificate S A corrupt c.msg c.signers

/-- A `Tob` together with the AVSS instances of the accepted dealers. `σ d` is the execution of
dealer `d`'s instance. -/
structure TobRun (S : Setup Party) (A : Api Party) (corrupt : Finset Party) (valid : Cert A → Bool)
    (view : Party → List (Cert A)) (σ : Party → ℕ → State A) (out : Party → Party → A.Output) :
    Prop extends Tob S A corrupt valid view where
  /-- The instance of each dealer an honest party accepted runs on the accepted message.
  Caller obligation. -/
  runs : ∀ i, i ∉ corrupt → ∀ c ∈ accepted S valid (view i),
    BasicRun A c.msg corrupt (σ c.dealer)
  /-- An honest party accepts a dealer only once it holds the output `out i d` of its instance.
  Caller obligation. -/
  holds_output : ∀ i, i ∉ corrupt → ∀ c ∈ accepted S valid (view i),
    ∃ n, (σ c.dealer n).output i = some (out i c.dealer)

section Lemmas

variable {S : Setup Party} {valid : Cert A → Bool}

lemma acceptStep_cases (acc : List (Cert A)) (c : Cert A) :
    acceptStep S valid acc c = acc ∨
      (valid c = true ∧ c.dealer ∉ acc.map Cert.dealer ∧ acceptStep S valid acc c = acc ++ [c]) := by
  unfold acceptStep
  split_ifs with h₁ h₂
  · exact .inl rfl
  · exact .inr ⟨h₂.1, h₂.2, rfl⟩
  · exact .inl rfl

lemma foldl_extends (l acc : List (Cert A)) : acc <+: l.foldl (acceptStep S valid) acc := by
  induction l generalizing acc with
  | nil => exact List.prefix_refl acc
  | cons c l ih =>
    refine List.IsPrefix.trans ?_ (ih _)
    rcases acceptStep_cases (S := S) (valid := valid) acc c with h | ⟨_, _, h⟩
    · rw [h]
    · rw [h]; exact List.prefix_append acc [c]

lemma foldl_done (l acc : List (Cert A))
    (h : S.t ≤ S.weightOf (acc.map Cert.dealer).toFinset) :
    l.foldl (acceptStep S valid) acc = acc := by
  induction l with
  | nil => rfl
  | cons c l ih => simp only [List.foldl_cons, acceptStep, if_pos h, ih]

/-- Accepted dealers are distinct and accepted certificates are valid. -/
lemma foldl_inv (l acc : List (Cert A)) (hnodup : (acc.map Cert.dealer).Nodup)
    (hvalid : ∀ c ∈ acc, valid c = true) :
    ((l.foldl (acceptStep S valid) acc).map Cert.dealer).Nodup ∧
      ∀ c ∈ l.foldl (acceptStep S valid) acc, valid c = true := by
  induction l generalizing acc with
  | nil => exact ⟨hnodup, hvalid⟩
  | cons c l ih =>
    apply ih
    · rcases acceptStep_cases (S := S) (valid := valid) acc c with h | ⟨_, hc, h⟩
      · rwa [h]
      · rw [h, List.map_append, List.map_singleton, List.nodup_append_comm, List.singleton_append]
        exact List.nodup_cons.mpr ⟨hc, hnodup⟩
    · rcases acceptStep_cases (S := S) (valid := valid) acc c with h | ⟨hv, _, h⟩
      · rwa [h]
      · rw [h]
        intro c' hc'
        rcases List.mem_append.mp hc' with hc' | hc'
        · exact hvalid c' hc'
        · rw [List.mem_singleton.mp hc']; exact hv

lemma accepted_inv (view : List (Cert A)) :
    ((accepted S valid view).map Cert.dealer).Nodup ∧ ∀ c ∈ accepted S valid view, valid c = true :=
  foldl_inv view [] List.nodup_nil (by simp)

lemma accepted_prefix {v w : List (Cert A)} (h : v <+: w) :
    accepted S valid v <+: accepted S valid w := by
  obtain ⟨r, rfl⟩ := h
  unfold accepted
  rw [List.foldl_append]
  exact foldl_extends r _

lemma accepted_eq_of_done {v w : List (Cert A)} (h : v <+: w) (hd : Done S valid v) :
    accepted S valid w = accepted S valid v := by
  obtain ⟨r, rfl⟩ := h
  unfold accepted
  rw [List.foldl_append]
  exact foldl_done r _ hd

omit [DecidableEq Party] in
/-- Two honest parties' views: one is a prefix of the other. -/
lemma Tob.views_comparable {corrupt : Finset Party} {view : Party → List (Cert A)}
    (h : Tob S A corrupt valid view) {i j : Party} (hi : i ∉ corrupt) (hj : j ∉ corrupt) :
    view i <+: view j ∨ view j <+: view i := by
  obtain ⟨log, hlog⟩ := h.same_log
  exact List.prefix_or_prefix_of_prefix (hlog i hi) (hlog j hj)

end Lemmas

variable {S : Setup Party} {corrupt : Finset Party} {valid : Cert A → Bool}
  {view : Party → List (Cert A)}

/-- **Same certificate per dealer.** If honest parties `i` and `j` have accepted certificates `c` and
`c'` of the same dealer, then `c = c'`. -/
theorem accepted_same_cert (h : Tob S A corrupt valid view) {i j : Party} (hi : i ∉ corrupt)
    (hj : j ∉ corrupt) {c c' : Cert A} (hc : c ∈ accepted S valid (view i))
    (hc' : c' ∈ accepted S valid (view j)) (hd : c.dealer = c'.dealer) : c = c' := by
  rcases h.views_comparable hi hj with hp | hp
  · exact List.inj_on_of_nodup_map (accepted_inv _).1 ((accepted_prefix hp).subset hc) hc' hd
  · exact List.inj_on_of_nodup_map (accepted_inv _).1 hc ((accepted_prefix hp).subset hc') hd

/-- **Same dealers.** Honest parties that are done have accepted the same certificates. -/
theorem done_accepted_eq (h : Tob S A corrupt valid view) {i j : Party} (hi : i ∉ corrupt)
    (hj : j ∉ corrupt) (hdi : Done S valid (view i)) (hdj : Done S valid (view j)) :
    accepted S valid (view i) = accepted S valid (view j) := by
  rcases h.views_comparable hi hj with hp | hp
  · exact (accepted_eq_of_done hp hdi).symm
  · exact accepted_eq_of_done hp hdj

/-- **Honest dealer inclusion.** A party that is done has accepted a certificate whose dealer is not
in `corrupt`. -/
theorem done_has_honest_dealer [Fintype Party] (hS : S.Valid)
    (hcorrupt : S.Tolerates corrupt) {v : List (Cert A)} (hd : Done S valid v) :
    ∃ c ∈ accepted S valid v, c.dealer ∉ corrupt := by
  by_contra h
  push Not at h
  have hsub : ((accepted S valid v).map Cert.dealer).toFinset ⊆ corrupt := by
    intro d hdm
    obtain ⟨c, hc, rfl⟩ := List.mem_map.mp (List.mem_toFinset.mp hdm)
    exact h c hc
  have hle := S.weightOf_mono hsub
  have hft := hS.f_lt_t
  unfold Done at hd
  unfold Setup.Tolerates at hcorrupt
  omega

/-- **DKG over the TOB: same secret.** There is a secret `s` such that `recover_c0(t, es) = Ok(s)`
for every list `es` of exactly `t` shares at distinct indices, each taken from the `DkOutput` that
`complete_dkg` returned to an honest party `i` that is done, on the outputs `i` holds from its
accepted dealers. -/
theorem dkg_recover_same_secret_of_tob [Fintype Party] (hS : S.Valid) (hA : Contracts S A)
    (hSh : Shamir.Contracts A.Sh) {D : DkgApi Party A} (hD : DkgContracts S A D)
    (hcorrupt : S.Tolerates corrupt) {σ : Party → ℕ → State A} {out : Party → Party → A.Output}
    (h : TobRun S A corrupt valid view σ out) :
    ∃ s, ∀ es : List (Shamir.Eval A.F),
      (∀ e ∈ es, ∃ i dk, i ∉ corrupt ∧ Done S valid (view i) ∧
        D.completeDkg (dkgInput ((accepted S valid (view i)).map Cert.dealer) out i) = some dk ∧
        e ∈ A.shareList (D.shares dk)) →
      (es.map (·.index)).Nodup → es.length = S.t → A.Sh.recoverC0 S.t es = .ok s := by
  have ht : 0 < S.t := by have := hS.f_lt_t; omega
  by_cases hdone : ∃ i₀, i₀ ∉ corrupt ∧ Done S valid (view i₀)
  swap
  · -- No honest party is done, so there are no such shares.
    refine ⟨0, fun es hes _ hlen => ?_⟩
    obtain ⟨e, he⟩ := List.exists_mem_of_length_pos (hlen ▸ ht)
    obtain ⟨i, _, hi, hdi, _⟩ := hes e he
    exact absurd ⟨i, hi, hdi⟩ hdone
  obtain ⟨i₀, hi₀, hd₀⟩ := hdone
  -- The certificates `i₀` accepted, one per dealer.
  have hne : (accepted S valid (view i₀)).map Cert.dealer ≠ [] := by
    intro hnil
    have := hd₀
    rw [Done, hnil] at this
    simp [Setup.weightOf] at this
    omega
  obtain ⟨d₀, hd₀'⟩ := List.exists_mem_of_ne_nil _ hne
  obtain ⟨c₀, -, -⟩ := List.mem_map.mp hd₀'
  haveI : Nonempty (Cert A) := ⟨c₀⟩
  have hex : ∀ d ∈ (accepted S valid (view i₀)).map Cert.dealer,
      ∃ c ∈ accepted S valid (view i₀), c.dealer = d := fun d hd => List.mem_map.mp hd
  choose! cf hcfL hcfd using hex
  have hcert : ∀ d ∈ (accepted S valid (view i₀)).map Cert.dealer,
      Certificate S A corrupt (cf d).msg (cf d).signers :=
    fun d hd => h.valid_cert _ ((accepted_inv _).2 _ (hcfL d hd))
  have hrun : ∀ d ∈ (accepted S valid (view i₀)).map Cert.dealer,
      BasicRun A (cf d).msg corrupt (σ d) := fun d hd => by
    have := h.runs i₀ hi₀ _ (hcfL d hd)
    rwa [hcfd d hd] at this
  obtain ⟨p, hp⟩ := dealer_polys hS hA hcorrupt hne hcert hrun
  refine ⟨_, fun es hes hnodup hlen =>
    recover_joint hSh hne (fun d hd => (hp d hd).1) (fun e he => ?_) hnodup hlen⟩
  -- Every honest party that is done has accepted the same certificates as `i₀`.
  obtain ⟨i, dk, hi, hdi, hdk, hmem⟩ := hes e he
  have hL := done_accepted_eq h.toTob hi hi₀ hdi hd₀
  rw [hL] at hdk
  have hout : ∀ d ∈ (accepted S valid (view i₀)).map Cert.dealer,
      ∃ n, (σ d n).output i = some (out i d) := fun d hd => by
    have := h.holds_output i hi _ (by rw [hL]; exact hcfL d hd)
    rwa [hcfd d hd] at this
  rw [dkg_shares hSh hD (fun d hd i n o hi ho => ((hp d hd).2 i n o hi ho).1) hi hout hdk, List.mem_map] at hmem
  obtain ⟨k, _, rfl⟩ := hmem
  rfl

end Protocol.Avss
