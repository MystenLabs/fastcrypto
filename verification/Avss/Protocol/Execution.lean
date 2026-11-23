/-
One AVSS instance (fastcrypto-threshold/src/threshold_schnorr/avss.rs) for one dealer, and the liveness
theorem `every_honest_party_gets_valid_shares`.

The protocol follows the numbered steps in the docs of avss.rs: (1) the dealer's message is
broadcast, receivers process it and sign it if their shares are valid, and a certificate is posted
on the total-order broadcast (TOB); (2) a receiver with invalid shares sends its complaint once the
certificate is on the TOB; (3) the signers answer complaints; (4) the accuser
verifies the responses and recovers its shares.

The assumptions about the caller and the network are the fields of `Certificate`,
`HonestComputes`, `Grows`, `BasicRun` and `Run`.
-/
import Avss.Protocol.Steps

namespace Protocol.Avss

variable {Party : Type} [Fintype Party] [DecidableEq Party]

/-- The certificate for the dealer's message `m`, signed by `signers`, that every honest receiver
accepts.

Using a single `m` for all honest receivers assumes that they all accept the same certificate for
this dealer; `accepted_same_cert` (Tob.lean) derives this from the TOB. -/
structure Certificate (S : Setup Party) (A : Api Party) (corrupt : Finset Party)
    (m : A.Message) (signers : Finset Party) : Prop where
  /-- The signers have total weight at least `t + f`. Caller obligation. -/
  weight : S.t + S.f ≤ S.weightOf signers
  /-- Every honest signer `j` got `Valid` from `process_message` on `m`. Caller obligation (an
  honest receiver signs only on `Valid`), and signatures cannot be forged. -/
  honest_signed_valid : ∀ j ∈ signers, j ∉ corrupt → ∃ o, A.processMessage j m = .valid o

/-- What the parties hold at one point in time, about the certified message `m`. Only the honest
parties' entries are constrained (by `HonestComputes`); the corrupt parties' entries are
arbitrary. -/
structure State (A : Api Party) where
  /-- The parties that hold `m` itself (not some other message from the same dealer). -/
  hasMessage : Set Party
  /-- `processed i = some r`: party `i` has run `process_message` on `m`, with result `r`. -/
  processed : Party → Option (Processed A.Output A.Complaint)
  /-- The parties that have sent their complaint about `m` to the other parties. -/
  complained : Set Party
  /-- `(accuser, j) ∈ complaintDelivered`: party `j` has received the accuser's complaint. -/
  complaintDelivered : Set (Party × Party)
  /-- `(j, accuser, r) ∈ responded`: party `j` has sent response `r` to the accuser. -/
  responded : Set (Party × Party × A.Response)
  /-- The verified complaint responses party `i` has collected. -/
  verified : Party → List A.Verified
  /-- Party `i`'s output for this dealer, once it has one. -/
  output : Party → Option A.Output

/-- Honest parties store exactly what the fastcrypto functions return. Each field constrains only
honest parties (`i ∉ corrupt`). Caller obligations. -/
structure HonestComputes (A : Api Party) (m : A.Message) (corrupt : Finset Party)
    (s : State A) : Prop where
  /-- A stored processing result is the result of `process_message` by `i` on the certified
  message `m` (not on another message from the same dealer). -/
  processed_eq : ∀ i r, i ∉ corrupt → s.processed i = some r → r = A.processMessage i m
  /-- A `Valid(o)` result is stored as the output `o`. -/
  stores_valid : ∀ i o, i ∉ corrupt → s.processed i = some (.valid o) → s.output i = some o
  /-- Every collected response was returned by `verify_complaint_response` for `i` on `m`. -/
  verified_ok : ∀ i v, i ∉ corrupt → v ∈ s.verified i → A.IsVerified i m v
  /-- The collected responses come from distinct responders. -/
  verified_nodup : ∀ i, i ∉ corrupt → ((s.verified i).map A.responderId).Nodup
  /-- An output is either the `Valid` result of `process_message` or a result of `recover` by
  `i` on `m`. -/
  output_from : ∀ i o, i ∉ corrupt → s.output i = some o →
    s.processed i = some (.valid o) ∨ ∃ vs, A.recover i m vs = some o

/-- From one point in time to the next, parties do not forget processing results or collected
responses. Caller obligation. -/
structure Grows (A : Api Party) (s s' : State A) : Prop where
  processed : ∀ i r, s.processed i = some r → s'.processed i = some r
  verified : ∀ i v, v ∈ s.verified i → v ∈ s'.verified i

/-- An execution: `σ n` is the state at time `n ∈ ℕ`. The set `corrupt` of Byzantine parties is
fixed for the whole execution (static corruption); they and the dealer may behave arbitrarily.

This structure covers getting and processing the certified message, without the complaint path.
"Eventually P" means "`P` holds at some time `n'`". -/
structure BasicRun (A : Api Party) (m : A.Message) (corrupt : Finset Party) (σ : ℕ → State A) :
    Prop where
  /-- At every time, honest parties store what the functions return. -/
  honest : ∀ n, HonestComputes A m corrupt (σ n)
  /-- At every step, honest parties keep what they stored. -/
  grows : ∀ n, Grows A (σ n) (σ (n + 1))
  /-- Every honest party eventually holds the certified message `m`. Caller obligation. -/
  gets_message : ∀ i, i ∉ corrupt → ∃ n, i ∈ (σ n).hasMessage
  /-- An honest party that holds `m` eventually runs `process_message` on it. Caller
  obligation. -/
  processes : ∀ i n, i ∉ corrupt → i ∈ (σ n).hasMessage → ∃ n' r, (σ n').processed i = some r

/-- A `BasicRun` together with the complaint path, in which the parties `signers` of the
certificate answer complaints. -/
structure Run (A : Api Party) (m : A.Message) (corrupt : Finset Party) (signers : Finset Party)
    (σ : ℕ → State A) : Prop extends BasicRun A m corrupt σ where
  /-- An honest party whose `process_message` returned `Complaint(c)` eventually sends it.
  Caller obligation. -/
  complains : ∀ i n c, i ∉ corrupt → (σ n).processed i = some (.complaint c) →
    ∃ n', i ∈ (σ n').complained
  /-- A complaint sent by an honest party eventually reaches every honest party. Network
  assumption. -/
  complaint_delivered : ∀ i j n, i ∉ corrupt → j ∉ corrupt → i ∈ (σ n).complained →
    ∃ n', (i, j) ∈ (σ n').complaintDelivered
  /-- If honest signer `j` has received the complaint `c` of `i` (the result of `process_message`
  for `i`), `j`'s own result is `Valid(o)`, and `handle_complaint` by `j` on `(m, i, c, o)` returns
  `Ok(r)`, then `j` eventually sends `r` to `i`. Caller obligation. -/
  responds : ∀ i j n c o r, j ∉ corrupt → j ∈ signers → (i, j) ∈ (σ n).complaintDelivered →
    A.processMessage i m = .complaint c → A.processMessage j m = .valid o →
    A.handleComplaint j m i c o = some r → ∃ n', (j, i, r) ∈ (σ n').responded
  /-- If honest party `j` has sent response `r` to honest party `i`, and
  `verify_complaint_response` by `i` on `(m, j, r)` returns `Ok`, then `i` eventually has a
  collected response from `j` (this one, or an earlier one from `j`). Network assumption
  (delivery) and caller obligation (`i` verifies and collects responses). -/
  response_delivered : ∀ i j r v n, i ∉ corrupt → j ∉ corrupt → (j, i, r) ∈ (σ n).responded →
    A.verifyComplaintResponse i m j r = some v →
    ∃ n', ∃ v' ∈ (σ n').verified i, A.responderId v' = j
  /-- If honest party `i` has a complaint and `recover` by `i` on `m` and its collected responses
  returns `Ok`, then `i` eventually has an output. Caller obligation. -/
  recovers : ∀ i n c o, i ∉ corrupt → (σ n).processed i = some (.complaint c) →
    A.recover i m ((σ n).verified i) = some o → ∃ n' o', (σ n').output i = some o'

section Lemmas

variable {A : Api Party} {m : A.Message} {corrupt signers : Finset Party} {σ : ℕ → State A}

omit [Fintype Party] [DecidableEq Party] in
lemma Run.processed_mono (h : Run A m corrupt signers σ) {n n' : ℕ} (hle : n ≤ n') {i r}
    (hr : (σ n).processed i = some r) : (σ n').processed i = some r := by
  induction n', hle using Nat.le_induction with
  | base => exact hr
  | succ k _ ih => exact (h.grows k).processed i r ih

omit [Fintype Party] [DecidableEq Party] in
lemma Run.verified_mono (h : Run A m corrupt signers σ) {n n' : ℕ} (hle : n ≤ n') {i v}
    (hv : v ∈ (σ n).verified i) : v ∈ (σ n').verified i := by
  induction n', hle using Nat.le_induction with
  | base => exact hv
  | succ k _ ih => exact (h.grows k).verified i v ih

omit [Fintype Party] in
/-- If each `P j` eventually holds and stays true once true, then at some time all of them hold
together. -/
lemma eventually_all (T : Finset Party) (P : Party → ℕ → Prop)
    (mono : ∀ j n n', n ≤ n' → P j n → P j n') (h : ∀ j ∈ T, ∃ n, P j n) :
    ∃ N, ∀ j ∈ T, P j N := by
  induction T using Finset.induction_on with
  | empty => exact ⟨0, by simp⟩
  | insert a T _ ih =>
    obtain ⟨N, hN⟩ := ih (fun j hj => h j (Finset.mem_insert_of_mem hj))
    obtain ⟨na, ha⟩ := h a (Finset.mem_insert_self a T)
    refine ⟨max N na, fun j hj => ?_⟩
    rcases Finset.mem_insert.mp hj with rfl | hj
    · exact mono _ _ _ (le_max_right _ _) ha
    · exact mono _ _ _ (le_max_left _ _) (hN j hj)

omit [Fintype Party] [DecidableEq Party] in
/-- An output an honest party holds is returned by `process_message` (as `Valid`) or by `recover`
on `m`. -/
lemma output_source {s : State A} (hs : HonestComputes A m corrupt s) {i : Party}
    (hi : i ∉ corrupt) {o : A.Output} (ho : s.output i = some o) :
    A.processMessage i m = .valid o ∨ ∃ vs, A.recover i m vs = some o := by
  rcases hs.output_from i o hi ho with hp | h
  · exact Or.inl (hs.processed_eq i _ hi hp).symm
  · exact Or.inr h

omit [Fintype Party] in
/-- Any output an honest party holds is valid: its shares pass `SharesForNode::verify`. -/
lemma output_valid {S : Setup Party} (hA : Contracts S A) {s : State A}
    (hs : HonestComputes A m corrupt s) {i : Party} (hi : i ∉ corrupt) {o : A.Output}
    (ho : s.output i = some o) : A.ValidOutput m i o := by
  rcases hs.output_from i o hi ho with hp | ⟨vs, hvs⟩
  · exact hA.process_valid i m o (hs.processed_eq i _ hi hp).symm
  · exact hA.recover_sound i m vs o hvs

end Lemmas

/-- **Liveness of AVSS.** Every honest party `i` eventually holds an output whose shares pass
`SharesForNode::verify(m, share_ids_of(i), i)`: from `process_message` directly, or from `recover`
after complaining. -/
theorem every_honest_party_gets_valid_shares {S : Setup Party} {A : Api Party}
    (hS : S.Valid) (hA : Contracts S A) {corrupt : Finset Party}
    (hcorrupt : S.Tolerates corrupt) {m : A.Message} {signers : Finset Party}
    (hcert : Certificate S A corrupt m signers) {σ : ℕ → State A}
    (hrun : Run A m corrupt signers σ) (i : Party) (hi : i ∉ corrupt) :
    ∃ n o, (σ n).output i = some o ∧ A.ValidOutput m i o := by
  -- The honest signers have weight at least `t`, so there is at least one.
  set H := signers.filter (· ∉ corrupt) with hHdef
  have hH : S.t ≤ S.weightOf H := S.honest_signers_weight signers corrupt hcert.weight hcorrupt
  have hHne : H.Nonempty := by
    rw [Finset.nonempty_iff_ne_empty]
    rintro hempty
    rw [hempty] at hH
    simp [Setup.weightOf] at hH
    exact absurd hH (by have := hS.f_lt_t; omega)
  have honestOfH : ∀ j ∈ H, j ∉ corrupt ∧ ∃ o, A.processMessage j m = .valid o := by
    intro j hj
    obtain ⟨hjs, hjc⟩ := Finset.mem_filter.mp hj
    exact ⟨hjc, hcert.honest_signed_valid j hjs hjc⟩
  -- Since an honest signer got a valid output, the message is not rejected outright.
  obtain ⟨j0, hj0⟩ := hHne
  obtain ⟨_, o0, ho0⟩ := honestOfH j0 hj0
  have hnotInvalid : A.processMessage i m ≠ .invalid := by
    intro hinv
    rw [(hA.process_invalid_iff i j0 m).mp hinv] at ho0
    cases ho0
  -- Receiver `i` eventually processes the message.
  obtain ⟨n0, hn0⟩ := hrun.gets_message i hi
  obtain ⟨n1, r, hr⟩ := hrun.processes i n0 hi hn0
  have hr' := (hrun.honest n1).processed_eq i r hi hr
  cases hpm : A.processMessage i m with
  | invalid => exact absurd hpm hnotInvalid
  | valid o =>
    -- Valid shares straight from the dealer.
    rw [hpm] at hr'
    subst hr'
    have ho := (hrun.honest n1).stores_valid i o hi hr
    exact ⟨n1, o, ho, output_valid hA (hrun.honest n1) hi ho⟩
  | complaint c =>
    rw [hpm] at hr'
    subst hr'
    obtain ⟨n2, hn2⟩ := hrun.complains i n1 c hi hr
    -- Every honest signer's response eventually reaches `i` and is collected.
    have hall : ∀ j ∈ H, ∃ n, ∃ v ∈ (σ n).verified i, A.responderId v = j := by
      intro j hj
      obtain ⟨hjc, oj, hoj⟩ := honestOfH j hj
      have hjs := (Finset.mem_filter.mp hj).1
      obtain ⟨n3, hn3⟩ := hrun.complaint_delivered i j n2 hi hjc hn2
      obtain ⟨rj, hrj⟩ := hA.handle_accepts i j m c oj hpm hoj
      obtain ⟨n4, hn4⟩ := hrun.responds i j n3 c oj rj hjc hjs hn3 hpm hoj hrj
      obtain ⟨v, hv⟩ := hA.response_verifies i j m c oj rj hoj hrj
      exact hrun.response_delivered i j rj v n4 hi hjc hn4 hv
    obtain ⟨N, hN⟩ := eventually_all H
      (fun j n => ∃ v ∈ (σ n).verified i, A.responderId v = j)
      (fun j n n' hle ⟨v, hv, hvj⟩ => ⟨v, hrun.verified_mono hle hv, hvj⟩) hall
    -- At time `N'` the accuser still has its complaint and has responses from all of `H`.
    set N' := max N n1
    have hproc : (σ N').processed i = some (.complaint c) :=
      hrun.processed_mono (le_max_right _ _) hr
    set vs := (σ N').verified i
    have hcover : H ⊆ (vs.map A.responderId).toFinset := by
      intro j hj
      obtain ⟨v, hv, hvj⟩ := hN j hj
      rw [List.mem_toFinset, List.mem_map]
      exact ⟨v, hrun.verified_mono (le_max_left _ _) hv, hvj⟩
    obtain ⟨o, ho⟩ := hA.recover_complete i m vs hnotInvalid
      (fun v hv => (hrun.honest N').verified_ok i v hi hv)
      ((hrun.honest N').verified_nodup i hi)
      (le_trans hH (S.weightOf_mono hcover))
    obtain ⟨n', o', ho'⟩ := hrun.recovers i N' c o hi hproc ho
    exact ⟨n', o', ho', output_valid hA (hrun.honest n') hi ho'⟩

end Protocol.Avss
