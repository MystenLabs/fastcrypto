-- THIS FILE IS AI-ONLY
/-
AVSS agreement: all honest receivers' shares fit one polynomial of degree below `t`, so any `t` of
them recover the same secret.
-/
import avss.Protocol.Execution

namespace Protocol.Avss

variable {Party : Type} [Fintype Party] [DecidableEq Party]
  {S : Setup Party} {A : Api Party}

/-- `process_message` does not return `Err` for any party on the certified message `m`. -/
lemma certified_not_invalid (hS : S.Valid) (hA : Contracts S A) {corrupt : Finset Party}
    (hcorrupt : S.Tolerates corrupt) {m : A.Message} {signers : Finset Party}
    (hcert : Certificate S A corrupt m signers) (i : Party) :
    A.processMessage i m ≠ .invalid := by
  have hH : S.t ≤ S.weightOf (signers.filter (· ∉ corrupt)) :=
    S.honest_signers_weight signers corrupt hcert.weight hcorrupt
  obtain ⟨j, hj⟩ : (signers.filter (· ∉ corrupt)).Nonempty := by
    rw [Finset.nonempty_iff_ne_empty]
    intro hempty
    rw [hempty] at hH
    simp [Setup.weightOf] at hH
    have := hS.f_lt_t
    omega
  obtain ⟨hjs, hjc⟩ := Finset.mem_filter.mp hj
  obtain ⟨o, ho⟩ := hcert.honest_signed_valid j hjs hjc
  intro hinv
  rw [(hA.process_invalid_iff i j m).mp hinv] at ho
  cases ho

/-- **Agreement.** There is a polynomial `p` with `degree_bound() < t` such that every output `o`
an honest party `i` holds, at any time, has shares `[p.eval(k) for k in share_ids_of(i)]` and
`o.feldman_commitment.eval(k) = G::generator() * p.eval(k)` for all `k`, whether `o` came from
`process_message` or from `recover`. (`i₀` is any party.) -/
theorem honest_outputs_agree (hS : S.Valid) (hA : Contracts S A) {corrupt : Finset Party}
    (hcorrupt : S.Tolerates corrupt) {m : A.Message} {signers : Finset Party}
    (hcert : Certificate S A corrupt m signers) {σ : ℕ → State A}
    (hrun : BasicRun A m corrupt σ) (i₀ : Party) :
    ∃ p, A.Sh.degreeBound p < S.t ∧ ∀ i n o, i ∉ corrupt → (σ n).output i = some o →
      A.shareList (A.shares o) = (A.shareIds i).map (A.Sh.eval p) ∧
        ∀ k, A.committed o k = (A.Sh.eval p k).value := by
  have hnot := certified_not_invalid hS hA hcorrupt hcert
  obtain ⟨p, hdeg, hbind⟩ := hA.feldman_binding i₀ m (hnot i₀)
  exact ⟨p, hdeg, fun i n o hi ho => ⟨hbind i _ (output_valid hA (hrun.honest n) hi ho),
    hA.output_commitment i m o (hnot i) (output_source (hrun.honest n) hi ho) p hdeg hbind⟩⟩

/-- **An honest dealer's secret is shared.** If `m` was returned by `d.create_message()`, there is
a polynomial `p` with `degree_bound() < t` and `p.c0() = d.secret` such that every output `o` an
honest party `i` holds, at any time, has shares `[p.eval(k) for k in share_ids_of(i)]`. (`i₀` is
any party.) -/
theorem honest_dealer_secret_shared (hS : S.Valid) (hA : Contracts S A) {corrupt : Finset Party}
    (hcorrupt : S.Tolerates corrupt) {d : A.Dealer} {m : A.Message}
    (hm : m ∈ (A.createMessage d).support) {signers : Finset Party}
    (hcert : Certificate S A corrupt m signers) {σ : ℕ → State A}
    (hrun : BasicRun A m corrupt σ) (i₀ : Party) :
    ∃ p, A.Sh.degreeBound p < S.t ∧ A.Sh.c0 p = A.secret d ∧
      ∀ i n o, i ∉ corrupt → (σ n).output i = some o →
        A.shareList (A.shares o) = (A.shareIds i).map (A.Sh.eval p) := by
  obtain ⟨p, hdeg, hbind⟩ :=
    hA.feldman_binding i₀ m (certified_not_invalid hS hA hcorrupt hcert i₀)
  exact ⟨p, hdeg, hA.create_secret d m hm p hdeg hbind, fun i n o hi ho =>
    hbind i _ (output_valid hA (hrun.honest n) hi ho)⟩

/-- **Same secret.** There is a polynomial `p` such that `recover_c0(t, es) = Ok(p.c0())` for every
list `es` of exactly `t` shares at distinct indices, each taken from an output some honest party
holds at some time. -/
theorem honest_shares_recover_same_secret (hS : S.Valid) (hA : Contracts S A)
    (hSh : Shamir.Contracts A.Sh) {corrupt : Finset Party}
    (hcorrupt : S.Tolerates corrupt) {m : A.Message} {signers : Finset Party}
    (hcert : Certificate S A corrupt m signers) {σ : ℕ → State A}
    (hrun : BasicRun A m corrupt σ) (i₀ : Party) :
    ∃ p, ∀ es : List (Shamir.Eval A.F),
      (∀ e ∈ es, ∃ i n o, i ∉ corrupt ∧ (σ n).output i = some o ∧
        e ∈ A.shareList (A.shares o)) →
      (es.map (·.index)).Nodup → es.length = S.t →
      A.Sh.recoverC0 S.t es = .ok (A.Sh.c0 p) := by
  obtain ⟨p, hdeg, hagree⟩ := honest_outputs_agree hS hA hcorrupt hcert hrun i₀
  refine ⟨p, fun es hes hnodup hlen => ?_⟩
  -- Every honest share is `p` evaluated at its own index.
  have heval : es = (es.map (·.index)).map (A.Sh.eval p) := by
    rw [List.map_map]
    conv_lhs => rw [← List.map_id es]
    refine List.map_congr_left fun e he => ?_
    obtain ⟨i, n, o, hi, ho, hmem⟩ := hes e he
    rw [(hagree i n o hi ho).1, List.mem_map] at hmem
    obtain ⟨k, _, rfl⟩ := hmem
    simp only [id, Function.comp_apply, hSh.eval_index]
  rw [heval]
  exact hSh.recover_c0 S.t p _ hdeg hnodup (by rw [List.length_map, hlen])

end Protocol.Avss
