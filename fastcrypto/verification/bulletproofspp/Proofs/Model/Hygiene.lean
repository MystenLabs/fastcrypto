-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Model.CircuitSoundness
import bulletproofspp.Model.RangeProof

/-!
# Fiat–Shamir hygiene

Which logs the verifier hashes. `ReadsOnly Q p t`: running `p` from `t` reads the oracle only at
logs satisfying `Q`, so any oracle that agrees with `t.oracle` there gives the same run.
-/

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

namespace BpppTranscript

/-- `t` with its oracle replaced by `o`. -/
def withOracle (t : BpppTranscript F E) (o : List (Entry F E) → F) : BpppTranscript F E :=
  { t with oracle := o }

/-- A run's result, with the oracle of its final transcript replaced by `o`. -/
def swapRes {α : Type} (o : List (Entry F E) → F) :
    Except Error (α × BpppTranscript F E) → Except Error (α × BpppTranscript F E)
  | .ok (a, t') => .ok (a, t'.withOracle o)
  | .error e => .error e

/-- Running `p` from `t` keeps the oracle, and reads it only at logs satisfying `Q`. -/
structure ReadsOnly {α : Type} (Q : List (Entry F E) → Prop) (p : TranscriptM F E α)
    (t : BpppTranscript F E) : Prop where
  keeps : ∀ a t', p.run t = .ok (a, t') → t'.oracle = t.oracle
  swap : ∀ o, (∀ q, Q q → o q = t.oracle q) → p.run (t.withOracle o) = swapRes o (p.run t)

variable {Q : List (Entry F E) → Prop}

@[simp] lemma withOracle_log (t : BpppTranscript F E) (o) : (t.withOracle o).log = t.log := rfl
@[simp] lemma withOracle_oracle (t : BpppTranscript F E) (o) : (t.withOracle o).oracle = o := rfl
@[simp] lemma extend_withOracle (t : BpppTranscript F E) (o) (es : List (Entry F E)) :
    (t.withOracle o).extend es = (t.extend es).withOracle o := rfl

lemma ReadsOnly.bind {α β : Type} {p : TranscriptM F E α} {f : α → TranscriptM F E β}
    {t : BpppTranscript F E} (hp : ReadsOnly Q p t)
    (hf : ∀ a t', p.run t = .ok (a, t') → ReadsOnly Q (f a) t') : ReadsOnly Q (p >>= f) t := by
  constructor
  · intro b t'' h
    rw [StateT.run_bind] at h
    rcases hr : p.run t with e | ⟨a, t'⟩
    · rw [hr] at h; cases h
    · rw [hr] at h
      exact ((hf a t' hr).keeps b t'' h).trans (hp.keeps a t' hr)
  · intro o ho
    rw [StateT.run_bind, StateT.run_bind, hp.swap o ho]
    rcases hr : p.run t with e | ⟨a, t'⟩
    · rfl
    · have hk := hp.keeps a t' hr
      exact (hf a t' hr).swap o fun q hq => by rw [hk]; exact ho q hq

lemma ReadsOnly.absorb (e : Entry F E) (t : BpppTranscript F E) : ReadsOnly Q (absorb e) t :=
  ⟨fun a t' h => by rw [run_absorb] at h; cases h; rfl,
    fun o _ => by rw [run_absorb, run_absorb]; rfl⟩

lemma ReadsOnly.challenge (l : String) (t : BpppTranscript F E)
    (hq : Q (t.log ++ [.challenge l])) : ReadsOnly Q (challenge_scalar l) t :=
  ⟨fun a t' h => by rw [run_challenge_scalar] at h; cases h; rfl,
    fun o ho => by
      rw [run_challenge_scalar, run_challenge_scalar]
      simp only [withOracle_log, withOracle_oracle, swapRes, ho _ hq]
      rfl⟩

lemma ReadsOnly.pure {α : Type} (a : α) (t : BpppTranscript F E) :
    ReadsOnly Q (Pure.pure a : TranscriptM F E α) t :=
  ⟨fun a' t' h => (by cases h; rfl), fun o _ => rfl⟩

lemma ReadsOnly.liftM {α : Type} (x : Except Error α) (t : BpppTranscript F E) :
    ReadsOnly Q (liftM x : TranscriptM F E α) t := by
  cases x with
  | error e => exact ⟨fun a t' h => (by cases h), fun o _ => rfl⟩
  | ok a => exact ⟨fun a' t' h => (by cases h; rfl), fun o _ => rfl⟩

lemma ReadsOnly.throw {α : Type} (e : Error) (t : BpppTranscript F E) :
    ReadsOnly Q (MonadExcept.throw e : TranscriptM F E α) t :=
  ⟨fun a t' h => (by cases h), fun o _ => rfl⟩

lemma ReadsOnly.ite {α : Type} {c : Prop} [Decidable c] {p q : TranscriptM F E α}
    {t : BpppTranscript F E} (hp : c → ReadsOnly Q p t) (hq : ¬c → ReadsOnly Q q t) :
    ReadsOnly Q (if c then p else q) t := by
  split_ifs with h
  · exact hp h
  · exact hq h

lemma liftM_run_eq {α : Type} (x : Except Error α) (t : BpppTranscript F E) {a : α}
    {t' : BpppTranscript F E} (h : (liftM x : TranscriptM F E α).run t = .ok (a, t')) : t' = t := by
  cases x <;> cases h; rfl

/-- A run that only absorbs `es` reads no oracle. -/
lemma ReadsOnly.of_run {α : Type} {p : TranscriptM F E α} (a : α) (es : List (Entry F E))
    (h : ∀ t, p.run t = .ok (a, t.extend es)) (t : BpppTranscript F E) : ReadsOnly Q p t :=
  ⟨fun a' t' h' => by rw [h] at h'; cases h'; rfl, fun o _ => by rw [h, h]; rfl⟩

end BpppTranscript

open BpppTranscript

namespace NormLinear

lemma verify_round_run (st : List F × F × F × List F × Weights F × Weights F) (r : E × E)
    (T : BpppTranscript F E) : ∃ st', (verify_round st r).run T =
      .ok (st', T.extend (roundEntries [r])) := by
  obtain ⟨c, rho, mu, gs, wh, wg⟩ := st
  obtain ⟨X, R⟩ := r
  simp only [verify_round, StateT.run_bind, run_append_point, ok_bind, run_challenge_scalar,
    extend_extend, StateT.run_pure, roundEntries, List.append_nil]
  exact ⟨_, rfl⟩

/-- The round loop reads the oracle only at the logs ending in each round's `gamma`. -/
lemma readsOnly_loop {Q : List (Entry F E) → Prop} : ∀ (rounds : List (E × E))
    (st : List F × F × F × List F × Weights F × Weights F) (T : BpppTranscript F E),
    (∀ i < rounds.length, Q (T.log ++ roundEntries (rounds.take (i + 1)))) →
    ReadsOnly Q (rounds.foldlM verify_round st) T
  | [], st, T, _ => ReadsOnly.pure st T
  | (X, R) :: rounds, st, T, hQ => by
    rw [List.foldlM_cons]
    refine ReadsOnly.bind ?_ fun st' T' h => readsOnly_loop rounds st' T' fun i hi => ?_
    · obtain ⟨c, rho, mu, gs, wh, wg⟩ := st
      simp only [verify_round]
      refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t1 h1 => ?_
      rw [run_append_point] at h1; cases h1
      refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t2 h2 => ?_
      rw [run_append_point] at h2; cases h2
      refine ReadsOnly.bind (ReadsOnly.challenge _ _ ?_) fun _ _ _ => ReadsOnly.pure _ _
      have := hQ 0 (by simp)
      simpa [roundEntries] using this
    · obtain ⟨st'', h'⟩ := verify_round_run st (X, R) T
      rw [h'] at h; cases h
      have := hQ (i + 1) (by simp; omega)
      simpa [roundEntries] using this

/-- `norm_linear::verify` reads the oracle only at the logs ending in each round's `gamma`, after
its domain separator. -/
lemma readsOnly_verify {Q : List (Entry F E) → Prop} (gens : Generators E) (c : List F) (ps : F) (pn : List F)
    (extra : List (F × E)) (rho : F) (proof : NormLinearProof F E) (T : BpppTranscript F E)
    (hQ : ∀ i < proof.rounds.length, Q (T.log ++
      [.message "dom-sep" ("norm_linear".toList.map Char.toNat)] ++
        roundEntries (proof.rounds.take (i + 1)))) :
    ReadsOnly Q (verify gens c ps pn extra rho proof) T := by
  simp only [verify, pure_bind]
  refine ReadsOnly.ite (fun _ => ReadsOnly.bind (ReadsOnly.throw _ _) fun _ _ h => by cases h)
    fun _ => ?_
  refine ReadsOnly.ite (fun _ => ReadsOnly.bind (ReadsOnly.throw _ _) fun _ _ h => by cases h)
    fun _ => ?_
  refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t3 h3 => ?_
  rw [show (domain_sep "norm_linear" : TranscriptM F E Unit).run T = _ from run_domain_sep T _]
    at h3
  cases h3
  refine ReadsOnly.bind (readsOnly_loop _ _ _ fun i hi => by simpa using hQ i hi) fun st t4 _ => ?_
  refine ReadsOnly.bind (ReadsOnly.of_run () _ (fun t => run_append_scalars t _ _) _)
    fun _ t5 _ => ?_
  refine ReadsOnly.bind (ReadsOnly.of_run () _ (fun t => run_append_scalars t _ _) _)
    fun _ t6 _ => ?_
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun r t7 _ => ?_
  exact ReadsOnly.ite (fun _ => ReadsOnly.pure _ _) fun _ => ReadsOnly.throw _ _

end NormLinear

namespace Circuit

open NormLinear

/-- The logs after the norm-linear domain separator at which `norm_linear::verify` draws each
round's `gamma`, continuing from the log `L`. -/
def nlLogs (L : List (Entry F E)) (rounds : List (E × E)) : List (List (Entry F E)) :=
  (List.range rounds.length).map fun i =>
    L ++ [.message "dom-sep" ("norm_linear".toList.map Char.toNat)] ++ roundEntries (rounds.take (i + 1))

/-- Every log at which `circuit::verify` draws a challenge. -/
def challengeLogs (t : BpppTranscript F E) (vcs : List (PedersenCommitment E))
    (proof : CircuitProof F E) : List (List (Entry F E)) :=
  [alphaLog t vcs proof, rhoLog t vcs proof, lamLog t vcs proof, betaLog t vcs proof,
    tauLog t vcs proof] ++ nlLogs (tauLog t vcs proof) proof.nl_proof.rounds

/-- `circuit::verify` reads the oracle only at `challengeLogs`. -/
lemma readsOnly_verify (gens : Generators E) (params : CircuitParams) (proof : CircuitProof F E)
    (vcs : List (PedersenCommitment E)) (t : BpppTranscript F E) :
    ReadsOnly (· ∈ challengeLogs t vcs proof) (verify gens params proof vcs) t := by
  simp only [verify, pure_bind]
  refine ReadsOnly.ite (fun _ => ReadsOnly.bind (ReadsOnly.throw _ _) fun _ _ h => by cases h)
    fun _ => ?_
  refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t1 h => ?_
  rw [show (domain_sep "bppp_circuit" : TranscriptM F E Unit).run t = _ from run_domain_sep t _]
    at h
  cases h
  refine ReadsOnly.bind (ReadsOnly.of_run () _ (fun t => run_append_commits t _ _) _)
    fun _ t2 h => ?_
  rw [run_append_commits] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t3 h => ?_
  rw [run_append_point] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t4 h => ?_
  rw [run_append_point] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.challenge _ _ ?_) fun alpha t5 h => ?_
  · simp [challengeLogs, alphaLog, preAlpha]
  rw [run_challenge_scalar] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t6 h => ?_
  rw [run_append_point] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.challenge _ _ ?_) fun rho t7 h => ?_
  · simp [challengeLogs, rhoLog, alphaLog, preAlpha]
  rw [run_challenge_scalar] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.challenge _ _ ?_) fun lambda t8 h => ?_
  · simp [challengeLogs, lamLog, rhoLog, alphaLog, preAlpha]
  rw [run_challenge_scalar] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.challenge _ _ ?_) fun beta t9 h => ?_
  · simp [challengeLogs, betaLog, lamLog, rhoLog, alphaLog, preAlpha]
  rw [run_challenge_scalar] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.absorb _ _) fun _ t12 h => ?_
  rw [run_append_point] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.challenge _ _ ?_) fun tau t13 h => ?_
  · simp [challengeLogs, tauLog, betaLog, lamLog, rhoLog, alphaLog, preAlpha]
  rw [run_challenge_scalar] at h; cases h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t14 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t15 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t16 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t17 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t18 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t19 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t20 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t21 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine ReadsOnly.bind (ReadsOnly.liftM _ _) fun _ t22 h => ?_
  obtain rfl := liftM_run_eq _ _ h
  refine NormLinear.readsOnly_verify _ _ _ _ _ _ _ _ fun i hi => ?_
  simp only [challengeLogs, nlLogs, List.mem_append, List.mem_map, List.mem_range]
  right
  refine ⟨i, hi, ?_⟩
  simp [tauLog, betaLog, lamLog, rhoLog, alphaLog, preAlpha]

end Circuit

namespace RangeProof

open Circuit

end RangeProof

/-! ## The challenge logs decode uniquely -/

/-- The labels under which points are absorbed. -/
def pointLabels : List String := ["V", "C_L", "C_O", "C_R", "C_S", "X", "R"]

/-- What Merlin absorbs for an entry: a message `(label, bytes)`, with points and scalars under
the encodings `encP`, `encS`, or a challenge `label`. Points and scalars are not tagged, as in
Rust. -/
def Entry.bytes (encP : E → List ℕ) (encS : F → List ℕ) : Entry F E → (String × List ℕ) ⊕ String
  | .message l d => .inl (l, d)
  | .point l p => .inl (l, encP p)
  | .scalar l s => .inl (l, encS s)
  | .challenge l => .inr l

/-- An entry whose label tells its kind: points under `pointLabels`, messages under other labels,
and no scalars. -/
def Entry.Labeled : Entry F E → Prop
  | .message l _ => l ∉ pointLabels
  | .point l _ => l ∈ pointLabels
  | .scalar _ _ => False
  | .challenge _ => True

lemma bytes_inj {encP : E → List ℕ} {encS : F → List ℕ} (hP : Function.Injective encP)
    {e e' : Entry F E} (he : e.Labeled) (he' : e'.Labeled)
    (h : e.bytes encP encS = e'.bytes encP encS) : e = e' := by
  cases e <;> cases e' <;> simp_all [Entry.bytes, Entry.Labeled, hP.eq_iff]

lemma map_bytes_inj {encP : E → List ℕ} {encS : F → List ℕ} (hP : Function.Injective encP) :
    ∀ {q q' : List (Entry F E)}, (∀ e ∈ q, e.Labeled) → (∀ e ∈ q', e.Labeled) →
      q.map (Entry.bytes encP encS) = q'.map (Entry.bytes encP encS) → q = q'
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | e :: q, e' :: q', hq, hq', h => by
    simp only [List.map_cons, List.cons.injEq] at h
    rw [bytes_inj hP (hq e (by simp)) (hq' e' (by simp)) h.1,
      map_bytes_inj hP (fun x hx => hq x (by simp [hx])) (fun x hx => hq' x (by simp [hx])) h.2]

lemma roundEntries_labeled : ∀ (rounds : List (E × E)), ∀ e ∈ NormLinear.roundEntries rounds,
    (e : Entry F E).Labeled
  | [] => by simp [NormLinear.roundEntries]
  | (X, R) :: rounds => by
    intro e he
    simp only [NormLinear.roundEntries, List.cons_append, List.nil_append, List.mem_cons] at he
    rcases he with rfl | rfl | rfl | he
    · simp [Entry.Labeled, pointLabels]
    · simp [Entry.Labeled, pointLabels]
    · simp [Entry.Labeled]
    · exact roundEntries_labeled rounds e he

namespace RangeProof

open Circuit

/-- The entries before `C_L`: the statement and the circuit's domain separator. -/
def stmtPrefix (dst : List ℕ) (bits : ℕ) (vcs : List (PedersenCommitment E)) : List (Entry F E) :=
  [.message "dom-sep" ("fastcrypto-bppp-range-proof-01".toList.map Char.toNat),
    .message "dst" dst, .message "n_bits" (u64_le_bytes bits), .message "m" (u64_le_bytes vcs.length),
    .message "dom-sep" ("bppp_circuit".toList.map Char.toNat)] ++ vcs.map (fun c => .point "V" c.point)

/-- Every challenge log starts with the statement, and every entry tells its kind by its label. -/
lemma challengeLogs_shape (o : List (Entry F E) → F) (dst : List ℕ) (bits : ℕ)
    (vcs : List (PedersenCommitment E)) (proof : Circuit.CircuitProof F E) :
    ∀ q ∈ Circuit.challengeLogs (transcript o dst bits vcs.length) vcs proof,
      (∃ rest, q = stmtPrefix dst bits vcs ++ rest) ∧ ∀ e ∈ q, e.Labeled := by
  intro q hq
  simp only [Circuit.challengeLogs, Circuit.nlLogs, List.mem_append, List.mem_cons,
    List.mem_map, List.mem_range, List.not_mem_nil, or_false] at hq
  have hpre : ∀ e ∈ stmtPrefix dst bits vcs, (e : Entry F E).Labeled := by
    intro e he
    simp only [stmtPrefix, List.cons_append, List.nil_append, List.mem_cons, List.mem_map] at he
    rcases he with rfl | rfl | rfl | rfl | rfl | ⟨c, _, rfl⟩ <;>
      simp [Entry.Labeled, pointLabels]
  have hlog : (transcript o dst bits vcs.length).log ++ Circuit.preAlpha vcs proof =
      stmtPrefix dst bits vcs ++ [.point "C_L" proof.c_l, .point "C_O" proof.c_o] := by
    simp [transcript, BpppTranscript.new, Circuit.preAlpha, stmtPrefix]
  have hlab : ∀ es : List (Entry F E), (∀ e ∈ es, e.Labeled) →
      ∀ e ∈ stmtPrefix dst bits vcs ++ [.point "C_L" proof.c_l, .point "C_O" proof.c_o] ++ es,
        e.Labeled := by
    intro es hes e he
    simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at he
    rcases he with (he | rfl | rfl) | he
    · exact hpre e he
    · simp [Entry.Labeled, pointLabels]
    · simp [Entry.Labeled, pointLabels]
    · exact hes e he
  rcases hq with (rfl | rfl | rfl | rfl | rfl) | ⟨i, -, rfl⟩
  all_goals
    simp only [Circuit.alphaLog, Circuit.rhoLog, Circuit.lamLog, Circuit.betaLog,
      Circuit.tauLog, hlog, List.append_assoc]
    refine ⟨⟨_, rfl⟩, ?_⟩
    rw [← List.append_assoc]
    refine hlab _ ?_
    simp only [List.forall_mem_append, List.forall_mem_cons, List.forall_mem_nil]
    and_intros
    all_goals first | exact roundEntries_labeled _ | simp [Entry.Labeled, pointLabels]

lemma sum_le_bytes (v k : ℕ) :
    ∑ i ∈ Finset.range k, v / 256 ^ i % 256 * 256 ^ i = v % 256 ^ k := by
  induction k with
  | zero => simp [Nat.mod_one]
  | succ k ih => rw [Finset.sum_range_succ, ih, Nat.mod_pow_succ, mul_comm]

/-- `u64::to_le_bytes` is injective on `u64`. -/
lemma u64_le_bytes_inj {v w : ℕ} (hv : v < 2 ^ 64) (hw : w < 2 ^ 64)
    (h : u64_le_bytes v = u64_le_bytes w) : v = w := by
  have key : ∀ x : ℕ, x < 2 ^ 64 →
      ∑ i ∈ Finset.range 8, (u64_le_bytes x).getD i 0 * 256 ^ i = x := fun x hx => by
    have e : ∀ i ∈ Finset.range 8, (u64_le_bytes x).getD i 0 * 256 ^ i =
        x / 256 ^ i % 256 * 256 ^ i := fun i hi => by
      rw [u64_le_bytes, List.getD_eq_getElem?_getD, List.getElem?_map,
        List.getElem?_range (Finset.mem_range.1 hi)]
      rfl
    rw [Finset.sum_congr rfl e, sum_le_bytes, Nat.mod_eq_of_lt (by norm_num at hx ⊢; omega)]
  rw [← key v hv, ← key w hw, h]

/-- Equal challenge logs come from the same statement. -/
lemma stmt_eq {dst dst' : List ℕ} {bits bits' : ℕ} {vcs vcs' : List (PedersenCommitment E)}
    {r r' : List (Entry F E)} (hb : bits < 2 ^ 64) (hb' : bits' < 2 ^ 64)
    (hm : vcs.length < 2 ^ 64) (hm' : vcs'.length < 2 ^ 64)
    (h : stmtPrefix dst bits vcs ++ r = stmtPrefix dst' bits' vcs' ++ r') :
    dst = dst' ∧ bits = bits' ∧ vcs = vcs' := by
  simp only [stmtPrefix, List.cons_append, List.nil_append, List.cons.injEq, Entry.message.injEq,
    true_and] at h
  obtain ⟨hd, hbits, hlen, h⟩ := h
  have hl := u64_le_bytes_inj hm hm' hlen
  obtain ⟨hv, -⟩ := List.append_inj h (by simp [hl])
  refine ⟨hd, u64_le_bytes_inj hb hb' hbits, ?_⟩
  refine List.map_injective_iff.2 (fun c c' e => ?_) hv
  cases c; cases c'; simp only [Entry.point.injEq, true_and] at e; rw [e]

lemma length_roundEntries : ∀ rounds : List (E × E),
    (NormLinear.roundEntries rounds : List (Entry F E)).length = 3 * rounds.length
  | [] => rfl
  | (_, _) :: rounds => by simp [NormLinear.roundEntries, length_roundEntries rounds]; ring

end RangeProof

end Bppp
