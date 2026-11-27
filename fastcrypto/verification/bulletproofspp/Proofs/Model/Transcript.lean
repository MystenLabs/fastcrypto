-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Transcript

/-!
# Lemmas about `transcript.rs`

How each transcript operation runs: it appends to the log and, for a challenge, reads `oracle`.
-/

namespace Bppp

variable {F E : Type}

namespace BpppTranscript

/-- The transcript `t` with `es` appended to its log. -/
def extend (t : BpppTranscript F E) (es : List (Entry F E)) : BpppTranscript F E :=
  { t with log := t.log ++ es }

@[simp] lemma extend_nil (t : BpppTranscript F E) : t.extend [] = t := by simp [extend]

@[simp] lemma extend_extend (t : BpppTranscript F E) (es es' : List (Entry F E)) :
    (t.extend es).extend es' = t.extend (es ++ es') := by simp [extend]

@[simp] lemma extend_oracle (t : BpppTranscript F E) (es : List (Entry F E)) :
    (t.extend es).oracle = t.oracle := rfl

@[simp] lemma extend_log (t : BpppTranscript F E) (es : List (Entry F E)) :
    (t.extend es).log = t.log ++ es := rfl

lemma run_absorb (t : BpppTranscript F E) (e : Entry F E) :
    (absorb e).run t = .ok ((), t.extend [e]) := by
  simp [absorb, StateT.run, modify, modifyGet, MonadStateOf.modifyGet, StateT.modifyGet, pure,
    Except.pure, extend]

lemma run_domain_sep (t : BpppTranscript F E) (label : String) :
    (domain_sep label).run t =
      .ok ((), t.extend [.message "dom-sep" (label.toList.map Char.toNat)]) :=
  run_absorb _ _

lemma run_append_point (t : BpppTranscript F E) (label : String) (p : E) :
    (append_point label p).run t = .ok ((), t.extend [.point label p]) := run_absorb _ _

lemma run_append_scalar (t : BpppTranscript F E) (label : String) (s : F) :
    (append_scalar label s).run t = .ok ((), t.extend [.scalar label s]) := run_absorb _ _

lemma run_append_scalars (t : BpppTranscript F E) (label : String) (ss : List F) :
    (append_scalars label ss).run t = .ok ((), t.extend (ss.map (.scalar label))) := by
  induction ss generalizing t with
  | nil => simp [append_scalars, StateT.run, pure, StateT.pure, Except.pure]
  | cons s ss ih =>
    have h : (append_scalars label (s :: ss) : TranscriptM F E Unit).run t =
        ((append_scalar label s : TranscriptM F E Unit).run t).bind
          fun p => (append_scalars label ss).run p.2 := rfl
    rw [h, run_append_scalar]
    simp only [Except.bind]
    rw [ih]; simp

lemma run_append_commits (t : BpppTranscript F E) (label : String)
    (cs : List (PedersenCommitment E)) :
    (append_commits label cs).run t = .ok ((), t.extend (cs.map fun c => .point label c.point)) := by
  induction cs generalizing t with
  | nil => simp [append_commits, StateT.run, pure, StateT.pure, Except.pure]
  | cons c cs ih =>
    have h : (append_commits label (c :: cs) : TranscriptM F E Unit).run t =
        ((append_point label c.point : TranscriptM F E Unit).run t).bind
          fun p => (append_commits label cs).run p.2 := rfl
    rw [h, run_append_point]
    simp only [Except.bind]
    rw [ih]; simp

lemma run_challenge_scalar (t : BpppTranscript F E) (label : String) :
    (challenge_scalar label : TranscriptM F E F).run t =
      .ok (t.oracle (t.log ++ [.challenge label]), t.extend [.challenge label]) := by
  simp [challenge_scalar, absorb, StateT.run, modify, modifyGet, MonadStateOf.modifyGet,
    StateT.modifyGet, pure, Except.pure, bind, StateT.bind, Except.bind, get, getThe,
    MonadStateOf.get, StateT.get, StateT.pure, extend]

end BpppTranscript

end Bppp
