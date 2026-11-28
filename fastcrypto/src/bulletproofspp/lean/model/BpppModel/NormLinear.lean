import BpppModel.Transcript
import BpppModel.Util

/-!
# `norm_linear.rs`

Serialization is not modelled.
-/

namespace Bppp

variable {F E : Type} [Add F] [Mul F] [Sub F] [Neg F] [Zero F] [One F] [Inv F] [NatCast F] [OfNat F 2] [DecidableEq F] [Add E] [Zero E] [SMul F E] [DecidableEq E]

/-- `FOLD_THRESHOLD`. -/
def FOLD_THRESHOLD : Nat := 6

/-- `FOLD_BATCH_ROUNDS`. -/
def FOLD_BATCH_ROUNDS : Nat := 3

variable (F E) in
/-- `NormLinearProof`. -/
structure NormLinearProof where
  rounds : List (E × E)
  l_final : F
  n_final : List F

variable (F) in
/-- `Opening`. -/
structure Opening where
  sigma : F
  l : List F
  n : List F

/-- `Generators::commit`. -/
def Generators.commit (self : Generators E) (opening : Opening F) : Result E :=
  self.msm opening.sigma opening.l opening.n [] []

namespace NormLinear

/-- `is_base_case`. -/
def is_base_case (l_len n_len : Nat) : Bool := l_len ≤ 1 && l_len + n_len < FOLD_THRESHOLD

theorem is_base_case_iff (l_len n_len : Nat) :
    is_base_case l_len n_len = true ↔ l_len ≤ 1 ∧ l_len + n_len < 6 := by
  simp only [is_base_case, Bool.and_eq_true, decide_eq_true_eq]; exact Iff.rfl

/-- `proof_shape`. -/
def proof_shape (l_len n_len : Nat) : Nat × Nat :=
  if _h : is_base_case l_len n_len then (0, n_len)
  else
    let (rounds, n_len) := proof_shape ((l_len + 1) / 2) ((n_len + 1) / 2)
    (rounds + 1, n_len)
termination_by l_len + n_len
decreasing_by rw [is_base_case_iff] at _h; omega

/-- The pairs `(v_0, v_1), (v_2, v_3), ...` of `v`, unzipped (`v.into_iter().tuples().unzip()`). -/
def unzip_pairs {α : Type} : List α → List α × List α
  | x :: y :: rest => let (a, b) := unzip_pairs rest; (x :: a, y :: b)
  | _ => ([], [])

/-- `split_even_odd`. -/
def split_even_odd (v : List F) : List F × List F :=
  unzip_pairs (if v.length % 2 ≠ 0 then v ++ [0] else v)

theorem unzip_pairs_length {α : Type} : ∀ v : List α,
    (unzip_pairs v).1.length = v.length / 2 ∧ (unzip_pairs v).2.length = v.length / 2
  | x :: y :: rest => by
    have := unzip_pairs_length rest
    simp only [unzip_pairs, List.length_cons]; omega
  | [] => by simp [unzip_pairs]
  | [_] => by simp [unzip_pairs]

omit [Add F] [Mul F] [Sub F] [Neg F] [One F] [Inv F] [NatCast F] [OfNat F 2] [DecidableEq F] in
theorem split_even_odd_length (v : List F) :
    (split_even_odd v).1.length = (v.length + 1) / 2 ∧ (split_even_odd v).2.length = (v.length + 1) / 2 := by
  unfold split_even_odd
  split
  · have := unzip_pairs_length (v ++ [0])
    simp only [List.length_append, List.length_singleton] at this; omega
  · have := unzip_pairs_length v; omega

/-- `interleave`. -/
def interleave (even odd : List F) : List F := (List.zip even odd).flatMap fun (x, y) => [x, y]

/-- `odd_only`. -/
def odd_only (odd : List F) : List F := odd.flatMap fun y => [0, y]

/-- `sparse_mul`. -/
def sparse_mul (a b : F) : F := if a = 0 then a else a * b

/-- `<[T]>::chunks`, for `n ≥ 1`. -/
def chunks {α : Type} (n : Nat) (l : List α) : List (List α) :=
  if _h : n = 0 ∨ l = [] then [] else l.take n :: chunks n (l.drop n)
termination_by l.length
decreasing_by
  simp only [not_or] at _h
  have := List.length_pos_iff.mpr _h.2
  simp only [List.length_drop]; omega

variable (F) in
/-- `Weights`. -/
structure Weights where
  w : List F

namespace Weights

/-- `Weights::new`. -/
def new : Weights F := ⟨[one]⟩

/-- `Weights::tensor`. -/
def tensor (self : Weights F) (coeffs : List F) : List F :=
  coeffs.flatMap fun c => self.w.map fun w => sparse_mul c w

/-- `Weights::tensor_pair`. -/
def tensor_pair (self : Weights F) (f0 f1 : F) : Weights F := ⟨self.tensor [f0, f1]⟩

/-- `Weights::len`. -/
def len (self : Weights F) : Nat := self.w.length

/-- `Weights::scale`. -/
def scale (self : Weights F) (s : F) : List F := self.w.map fun w => sparse_mul s w

/-- `Weights::contract`. -/
def contract (self : Weights F) (points : List E) : Result (List E) :=
  (chunks self.len points).mapM fun chunk => multi_scalar_mul (self.w.take chunk.length) chunk

end Weights

variable (F E) in
/-- `BasePoints`. -/
inductive BasePoints
  | Crs (gens : Generators E)
  | Folded (g : E) (h_vec g_vec : List E)

variable (F E) in
/-- `LazyBases`. -/
structure LazyBases where
  points : BasePoints E
  w_h : Weights F
  w_g : Weights F

namespace LazyBases

/-- `LazyBases::new`. -/
def new (gens : Generators E) : LazyBases F E := ⟨.Crs gens, .new, .new⟩

/-- `LazyBases::fold`. -/
def fold (self : LazyBases F E) (rho gamma : F) : LazyBases F E :=
  { self with w_h := self.w_h.tensor_pair one gamma, w_g := self.w_g.tensor_pair rho gamma }

/-- `LazyBases::points`. -/
def points' (self : LazyBases F E) : E × List E × List E :=
  match self.points with
  | .Crs gens => (gens.g, gens.h_vec, gens.g_vec)
  | .Folded g h_vec g_vec => (g, h_vec, g_vec)

/-- `LazyBases::len`. -/
def len (self : LazyBases F E) : Nat × Nat :=
  let (_, h_vec, g_vec) := self.points'
  (h_vec.length, g_vec.length)

/-- `LazyBases::msm`, which takes `&mut self` and so returns the updated bases. -/
def msm (self : LazyBases F E) (sigma : F) (l n : List F) :
    Result (E × LazyBases F E) := do
  let self ← if self.w_h.len = 2 ^ FOLD_BATCH_ROUNDS then do
      let (g, h_vec, g_vec) := self.points'
      let folded := (← self.w_h.contract h_vec, ← self.w_g.contract g_vec)
      pure { points := .Folded g folded.1 folded.2, w_h := .new, w_g := .new }
    else pure self
  let (h_len, g_len) := self.len
  let h_scalars := (self.w_h.tensor l).take h_len
  let g_scalars := (self.w_g.tensor n).take g_len
  let point ← match self.points with
    | .Crs gens => gens.msm sigma h_scalars g_scalars [] []
    | .Folded g h_vec g_vec =>
      let (sc, pts) := (((sigma, g) :: List.zip h_scalars h_vec ++ List.zip g_scalars g_vec).filter
        fun (s, _) => s ≠ 0).unzip
      multi_scalar_mul sc pts
  pure (point, self)

end LazyBases

open BpppTranscript

/-- The round loop of `norm_linear::prove`: one round per call, until the base case. -/
def prove_loop (bases : LazyBases F E) (c : List F) (rho : F) (l n : List F) :
    TranscriptM F E (NormLinearProof F E) := do
  if _h : is_base_case l.length n.length then do
    append_scalars "l_final" l
    append_scalars "n_final" n
    return { rounds := [], l_final := l.headD 0, n_final := n }
  else do
    let l0 := (split_even_odd l).1
    let l1 := (split_even_odd l).2
    let n0 := (split_even_odd n).1
    let n1 := (split_even_odd n).2
    let c0 := (split_even_odd c).1
    let c1 := (split_even_odd c).2
    let mu := rho * rho
    let mu2 := mu * mu
    let rho_inv ← inverse rho
    let two : F := 2
    let vx := two * rho_inv * weighted_inner_product n0 n1 mu2 + inner_product c0 l1 +
      inner_product c1 l0
    let vr := weighted_norm n1 mu2 + inner_product c1 l1
    let (x_point, bases) ← bases.msm vx (interleave l1 l0)
      (interleave (vec_scalar_mul rho n1) (vec_scalar_mul rho_inv n0))
    let (r_point, bases) ← bases.msm vr (odd_only l1) (odd_only n1)
    append_point "X" x_point
    append_point "R" r_point
    let gamma ← challenge_scalar "gamma"
    let proof ← prove_loop (bases.fold rho gamma) (vec_add c0 (vec_scalar_mul gamma c1)) mu
      (vec_add l0 (vec_scalar_mul gamma l1))
      (vec_add (vec_scalar_mul rho_inv n0) (vec_scalar_mul gamma n1))
    return { proof with rounds := (x_point, r_point) :: proof.rounds }
termination_by l.length + n.length
decreasing_by
  rw [is_base_case_iff] at _h
  have hl := split_even_odd_length l
  have hn := split_even_odd_length n
  simp only [vec_add, vec_scalar_mul, List.length_zipWith, List.length_map]
  omega

/-- `norm_linear::prove`. -/
def prove (gens : Generators E) (c : List F) (rho : F) (opening : Opening F) :
    TranscriptM F E (NormLinearProof F E) := do
  domain_sep "norm_linear"
  prove_loop (.new gens) c rho opening.l opening.n

/-- An iteration of the round loop of `norm_linear::verify`, on the state
`(c, rho, mu, gammas, w_h, w_g)`. -/
def verify_round (st : List F × F × F × List F × Weights F × Weights F) (round : E × E) :
    TranscriptM F E (List F × F × F × List F × Weights F × Weights F) := do
  let (c, rho, mu, gammas, w_h, w_g) := st
  let (x_point, r_point) := round
  append_point "X" x_point
  append_point "R" r_point
  let gamma ← challenge_scalar "gamma"
  let c0 := (split_even_odd c).1
  let c1 := (split_even_odd c).2
  pure (vec_add c0 (vec_scalar_mul gamma c1), mu, mu * mu, gammas ++ [gamma],
    w_h.tensor_pair one gamma, w_g.tensor_pair rho gamma)

/-- `norm_linear::verify`. -/
def verify (gens : Generators E) (c : List F) (p_s : F) (p_n : List F) (extra : List (F × E))
    (rho : F) (proof : NormLinearProof F E) : TranscriptM F E Unit := do
  if c.length ≠ gens.h_vec.length ∨ p_n.length ≠ gens.g_vec.length then
    throw .InvalidInput
  let (rounds, n_len) := proof_shape gens.h_vec.length gens.g_vec.length
  if proof.rounds.length ≠ rounds ∨ proof.n_final.length ≠ n_len then
    throw .InvalidProof
  domain_sep "norm_linear"
  let (c, _, mu, gammas, w_h, w_g) ← proof.rounds.foldlM verify_round
    (c, rho, rho * rho, ([] : List F), Weights.new, Weights.new)
  append_scalars "l_final" [proof.l_final]
  append_scalars "n_final" proof.n_final
  let sigma := c.headD 0 * proof.l_final + weighted_norm proof.n_final mu
  let l := (w_h.scale proof.l_final).take gens.h_vec.length
  let n := List.zipWith (fun w p_n_i => w - p_n_i) ((w_g.tensor proof.n_final).take gens.g_vec.length) p_n
  let dynamic := extra.map (fun (s, p) => (-s, p)) ++
    (List.zip proof.rounds gammas).flatMap fun ((x_point, r_point), gamma) =>
      [(-gamma, x_point), (one - gamma * gamma, r_point)]
  let result ← gens.msm (sigma - p_s) l n (dynamic.map (·.1)) (dynamic.map (·.2))
  if result = 0 then pure () else throw .InvalidProof

end NormLinear

end Bppp
