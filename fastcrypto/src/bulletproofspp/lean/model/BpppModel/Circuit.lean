import BpppModel.Constraints
import BpppModel.NormLinear

/-!
# `circuit.rs`

The prover's random draws are an input (`Randomness`), indexed by slot. Serialization is not
modelled.
-/

namespace Bppp

variable {F E : Type} [Add F] [Mul F] [Sub F] [Neg F] [Zero F] [One F] [Inv F] [NatCast F] [OfNat F 2] [DecidableEq F] [Add E] [Zero E] [SMul F E] [DecidableEq E]

namespace Circuit

/-- `CR_POWERS`. -/
def CR_POWERS : List Int := [-1, 1, 2, 3, 5, 6, 7]

/-- `C_S_POWER`. -/
def C_S_POWER : Int := -1

/-- `C_O_POWER`. -/
def C_O_POWER : Int := 0

/-- `C_L_POWER`. -/
def C_L_POWER : Int := 1

/-- `C_R_POWER`. -/
def C_R_POWER : Int := 2

/-- `V_HAT_POWER`. -/
def V_HAT_POWER : Int := 3

variable (F E) in
/-- `CircuitProof`. -/
structure CircuitProof where
  c_l : E
  c_o : E
  c_r : E
  c_s : E
  nl_proof : NormLinearProof F E

/-- `c`. -/
def c (constraints : Constraints F) (beta : F) : Laurent (List F) :=
  Laurent.from_terms ((0, constraints.cl_v) ::
    CR_POWERS.zipIdx.map fun (a, j) => (a, (List.replicate H_LEN 0).set j beta))

/-- `message_opening`. -/
def message_opening (r n : List F) : Opening F := ⟨r.headD 0, r.drop 1 ++ [0], n⟩

/-- `blinding_vector`, with `rng p` the draw for slot `p`. -/
def blinding_vector (rng : Nat → F) (e : Int) : List F :=
  rng 0 :: CR_POWERS.zipIdx.map fun (a, p) =>
    let power := e + a
    if power = -1 ∨ power + 1 ∈ CR_POWERS then rng (p + 1) else 0

/-- `reciprocals`. -/
def reciprocals (params : CircuitParams) (n_l : List F) (alpha : F) : Result (List F) := do
  let denominators := (n_l.take params.n_d).map (alpha + ·)
  pure (pad_to (← batch_invert denominators) params.nm)

variable (F) in
/-- `Witness`. -/
structure Witness where
  values : List F
  blindings : List F
  off_plane : List (List F × F)
  n_l : List F
  n_o : List F
  r_o : List F
  r_l : List F
  r_r : List F
  n_s : List F
  l_s : F

variable (F) in
/-- The draws of `Witness::new` from `rng`. -/
structure Randomness where
  r_o : Nat → F
  r_l : Nat → F
  r_r : Nat → F
  n_s : Nat → F
  l_s : F

namespace Witness

/-- `Witness::new`. -/
def new (params : CircuitParams) (rng : Randomness F) (values : List Nat) (blindings : List F) :
    Witness F :=
  let digits := values.flatMap fun v => to_digits v params.d
  { values := to_scalars values
    blindings
    off_plane := []
    n_l := pad_to (to_scalars digits) params.nm
    n_o := pad_to (to_scalars (multiplicities digits)) params.nm
    r_o := blinding_vector rng.r_o C_O_POWER
    r_l := blinding_vector rng.r_l C_L_POWER
    r_r := blinding_vector rng.r_r C_R_POWER
    n_s := (List.range params.nm).map rng.n_s
    l_s := rng.l_s }

/-- `Witness::input_commitments`, under the Pedersen bases `G`, `H`. -/
def input_commitments (self : Witness F) (G H : E) (gens : Generators E) :
    Result (List (PedersenCommitment E)) :=
  (List.zip self.values self.blindings).zipIdx.mapM fun ((v, s), i) => do
    let commitment := PedersenCommitment.new G H v s
    match self.off_plane[i]? with
    | some (n, l) =>
      let p ← multi_scalar_mul (n ++ [l]) (gens.g_vec ++ [gens.h_vec.getD (H_LEN - 1) 0])
      pure ⟨commitment.point + p⟩
    | none => pure commitment

end Witness

variable (F) in
/-- `CombinedOpening`. -/
structure CombinedOpening where
  sigma : Laurent F
  l : Laurent (List F)
  n : Laurent (List F)

namespace CombinedOpening

/-- `CombinedOpening::from_terms`. -/
def from_terms (terms : List (Int × Opening F)) : CombinedOpening F :=
  ⟨.from_terms (terms.map fun (p, o) => (p, o.sigma)),
    .from_terms (terms.map fun (p, o) => (p, o.l)), .from_terms (terms.map fun (p, o) => (p, o.n))⟩

/-- `CombinedOpening::with_r_s`. -/
def with_r_s (self : CombinedOpening F) (r_s0 : F) (h : List F) : CombinedOpening F :=
  { self with sigma := self.sigma + .monomial C_S_POWER r_s0, l := self.l + .monomial C_S_POWER h }

/-- `CombinedOpening::eval`. -/
def eval (self : CombinedOpening F) (tau : F) : Result (Opening F) := do
  pure ⟨← self.sigma.eval tau, ← self.l.eval tau, ← self.n.eval tau⟩

end CombinedOpening

/-- `f`. -/
def f (opening : CombinedOpening F) (c : Laurent (List F)) (norm_weights : List F) : Laurent F :=
  opening.sigma - c.inner_product opening.l - opening.n.weighted_inner_product opening.n norm_weights

/-- `solve_r_s`. -/
def solve_r_s (constraints : Constraints F) (f_bar : Laurent F) (l_s beta : F) :
    Result (F × List F) := do
  let beta_inv ← inverse beta
  let h := CR_POWERS.map (fun a => f_bar.coeff (a - 1) * beta_inv) ++ [l_s]
  pure (inner_product constraints.cl_v h - f_bar.coeff (-1), h)

/-- `opening_without_r_s`. -/
def opening_without_r_s (params : CircuitParams) (constraints : Constraints F)
    (witness : Witness F) (n_r : List F) (delta delta_inv : F) : CombinedOpening F :=
  let two : F := 2
  let weights := (constraints.lambdas.take params.m).map (two * ·)
  let (n_v_hat, l_v_hat) := (List.zip witness.off_plane weights).foldl
    (fun (n_v_hat, l_v_hat) ((n_i, l_i), w) =>
      (vec_add n_v_hat (vec_scalar_mul w n_i), l_v_hat + w * l_i))
    (List.replicate params.nm 0, 0)
  let v_hat : Opening F := ⟨inner_product weights witness.values,
    ((List.replicate H_LEN 0).set 0 (inner_product weights witness.blindings)).set (H_LEN - 1)
      l_v_hat, n_v_hat⟩
  let o := message_opening witness.r_o witness.n_o
  let delta_o : Opening F := ⟨delta * o.sigma, vec_scalar_mul delta o.l, vec_scalar_mul delta o.n⟩
  let ⟨sigma, l, n⟩ := CombinedOpening.from_terms [(C_O_POWER, delta_o),
    (C_L_POWER, message_opening witness.r_l witness.n_l),
    (C_R_POWER, message_opening witness.r_r n_r), (V_HAT_POWER, v_hat)]
  let p_n := constraints.p_n delta_inv
  let p_s := p_n.weighted_inner_product p_n constraints.norm_weights +
    Laurent.monomial 3 (two * (constraints.lambda_al + constraints.mu_am))
  ⟨sigma + p_s, l, n + Laurent.monomial C_S_POWER witness.n_s + p_n⟩

/-- `commit_c_s`. -/
def commit_c_s (gens : Generators E) (params : CircuitParams) (constraints : Constraints F)
    (witness : Witness F) (n_r : List F) (c : Laurent (List F)) (beta delta delta_inv : F) :
    Result (E × CombinedOpening F) := do
  let opening := opening_without_r_s params constraints witness n_r delta delta_inv
  let f_bar := f opening c constraints.norm_weights
  let (r_s0, h) ← solve_r_s constraints f_bar witness.l_s beta
  let c_s ← gens.commit ⟨r_s0, h, witness.n_s⟩
  pure (c_s, opening.with_r_s r_s0 h)

open BpppTranscript

/-- `prove_witness`; `G`, `H` are the Pedersen bases. -/
def prove_witness (G H : E) (gens : Generators E) (params : CircuitParams)
    (witness : Witness F) (reciprocals_of : F → Result (List F)) :
    TranscriptM F E (CircuitProof F E × List (PedersenCommitment E)) := do
  let v_commitments ← witness.input_commitments G H gens
  domain_sep "bppp_circuit"
  append_commits "V" v_commitments
  -- Step 1
  let c_l ← gens.commit (message_opening witness.r_l witness.n_l)
  let c_o ← gens.commit (message_opening witness.r_o witness.n_o)
  append_point "C_L" c_l
  append_point "C_O" c_o
  -- Step 2
  let alpha ← challenge_scalar "alpha"
  -- Step 3
  let n_r ← reciprocals_of alpha
  let c_r ← gens.commit (message_opening witness.r_r n_r)
  append_point "C_R" c_r
  -- Step 4
  let rho ← challenge_scalar "rho"
  let lambda ← challenge_scalar "lambda"
  let beta ← challenge_scalar "beta"
  let delta ← challenge_scalar "delta"
  let mu := rho * rho
  let delta_inv ← inverse delta
  let constraints ← Constraints.new params alpha mu lambda
  -- Step 5
  let c := c constraints beta
  let (c_s, opening) ← commit_c_s gens params constraints witness n_r c beta delta delta_inv
  append_point "C_S" c_s
  -- Step 6
  let tau ← challenge_scalar "tau"
  -- Step 7
  let nl_proof ← NormLinear.prove gens (← c.eval tau) rho (← opening.eval tau)
  pure ({ c_l, c_o, c_r, c_s, nl_proof }, v_commitments)

/-- `prove`, with the draws `rng`; `G`, `H` are the Pedersen bases. -/
def prove (G H : E) (gens : Generators E) (params : CircuitParams) (rng : Randomness F)
    (values : List Nat) (blindings : List F) :
    TranscriptM F E (CircuitProof F E × List (PedersenCommitment E)) := do
  if values.length ≠ params.m ∨ blindings.length ≠ params.m ∨
      gens.g_vec.length ≠ params.nm ∨ values.any (fun v => !params.range.is_in_range v) then
    throw .InvalidInput
  let witness : Witness F := .new params rng values blindings
  prove_witness G H gens params witness fun alpha => reciprocals params witness.n_l alpha

/-- `verify`. -/
def verify (gens : Generators E) (params : CircuitParams) (proof : CircuitProof F E)
    (v_commitments : List (PedersenCommitment E)) : TranscriptM F E Unit := do
  if v_commitments.length ≠ params.m ∨ gens.g_vec.length ≠ params.nm then
    throw .InvalidInput
  domain_sep "bppp_circuit"
  append_commits "V" v_commitments
  append_point "C_L" proof.c_l
  append_point "C_O" proof.c_o
  let alpha ← challenge_scalar "alpha"
  append_point "C_R" proof.c_r
  let rho ← challenge_scalar "rho"
  let lambda ← challenge_scalar "lambda"
  let beta ← challenge_scalar "beta"
  let delta ← challenge_scalar "delta"
  let mu := rho * rho
  let delta_inv ← inverse delta
  append_point "C_S" proof.c_s
  let tau ← challenge_scalar "tau"
  let tau_pow := fun (power : Int) => (Laurent.monomial power (one : F)).eval tau
  let constraints ← Constraints.new params alpha mu lambda
  let p_n_tau ← (constraints.p_n delta_inv).eval tau
  let p_s_tau := weighted_norm p_n_tau mu +
    2 * (constraints.lambda_al + constraints.mu_am) * (← tau_pow 3)
  let c_tau ← (c constraints beta).eval tau
  let extra := [(← tau_pow C_S_POWER, proof.c_s), (delta * (← tau_pow C_O_POWER), proof.c_o),
    (← tau_pow C_L_POWER, proof.c_l), (← tau_pow C_R_POWER, proof.c_r)]
  let v_hat_weight := 2 * (← tau_pow V_HAT_POWER)
  let extra := extra ++ v_commitments.zipIdx.map fun (v_i, i) =>
    (v_hat_weight * constraints.lambdas.getD i 0, v_i.point)
  NormLinear.verify gens c_tau p_s_tau p_n_tau extra rho proof.nl_proof

end Circuit

end Bppp
