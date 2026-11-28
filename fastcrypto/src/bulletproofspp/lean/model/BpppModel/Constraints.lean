import BpppModel.Laurent

/-!
# `constraints.rs`

`CircuitParams` is declared in `circuit.rs`, and here since `constraints.rs` uses it.
`value_row` is test-only and is not modelled.
-/

namespace Bppp

variable {F : Type} [Add F] [Mul F] [Sub F] [Neg F] [Zero F] [One F] [Inv F] [NatCast F] [OfNat F 2] [DecidableEq F]

/-- `CircuitParams`. -/
structure CircuitParams where
  range : Range
  m : Nat
  d : Nat
  n_d : Nat
  nm : Nat

/-- `CircuitParams::new`. -/
def CircuitParams.new (range : Range) (m : Nat) : Result CircuitParams :=
  if m = 0 then .error .InvalidInput
  else
    let d := range.bits / Nat.log2 BASE
    let n_d := m * d
    let nm := next_power_of_two (max n_d BASE)
    .ok { range, m, d, n_d, nm }

variable (F) in
/-- `Constraints`. -/
structure Constraints where
  norm_weights : List F
  cn_l : List F
  cn_r : List F
  cn_o : List F
  cn_v : List F
  cl_v : List F
  lambda_al : F
  mu_am : F
  lambdas : List F

variable (F) in
/-- The state of the main loop of `Constraints::new`. -/
structure Constraints.Loop where
  norm_weights : List F
  cn_l : List F
  cn_r : List F
  cn_v : List F
  mu_am : F
  mu_pow : F
  mu_inv_pow : F
  base_pow : F

namespace Constraints

/-- Iteration `k` of the main loop of `Constraints::new`. -/
def loop_step (params : CircuitParams) (alpha mu mu_inv : F) (lambdas shape : List F)
    (st : Loop F) (k : Nat) : Loop F :=
  let lam_m := lambdas.getD params.m 0
  let base : F := BASE
  let mu_pow := st.mu_pow * mu
  let mu_inv_pow := st.mu_inv_pow * mu_inv
  let norm_weights := st.norm_weights ++ [mu_pow]
  let (cn_l, cn_r, mu_am, base_pow) :=
    if k < params.n_d then
      let mu_am := st.mu_am + mu_pow
      let base_pow := if k % params.d = 0 then one else st.base_pow
      (st.cn_l ++ [lambdas.getD (k / params.d) 0 * base_pow * mu_inv_pow],
        st.cn_r ++ [lam_m * mu_inv_pow + alpha], mu_am, base_pow * base)
    else (st.cn_l ++ [0], st.cn_r ++ [0], st.mu_am, st.base_pow)
  let cn_v := st.cn_v ++ [shape.getD k 0 * mu_inv_pow]
  { norm_weights, cn_l, cn_r, cn_v, mu_am, mu_pow, mu_inv_pow, base_pow }

/-- `Constraints::new`. -/
def new (params : CircuitParams) (alpha mu lambda : F) : Result (Constraints F) := do
  let mu_inv ← inverse mu
  let lambdas := power_vector lambda (params.m + 1)
  let lam_m := lambdas.getD params.m 0
  let shape := iterate (· * lam_m) (lambda * lam_m) (params.nm + H_LEN - 1)
  let st := (List.range params.nm).foldl (loop_step params alpha mu mu_inv lambdas shape)
    ⟨[], [], [], [], 0, one, one, one⟩
  let bm1 := BASE - 1
  let denominators := (List.range bm1).map fun k =>
    alpha * (alpha + ((k + 1 : Nat) : F)) * st.norm_weights.getD k 0
  let inverses ← batch_invert denominators
  let cn_o := pad_to ((List.range bm1).map fun k =>
    ((k + 1 : Nat) : F) * lam_m * inverses.getD k 0) params.nm
  let lambda_al := (params.n_d : F) * lam_m * (← inverse alpha)
  let cl_v := 0 :: (List.range' 1 (H_LEN - 1)).map fun p => shape.getD (params.nm + p - 1) 0
  return ⟨st.norm_weights, st.cn_l, st.cn_r, cn_o, st.cn_v, cl_v, lambda_al, st.mu_am, lambdas⟩

variable (self : Constraints F)

/-- `Constraints::p_n`. -/
def p_n (delta_inv : F) : Laurent (List F) :=
  .new 0 [self.cn_v, self.cn_r, self.cn_l, vec_scalar_mul delta_inv self.cn_o]

end Constraints

end Bppp
