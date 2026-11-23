/-
The AVSS functions of fastcrypto-threshold/src/threshold_schnorr/avss.rs as black boxes (`Api`), and
what we expect from them (`Contracts`).
-/
import Avss.Protocol.Setup
import Shamir.Protocol.Steps

namespace Protocol.Avss

/-- Result of `Receiver::process_message`. -/
inductive Processed (Output Complaint : Type) where
  /-- `Err(InvalidMessage)` or `Err(InvalidInput)`: the message is ignored. -/
  | invalid
  /-- `Ok(ProcessedMessage::Valid(output))`. -/
  | valid (output : Output)
  /-- `Ok(ProcessedMessage::Complaint(complaint))`. -/
  | complaint (complaint : Complaint)

/-- The AVSS API of fastcrypto as black boxes, with the names and inputs/outputs of the Rust
functions and no implementation.

The functions are total, pure and deterministic. In particular:
* a Rust `Err` is `none` (or `Processed.invalid`); a panic cannot be represented, so a contract
  saying a function returns a value also claims that it does not panic on those inputs;
* `process_message` uses an `rng` only to create the complaint's proof; that randomness is
  abstracted away.

All receivers are configured alike: the same `Nodes`, `Parameters`, session id and `commitment`,
and each receiver's encryption key matches its public key in `Nodes`. Several contracts rely on
this; they say so. -/
structure Api (Party : Type) where
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Message`: the dealer's broadcast (Feldman
  commitment and encrypted shares). -/
  Message : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Complaint`. -/
  Complaint : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::ComplaintResponse`. -/
  Response : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::VerifiedComplaintResponse`. -/
  Verified : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::AvssOutput`. -/
  Output : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::SharesForNode`. -/
  Shares : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::process_message`, run by receiver `i`. -/
  processMessage : (i : Party) → Message → Processed Output Complaint
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::handle_complaint`, run by `j` with its
  own output. `none` is an `Err`. -/
  handleComplaint : (j : Party) → Message → (accuser : Party) → Complaint → Output →
    Option Response
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::verify_complaint_response`, run by the
  accuser `i`. `none` is an `Err`. -/
  verifyComplaintResponse : (i : Party) → Message → (responder : Party) → Response →
    Option Verified
  /-- `fastcrypto_threshold::threshold_schnorr::avss::VerifiedComplaintResponse::responder_id`. -/
  responderId : Verified → Party
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Receiver::recover`, run by the accuser `i`. `none`
  is an `Err`. -/
  recover : (i : Party) → Message → List Verified → Option Output
  /-- `fastcrypto_threshold::threshold_schnorr::avss::AvssOutput::my_shares`. -/
  shares : Output → Shares
  /-- `fastcrypto_threshold::threshold_schnorr::avss::SharesForNode::verify` with `share_ids_of(i)` and
  `i`, `is_ok()`: the share indices are exactly `share_ids_of(i)`, in order, and each share is
  consistent with the message's Feldman commitment. -/
  verifyShares : Message → (i : Party) → Shares → Bool
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Dealer`. -/
  Dealer : Type
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Dealer::create_message`: the distribution of the
  message it returns, over the randomness of `rng`. -/
  createMessage : Dealer → PMF Message
  /-- The scalar field, `fastcrypto_threshold::threshold_schnorr::S`. -/
  F : Type
  [instField : Field F]
  [instFintype : Fintype F]
  /-- `fastcrypto_threshold::threshold_schnorr::avss::Dealer::secret`: the `secret` passed to
  `Dealer::new`, or the one sampled there if it is `None`. -/
  secret : Dealer → F
  /-- `fastcrypto_threshold::threshold_schnorr::avss::AvssOutput::feldman_commitment`, evaluated:
  `committed o k = x` means `o.feldman_commitment.eval(k) = G::generator() * x`. The group is not
  modelled; this uses that `x ↦ G::generator() * x` is a bijection. -/
  committed : Output → Shamir.ShareIndex → F
  /-- `fastcrypto_threshold::polynomial::Poly` over `S` and its API, as specified in
  `Protocol.Shamir`. -/
  Sh : Shamir.Api F
  /-- `fastcrypto_threshold::nodes::Nodes::share_ids_of`. -/
  shareIds : Party → List Shamir.ShareIndex
  /-- `fastcrypto_threshold::threshold_schnorr::avss::SharesForNode::shares`. -/
  shareList : Shares → List (Shamir.Eval F)

attribute [instance] Api.instField Api.instFintype

open scoped ENNReal

variable {Party : Type} [DecidableEq Party]

/-- `o` holds valid shares for party `i` on message `m`: its shares pass
`SharesForNode::verify(m, share_ids_of(i), i)`. -/
def Api.ValidOutput (A : Api Party) (m : A.Message) (i : Party) (o : A.Output) : Prop :=
  A.verifyShares m i (A.shares o) = true

/-- Every receiver finds `m` valid: `Rᵢ.process_message(m) = Valid(o)` for some `o`, for every
`i`. -/
def Api.AllValid (A : Api Party) (m : A.Message) : Prop :=
  ∀ i, ∃ o, A.processMessage i m = .valid o

/-- `v` was returned by `verify_complaint_response` for accuser `i` on message `m`, for some
responder and response. -/
def Api.IsVerified (A : Api Party) (i : Party) (m : A.Message) (v : A.Verified) : Prop :=
  ∃ j r, A.verifyComplaintResponse i m j r = some v

/-- What we expect from the Rust functions. `Rᵢ` is party `i`'s `Receiver`. Several contracts rely
on all receivers being configured alike (see `Api`). -/
structure Contracts (S : Setup Party) (A : Api Party) : Prop where
  /-- `Rᵢ.process_message(m) = Valid(o)` ⇒ `o.my_shares.verify(m, share_ids_of(i), i)` is `Ok`. -/
  process_valid : ∀ i m o, A.processMessage i m = .valid o → A.ValidOutput m i o
  /-- `Rᵢ.process_message(m) = Err` ⇔ `Rⱼ.process_message(m) = Err`. -/
  process_invalid_iff : ∀ i j m,
    A.processMessage i m = .invalid ↔ A.processMessage j m = .invalid
  /-- `Rᵢ.process_message(m) = Complaint(c)` and `Rⱼ.process_message(m) = Valid(o)` ⇒
  `Rⱼ.handle_complaint(m, i, c, o) = Ok(r)` for some `r`. -/
  handle_accepts : ∀ i j m c o, A.processMessage i m = .complaint c →
    A.processMessage j m = .valid o → ∃ r, A.handleComplaint j m i c o = some r
  /-- `Rⱼ.process_message(m) = Valid(o)` and `Rⱼ.handle_complaint(m, i, c, o) = Ok(r)` ⇒
  `Rᵢ.verify_complaint_response(m, j, r) = Ok(v)` for some `v`. -/
  response_verifies : ∀ i j m c o r, A.processMessage j m = .valid o →
    A.handleComplaint j m i c o = some r → ∃ v, A.verifyComplaintResponse i m j r = some v
  /-- `Rᵢ.verify_complaint_response(m, j, r) = Ok(v)` ⇒ `v.responder_id = j`. -/
  verify_binds : ∀ i m j r v, A.verifyComplaintResponse i m j r = some v → A.responderId v = j
  /-- `Rᵢ.process_message(m) ≠ Err`, each `v ∈ vs` is returned by
  `Rᵢ.verify_complaint_response(m, …)`, and the responders of `vs` are distinct with total weight
  `≥ t` ⇒ `Rᵢ.recover(m, vs) = Ok(o)` for some `o`. -/
  recover_complete : ∀ i m (vs : List A.Verified), A.processMessage i m ≠ .invalid →
    (∀ v ∈ vs, A.IsVerified i m v) → (vs.map A.responderId).Nodup →
    S.t ≤ S.weightOf (vs.map A.responderId).toFinset →
    ∃ o, A.recover i m vs = some o
  /-- `Rᵢ.recover(m, vs) = Ok(o)` ⇒ `o.my_shares.verify(m, share_ids_of(i), i)` is `Ok`. -/
  recover_sound : ∀ i m (vs : List A.Verified) o, A.recover i m vs = some o → A.ValidOutput m i o
  /-- `Pr[some Rᵢ.process_message(m) is not Valid] ≤ 1/|S|` for `m = d.create_message()`, where
  `|S|` is the size of the scalar field. -/
  create_valid : ∀ d, (A.createMessage d).toOuterMeasure {m | ¬ A.AllValid m} ≤
    (Fintype.card A.F : ℝ≥0∞)⁻¹
  /-- `m = d.create_message()` ⇒ every `p` with `p.degree_bound() < t` such that, for all `j` and
  `sh`, `sh.verify(m, share_ids_of(j), j)` is `Ok` ⇒ `sh.shares = [p.eval(k) for k in
  share_ids_of(j)]`, has `p.c0() = d.secret`. -/
  create_secret : ∀ d m, m ∈ (A.createMessage d).support → ∀ p, A.Sh.degreeBound p < S.t →
    (∀ j sh, A.verifyShares m j sh = true → A.shareList sh = (A.shareIds j).map (A.Sh.eval p)) →
    A.Sh.c0 p = A.secret d
  /-- `Rᵢ.process_message(m) ≠ Err` ⇒ there is a `p` with `p.degree_bound() < t` such that, for
  all `j` and `sh`, `sh.verify(m, share_ids_of(j), j)` is `Ok` ⇒
  `sh.shares = [p.eval(k) for k in share_ids_of(j)]`. -/
  feldman_binding : ∀ i m, A.processMessage i m ≠ .invalid →
    ∃ p, A.Sh.degreeBound p < S.t ∧
      ∀ j sh, A.verifyShares m j sh = true → A.shareList sh = (A.shareIds j).map (A.Sh.eval p)
  /-- `Rᵢ.process_message(m) ≠ Err`, `o` is returned by `Rᵢ.process_message(m)` (as `Valid(o)`) or
  by `Rᵢ.recover(m, vs)`, and `p` with `p.degree_bound() < t` is such that, for all `j` and `sh`,
  `sh.verify(m, share_ids_of(j), j)` is `Ok` ⇒ `sh.shares = [p.eval(k) for k in share_ids_of(j)]`
  ⇒ `o.feldman_commitment.eval(k) = G::generator() * p.eval(k)` for all `k`. -/
  output_commitment : ∀ i m o, A.processMessage i m ≠ .invalid →
    (A.processMessage i m = .valid o ∨ ∃ vs, A.recover i m vs = some o) →
    ∀ p, A.Sh.degreeBound p < S.t →
      (∀ j sh, A.verifyShares m j sh = true → A.shareList sh = (A.shareIds j).map (A.Sh.eval p)) →
      ∀ k, A.committed o k = (A.Sh.eval p k).value

end Protocol.Avss
