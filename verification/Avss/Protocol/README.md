# AVSS: protocol level

The AVSS protocol of `fastcrypto_threshold::threshold_schnorr::avss`, and DKG and key rotation
built on it, with the link to the code. Each file builds on the ones above it.

| File | Contents |
|---|---|
| `Setup.lean` | Parties, weights, `t` and `f` (`Setup`), `weightOf`, `Tolerates`, the checks of `Parameters::validate` (`Valid`), and weight lemmas. |
| `Steps.lean` | The functions of `avss.rs` as black boxes (`Api`) and the lemmas the protocol needs from them (`Contracts`). |
| `Execution.lean` | The execution model and its assumptions (`Certificate`, `State`, `HonestComputes`, `Grows`, `BasicRun`, `Run`), and liveness. |
| `HonestDealer.lean` | A dealer whose message every receiver finds valid: no complaints, certifiable when the honest weight is at least `t + f`, and corrupt parties can block certification. |
| `Agreement.lean` | All honest outputs fit one polynomial, so any `t` honest shares recover the same secret. |
| `Dkg.lean` | `complete_dkg` as a black box with its lemmas (`DkgApi`, `DkgContracts`), and the DKG theorems. |
| `Tob.lean` | Reading dealer certificates from the total-order broadcast (`Cert`, `accepted`, `Tob`, `TobRun`). |
| `KeyRotation.lean` | Key rotation: receivers with a `commitment` and `complete_key_rotation` as black boxes (`RotationApi`, `RotationContracts`), and the instance resharing a share `s` (`RotationApi.at`). |
| `Liveness.lean` | The TOB over time (`TobLive`) and DKG liveness. |
| `Link.lean` | The `Api` of the generated code (`Link.api`), the proof of `Contracts` for it, and liveness, agreement and the honest-dealer theorem for the code. |
| `LinkRotation.lean` | `process_matches_commitment` and `rotation_interpolates` for the generated code. |

The group is not modelled: a commitment `G::generator() * x` is represented by `x`
(`Api.committed`, `DkgApi.commitmentForIndex`).

## Theorems

Proved from the lemmas below and the assumptions of `Execution.lean`, `Tob.lean`,
`KeyRotation.lean` and `Liveness.lean`, with no `sorry` or axioms. The corrupt parties have weight
at most `f` (`Setup.Tolerates`) and the parameters pass `Parameters::validate` (`Setup.Valid`).

| Theorem | File | Statement |
|---|---|---|
| `every_honest_party_gets_valid_shares` | `Execution.lean` | Liveness: for a certified message, every honest party eventually holds shares that pass `SharesForNode::verify`, directly or through complaints and `recover`. |
| `honest_dealer_no_complaints` | `HonestDealer.lean` | If every receiver finds the message valid, every honest party gets valid shares from `process_message` and never complains. |
| `honest_dealer_certifiable` | `HonestDealer.lean` | Such a message is certified by the honest parties if their weight is at least `t + f`. |
| `honest_dealer_certifiable_of_params` | `HonestDealer.lean` | The same when `W ≥ t + 2f`. |
| `corrupt_can_block_certificate` | `HonestDealer.lean` | If `W < t + f + weightOf(corrupt)`, every certificate needs a corrupt signer, so the corrupt parties can block even an honest dealer. `validate` allows this. |
| `honest_outputs_agree` | `Agreement.lean` | All honest outputs of a certified message fit one polynomial of degree `< t`, in their shares and their Feldman commitments. |
| `honest_shares_recover_same_secret` | `Agreement.lean` | Any `t` honest shares at distinct indices give the same `recover_c0`. |
| `honest_dealer_secret_shared` | `Agreement.lean` | For a message from `create_message`, the polynomial all honest outputs fit has the dealer's `secret` as constant term. |
| `dkg_completes` | `Dkg.lean` | `complete_dkg` returns `Ok` for every honest party, given certified dealers of weight `≥ t`. |
| `dkg_outputs_agree` | `Dkg.lean` | Honest `complete_dkg` outputs are shares of the sum of the dealers' polynomials, and their `commitment_for_index(k)` commits to its value at `k`. |
| `dkg_recover_same_secret` | `Dkg.lean` | Any `t` honest DKG shares recover the sum of the dealers' secrets. |
| `accepted_same_cert` | `Tob.lean` | Honest parties accept the same certificate for each dealer. |
| `done_accepted_eq` | `Tob.lean` | Honest parties that are done accept the same dealers. |
| `done_has_honest_dealer` | `Tob.lean` | The dealers a party accepts once done include one that is not corrupt. |
| `dkg_recover_same_secret_of_tob` | `Tob.lean` | DKG over the TOB: any `t` honest DKG shares recover one joint secret, without assuming the parties agree on the dealers. |
| `key_rotation_keeps_secret` | `KeyRotation.lean` | If every honest party combines the outputs of the same `t_old` resharing instances with `complete_key_rotation`, the new shares lie on one polynomial of degree `< t` with the old secret as constant term, and `commitment_for_index(k)` commits to its value at `k`. |
| `every_honest_party_completes_dkg` | `Liveness.lean` | DKG liveness: every honest party is eventually done, holds an output from each dealer it accepted, and `complete_dkg` returns `Ok` on them. |

## Lemmas about the code

What the theorems assume about the Rust code; the Lean docs are the precise statements. The last
column says how each holds for the generated code (`Link.api`): proved in `Link.lean` or
`LinkRotation.lean` from the primitive lemma named, or a hypothesis there.

| Lemma | Statement | For the code |
|---|---|---|
| `process_valid` | `process_message` returning `Valid(o)` ⇒ `o`'s shares verify. | Proved (`process_valid`) |
| `process_invalid_iff` | `process_message` is `Err` for one receiver iff for all. | Proved (`process_invalid_iff`) |
| `handle_accepts` | A complaint from `process_message` is answered by `handle_complaint` of any receiver with `Valid`. | Proved (`handle_accepts`) |
| `response_verifies` | Such a response passes `verify_complaint_response`. | Proved (`response_verifies`) |
| `verify_binds` | A verified response's `responder_id` is the given responder. | Proved (`verify_binds`) |
| `recover_complete` | `recover` succeeds on verified responses from distinct parties of weight `≥ t`. | Proved (`recover_complete`) |
| `recover_sound` | `recover` returning `Ok(o)` ⇒ `o`'s shares verify. | Proved (`recover_sound`) |
| `feldman_binding` | A message accepted by any receiver binds all verifying shares to one polynomial of degree `< t`. | Proved (`feldman_binding`) |
| `create_valid` | A message from `create_message` is valid for all receivers except with probability `≤ 1/|S|`. | Hypothesis (`CreateValid`) |
| `create_secret` | The polynomial a message from `create_message` binds to has the dealer's `secret` as constant term. | Hypothesis (`CreateSecret`) |
| `output_commitment` | An output's Feldman commitment at `k` commits to the value at `k` of the polynomial the message binds to. | Hypothesis (`OutputCommitment`) |
| `complete_sum` | `complete_dkg`'s shares are the sums of the dealers' shares. | Not linked: `complete_dkg` is not translated (it uses a `HashMap`) |
| `complete_ok` | `complete_dkg` succeeds on distinct dealers of weight `≥ t` with shares at the same indices. | Not linked, as above |
| `complete_commitments` | `complete_dkg`'s `commitment_for_index(k)` is the sum of the outputs' Feldman commitments at `k`. | Not linked, as above |
| `process_matches_commitment` | A message accepted by a receiver with `commitment = g^s` binds to a polynomial with constant term `s`. | Proved (`LinkRotation.process_matches_commitment`) |
| `rotation_interpolates` | Each share from `complete_key_rotation` is `recover_c0` of the outputs' shares at that index. | Proved (`LinkRotation.rotation_interpolates`, from `complete_key_rotation_ok`) |
| `rotation_commitments` | `complete_key_rotation`'s `commitment_for_index(k)` is the Lagrange combination of the outputs' Feldman commitments at `k`. | Not proved yet |

Key rotation also assumes all of `Contracts` for each resharing instance (`RotationApi.at s`): its
receivers have `commitment = g^s` and its dealers have `secret = s`. The two rotation lemmas are
proved as separate theorems; `RotationApi` and `RotationContracts` are not yet assembled for the
code.

## The link to the code

`Link.api` builds `Api` from the generated functions:

* The parties are the ids that `nodes.weight_of` accepts, and `weight(j)` is what it returns. `t`
  and `f` are those of `params`.
* Party `j` runs the receiver `recv(j)`, whose id is `j`. All receivers have the same `nodes`,
  `params`, `sid` and `commitment`. `recv(j)` passes the randomness `rng(j)` to `process_message`.
* A Rust `Err`, a panic and a call that does not return all become `none` (or `invalid` for
  `process_message`).
* The dealers stay abstract (`Link.Dealers`): their type, `create_message`'s distribution and their
  `secret`. So do `complete_dkg` and `commitment_for_index` (`LinkRotation.dkgApi`).
* `Link.Scalars` gives what `Api` needs and the code does not: the scalar field `F` and a map from
  secp256k1 scalars to it, `G::generator() * x` for `x` in `F` (`gen`), how a share index becomes a
  `NonZeroU16` (`ofIndex`), and the scalar-polynomial functions AVSS does not call
  (`rand_fixed_c0`, `add`, `mul`, `recover_c0`). `eval`, `degree_bound` and `c0` are the generated
  `Poly::eval`, `Poly::degree` and `Poly::c0`.

`Link.contracts` proves `Contracts` for `Link.api` from the primitive lemmas, under their
hypotheses (`../README.md`) and these, together `Link.Assumptions`:

* `CreateValid`, `CreateSecret`, `OutputCommitment`: the three lemmas the table lists as
  hypotheses. The first two are about `create_message`'s distribution and the dealer, which is not
  translated.
* `NonZeroModel`: `NonZeroU16::get` returns a positive value that determines the `NonZeroU16`, and
  `get()` of `ofIndex(k)` is `k`.
* Every party has share ids (`share_ids_of(j)` is `Ok`), and the weights of any set of parties add
  up to at most `u16::MAX`.
* `process_message` returns, without a panic, for every party and message.

`LinkRotation.process_matches_commitment` also assumes:

* `CommitmentOpening` (which implies `CommitmentBinding`): a commitment `c` of degree `d` opens to a
  scalar polynomial `p` of degree `≤ d` whose `eval` returns, a share passes `verify_share` exactly
  when its value is `p.eval` at its index, and `c.c0() = G::generator() * p.c0()`.
* `gen` is injective, and `PointEqSound`: `==` on secp256k1 points is `true` only for equal points.
* `SharesCoverT`: the parties' share ids include `t` distinct indices.
* `Shamir.Contracts` for the link's scalar-polynomial functions (only `recover_c0` is used).

`LinkRotation.rotation_interpolates` also assumes `ScalarHom` and `LagrangeRecover`: `recover_c0` is
`Σⱼ yⱼ·λⱼ·c` for the coefficients `(c, λ)` that `get_lagrange_coefficients_for_c0` returns for the
same indices, as `recover_c0` computes it.

The Verus proofs of some of the lemmas are in
[MystenLabs/fastcrypto#1155](https://github.com/MystenLabs/fastcrypto/pull/1155).
