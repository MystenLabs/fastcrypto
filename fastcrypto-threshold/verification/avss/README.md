<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto_threshold::threshold_schnorr::avss`

Proofs about fastcrypto-threshold's AVSS (`fastcrypto-threshold/src/threshold_schnorr/avss.rs`),
and the DKG and key rotation built on it.

* **Protocols.** The protocol theorems are about executions with Byzantine parties. They are
  proved in `Protocol/` with the Rust functions as black boxes, from properties of those functions
  (listed [below](#properties-of-the-rust-functions)) and an explicit model of the network and the
  callers ([below](#network-and-callers)). They hold for any implementation with those
  properties.
* **Primitives.** Most of those properties are proved for the Rust code, against a Lean
  translation of it made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust
  code carries no annotations. It is written in a style Aeneas can translate: loops instead of
  iterator chains and closures, and its `tracing` logging compiled out under `cfg(aeneas)`, which
  Charon sets.

`Theorems.lean` states the protocol theorems marked *for the code* below with the translated
functions in place of the black boxes. Every declaration has a doc comment stating it in Rust
terms.

## Theorems

### Protocols

The parties have weights, a threshold `t` and a bound `f` on the corrupt weight, as in
`Parameters`. The parameters pass `Parameters::validate`, and the corrupt parties, which may behave
arbitrarily and are fixed for the run, have weight at most `f`. A message `m` is *certified* by
`signers` if the signers have weight at least `t + f` and every honest signer got `Valid` from
`process_message(m)` (`Certificate`).

#### AVSS

1. **`every_honest_party_gets_valid_shares`: AVSS is live.** *For the code.* For a certified
   message, every honest party `i` eventually holds an output whose shares pass
   `SharesForNode::verify(m, share_ids_of(i), i)`, directly from `process_message` or through
   complaints and `recover`.

2. **`honest_outputs_agree`: honest outputs agree.** *For the code.* There is one polynomial of
   degree `< t` that all outputs honest parties hold for a certified message fit: their shares are
   its evaluations at their share ids, and their Feldman commitment at `k` commits to its value at
   `k`. So any `t` honest shares at distinct indices give the same `recover_c0`
   (`honest_shares_recover_same_secret`).

3. **`honest_dealer_secret_shared`: an honest dealer's secret is shared.** For a message from
   `create_message`, the polynomial of theorem 2 has the dealer's `secret` as constant term.

4. **`honest_dealer_no_complaints`: an honest dealer gets no complaints.** *For the code.* If every
   receiver finds `m` valid, every honest party gets valid shares from `process_message` and never
   complains. Such a message is certified by the honest parties if their weight is at least
   `t + f` (`honest_dealer_certifiable`), which holds when the total weight is at least `t + 2f`
   (`honest_dealer_certifiable_of_params`).

5. **`corrupt_can_block_certificate`: corrupt parties can block a dealer.** If the total weight is
   below `t + f + weight(corrupt)`, every certificate needs a corrupt signer, so the corrupt
   parties can block even an honest dealer. `validate` allows this.

#### DKG

Each party combines the outputs of the dealers it accepted with `complete_dkg`.

6. **`dkg_outputs_agree` and `dkg_recover_same_secret`: DKG shares agree.** If all honest parties
   combine the outputs of the same certified dealers of weight `≥ t`, `complete_dkg` returns `Ok`
   for each of them (`dkg_completes`), their shares are shares of the sum of the dealers'
   polynomials, `commitment_for_index(k)` commits to its value at `k`, and any `t` honest DKG
   shares recover the sum of the dealers' secrets.

7. **`dkg_recover_same_secret_of_tob`: DKG over the total-order broadcast.** When each party
   accepts the first certified dealers on the TOB until their weight reaches `t`, any `t` honest
   DKG shares recover one joint secret, without assuming that the parties agree on the dealers:
   honest parties accept the same certificate for each dealer (`accepted_same_cert`), the same
   dealers once done (`done_accepted_eq`), and at least one dealer that is not corrupt
   (`done_has_honest_dealer`).

8. **`every_honest_party_completes_dkg`: DKG is live.** Every honest party is eventually done,
   holds an output from each dealer it accepted, and `complete_dkg` returns `Ok` on them.

#### Key rotation

Each old share `s_u` is reshared by its own AVSS instance, whose receivers have
`commitment = Some(G::generator() * s_u)`, and each party combines `t_old` of the outputs with
`complete_key_rotation`.

9. **`key_rotation_keeps_secret`: key rotation keeps the secret.** If every honest party combines
   the outputs of the same `t_old` resharing instances, the new shares lie on one polynomial of
   degree `< t` with the old secret as constant term, and `commitment_for_index(k)` commits to its
   value at `k`.

### Primitives

`Rᵢ` is the `Receiver` of party `i`. "Receivers configured alike" have the same `nodes`, `params`,
`sid` and `commitment`. These hold for the code, under the assumptions [below](#for-the-code).

10. **`feldman_binding`: an accepted message binds the shares.** If `Rᵢ.process_message(m)` does
    not return an error, there is a scalar polynomial `p` of degree `< t` such that every share
    that passes `SharesForNode::verify(m, ids, j)`, for any `j`, is `p` evaluated at its index. A
    dealer cannot give two parties shares of different polynomials for the same message.

11. **`process_invalid_iff`: receivers agree on invalid messages.** For receivers configured
    alike, `Rᵢ.process_message(m)` returns an error iff `Rⱼ.process_message(m)` does.

12. **`handle_accepts` and `response_verifies`: complaints are answered.** For receivers
    configured alike, if `Rᵢ.process_message(m)` returns a complaint and `Rⱼ.process_message(m)`
    returns valid shares, `Rⱼ.handle_complaint` answers the complaint, and
    `Rᵢ.verify_complaint_response` accepts the answer.

13. **`recover_sound` and `recover_complete`: recovery works.** If `Rᵢ.recover(m, vs)` returns
    shares, they pass `SharesForNode::verify(m, share_ids_of(i), i)`. If `Rᵢ.process_message(m)`
    did not return an error and `vs` are responses that `Rᵢ.verify_complaint_response` accepted,
    from distinct responders with total weight between `t` and `u16::MAX`, `Rᵢ.recover(m, vs)`
    returns shares.

14. **`complete_key_rotation_ok` and `complete_key_rotation_commitment`: key rotation
    interpolates.** If `complete_key_rotation(t, i, nodes, outputs)` returns `dk`, there are `t`
    outputs, and with `(c, λ)` the Lagrange coefficients for their indices, `dk`'s share at each
    of `share_ids_of(i)` is `Σᵤ λᵤ·c` times output `u`'s share there, and
    `dk.commitment_for_index(k)` is `G::generator() * Σᵤ λᵤ·c·yᵤ` where output `u`'s commitment
    is `G::generator() * yᵤ` at `k`.

## What is assumed

Each named assumption is a `def` or `structure` in the Lean files, and each theorem takes the ones
it needs as hypotheses. There is no `sorry`, and no axiom beyond the translation's.

### Network and callers

A run is the states `σ n` of the parties at times `n ∈ ℕ`. Each assumption is a field of the
structure named, documented as a *caller obligation* (something an application such as Hashi must
do) or a *network assumption*; `grep -rni "caller obligation" Protocol` lists them.

* **`Certificate`** (caller): the signers have weight at least `t + f`, and an honest party signs
  only on `Valid`. Signatures cannot be forged.
* **`BasicRun`**, for all the protocol theorems (caller): honest parties store exactly what the
  functions return (`HonestComputes`), never forget it (`Grows`), eventually hold the certified
  message, and run `process_message` on it.
* **`Run`**, for theorems 1 and 8: `BasicRun`, and honest parties send their complaints, honest
  signers answer the complaints they can answer, and a party with a complaint runs `recover` on
  the responses it verified (caller). Complaints and responses between honest parties are
  delivered (network).
* **`Tob` and `TobRun`**, for theorem 7: honest parties read prefixes of one log (network), check
  certificates (caller), and run the instance of each dealer they accept and hold its output
  (caller). **`TobLive`**, for theorem 8, adds: views only grow, and every honest dealer's
  certificate eventually reaches every honest party (network), once the dealer gets one and posts
  it (caller).
* **The same inputs**, for theorems 6 and 9: all honest parties pass the same dealers to
  `complete_dkg`, and the same `t_old` outputs to `complete_key_rotation` (caller).

### Properties of the Rust functions

The protocol theorems assume these properties of the Rust functions (the fields of `Contracts`,
`DkgContracts` and `RotationContracts`). The last column says whether each is proved for the code,
by the `Protocol/Link*.lean` files.

| Property | Statement | For the code |
|---|---|---|
| `process_valid` | `process_message` returning `Valid(o)` ⇒ `o`'s shares verify. | Proved |
| `process_invalid_iff` | `process_message` is `Err` for one receiver iff for all. | Proved (11) |
| `handle_accepts` | A complaint from `process_message` is answered by `handle_complaint` of any receiver with `Valid`. | Proved (12) |
| `response_verifies` | Such a response passes `verify_complaint_response`. | Proved (12) |
| `verify_binds` | A verified response's `responder_id` is the given responder. | Proved |
| `recover_complete` | `recover` succeeds on verified responses from distinct parties of weight `≥ t`. | Proved (13) |
| `recover_sound` | `recover` returning `Ok(o)` ⇒ `o`'s shares verify. | Proved (13) |
| `feldman_binding` | A message accepted by any receiver binds all verifying shares to one polynomial of degree `< t`. | Proved (10) |
| `output_commitment` | An output's Feldman commitment at `k` commits to the value at `k` of the polynomial the message binds to. | Proved |
| `create_valid` | A message from `create_message` is valid for all receivers except with probability `≤ 1/|S|`. | Assumed (`CreateValid`) |
| `create_secret` | The polynomial a message from `create_message` binds to has the dealer's `secret` as constant term. | Assumed (`CreateSecret`) |
| `complete_sum` | `complete_dkg`'s shares are the sums of the dealers' shares. | Not linked: `complete_dkg` is not translated (it takes a `HashMap`) |
| `complete_ok` | `complete_dkg` succeeds on distinct dealers of weight `≥ t` with shares at the same indices. | Not linked, as above |
| `complete_commitments` | `complete_dkg`'s `commitment_for_index(k)` is the sum of the outputs' Feldman commitments at `k`. | Not linked, as above |
| `process_matches_commitment` | A message accepted by a receiver with `commitment = G::generator() * s` binds to a polynomial with constant term `s`. | Proved |
| `rotation_interpolates` | Each share from `complete_key_rotation` is `recover_c0` of the outputs' shares at that index. | Proved (14) |
| `rotation_commitments` | `complete_key_rotation`'s `commitment_for_index(k)` is the Lagrange combination of the outputs' Feldman commitments at `k`. | Proved (14) |

Key rotation also assumes `Contracts` for each resharing instance, whose receivers have
`commitment = G::generator() * s` and whose dealers have `secret = s`. The DKG and key-rotation
theorems also assume the properties of `polynomial.rs` listed in `../polynomial/README.md`
(`Shamir.Contracts`).

### For the code

`Link.api` builds the black boxes from the translated functions. The parties are the ids that
`nodes.weight_of` accepts, with the weights it returns, and party `j` runs a receiver with id `j`;
all receivers have the same `nodes`, `params`, `sid` and `commitment`. A Rust `Err`, a panic and a
call that does not return all become a failure. The group is not modelled: `G::generator() * x`
is `gen(x)` for `x` in a field `F` (`Link.Scalars`).

The proofs about the code assume:

* **Translation.** The proofs are about the Lean code in `Generated/`, so they trust that Charon
  and Aeneas translate `avss.rs` faithfully. They also trust the changes `fix_aeneas_output.py`
  makes to that code:
  * serde's traits refer to each other, which Lean does not accept for structures. Their
    structures are emptied, and the derived `Serialize` and `Deserialize` code of the AVSS types
    becomes axioms. No proof uses serialization.
  * `core::num::nonzero::ZeroablePrimitive` gets two fields with the same name. One is renamed.
  * An instance that refers to itself (the `BCSSerialized` impl of `SharesForNode`), and any
    function whose body Aeneas could not translate (`check_recovery_proof`, because of its
    closure), become axioms.
  * A Rust parameter named `nodes` (of `complete_key_rotation`) shadows the `nodes` module, so the
    generated code refers to that module's functions from the root namespace.
  * Two functions that Aeneas' library does not model are defined: `Result::is_err` returns `true`
    exactly for `Err`, and `IntoIterator::into_iter` for `&Vec` returns an iterator over the
    vector's elements.

  Code in other modules and crates is opaque: Lean sees only the signatures of what `avss.rs`
  calls, and those functions are arbitrary unless an assumption below says otherwise.
* **Standard library and opaque types.** `SharesForNode::clone` and `Poly::clone` return their
  argument (`CloneIsId`, `PolyCloneIsId`), `Poly::eq` of a polynomial with itself is `true`
  (`PolyEqRefl`), `==` on secp256k1 points is `true` only for equal points (`PointEqSound`), and
  `NonZeroU16::get` returns a positive value that determines the `NonZeroU16` (`NonZeroGetInj`,
  `NonZeroModel`).
* **Recovery proof** (`RecoveryComplete`). For receivers configured alike, a complaint
  `Rᵢ.create_complaint` makes about a message whose shares `Rᵢ.verify_message` rejected is accepted
  by `Rⱼ.check_recovery_proof`.
* **Interpolation** (`InterpolationComplete`). For a message that passes `Rᵢ.check_message`, the
  shares of responses `Rᵢ.verify_complaint_response` returned for distinct responders of total
  weight `≥ t` make `SharesForNode::recover` return shares that verify for `Rᵢ`.
* **Feldman commitments over secp256k1** (`CommitmentOpening`). A commitment `c` of degree `d`
  opens to a scalar polynomial `p` of degree `≤ d` such that `p.eval(k)` returns and
  `c.eval(k) = G::generator() * p.eval(k)` for every `k`, a share passes `verify_share` exactly
  when its value is `p.eval` at its index, and `c.c0() = G::generator() * p.c0()`. It implies
  `CommitmentBinding`, which theorem 10 takes.
* **Group and scalars.** `gen` is injective, and `Poly::eval` on a commitment returns a multiple of
  `G::generator()` (`EvalInGroup`). A map from secp256k1 scalars to `F` takes the `zero`, `+=` and
  `*` that `complete_key_rotation` uses to `F`'s (`ScalarHom`).
* **`polynomial.rs`**, which is not translated. Scalar polynomials of degree `< t` that agree at
  `t` distinct indices agree everywhere (`EvalDetermined`). `recover_c0` is `Σⱼ yⱼ·λⱼ·c` for the
  coefficients `(c, λ)` that `get_lagrange_coefficients_for_c0` returns for the same indices
  (`LagrangeRecover`). `Poly::multi_scalar_mul` and `eval_range` evaluate as their docs say
  (`MsmEval`, `EvalRangeSound`).
* **Dealer** (`CreateValid`, `CreateSecret`): the two properties assumed above. The dealer is not
  translated: its type, `create_message`'s distribution and its `secret` stay abstract
  (`Link.Dealers`).
* **Nodes and parameters.** Every party has share ids (`share_ids_of(j)` is `Ok`), the weights of
  any set of parties add up to at most `u16::MAX`, and the share ids include `t` distinct indices
  (`SharesCoverT`).
* **`process_message`** returns, without a panic, for every party and message.

`Theorems.lean` bundles these as `Link.Assumptions`.

## What is not proved

* `create_valid` and `create_secret` are assumed: `Dealer` is not translated.
* `complete_dkg` is not translated: it takes a `HashMap`. So the DKG properties are not proved for
  the code, and the DKG theorems are not stated for it.
* `polynomial.rs` is not translated, so its properties are assumed.
* The key-rotation properties are proved for the code, but theorem 9 is not yet stated for it.

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | Theorems 1, 2 and 4 for the code, and their assumptions together (`Link.Assumptions`). |
| `Protocol/Setup.lean` | Parties, weights, `t` and `f` (`Setup`), and the checks of `Parameters::validate` (`Valid`). |
| `Protocol/Steps.lean` | The functions of `avss.rs` as black boxes (`Api`) and their properties (`Contracts`). |
| `Protocol/Execution.lean` | The execution model (`Certificate`, `State`, `BasicRun`, `Run`), and theorem 1. |
| `Protocol/Agreement.lean` | Theorems 2 and 3. |
| `Protocol/HonestDealer.lean` | Theorems 4 and 5. |
| `Protocol/Dkg.lean` | `complete_dkg` as a black box with its properties (`DkgApi`, `DkgContracts`), and theorem 6. |
| `Protocol/Tob.lean` | Reading certificates from the total-order broadcast (`Tob`, `TobRun`), and theorem 7. |
| `Protocol/Liveness.lean` | The TOB over time (`TobLive`), and theorem 8. |
| `Protocol/KeyRotation.lean` | Receivers with a `commitment` and `complete_key_rotation` as black boxes (`RotationApi`, `RotationContracts`), and theorem 9. |
| `Protocol/Link.lean`, `Protocol/LinkCommitment.lean`, `Protocol/LinkRotation.lean` | The black boxes built from the translated functions (`Link.api`), and the proofs that they have the properties. |
| `FeldmanBinding.lean` | Theorem 10. |
| `ProcessInvalidIff.lean` | Theorem 11. |
| `HandleAccepts.lean`, `ResponseVerifies.lean` | Theorem 12. |
| `RecoverSound.lean`, `RecoverComplete.lean` | Theorem 13. |
| `KeyRotation.lean`, `RotationCommitment.lean` | Theorem 14. |
| `VerifyBinds.lean`, `ProcessValid.lean`, `VerifyComplete.lean`, `OutputCommitment.lean`, `Loops.lean` | Further properties of the receiver functions, for the link. |
| `Result.lean` | Reasoning about the generated `Result`, and the `ok_inv` tactic. |
| `Generated/` | The translation of `avss.rs`, made by `extract.sh`. |
| `extract.sh` | Regenerates `Generated/`: get `charon` and `aeneas` from the Aeneas release it names and run `CHARON=... AENEAS=... ./extract.sh`. |
| `fix_aeneas_output.py` | Patches Aeneas output that Lean rejects. Called by `extract.sh`. |

The Verus proofs of some of these results are in
[MystenLabs/fastcrypto#1155](https://github.com/MystenLabs/fastcrypto/pull/1155).
