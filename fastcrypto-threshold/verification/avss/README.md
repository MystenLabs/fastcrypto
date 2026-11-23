<!-- THIS FILE IS AI-ONLY -->
# `fastcrypto_threshold::threshold_schnorr::avss`

Proofs about fastcrypto-threshold's AVSS (`fastcrypto-threshold/src/threshold_schnorr/avss.rs`),
against a Lean translation of the Rust code made by
[Charon and Aeneas](https://github.com/AeneasVerif/aeneas). The Rust code carries no annotations.
It is written in a style Aeneas can translate: loops instead of iterator chains and closures, and
its `tracing` logging compiled out under `cfg(aeneas)`, which Charon sets.

The theorems are listed below. `Protocol/` has the protocol-level theorems, for AVSS, DKG and key
rotation, with the functions as black boxes; see `Protocol/README.md`. Every declaration has a doc
comment stating it in Rust terms.

## Theorems

`Rᵢ` is the `Receiver` of party `i`. "Receivers configured alike" have the same `nodes`, `params`,
`sid` and `commitment`.

### About the receiver functions alone

1. **`feldman_binding`: an accepted message binds the shares.** If `Rᵢ.process_message(m)` does
   not return an error, there is a scalar polynomial `p` of degree `< t` such that every share that
   passes `SharesForNode::verify(m, ids, j)`, for any `j`, is `p` evaluated at its index. A dealer
   cannot give two parties shares of different polynomials for the same message.

2. **`process_invalid_iff`: receivers agree on invalid messages.** For receivers configured alike,
   `Rᵢ.process_message(m)` returns an error iff `Rⱼ.process_message(m)` does.

3. **`handle_accepts` and `response_verifies`: complaints are answered.** For receivers configured
   alike, if `Rᵢ.process_message(m)` returns a complaint and `Rⱼ.process_message(m)` returns valid
   shares, `Rⱼ.handle_complaint` answers the complaint, and `Rᵢ.verify_complaint_response`
   accepts the answer.

4. **`recover_sound` and `recover_complete`: recovery works.** If `Rᵢ.recover(m, vs)` returns
   shares, they pass `SharesForNode::verify(m, share_ids_of(i), i)`. If `Rᵢ.process_message(m)`
   did not return an error and `vs` are responses that `Rᵢ.verify_complaint_response` accepted,
   from distinct responders with total weight between `t` and `u16::MAX`, `Rᵢ.recover(m, vs)`
   returns shares.

5. **`complete_key_rotation_ok` and `complete_key_rotation_commitment`: key rotation
   interpolates.** If `complete_key_rotation(t, i, nodes, outputs)` returns `dk`, there are `t`
   outputs, and with `(c, λ)` the Lagrange coefficients for their indices, `dk`'s share at each
   of `share_ids_of(i)` is `Σᵤ λᵤ·c` times output `u`'s share there, and
   `dk.commitment_for_index(k)` is `G::generator() * Σᵤ λᵤ·c·yᵤ` where output `u`'s commitment is
   `G::generator() * yᵤ` at `k`.

### About a protocol run (`Theorems.lean`)

Let `m` be a message certified by `signers`: each signer's `process_message(m)` did not return an
error, and the signers have weight at least `t` (`Certificate`). The corrupt parties have weight
at most `f`, and the parameters pass `Parameters::validate`.

6. **`every_honest_party_gets_valid_shares`: AVSS is live.** In an execution in which honest
   parties process `m`, answer complaints and recover as the protocol says (`Run`), every honest
   party `i` eventually holds an output whose shares pass
   `SharesForNode::verify(m, share_ids_of(i), i)`, directly from `process_message` or through
   complaints and `recover`.

7. **`honest_outputs_agree`: honest outputs agree.** There is one polynomial of degree `< t` that
   all outputs honest parties hold for `m` fit: their shares are its evaluations at their share
   ids, and their Feldman commitment at `k` commits to its value at `k`. So any `t` honest shares
   recover the same secret.

8. **`honest_dealer_no_complaints`: an honest dealer gets no complaints.** If every receiver finds
   `m` valid, every honest party eventually holds an output from `process_message` whose shares
   verify, and never complains.

Each theorem takes the assumptions [below](#what-is-assumed) that it needs; 6–8 take them all,
bundled as `Link.Assumptions`.

## Files

| File | Contents |
|---|---|
| `Theorems.lean` | Theorems 6–8, and their assumptions together (`Assumptions`). |
| `FeldmanBinding.lean` | Theorem 1, and what a message that passes `check_message` satisfies. |
| `ProcessInvalidIff.lean` | Theorem 2. |
| `HandleAccepts.lean`, `ResponseVerifies.lean` | Theorem 3. |
| `RecoverSound.lean`, `RecoverComplete.lean` | Theorem 4. |
| `KeyRotation.lean`, `RotationCommitment.lean` | Theorem 5. |
| `VerifyBinds.lean`, `ProcessValid.lean`, `VerifyComplete.lean`, `OutputCommitment.lean` | What `verify_complaint_response`, `process_message`, `SharesForNode::verify` and `recover` return, for the link to the code. |
| `Loops.lean` | The loops of `recover` and `all_distinct`. |
| `Result.lean` | Reasoning about the generated `Result`, and the `ok_inv` tactic: `ok_inv at h` breaks `h : f .. = ok y` into one hypothesis per step of `f`. |
| `Protocol/` | The protocol-level theorems and the link to the code. See `Protocol/README.md`. |
| `Generated/` | The translation of `avss.rs`, made by `extract.sh`. Code in other modules and crates is opaque: Lean sees only the signatures of what `avss.rs` calls, and of `Poly::eval`. |
| `extract.sh` | Regenerates `Generated/`. |
| `fix_aeneas_output.py` | Patches Aeneas output that Lean rejects. Called by `extract.sh`. |

To regenerate `Generated/` after changing `avss.rs`, get `charon` and `aeneas` from the Aeneas
release named in `extract.sh` and run `CHARON=... AENEAS=... ./extract.sh`.

## What is assumed

Each named assumption is a `def` or `structure` in the Lean files, and each theorem takes
the ones it needs as hypotheses. Opaque functions are arbitrary unless an assumption says
otherwise. A Rust `Err` is `ok (Err _)`, and a panic or a call that does not return is a Lean
`Result` other than `ok`.

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
  `CommitmentBinding`, which `feldman_binding` takes.
* **Group and scalars.** The group is not modelled: `G::generator() * x` is `gen(x)` for `x` in a
  field `F` (`Link.Scalars`), and `gen` is injective. `Poly::eval` on a commitment returns a
  multiple of `G::generator()` (`EvalInGroup`). A map from secp256k1 scalars to `F` takes the
  `zero`, `+=` and `*` that `complete_key_rotation` uses to `F`'s (`ScalarHom`).
* **`polynomial.rs`**, which is not translated. Scalar polynomials of degree `< t` that agree at
  `t` distinct indices agree everywhere (`EvalDetermined`). `recover_c0` is `Σⱼ yⱼ·λⱼ·c` for the
  coefficients `(c, λ)` that `get_lagrange_coefficients_for_c0` returns for the same indices
  (`LagrangeRecover`). `Poly::multi_scalar_mul` and `eval_range` evaluate as their docs say
  (`MsmEval`, `EvalRangeSound`). `Protocol/` also takes the lemmas of `polynomial/Protocol` about
  them as hypotheses.
* **Dealer** (`CreateValid`, `CreateSecret`). A message from `create_message` is valid for all
  receivers except with probability `≤ 1/|S|`, and binds to a polynomial with the dealer's
  `secret` as constant term. The dealer is not translated: its type, `create_message`'s
  distribution and its `secret` stay abstract (`Link.Dealers`).
* **Nodes and parameters.** Every party has share ids (`share_ids_of(j)` is `Ok`), the weights of
  any set of parties add up to at most `u16::MAX`, and the share ids include `t` distinct indices
  (`SharesCoverT`).
* **`process_message`** returns, without a panic, for every party and message.
* **Network and callers.** The execution model of `Protocol/` (`Certificate`, `Run`, ...), listed
  in `Protocol/README.md`.

## What is not proved

* `create_valid` and `create_secret` are assumptions, as above: `Dealer` is not translated.
* `complete_dkg` is not translated: it takes a `HashMap`. So the DKG lemmas are not proved for the
  code, and the DKG theorems of `Protocol/` are not stated for it.
* `polynomial.rs` is not translated, so its lemmas are assumptions.
* The three key-rotation lemmas (`process_matches_commitment`, `rotation_interpolates`,
  `rotation_commitments`) are proved for the code, but `key_rotation_keeps_secret` is not yet
  stated for it.

The Verus proofs of some of these results are in
[MystenLabs/fastcrypto#1155](https://github.com/MystenLabs/fastcrypto/pull/1155).
