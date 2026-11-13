# Verification

Formal checks of fastcrypto code. Code that only verifiers read lives here. The Rust sources
carry annotations only, gated on `cfg(verus_keep_ghost)`, which is set only when Verus runs, so
normal builds do not see them.

## Verus

`fastcrypto-threshold/` holds the Verus declarations for the `fastcrypto-threshold` crate:

| File | Included from | Contents |
|---|---|---|
| `specs.rs` | `src/lib.rs` | What Verus may assume about types and traits from other crates, and the spec functions and lemma for the AVID sender check. |
| `avss.rs` | `src/threshold_schnorr/avss.rs`, as a child module so it can read private fields | Spec functions for AVSS. |

To check the proofs, install [Verus](https://github.com/verus-lang/verus) (the `vstd` version
in `fastcrypto-threshold/Cargo.toml` must match the Verus release) and run, in
`fastcrypto-threshold`:

```bash
cargo verus focus --features verus
```

### What is proved

| Rust function | Contract | Lean contract |
|---|---|---|
| `avid::senders_weight` | Returns the senders' total weight exactly when they are nonempty, distinct parties, and `None` otherwise. Never panics or overflows. | The sender check inside `decode_quorum` and `decode_total` (`Avid/Steps.lean`) |
| `avss::Receiver::verify_complaint_response` | `Ok(v)` ⇒ `v.responder_id = responder_id`. | `verify_binds` (`Avss/Steps.lean`) |
| `avss::Receiver::recover` | `Ok(o)` ⇒ `verifies(o.my_shares, message, share_ids_of(nodes, id), id)`. | `recover_sound` (`Avss/Steps.lean`) |
| `avss::Receiver::process_message` | `Ok(Valid(o))` ⇒ `verifies(o.my_shares, message, share_ids_of(nodes, id), id)`. | `process_valid` (`Avss/Steps.lean`) |

### What is trusted

Each item below is marked `external_body` (Verus takes the signature and does not read the body)
or declared in `specs.rs`. Only the first three have a spec. Verus assumes what it says.

* `SharesForNode::verify`: `Ok` ⇒ `verifies(shares, message, ids, receiver)`, an uninterpreted
  predicate. So `verify` is assumed to be a deterministic check.
* `Nodes::share_ids_of`: `Ok(ids)` ⇒ `ids = share_ids_of(nodes, id)`, also uninterpreted.
* `Receiver::my_indices`: returns `share_ids_of(nodes, id)`. This includes that its `unwrap` does
  not panic.
* With no spec: `Receiver::recover_shares`, `warn_unverified_recovery`, `Receiver::check_message`,
  `Receiver::decrypt_my_shares`, `Receiver::create_complaint`, the `From<u128>` impls of the
  scalars and `Clone` for `Poly`.
* Opaque types: `Nodes`, `Poly`, `PrivateKey`, `MultiRecipientEncryption`, `SharesForNode`,
  `Complaint`, `Parameters`, and the group, scalar and error types of fastcrypto.
* The traits `AdditiveGroup`, `Module`, `Scalar`, `GroupElement`, `AllowedRng`, `Zeroize`, rand's
  `RngCore` and `CryptoRng`, and serde's `Serialize`, `Deserialize` and `DeserializeOwned`,
  restated with their bounds.

### Code changed for Verus

* `avid::senders_weight` replaces the `all_unique` and `total_weight_of` check in
  `decode_or_complain` with a loop that Verus can check.
* `Receiver::recover` moves its checks and interpolation into `recover_shares` and its logging
  into `warn_unverified_recovery`, and `Receiver::verify_message` moves its checks on the message
  into `check_message` and its decryption into `decrypt_my_shares`, since Verus cannot check
  iterator chains, closures or `tracing` macros. The rest of `verify_message` is written out as
  steps instead of an `and_then` closure.
* fastcrypto's `GroupElement` is split into `AdditiveGroup`, `Module<S>` and `GroupElement`, and
  `Scalar` is a `Module<Self>` instead of a `GroupElement`. Verus rejects the previous traits as
  cyclic, since a scalar was a group element whose scalar type is itself.
* `RistrettoScalar` implements `From<u128>` and `From<u64>` directly instead of through
  `derive_more`'s generic `#[from(forward)]`.
* `fastcrypto-threshold` allows `unsafe` code only when Verus runs, since Verus's
  `assume_specification` expands to it.
