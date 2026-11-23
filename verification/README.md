<!-- THIS FILE IS AI-ONLY -->
# Verification

Machine-checked proofs about fastcrypto's code. Each folder is a separate project with its own
README that lists what is proved and under which assumptions.

| Folder | Code | Tool |
|---|---|---|
| `lean-merkle/` | `fastcrypto::merkle`: binding and completeness of `MerkleProof::verify` and `verify_for_trusted_tree`. | Lean, on a translation by Charon and Aeneas. |
