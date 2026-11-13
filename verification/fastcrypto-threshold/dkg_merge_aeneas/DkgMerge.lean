/-
Copyright (c) 2022, Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0

Properties of the DKG's `Party::merge` in fastcrypto-threshold. See README.md for what is proved
and how.
-/
import DkgMerge.Proofs

-- The main theorem depends only on Lean's standard axioms: no `sorry`, and no axiom added by hand.
/--
info: 'DkgMerge.merge_spec' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms DkgMerge.merge_spec
