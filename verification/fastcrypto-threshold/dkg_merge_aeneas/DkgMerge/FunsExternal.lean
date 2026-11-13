/-
Copyright (c) 2022, Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0

Models of the external functions that the translation calls but the Aeneas standard library does
not cover. Unlike `Types.lean` and `Funs.lean`, this file is written by hand (from the
`FunsExternal_Template.lean` that Aeneas generates), and it is part of the trusted base.

`Option::clone` is modelled as the standard library defines it. The other three are only used to
build the messages of errors: `to_string` and `Display for str` build the message of a
`GeneralError`, and `Debug for FastCryptoError` is what `Result::expect` would print. The models
say that they succeed, which is true in Rust apart from running out of memory, and they don't
model the contents of the strings: no theorem depends on them.
-/
module
public import Aeneas
public import DkgMerge.Types
@[expose] public section
open Aeneas Aeneas.Std Result
open DkgMerge

/-- [core::fmt::{impl core::fmt::Display for str}::fmt] -/
@[rust_fun "core::fmt::{core::fmt::Display<str>}::fmt"]
def Str.Insts.CoreFmtDisplay.fmt :
    Str → core.fmt.Formatter → Result ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter) :=
  fun _ formatter => ok (core.result.Result.Ok (), formatter)

/-- [core::option::{impl core::clone::Clone for core::option::Option<T>}::clone] -/
@[rust_fun "core::option::{core::clone::Clone<core::option::Option<@T>>}::clone"]
def core.option.Option.Insts.CoreCloneClone.clone
    {T : Type _} (cloneCloneInst : core.clone.Clone T) : Option T → Result (Option T)
  | none => ok none
  | some x => do
    let y ← cloneCloneInst.clone x
    ok (some y)

/-- [alloc::string::{impl alloc::string::ToString for T}::to_string] -/
@[rust_fun "alloc::string::{alloc::string::ToString<@T>}::to_string"]
def alloc.string.ToString.Blanket.to_string
    {T : Type _} (_corefmtDisplayInst : core.fmt.Display T) : T → Result String :=
  fun _ => ok ""

/-- [fastcrypto::error::{impl core::fmt::Debug for fastcrypto::error::FastCryptoError}::fmt] -/
@[rust_fun "fastcrypto::error::{core::fmt::Debug<fastcrypto::error::FastCryptoError>}::fmt"]
def fastcrypto.error.FastCryptoError.Insts.CoreFmtDebug.fmt :
    fastcrypto.error.FastCryptoError → core.fmt.Formatter →
      Result ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter) :=
  fun _ formatter => ok (core.result.Result.Ok (), formatter)
