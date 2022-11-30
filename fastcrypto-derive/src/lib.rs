// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]

//! This crate contains the `SilentDebug` and `SilentDisplay` derive macros.
//! which help to avoid accidentally printing sensitive data.
//! Imported from diem-crypto-derive@0.0.3
//! https://github.com/diem/diem/blob/release-1.4.3/crypto/crypto-derive/src/lib.rs#L113

use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

/// Derive the `SilentDisplay` trait, which is an implementation of `Display` that does not print the contents of the struct.
/// This is useful for structs that contain sensitive data, such as private keys.
#[proc_macro_derive(SilentDisplay)]
pub fn silent_display(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let (impl_generics, type_generics, where_clause) = &ast.generics.split_for_impl();
    let gen = quote! {
        // In order to ensure that secrets are never leaked, Display is elided
        impl #impl_generics ::std::fmt::Display for #name #type_generics #where_clause {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    };
    gen.into()
}

#[proc_macro_derive(SilentDebug)]
/// Derive the `SilentDebug` trait, which is an implementation of `Debug` that does not print the contents of the struct.
/// This is useful for structs that contain sensitive data, such as private keys.
pub fn silent_debug(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let (impl_generics, type_generics, where_clause) = &ast.generics.split_for_impl();
    let gen = quote! {
        // In order to ensure that secrets are never leaked, Debug is elided
        impl #impl_generics ::std::fmt::Debug for #name #type_generics #where_clause {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    };
    gen.into()
}

/// Extend implementations of Add, Sub, Mul<GroupElement::ScalarType> and Neg into implementations of
/// Add, Sub, Neg, AddAssign, SubAssign and MulAssign for all combinations of borrowed and owned inputs.
#[proc_macro_derive(GroupOpsExtend)]
pub fn group_ops(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;

    let gen = quote! {

        // Implement all combinations of borrowed and owned inputs assuming we have implemented the
        // Add, Sub, Neg and Mul<GroupElement::ScalarType> for the given type.

        auto_ops::impl_op!(+ |a: &#name, b: &#name| -> #name { <#name as core::ops::Add>::add(*a, *b) });
        auto_ops::impl_op!(+ |a: &#name, b: #name| -> #name { <#name as core::ops::Add>::add(*a, b) });
        auto_ops::impl_op!(+ |a: #name, b: &#name| -> #name { <#name as core::ops::Add>::add(a, *b) });

        auto_ops::impl_op!(- |a: &#name, b: &#name| -> #name { <#name as core::ops::Sub>::sub(*a, *b) });
        auto_ops::impl_op!(- |a: &#name, b: #name| -> #name { <#name as core::ops::Sub>::sub(*a, b) });
        auto_ops::impl_op!(- |a: #name, b: &#name| -> #name { <#name as core::ops::Sub>::sub(a, *b) });

        auto_ops::impl_op_ex!(+= |a: &mut #name, b: &#name| { *a = <#name as core::ops::Add>::add(*a, *b) });
        auto_ops::impl_op_ex!(-= |a: &mut #name, b: &#name| { *a = <#name as core::ops::Sub>::sub(*a, *b) });
        auto_ops::impl_op_ex!(*= |a: &mut #name, b: &<#name as GroupElement>::ScalarType| { *a = <#name as core::ops::Mul<<#name as GroupElement>::ScalarType>>::mul(*a, *b) });

        auto_ops::impl_op!(* |a: &#name, b: &<#name as GroupElement>::ScalarType| -> #name { <#name as core::ops::Mul<<#name as GroupElement>::ScalarType>>::mul(*a, *b) });
        auto_ops::impl_op!(* |a: &#name, b: <#name as GroupElement>::ScalarType| -> #name { <#name as core::ops::Mul<<#name as GroupElement>::ScalarType>>::mul(*a, b) });
        auto_ops::impl_op!(* |a: #name, b: &<#name as GroupElement>::ScalarType| -> #name { <#name as core::ops::Mul<<#name as GroupElement>::ScalarType>>::mul(a, *b) });

        auto_ops::impl_op!(- |a: &#name| -> #name { <#name as core::ops::Neg>::neg(*a) });
    };
    gen.into()
}
