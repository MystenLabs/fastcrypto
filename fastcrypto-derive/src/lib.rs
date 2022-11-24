// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]

//! This crate contains the `SilentDebug` and `SilentDisplay` derive macros.
//! which help to avoid accidentally printing sensitive data.
//! Imported from diem-crypto-derive@0.0.3
//! https://github.com/diem/diem/blob/release-1.4.3/crypto/crypto-derive/src/lib.rs#L113

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

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

/// Derive the `SilentDebug` trait, which is an implementation of `Debug` that does not print the contents of the struct.
/// This is useful for structs that contain sensitive data, such as private keys.
#[proc_macro_derive(SilentDebug)]
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

/// Add<&Self>, Add<Self> for a NewType which inner type has an Add<&Self> for Self
#[proc_macro_derive(AddSelfRef)]
pub fn derive_add_self_ref_newtype(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let name = &item.ident;

    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    quote!(
        #[automatically_derived]
        impl <#impl_generics> ::core::ops::Add<&Self> for #name #ty_generics #where_clause
        {
            type Output = Self;

            #[inline]
            fn add(self, other: &Self) -> Self::Output {
                Self(self.0 + &other.0)
            }
        }

        #[automatically_derived]
        impl #impl_generics ::core::ops::Add<Self> for #name #ty_generics #where_clause
        {
            type Output = Self;

            #[inline]
            fn add(self, other: Self) -> Self::Output {
                Self(self.0 + &other.0)
            }
        }
    )
    .into()
}

/// AddAssign<&Self>, AddAssign<Self> for a NewType which inner type has an AddAssign<&Self> for Self
#[proc_macro_derive(AddAssignSelfRef)]
pub fn derive_add_assign_self_ref_newtype(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let name = &item.ident;

    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    quote!(
        #[automatically_derived]
        impl #impl_generics ::core::ops::AddAssign<&Self> for #name #ty_generics #where_clause
        {
            #[inline]
            fn add_assign(&mut self, other: &Self) {
                self.0 += &other.0
            }
        }

        #[automatically_derived]
        impl #impl_generics ::core::ops::AddAssign<Self> for #name #ty_generics #where_clause
        {
            #[inline]
            fn add_assign(&mut self, other: Self) {
                self.0 += &other.0
            }
        }
    )
    .into()
}

/// Sub<&Self>, Sub<Self> for a NewType which inner type has a Sub<&Self> for Self
#[proc_macro_derive(SubSelfRef)]
pub fn derive_sub_self_ref_newtype(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let name = &item.ident;

    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    quote!(
        #[automatically_derived]
        impl #impl_generics ::core::ops::Sub<&Self> for #name #ty_generics #where_clause
        {
            type Output = Self;

            #[inline]
            fn sub(self, other: &Self) -> Self::Output {
                Self(self.0 - &other.0)
            }
        }

        #[automatically_derived]
        impl #impl_generics ::core::ops::Sub<Self> for #name #ty_generics #where_clause
        {
            type Output = Self;

            #[inline]
            fn sub(self, other: Self) -> Self::Output {
                Self(self.0 - &other.0)
            }
        }
    )
    .into()
}

/// SubAssign<&Self>, SubAssign<Self> for a NewType which inner type has a SubAssign<&Self> for Self
#[proc_macro_derive(SubAssignSelfRef)]
pub fn derive_sub_assign_self_ref_newtype(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let name = &item.ident;

    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    quote!(
        #[automatically_derived]
        impl <#impl_generics> ::core::ops::SubAssign<&Self> for #name #ty_generics #where_clause
        {
            #[inline]
            fn sub_assign(&mut self, other: &Self) {
                self.0 -= &other.0
            }
        }

        #[automatically_derived]
        impl <#impl_generics> ::core::ops::SubAssign<Self> for #name #ty_generics #where_clause
        {
            #[inline]
            fn sub_assign(&mut self, other: Self) {
                self.0 -= &other.0
            }
        }
    )
    .into()
}

/// Neg for a NewType which inner type has an Neg for Self
#[proc_macro_derive(NegSelf)]
pub fn derive_neg_self_newtype(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);
    let name = &item.ident;

    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    quote!(
        #[automatically_derived]
        impl #impl_generics ::core::ops::Neg for #name #ty_generics #where_clause
        {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self::Output {
                Self(- self.0)
            }
        }
    )
    .into()
}
