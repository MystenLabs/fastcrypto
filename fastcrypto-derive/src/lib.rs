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

fn get_type_from_attrs(attrs: &[syn::Attribute], attr_name: &str) -> syn::Result<syn::LitStr> {
    attrs
        .iter()
        .find(|attr| attr.path.is_ident(attr_name))
        .map_or_else(
            || {
                Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    format!("Could not find attribute {}", attr_name),
                ))
            },
            |attr| match attr.parse_meta()? {
                syn::Meta::NameValue(meta) => {
                    if let syn::Lit::Str(lit) = &meta.lit {
                        Ok(lit.clone())
                    } else {
                        Err(syn::Error::new_spanned(
                            meta,
                            &format!("Could not parse {} attribute", attr_name)[..],
                        ))
                    }
                }
                bad => Err(syn::Error::new_spanned(
                    bad,
                    &format!("Could not parse {} attribute", attr_name)[..],
                )),
            },
        )
}

/// Overload group operations for a struct implementing [AdditiveGroupElement].
#[proc_macro_derive(GroupOps, attributes(GroupType, ScalarType))]
pub fn group_ops(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;

    // Parse group type
    let group_type = get_type_from_attrs(&ast.attrs, "GroupType").unwrap();
    let group: syn::Type = group_type.parse().unwrap();

    // Parse scalar type
    let scalar_type = get_type_from_attrs(&ast.attrs, "ScalarType").unwrap();
    let scalar: syn::Type = scalar_type.parse().unwrap();

    let gen = quote! {
        impl_op_ex!(+ |a: &#name, b: &#name| -> #name { #group::add(a, b) });
        impl_op_ex!(+= |a: &mut #name, b: &#name| { *a = #group::add(a, b) });
        impl_op_ex!(-= |a: &mut #name, b: &#name| { *a = #group::sub(a, b) });
        impl_op_ex!(*= |a: &mut #name, b: &#scalar| { *a = #group::mul(b, a) });
        impl_op_ex!(- |a: &#name, b: &#name| -> #name { #group::sub(a, b) });
        impl_op_ex_commutative!(* |a: &#scalar, b: &#name| -> #name { #group::mul(a, b) });
        impl_op_ex!(- |a: &#name| -> #name { #group::neg(a) });
        impl_op_ex_commutative!(* |a: u64, b: &#name| -> #name { #group::mul(&#scalar::from(a), b) });
        impl_op_ex!(*= |a: &mut #name, b: u64| { *a = #group::mul(&#scalar::from(b), a) });
    };
    gen.into()
}
