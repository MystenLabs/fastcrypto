// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

// Imported from diem-crypto-derive@0.0.3
// https://github.com/diem/diem/blob/release-1.4.3/crypto/crypto-derive/src/lib.rs#L113

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
