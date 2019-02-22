#![recursion_limit = "128"]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, LitByteStr, Type};

#[proc_macro_derive(uSerialize)]
pub fn serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let error = quote!(compile_error!(
        "`#[derive(uSerialize)]` can only be used on `struct`s with named fields"
    ))
    .into();

    match input.data {
        Data::Struct(s) => {
            let ident = input.ident;

            let fields = match s.fields {
                Fields::Named(fields) => fields.named,
                _ => return error,
            };

            if fields.is_empty() {
                return error;
            }

            let mut exprs = vec![];
            let mut is_first = true;
            for field in fields {
                if is_first {
                    is_first = false;
                } else {
                    exprs.push(quote!(
                        cursor.push_byte(b',')?;
                    ));
                }

                let ident = field.ident.expect("unreachable");
                let lit = LitByteStr::new(ident.to_string().as_bytes(), ident.span());
                exprs.push(quote!(
                    ujson::ser::field_name(#lit, cursor)?;
                    cursor.push_byte(b':')?;
                ));

                let ty = &field.ty;
                match ty {
                    Type::Array(array) => {
                        let ty = &array.elem;

                        exprs.push(quote!(
                            <[#ty]>::serialize(&self.#ident, cursor)?;
                        ));
                    }

                    _ => {
                        exprs.push(quote!(
                            #ty::serialize(&self.#ident, cursor)?;
                        ));
                    }
                }
            }

            quote!(
                impl ujson::Serialize for #ident {
                    #[deny(unused_must_use)]
                    fn serialize(&self, cursor: &mut ujson::ser::Cursor) -> Result<(), ()> {
                        use ujson::Serialize;

                        cursor.push_byte(b'{')?;
                        #(#exprs)*
                        cursor.push_byte(b'}')
                    }
                }
            )
            .into()
        }

        _ => error,
    }
}

#[proc_macro_derive(uDeserialize)]
pub fn deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let error = quote!(compile_error!(
        "`#[derive(uSerialize)]` can only be used on `struct`s with named fields"
    ))
    .into();

    match input.data {
        Data::Struct(s) => {
            let ident = input.ident;

            let fields = match s.fields {
                Fields::Named(fields) => fields.named,
                _ => return error,
            };

            if fields.is_empty() {
                return error;
            }

            let nfields = fields.len();
            let mut field_names = vec![];
            let mut field_exprs = vec![];
            let mut branches = vec![];
            for field in fields {
                let ident = field.ident.expect("unreachable");
                let lit = LitByteStr::new(ident.to_string().as_bytes(), ident.span());
                let ty = field.ty;
                field_exprs.push(quote!(#ident: #ident.ok_or(())?));
                field_names.push(ident.clone());

                branches.push(quote!(
                    cursor.matches_byte_string(#lit)? {
                        if #ident.is_some() {
                            return Err(());
                        }

                        cursor.parse_whitespace();
                        cursor.expect(b':')?;
                        cursor.parse_whitespace();
                        #ident = Some(#ty::deserialize(cursor)?);
                        is_first = false;
                        cursor.parse_whitespace();
                    }
                ))
            }

            quote!(
                impl ujson::Deserialize for #ident {
                    #[deny(unused_must_use)]
                    fn deserialize(cursor: &mut ujson::de::Cursor) -> Result<Self, ()> {
                        use ujson::Deserialize;

                        const FIELDS: usize = #nfields;

                        #(let mut #field_names = None;)*
                        let mut is_first = true;

                        cursor.expect(b'{')?;
                        cursor.parse_whitespace();

                        for _ in 0..FIELDS {
                            if !is_first {
                                cursor.expect(b',')?;
                                cursor.parse_whitespace();
                            }

                            #(if #branches else)* {
                                return Err(());
                            }
                        }

                        cursor.expect(b'}')?;

                        Ok(#ident {
                            #(#field_exprs,)*
                        })
                    }
                }
            )
            .into()
        }

        _ => error,
    }
}
