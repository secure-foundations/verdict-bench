use std::collections::HashMap;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn_verus::parse::{Parse, ParseStream};
use syn_verus::punctuated::Punctuated;
use syn_verus::{parse_macro_input, parse_str, AngleBracketedGenericArguments, Error, Field, Fields, FieldsNamed, Ident, Item, ItemStruct, Path, PathArguments, PathSegment, Type, TypePath};

struct Items(Vec<Item>);

impl Parse for Items {
    fn parse(input: ParseStream) -> syn_verus::parse::Result<Items> {
        let mut items = Vec::new();
        while !input.is_empty() {
            items.push(input.parse()?);
        }
        Ok(Items(items))
    }
}

struct Context {
    custom_types: HashMap<String, (String, String)>,
}

/// Convert a &str into a simple type
fn str_to_type(s: &str) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: Path {
            leading_colon: None,
            segments: {
                let mut segments = Punctuated::new();
                segments.push(PathSegment {
                    ident: Ident::new(s, Span::call_site()),
                    arguments: PathArguments::None,
                });
                segments
            },
        },
    })
}

fn str_to_type_with_param(s: &str, param: Type) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: Path {
            leading_colon: None,
            segments: {
                let mut segments = Punctuated::new();
                segments.push(PathSegment {
                    ident: Ident::new(s, Span::call_site()),

                    // Add one type argument
                    arguments: PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                        colon2_token: Default::default(),
                        lt_token: Default::default(),
                        args: {
                            let mut args = Punctuated::new();
                            args.push(syn_verus::GenericArgument::Type(param));
                            args
                        },
                        gt_token: Default::default(),
                    }),
                });
                segments
            },
        },
    })
}

/// Get the name of a type
/// e.g. Option<..> => Option, i32 => i32
fn get_type_name(ty: &Type) -> Result<String, Error> {
    if let Type::Path(type_path) = ty {
        let segments: Vec<_> = type_path.path.segments.iter().collect();
        if segments.len() == 1 {
            return Ok(segments[0].ident.to_string());
        }
    }

    Err(Error::new_spanned(ty, "expect a simple type"))
}

/// Get the n-th type parameter
fn get_type_param(ty: &Type, n: usize) -> Result<Type, Error> {
    if let Type::Path(type_path) = ty {
        let segments: Vec<_> = type_path.path.segments.iter().collect();
        if segments.len() == 1 {
            if let PathArguments::AngleBracketed(args) = &segments[0].arguments {
                if let Some(arg) = args.args.iter().nth(n) {
                    if let syn_verus::GenericArgument::Type(ty) = arg {
                        return Ok(ty.clone());
                    } else {
                        return Err(Error::new_spanned(arg, "expect a type parameter"));
                    }
                }
            }
        }
    }

    Err(Error::new_spanned(ty, "expect a simple type"))
}

/// Convert a rspec type to both spec and exec types
fn type_to_spec_and_exec(ctx: &mut Context, ty: &Type) -> Result<(Type, Type), Error> {
    let ident = get_type_name(ty)?;

    if let Some((spec_name, exec_name)) = ctx.custom_types.get(&ident.to_string()) {
        return Ok((str_to_type(spec_name), str_to_type(exec_name)));
    }

    let typ_name = ident.to_string();

    match typ_name.as_str() {
        "SpecString" => Ok((
            str_to_type_with_param("Seq", str_to_type("char")),
            str_to_type("String"),
        )),

        // Integer/float types can stay the same
        "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64" | "u128" |
        "f32" | "f64" | "bool" | "char" => Ok((ty.clone(), ty.clone())),

        "int" => Ok((parse_str("int").unwrap(), parse_str("i64").unwrap())),

        // Option<T> => Option<spec T>, Option<exec T>
        "Option" => {
            // Get the type parameter
            let param = get_type_param(ty, 0)?;
            let (spec_ty, exec_ty) = type_to_spec_and_exec(ctx, &param)?;

            Ok((
                str_to_type_with_param("Option", spec_ty),
                str_to_type_with_param("Option", exec_ty),
            ))
        }

        // Seq<T> => Seq<spec T>, Vec<exec T>
        "Seq" => {
            // Get the type parameter
            let param = get_type_param(ty, 0)?;
            let (spec_ty, exec_ty) = type_to_spec_and_exec(ctx, &param)?;

            Ok((
                str_to_type_with_param("Seq", spec_ty),
                str_to_type_with_param("Vec", exec_ty),
            ))
        }

        _ => Err(Error::new_spanned(ty, "unsupported type")),
    }
}

/// Generate a view expression for a field (from the original rspec definition)
fn generate_field_view(field: &Field, field_expr: TokenStream2) -> TokenStream2 {
    // Use a deep view for Option and Seq
    if let Ok(name) = get_type_name(&field.ty) {
        match name.as_str() {
            "Option" => {
                return quote! {
                    match #field_expr {
                        Some(v) => Some(v.view()),
                        None => None,
                    }
                };
            }

            "Seq" => {
                return quote! {
                    Seq::new(#field_expr.view().len(), |i| #field_expr.view()[i].view())
                };
            }

            _ => {}
        }
    }

    // By default, just calls the view method
    quote! { #field_expr.view() }
}

/// Generate spec and exec versions of the given struct
fn generate_struct(ctx: &mut Context, item_struct: &ItemStruct) -> Result<(ItemStruct, ItemStruct, TokenStream2), Error> {
    if !item_struct.generics.params.is_empty() {
        return Err(Error::new_spanned(&item_struct.generics, "generics not supported"));
    }

    let (spec_struct, exec_struct, view_impl) = match &item_struct.fields {
        syn_verus::Fields::Named(fields_named) => {
            let (spec_fields, exec_fields) =
                fields_named.named
                    .iter()
                    .map(|field| {
                        let (spec_ty, exec_ty) = type_to_spec_and_exec(ctx, &field.ty)?;
                        Ok((
                            Field { ty: spec_ty, ..field.clone() },
                            Field { ty: exec_ty, ..field.clone() },
                        ))
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .unzip();

            let spec_name = &item_struct.ident;
            let exec_name = Ident::new(&format!("Exec{}", item_struct.ident), Span::call_site());

            let field_views = fields_named.named.iter().map(|field| {
                let field_name = &field.ident;
                let view = generate_field_view(field, quote! { self.#field_name });
                quote! { #field_name: #view }
            });

            // Generate a (deep) View from exec to spec
            let view_impl = quote! {
                impl View for #exec_name {
                    type V = #spec_name;

                    closed spec fn view(&self) -> #spec_name {
                        #spec_name {
                            #(#field_views,)*
                        }
                    }
                }
            };

            // Construct two new structs with the fields replaced
            (
                ItemStruct {
                    ident: item_struct.ident.clone(),
                    fields: Fields::Named(FieldsNamed {
                        named: spec_fields,
                        ..fields_named.clone()
                    }),
                    ..item_struct.clone()
                },
                ItemStruct {
                    ident: exec_name,
                    fields: Fields::Named(FieldsNamed {
                        named: exec_fields,
                        ..fields_named.clone()
                    }),
                    ..item_struct.clone()
                },
                view_impl,
            )
        }
        syn_verus::Fields::Unnamed(..) => unimplemented!(),
        syn_verus::Fields::Unit => unimplemented!(),
    };

    // Add an entry to the custom types map
    ctx.custom_types.insert(
        item_struct.ident.to_string(),
        (spec_struct.ident.to_string(), exec_struct.ident.to_string()),
    );

    Ok((spec_struct, exec_struct, view_impl))
}

fn compile_rspec(items: Items) -> Result<TokenStream2, Error> {
    let mut new_items = Vec::new();

    let mut ctx = Context {
        custom_types: HashMap::new(),
    };

    for item in items.0 {
        let new_item = match item {
            Item::Fn(item_fn) => {
                println!("fn: {}", item_fn.sig.ident);

                quote! {
                    #item_fn
                }
            }

            Item::Struct(item_struct) => {
                println!("struct: {}", item_struct.ident);

                // TODO: generate a spec version and an exec version
                // TODO: generate a View between them

                let (spec_struct, exec_struct, view_impl) = generate_struct(&mut ctx, &item_struct)?;

                println!("spec: {}", quote! { #spec_struct });
                println!("exec: {}", quote! { #exec_struct });
                println!("view: {}", view_impl);

                quote! {
                    #spec_struct
                    #exec_struct
                    #view_impl
                }
            }
            _ => unimplemented!(),
        };

        new_items.push(new_item);
    }

    Ok(quote! { ::builtin_macros::verus! { #(#new_items)* } })
}

/// For spec struct, generate an exec version of the struct with View trait that sends to
/// the spec version
/// For each spec fn, also generate an exec version with a proof that generates the same
/// output as the spec function
#[proc_macro]
pub fn rspec(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input as Items);
    // quote! { ::builtin_macros::verus! { #input } }.into()

    match compile_rspec(items) {
        Ok(token_stream) => token_stream.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
