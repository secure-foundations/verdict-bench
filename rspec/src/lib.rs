use std::collections::HashMap;
use std::hash::Hash;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn_verus::parse::{Parse, ParseStream};
use syn_verus::punctuated::Punctuated;
use syn_verus::{parse_macro_input, parse_str, AngleBracketedGenericArguments, BigAnd, BigOr, BinOp, Block, Error, Expr, ExprBinary, ExprBlock, ExprCall, ExprIf, ExprLit, ExprParen, ExprPath, ExprReference, ExprUnary, Field, Fields, FieldsNamed, FnArg, FnArgKind, FnMode, Ident, Item, ItemFn, ItemStruct, Lit, Local, ModeExec, Pat, PatType, Path, PathArguments, PathSegment, Publish, ReturnType, Signature, Stmt, Type, TypePath, TypeReference, UnOp};

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
    functions: HashMap<String, String>,
}

/// Convert a &str into a simple type
fn str_to_type(s: &str) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: Path {
            leading_colon: None,
            segments:
                Punctuated::from_iter([
                    PathSegment {
                        ident: Ident::new(s, Span::call_site()),
                        arguments: PathArguments::None,
                    },
                ]),
        },
    })
}

fn str_to_type_with_param(s: &str, param: Type) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: Path {
            leading_colon: None,
            segments:
                Punctuated::from_iter([
                    PathSegment {
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
                    }
                ]),
        },
    })
}

fn path_to_rspec_lib(s: &str) -> Path {
    Path {
        leading_colon: Some(Default::default()),
        segments:
            Punctuated::from_iter([
                PathSegment {
                    ident: Ident::new("rspec_lib", Span::call_site()),
                    arguments: PathArguments::None,
                },
                PathSegment {
                    ident: Ident::new(s, Span::call_site()),
                    arguments: PathArguments::None,
                },
            ]),
    }
}

// /// Wrap an expr in reference
// fn expr_reference(expr: Expr) -> Expr {
//     Expr::Reference(ExprReference {
//         attrs: Vec::new(),
//         and_token: Default::default(),
//         raw: Default::default(),
//         mutability: None,
//         expr: Box::new(Expr::Paren(ExprParen {
//             attrs: Vec::new(),
//             paren_token: Default::default(),
//             expr: Box::new(expr),
//         })),
//     })
// }

// /// Wrap an expr in dereference
// fn expr_dereference(expr: Expr) -> Expr {
//     Expr::Unary(ExprUnary {
//         attrs: Vec::new(),
//         op: UnOp::Deref(Default::default()),
//         expr: Box::new(expr),
//     })
// }

/// Wrap a reference around a type
fn type_to_reference(ty: impl Into<Type>) -> Type {
    Type::Reference(TypeReference {
        and_token: Default::default(),
        lifetime: None,
        mutability: None,
        elem: Box::new(ty.into()),
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

struct CompiledType {
    /// When used in spec mode
    spec: Type,
    /// When used in exec mode
    exec: Type,
}

/// Convert a rspec type to both spec and exec types
fn type_to_spec_and_exec(ctx: &mut Context, ty: &Type) -> Result<CompiledType, Error> {
    // If the type is a reference type, convert the inner type
    if let Type::Reference(type_ref) = ty {
        if type_ref.mutability.is_some() {
            return Err(Error::new_spanned(ty, "mutable references are not supported"));
        }

        let compiled = type_to_spec_and_exec(ctx, &type_ref.elem)?;
        return Ok(CompiledType {
            spec: type_to_reference(compiled.spec),
            exec: type_to_reference(compiled.exec),
        });
    }

    let ident = get_type_name(ty)?;

    if let Some((spec_name, exec_name)) = ctx.custom_types.get(&ident.to_string()) {
        return Ok(CompiledType {
            spec: str_to_type(spec_name),
            exec: str_to_type(exec_name),
        });
    }

    let typ_name = ident.to_string();

    match typ_name.as_str() {
        "SpecString" => Ok(CompiledType {
            spec: str_to_type_with_param("Seq", str_to_type("char")),
            exec: str_to_type("String"),
        }),

        // Integer/float types can stay the same
        "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64" | "u128" |
        "f32" | "f64" | "bool" | "char" =>
            Ok(CompiledType {
                spec: ty.clone(),
                exec: ty.clone(),
            }),

        "int" =>
            Ok(CompiledType {
                spec: str_to_type("i64"),
                exec: str_to_type("i64"),
            }),

        // Option<T> => Option<spec T>, Option<exec T>
        "Option" => {
            // Get the type parameter
            let param = get_type_param(ty, 0)?;
            let compiled = type_to_spec_and_exec(ctx, &param)?;

            Ok(CompiledType {
                spec: str_to_type_with_param("Option", compiled.spec),
                exec: str_to_type_with_param("Option", compiled.exec.clone()),
            })
        }

        // Seq<T> => Seq<spec T>, Vec<exec T>
        "Seq" => {
            // Get the type parameter
            let param = get_type_param(ty, 0)?;
            let compiled = type_to_spec_and_exec(ctx, &param)?;

            Ok(CompiledType {
                spec: str_to_type_with_param("Seq", compiled.spec),
                exec: str_to_type_with_param("Vec", compiled.exec.clone()),
            })
        }

        _ => Err(Error::new_spanned(ty, "unsupported/unknown type")),
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
fn compile_struct(ctx: &mut Context, item_struct: &ItemStruct) -> Result<(ItemStruct, ItemStruct, TokenStream2), Error> {
    if !item_struct.generics.params.is_empty() {
        return Err(Error::new_spanned(&item_struct.generics, "generics not supported"));
    }

    let (spec_struct, exec_struct, view_impl) = match &item_struct.fields {
        syn_verus::Fields::Named(fields_named) => {
            let (spec_fields, exec_fields) =
                fields_named.named
                    .iter()
                    .map(|field| {
                        let compiled = type_to_spec_and_exec(ctx, &field.ty)?;
                        Ok((
                            Field { ty: compiled.spec, ..field.clone() },
                            Field { ty: compiled.exec, ..field.clone() },
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
        syn_verus::Fields::Unnamed(..) => return Err(Error::new_spanned(item_struct, "unnamed fields not supported")),
        syn_verus::Fields::Unit => return Err(Error::new_spanned(item_struct, "unit struct not supported")),
    };

    // Add an entry to the custom types map
    ctx.custom_types.insert(
        item_struct.ident.to_string(),
        (spec_struct.ident.to_string(), exec_struct.ident.to_string()),
    );

    Ok((spec_struct, exec_struct, view_impl))
}

/**
 * Expressions to support
 * - Equality, comparisons, and binary exprs are compiled as they are (and hopefully the type matches; if not use built-in functions and traits)
 * - Logical operators (&&, ||, &&&, |||, not, ==>)
 * - Guarded forall/exists
 * - Indexing
 * - Match and "matches"
 * - Field expression (a.b.c ==> &a.b.c)
 * - Function/method calls
 * - Block expr
 * - If stmt
 */
fn compile_expr(ctx: &mut Context, expr: &Expr) -> Result<Expr, Error> {
    match expr {
        // Some of the operations (e.g. == for strings)
        // lack built-in exec support in Verus, so we replace
        // them with custom operations implemented in rspec_lib::*
        Expr::Binary(expr_binary) =>
            match &expr_binary.op {
                // Replace `a == b` with `::rspec::eq_other(a, b)`
                BinOp::Eq(..) =>
                    Ok(Expr::Call(ExprCall {
                        attrs: Vec::new(),
                        func: Box::new(Expr::Path(ExprPath {
                            attrs: Vec::new(),
                            qself: None,
                            path: path_to_rspec_lib("eq"),
                        })),
                        paren_token: Default::default(),
                        args: Punctuated::from_iter([
                            compile_expr(ctx, &expr_binary.left)?,
                            compile_expr(ctx, &expr_binary.right)?,
                        ]),
                    })),

                // By default, we just clone the same binary operation
                _ => Ok(Expr::Binary(ExprBinary {
                    left: Box::new(compile_expr(ctx, &expr_binary.left)?),
                    right: Box::new(compile_expr(ctx, &expr_binary.right)?),
                    ..expr_binary.clone()
                }))
            }

        Expr::Unary(expr_unary) =>
            Ok(Expr::Unary(ExprUnary {
                expr: Box::new(compile_expr(ctx, &expr_unary.expr)?),
                ..expr_unary.clone()
            })),

        Expr::Paren(expr_paren) =>
            Ok(Expr::Paren(ExprParen {
                expr: Box::new(compile_expr(ctx, &expr_paren.expr)?),
                ..expr_paren.clone()
            })),

        Expr::Block(expr_block) =>
            Ok(Expr::Block(ExprBlock {
                block: compile_block(ctx, &expr_block.block)?,
                ..expr_block.clone()
            })),

        Expr::BigAnd(big_and) =>
            Ok(Expr::BigAnd(BigAnd {
                exprs: big_and.exprs
                    .iter()
                    .map(|(tok, expr)| Ok((tok.clone(), Box::new(compile_expr(ctx, expr)?))))
                    .collect::<Result<_, Error>>()?,
            })),

        Expr::BigOr(big_or) =>
            Ok(Expr::BigOr(BigOr {
                exprs: big_or.exprs
                    .iter()
                    .map(|(tok, expr)| Ok((tok.clone(), Box::new(compile_expr(ctx, expr)?))))
                    .collect::<Result<_, Error>>()?,
            })),

        Expr::If(expr_if) =>
            Ok(Expr::If(ExprIf {
                cond: Box::new(compile_expr(ctx, &expr_if.cond)?),
                then_branch: compile_block(ctx, &expr_if.then_branch)?,
                else_branch: if let Some((tok, expr)) = &expr_if.else_branch {
                    Some((tok.clone(), Box::new(compile_expr(ctx, expr)?)))
                } else {
                    return Err(Error::new_spanned(expr, "unsupported if statement without else branch"));
                },
                ..expr_if.clone()
            })),

        // For field expressions, wrap the result in a reference
        Expr::Field(..) => Ok(expr.clone()),

        // Rewrite `<string literal>@` to `<string literal>`
        // but throws an error on anything else
        Expr::View(view) =>
            match view.expr.as_ref() {
                Expr::Lit(ExprLit { lit: Lit::Str(..), .. }) => Ok(view.expr.as_ref().clone()),
                _ => Err(Error::new_spanned(view, "only string literals are supported for view expression (@)")),
            }

        Expr::Call(expr_call) =>
            Ok(Expr::Call(ExprCall {
                func: Box::new(compile_expr(ctx, &expr_call.func)?),
                args: expr_call.args.iter().map(|arg| compile_expr(ctx, arg)).collect::<Result<_, Error>>()?,
                ..expr_call.clone()
            })),

        Expr::Index(expr_index) => todo!(),
        Expr::Match(expr_match) => todo!(),
        Expr::MethodCall(expr_method_call) => todo!(),
        Expr::Matches(expr_matches) => todo!(),

        // NOTE: forall |i| ...
        // is represented as a unary operator ("forall")
        // applied to a closure

        // Maybe?
        // Expr::Let(expr_let) => todo!(),
        // Expr::Struct(expr_struct) => todo!(),
        // Expr::Tuple(expr_tuple) => todo!(),
        // Expr::Verbatim(token_stream) => todo!(),
        // Expr::View(view) => todo!(),
        // Expr::Is(expr_is) => todo!(),
        // Expr::Has(expr_has) => todo!(),
        // Expr::GetField(expr_get_field) => todo!(),
        // Expr::Cast(expr_cast) => todo!(),

        Expr::Reference(expr_reference) =>
            Ok(Expr::Reference(ExprReference {
                expr: Box::new(compile_expr(ctx, &expr_reference.expr)?),
                ..expr_reference.clone()
            })),

        Expr::Lit(lit) =>
            match &lit.lit {
                Lit::Str(..) => Ok(expr.clone()),
                Lit::Byte(..) | Lit::Char(..) | Lit::Int(..) | Lit::Float(..) | Lit::Bool(..) =>
                    // Ok(expr_reference(expr.clone())),
                    Ok(expr.clone()),

                _ => Err(Error::new_spanned(lit, "unsupported literal")),
            }

        Expr::Macro(..) => Ok(expr.clone()),
        Expr::Path(path) => {
            // If the path is a function, replace it with the exec version
            let segments: Vec<_> = path.path.segments.iter().collect();
            if segments.len() == 1 {
                let name = segments[0].ident.to_string();

                if ctx.functions.contains_key(&name) {
                    return Ok(Expr::Path(ExprPath {
                        attrs: Vec::new(),
                        qself: None,
                        path: Path {
                            leading_colon: None,
                            segments:
                                Punctuated::from_iter([
                                    PathSegment {
                                        ident: Ident::new(&ctx.functions[&name], Span::call_site()),
                                        arguments: PathArguments::None,
                                    },
                                ]),
                        },
                    }));
                }
            }

            Ok(expr.clone())
        }

        _ => Err(Error::new_spanned(expr, "unsupported expression")),
    }
}

fn compile_stmt(ctx: &mut Context, stmt: &Stmt) -> Result<Stmt, Error> {
    match stmt {
        Stmt::Local(local) => {
            let Some((tok, expr)) = &local.init else {
                return Err(Error::new_spanned(stmt, "unsupported let statement without initializer"));
            };

            Ok(Stmt::Local(Local {
                init: Some((tok.clone(), Box::new(compile_expr(ctx, expr)?))),
                ..local.clone()
            }))
        }

        Stmt::Expr(expr) => Ok(Stmt::Expr(compile_expr(ctx, expr)?)),

        _ => return Err(Error::new_spanned(stmt, "unsupported statement")),
    }
}

fn compile_block(ctx: &mut Context, block: &Block) -> Result<Block, Error> {
    Ok(Block {
        stmts: block.stmts.iter().map(|stmt| compile_stmt(ctx, stmt)).collect::<Result<_, Error>>()?,
        ..block.clone()
    })
}

fn compile_signature(ctx: &mut Context, sig: &Signature) -> Result<Signature, Error> {
    let exec_name: String = format!("exec_{}", sig.ident);
    ctx.functions.insert(sig.ident.to_string(), exec_name.clone());

    // Change each parameter to the reference of the exec type
    let params = sig.inputs.iter().map(|param| {
        if let FnArgKind::Typed(pat_type) = &param.kind {
            let compiled = type_to_spec_and_exec(ctx, &pat_type.ty)?;
            Ok(FnArg {
                kind: FnArgKind::Typed(PatType {
                    ty: Box::new(compiled.exec),
                    ..pat_type.clone()
                }),
                ..param.clone()
            })
        } else {
            Err(Error::new_spanned(sig, "unsupported parameter type"))
        }
    }).collect::<Result<_, Error>>()?;

    // Change the return type to the reference of the exec type
    let return_type = match &sig.output {
        ReturnType::Type(tok, tracked, pat, ty) => {
            let compiled = type_to_spec_and_exec(ctx, ty)?;
            ReturnType::Type(
                tok.clone(),
                *tracked,
                pat.clone(),
                Box::new(compiled.exec),
            )
        }

        ReturnType::Default => ReturnType::Default,
    };

    Ok(Signature {
        // Change to exec mode
        publish: Publish::Default,
        mode: FnMode::Default,

        ident: Ident::new(&exec_name, Span::call_site()),
        inputs: params,
        output: return_type,

        ..sig.clone()
    })
}

fn compile_spec_fn(ctx: &mut Context, item_fn: &ItemFn) -> Result<ItemFn, Error> {
    Ok(ItemFn {
        sig: compile_signature(ctx, &item_fn.sig)?,
        block: Box::new(compile_block(ctx, &item_fn.block)?),
        ..item_fn.clone()
    })
}

fn compile_rspec(items: Items) -> Result<TokenStream2, Error> {
    let mut new_items = Vec::new();

    let mut ctx = Context {
        custom_types: HashMap::new(),
        functions: HashMap::new(),
    };

    for item in items.0.iter() {
        let new_item = match item {
            Item::Fn(item_fn) => {
                match &item_fn.sig.mode {
                    FnMode::Spec(..) => {}
                    _ => return Err(Error::new_spanned(item_fn, "only spec functions are supported")),
                }

                let exec_fn = compile_spec_fn(&mut ctx, item_fn)?;

                println!("{}", quote! { #item_fn });
                println!("{}", quote! { #exec_fn });

                quote! {
                    #item_fn
                    #exec_fn
                }
            }

            Item::Struct(item_struct) => {
                let (spec_struct, exec_struct, view_impl) = compile_struct(&mut ctx, &item_struct)?;

                println!("{}", quote! { #spec_struct });
                println!("{}", quote! { #exec_struct });
                println!("{}", view_impl);

                quote! {
                    #spec_struct
                    #exec_struct
                    #view_impl
                }
            }

            _ => return Err(Error::new_spanned(item, "unsupported item")),
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
