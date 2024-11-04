use std::collections::HashMap;
use std::path;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn_verus::parse::{Parse, ParseStream};
use syn_verus::punctuated::Punctuated;
use syn_verus::{parse_macro_input, AngleBracketedGenericArguments, BigAnd, BigOr, BinOp, Block, Ensures, Error, Expr, ExprBinary, ExprBlock, ExprCall, ExprIf, ExprLit, ExprParen, ExprPath, ExprReference, ExprUnary, Field, Fields, FieldsNamed, FnArg, FnArgKind, FnMode, GenericArgument, Ident, Item, ItemEnum, ItemFn, ItemStruct, Lit, Local, ModeExec, Pat, PatIdent, PatType, Path, PathArguments, PathSegment, Publish, ReturnType, Signature, Specification, Stmt, Type, TypePath, TypeReference, UnOp, View};

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
    structs: HashMap<String, ItemStruct>,
    enums: HashMap<String, ItemEnum>,
    fns: HashMap<String, ItemFn>,
}

struct CompiledType {
    /// When used in spec mode
    spec: Type,
    /// When used in exec mode
    exec: Type,
}

macro_rules! path {
    ($($segment:expr),*) => {
        Path {
            leading_colon: None,
            segments: Punctuated::from_iter([ $($segment),* ]),
        }
    };

    (:: $($segment:expr),*) => {
        Path {
            leading_colon: Some(Default::default()),
            segments: Punctuated::from_iter([ $($segment),* ]),
        }
    };
}

macro_rules! seg {
    ($name:expr $(, $param:expr)*) => {{
        let params: Vec<GenericArgument> = vec![ $(GenericArgument::Type($param)),* ];
        PathSegment {
            ident: Ident::new($name, Span::call_site()),
            arguments: if params.len() == 0 {
                PathArguments::None
            } else {
                PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                    colon2_token: Default::default(),
                    lt_token: Default::default(),
                    args: Punctuated::from_iter(params),
                    gt_token: Default::default(),
                })
            },
        }
    }};
}

macro_rules! expr_path {
    ($($tt:tt)*) => {
        Expr::Path(ExprPath {
            attrs: Vec::new(),
            qself: None,
            path: path!($($tt)*),
        })
    }
}

macro_rules! expr_view {
    ($expr:expr) => {
        Expr::View(View {
            attrs: Vec::new(),
            expr: Box::new($expr),
            at_token: Default::default(),
        })
    }
}

macro_rules! expr_binary {
    ($left:expr, $op:ident, $right:expr) => {
        Expr::Binary(ExprBinary {
            attrs: Vec::new(),
            left: Box::new($left),
            op: BinOp::$op(Default::default()),
            right: Box::new($right),
        })
    }
}

fn exec_type_name(name: &str) -> String {
    format!("Exec{}", name)
}

fn exec_fn_name(name: &str) -> String {
    format!("exec_{}", name)
}

/// Convert a &str into a simple type
fn new_simple_type(s: &str) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: path![seg!(s)],
    })
}

fn new_simple_type_with_param(s: &str, param: Type) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: path![seg!(s, param)],
    })
}

/// Wrap an expr in reference
fn new_expr_ref(expr: Expr) -> Expr {
    Expr::Reference(ExprReference {
        attrs: Vec::new(),
        and_token: Default::default(),
        raw: Default::default(),
        mutability: None,
        // TODO: is paren necessary?
        expr: Box::new(Expr::Paren(ExprParen {
            attrs: Vec::new(),
            paren_token: Default::default(),
            expr: Box::new(expr),
        })),
    })
}

// /// Wrap an expr in dereference
// fn expr_dereference(expr: Expr) -> Expr {
//     Expr::Unary(ExprUnary {
//         attrs: Vec::new(),
//         op: UnOp::Deref(Default::default()),
//         expr: Box::new(expr),
//     })
// }

/// Wrap a reference around a type
fn new_type_ref(ty: Type) -> Type {
    Type::Reference(TypeReference {
        and_token: Default::default(),
        lifetime: None,
        mutability: None,
        elem: Box::new(ty.into()),
    })
}

/// Get the name of a type
/// e.g. Option<..> => Option, i32 => i32
fn get_simple_type_name(ty: &Type) -> Result<String, Error> {
    if let Type::Path(type_path) = ty {
        let segments: Vec<_> = type_path.path.segments.iter().collect();
        if segments.len() == 1 {
            return Ok(segments[0].ident.to_string());
        }
    }

    Err(Error::new_spanned(ty, "expect a simple type"))
}

/// Get the n-th type parameter
fn get_simple_type_param(ty: &Type, n: usize) -> Result<Type, Error> {
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

/// Convert a spec type to an exec type
/// TODO: &SpecString => &str?
fn compile_type(ctx: &Context, ty: &Type) -> Result<Type, Error> {
    match ty {
        Type::Reference(type_ref) => {
            if type_ref.mutability.is_some() {
                return Err(Error::new_spanned(ty, "mutable references are not supported"));
            }

            Ok(new_type_ref(compile_type(ctx, &type_ref.elem)?))
        }

        Type::Path(..) => {
            let name = get_simple_type_name(ty)?;

            // If this is a type defined in the context of rspec
            // we directly use the name of the exec version of the type
            if ctx.structs.contains_key(&name) {
                return Ok(new_simple_type(&exec_type_name(&name)));
            }

            match name.as_str() {
                "SpecString" => Ok(new_simple_type("String")),

                // Integer/float types can stay the same
                "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64" | "u128" |
                "f32" | "f64" | "bool" | "char" =>
                    Ok(ty.clone()),

                // TODO: do we want this?
                "int" => Ok(new_simple_type("i64")),

                // Option<T> => Option<exec(T)>
                "Option" => {
                    let param = get_simple_type_param(ty, 0)?;
                    Ok(new_simple_type_with_param("Option", compile_type(ctx, &param)?))
                }

                // Seq<T> => Vec<exec(T)>
                "Seq" => {
                    let param = get_simple_type_param(ty, 0)?;
                    Ok(new_simple_type_with_param("Vec", compile_type(ctx, &param)?))
                }

                _ => Err(Error::new_spanned(ty, "unsupported/unknown simple type")),
            }
        }

        _ => Err(Error::new_spanned(ty, "unsupported/unknown type")),
    }
}

/// Generate a view expression for a field (from the original rspec definition)
fn generate_field_view(field: &Field, field_expr: TokenStream2) -> TokenStream2 {
    // Use a deep view for Option and Seq
    if let Ok(name) = get_simple_type_name(&field.ty) {
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

/// Generate exec version of the given struct as well as a deep View impl
fn compile_struct(ctx: &Context, item_struct: &ItemStruct) -> Result<(ItemStruct, TokenStream2), Error> {
    if !item_struct.generics.params.is_empty() {
        return Err(Error::new_spanned(&item_struct.generics, "generics not supported"));
    }

    match &item_struct.fields {
        Fields::Named(fields_named) => {
            // Convert each field type to the exec version
            let exec_fields =
                fields_named.named
                    .iter()
                    .map(|field| Ok(Field { ty: compile_type(ctx, &field.ty)?, ..field.clone() }))
                    .collect::<Result<_, Error>>()?;

            let spec_name = &item_struct.ident;
            let exec_name = Ident::new(&exec_type_name(&item_struct.ident.to_string()), Span::call_site());

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
            Ok((
                ItemStruct {
                    ident: exec_name,
                    fields: Fields::Named(FieldsNamed {
                        named: exec_fields,
                        ..fields_named.clone()
                    }),
                    ..item_struct.clone()
                },
                view_impl
            ))
        }

        _ => return Err(Error::new_spanned(item_struct, "unsupported form of struct")),
    }
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
fn compile_expr(ctx: &Context, expr: &Expr) -> Result<Expr, Error> {
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
                        func: Box::new(expr_path![seg!("rspec_lib"), seg!("eq")]),
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

                if ctx.fns.contains_key(&name) {
                    return Ok(expr_path![seg!(&exec_fn_name(&name))]);
                }
            }

            Ok(expr.clone())
        }

        _ => Err(Error::new_spanned(expr, "unsupported expression")),
    }
}

fn compile_stmt(ctx: &Context, stmt: &Stmt) -> Result<Stmt, Error> {
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

fn compile_block(ctx: &Context, block: &Block) -> Result<Block, Error> {
    Ok(Block {
        stmts: block.stmts.iter().map(|stmt| compile_stmt(ctx, stmt)).collect::<Result<_, Error>>()?,
        ..block.clone()
    })
}

fn compile_signature(ctx: &Context, sig: &Signature) -> Result<Signature, Error> {
    // Change each parameter to the reference of the exec type
    let params = sig.inputs.iter().map(|param| {
        if let FnArgKind::Typed(pat_type) = &param.kind {
            Ok(FnArg {
                kind: FnArgKind::Typed(PatType {
                    ty: Box::new(compile_type(ctx, &pat_type.ty)?),
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
        ReturnType::Type(tok, tracked, _, ty) => {
            ReturnType::Type(
                tok.clone(),
                *tracked,
                // Generate a variable for the return value (for the ensure clause)
                // e.g. (_res: return_type)
                Some(Box::new((
                    Default::default(),
                    Pat::Ident(PatIdent {
                        attrs: Vec::new(),
                        by_ref: None,
                        mutability: None,
                        ident: Ident::new("_res", Span::call_site()),
                        subpat: None,
                    }),
                    Default::default(),
                ))),
                // Attach the compiled type
                Box::new(compile_type(ctx, ty)?),
            )
        }

        ReturnType::Default => ReturnType::Default,
    };

    // Add an ensure clause to state that the exec function returns the
    // same value as the spec function
    // _res@ == spec_fn(<views of inputs, with references if necessary>)

    // Generate the argument list
    let args = sig.inputs.iter().map(|param| {
            // Check if the function arguments fits the correct form
            // i.e. <ident>: <ty>
            if let FnArgKind::Typed(PatType {
                pat, ty, ..
            }) = &param.kind {
                if let Pat::Ident(PatIdent { ident, .. }) = pat.as_ref() {
                    let view = expr_view!(expr_path![seg!(&ident.to_string())]);

                    // If the target type has a reference, we add one too
                    // NOTE: assuming there is at most one level of reference
                    return Ok(if let Type::Reference(..) = ty.as_ref() {
                        new_expr_ref(view)
                    } else {
                        view
                    });
                }
            }

            Err(Error::new_spanned(sig, "unsupported parameter type"))
        }).collect::<Result<_, Error>>()?;

    // Generate the final ensure expression
    let ensure_expr = expr_binary!(
        expr_view!(expr_path![seg!("_res")]),
        Eq,
        Expr::Call(ExprCall {
            attrs: Vec::new(),
            func: Box::new(expr_path![seg!(&sig.ident.to_string())]),
            paren_token: Default::default(),
            args,
        })
    );

    Ok(Signature {
        // Change to exec mode
        publish: Publish::Default,
        mode: FnMode::Default,

        ident: Ident::new(&exec_fn_name(&sig.ident.to_string()), Span::call_site()),
        inputs: params,
        output: return_type,

        ensures: Some(Ensures {
            attrs: Vec::new(),
            token: Default::default(),
            exprs: Specification {
                exprs: Punctuated::from_iter([ensure_expr]),
            },
        }),

        ..sig.clone()
    })
}

fn compile_spec_fn(ctx: &Context, item_fn: &ItemFn) -> Result<ItemFn, Error> {
    Ok(ItemFn {
        sig: compile_signature(ctx, &item_fn.sig)?,
        block: Box::new(compile_block(ctx, &item_fn.block)?),
        ..item_fn.clone()
    })
}

fn compile_rspec(items: Items) -> Result<TokenStream2, Error> {
    let mut output = Vec::new();

    let mut ctx = Context {
        structs: HashMap::new(),
        enums: HashMap::new(),
        fns: HashMap::new(),
    };

    let mut struct_names = Vec::new();
    let mut fn_names = Vec::new();

    // Iterate through the items once, and copies them to the output as they are
    for item in items.0 {
        match item {
            Item::Fn(item_fn) => {
                match &item_fn.sig.mode {
                    FnMode::Spec(..) => {}
                    _ => return Err(Error::new_spanned(item_fn, "only spec functions are supported")),
                }

                output.push(quote! { #item_fn });

                fn_names.push(item_fn.sig.ident.to_string());
                ctx.fns.insert(item_fn.sig.ident.to_string(), item_fn);
            }

            Item::Struct(item_struct) => {
                output.push(quote! { #item_struct });

                struct_names.push(item_struct.ident.to_string());
                ctx.structs.insert(item_struct.ident.to_string(), item_struct);
            }

            _ => return Err(Error::new_spanned(item, "unsupported item")),
        };
    }

    // For each struct, generate an exec version and a (deep) View impl
    for name in struct_names {
        let item_struct = &ctx.structs[&name];
        let (exec_struct, view_impl) = compile_struct(&ctx, item_struct)?;
        output.push(quote! { #exec_struct });
        output.push(view_impl);
    }

    // For each function, generate an exec version
    for name in fn_names {
        let item_fn = &ctx.fns[&name];
        let exec_fn = compile_spec_fn(&ctx, item_fn)?;
        output.push(quote! { #exec_fn });
    }

    println!("########################################");
    for item in output.iter() {
        println!("{}", item);
    }

    Ok(quote! { ::builtin_macros::verus! { #(#output)* } })
}

/// For spec struct, generate an exec version of the struct with View trait that sends to
/// the spec version
/// For each spec fn, also generate an exec version with a proof that generates the same
/// output as the spec function
///
/// Some simplifying assumptions:
///   1. No name clash (e.g. no local variable that shadows the exec_* functions)
///
/// Note that this macro does not perform all the checks required for the generated
/// code to be type/lifetime correct
#[proc_macro]
pub fn rspec(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input as Items);

    match compile_rspec(items) {
        Ok(token_stream) => token_stream.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
