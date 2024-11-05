use std::collections::HashMap;
use std::fmt;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn_verus::parse::{Parse, ParseStream};
use syn_verus::punctuated::Punctuated;
use syn_verus::{parse_macro_input, AngleBracketedGenericArguments, Arm, BigAnd, BigOr, BinOp, Block, Ensures, Error, Expr, ExprBinary, ExprBlock, ExprCall, ExprCast, ExprClosure, ExprField, ExprIf, ExprIndex, ExprLit, ExprMatch, ExprMethodCall, ExprParen, ExprPath, ExprReference, ExprUnary, Field, Fields, FieldsNamed, FnArg, FnArgKind, FnMode, GenericArgument, Ident, Item, ItemEnum, ItemFn, ItemMod, ItemStruct, Lit, Local, ModeExec, Pat, PatIdent, PatPath, PatReference, PatTuple, PatTupleStruct, PatType, Path, PathArguments, PathSegment, Publish, ReturnType, Signature, Specification, Stmt, Type, TypePath, TypeReference, UnOp, View};
use prettyplease_verus::unparse_expr;

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

#[derive(Clone)]
struct LocalContext {
    vars: HashMap<String, Option<Box<Type>>>,
}

impl fmt::Display for LocalContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{")?;

        for (i, (name, ty)) in self.vars.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }

            if let Some(ty) = ty {
                write!(f, "{}: {}", name, quote! { #ty })?;
            } else {
                write!(f, "{}: <unknown>", name)?;
            }
        }

        write!(f, "}}")
    }
}

fn unparse_item(item: Item) -> String {
    let file = syn_verus::File {
        attrs: vec![],
        items: vec![item],
        shebang: None,
    };
    prettyplease_verus::unparse(&file)
}

fn unparse_item_token_stream(item: &TokenStream2) -> String {
    let item = syn_verus::parse2(item.clone()).unwrap();
    unparse_item(item)
}

fn unparse_expr_token_stream(expr: &TokenStream2) -> String {
    let expr = syn_verus::parse2(expr.clone()).unwrap();
    unparse_expr(&expr)
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
    };
}

macro_rules! expr_view {
    ($expr:expr) => {
        // Expr::View(View {
        //     attrs: Vec::new(),
        //     expr: Box::new($expr),
        //     at_token: Default::default(),
        // })
        expr_method_call!($expr, "deep_view")
    };
}

macro_rules! expr_binary {
    ($left:expr, $op:ident, $right:expr $(,)?) => {
        Expr::Binary(ExprBinary {
            attrs: Vec::new(),
            left: Box::new($left),
            op: BinOp::$op(Default::default()),
            right: Box::new($right),
        })
    };
}

macro_rules! expr_unary {
    ($op:ident, $expr:expr $(,)?) => {
        Expr::Unary(ExprUnary {
            attrs: Vec::new(),
            op: UnOp::$op(Default::default()),
            expr: Box::new($expr),
        })
    };
}

macro_rules! expr_call {
    ($func:expr, $($arg:expr),* $(,)?) => {
        Expr::Call(ExprCall {
            attrs: Vec::new(),
            func: Box::new($func),
            paren_token: Default::default(),
            args: Punctuated::from_iter([ $($arg),* ]),
        })
    };

    // All args provided as an argument
    ($func:expr; $args:expr) => {
        Expr::Call(ExprCall {
            attrs: Vec::new(),
            func: Box::new($func),
            paren_token: Default::default(),
            args: $args,
        })
    };
}

macro_rules! expr_method_call {
    // $method expected to be a &str
    ($receiver:expr, $method:expr $(, $arg:expr)* $(,)?) => {{
        let args: Vec<Expr> = vec![ $( $arg ),* ];
        Expr::MethodCall(ExprMethodCall {
            attrs: Vec::new(),
            receiver: Box::new($receiver),
            dot_token: Default::default(),
            method: Ident::new($method, Span::call_site()),
            turbofish: None,
            paren_token: Default::default(),
            args: Punctuated::from_iter(args),
        })
    }};
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

// Assuming the path contains only one segment
fn get_simple_path_name(path: &Path) -> Result<String, Error> {
    let segments: Vec<_> = path.segments.iter().collect();
    if segments.len() == 1 {
        return Ok(segments[0].ident.to_string());
    }

    Err(Error::new_spanned(path, "expect a simple path"))
}

/// Get the name of a type
/// e.g. Option<..> => Option, i32 => i32
fn get_simple_type_name(ty: &Type) -> Result<String, Error> {
    if let Type::Path(type_path) = ty {
        get_simple_path_name(&type_path.path)
    } else {
        Err(Error::new_spanned(ty, "expect a simple type"))
    }
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

/// Simple pattern is either a variable (`a`) or a typed variable (`a: T`)
fn get_simple_pat(pat: &Pat) -> Result<(&Ident, Option<Box<Type>>), Error> {
    if let Pat::Ident(pat_ident) = pat {
        return Ok((&pat_ident.ident, None));
    } if let Pat::Type(PatType { pat, ty, .. }) = pat {
        if let Pat::Ident(pat_ident) = pat.as_ref() {
            return Ok((&pat_ident.ident, Some(ty.clone())));
        }
    }

    Err(Error::new_spanned(pat, "expect a simple pattern (variable or typed variable)"))
}

/// Check that the expr is a simple variable and return the identifier
fn get_simple_var(expr: &Expr) -> Result<&Ident, Error> {
    if let Expr::Path(ExprPath { path, .. }) = expr {
        let segments: Vec<_> = path.segments.iter().collect();
        if segments.len() == 1 {
            return Ok(&segments[0].ident);
        }
    }

    Err(Error::new_spanned(expr, "expect a simple variable"))
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
                "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "isize" |
                "f32" | "f64" | "bool" | "char" =>
                    Ok(ty.clone()),

                // TODO: do we want this?
                // "int" => Ok(new_simple_type("i64")),

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
    // // Use a deep view for Option and Seq
    // if let Ok(name) = get_simple_type_name(&field.ty) {
    //     match name.as_str() {
    //         "Option" => {
    //             return quote! {
    //                 match #field_expr {
    //                     Some(v) => Some(v.view()),
    //                     None => None,
    //                 }
    //             };
    //         }

    //         "Seq" => {
    //             return quote! {
    //                 Seq::new(#field_expr.view().len(), |i| #field_expr.view()[i].view())
    //             };
    //         }

    //         _ => {}
    //     }
    // }

    // By default, just calls the view method
    quote! { #field_expr.deep_view() }
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
                impl DeepView for #exec_name {
                    type V = #spec_name;

                    closed spec fn deep_view(&self) -> #spec_name {
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

fn compile_path(ctx: &Context, path: &Path) -> Result<Path, Error> {
    if path.segments.len() == 1 {
        let name = get_simple_path_name(&path)?;

        if ctx.structs.contains_key(&name) {
            Ok(path![seg!(&exec_type_name(&name))])
        } else if ctx.enums.contains_key(&name) {
            Ok(path![seg!(&exec_type_name(&name))])
        } else {
            Ok(path.clone())
        }
    } else if path.segments.len() == 2 {
        let name = path.segments[1].ident.to_string();

        if ctx.structs.contains_key(&name) {
            Ok(path![seg!(&exec_type_name(&name)), path.segments[1].clone()])
        } else if ctx.enums.contains_key(&name) {
            Ok(path![seg!(&exec_type_name(&name)), path.segments[1].clone()])
        } else {
            Ok(path.clone())
        }
    } else {
        Err(Error::new_spanned(path, "unsupported path"))
    }
}

fn compile_pattern(ctx: &Context, local: &mut LocalContext, pat: &Pat) -> Result<Pat, Error> {
    match pat {
        Pat::Ident(pat_ident) => {
            local.vars.insert(pat_ident.ident.to_string(), None);
            Ok(pat.clone())
        }

        Pat::Path(pat_path) =>
            Ok(Pat::Path(PatPath {
                path: compile_path(ctx, &pat_path.path)?,
                ..pat_path.clone()
            })),

        Pat::Reference(pat_reference) =>
            Ok(Pat::Reference(PatReference {
                pat: Box::new(compile_pattern(ctx, local, &pat_reference.pat)?),
                ..pat_reference.clone()
            })),

        // TODO: infer more types
        Pat::Type(pat_type) =>
            Ok(Pat::Type(PatType {
                pat: Box::new(compile_pattern(ctx, local, &pat_type.pat)?),
                ty: Box::new(compile_type(ctx, &pat_type.ty)?),
                ..pat_type.clone()
            })),

        Pat::Wild(..) => Ok(pat.clone()),
        Pat::Rest(..) => Ok(pat.clone()),

        Pat::TupleStruct(pat_tuple_struct) =>
            Ok(Pat::TupleStruct(PatTupleStruct {
                path: compile_path(ctx, &pat_tuple_struct.path)?,
                pat: PatTuple {
                    elems: pat_tuple_struct.pat.elems
                        .iter()
                        .map(|pat| compile_pattern(ctx, local, pat))
                        .collect::<Result<_, Error>>()?,
                    ..pat_tuple_struct.pat.clone()
                },
                ..pat_tuple_struct.clone()
            })),

        // TODO: maybe?
        // Pat::TupleStruct(pat_tuple_struct) => todo!(),
        // Pat::Tuple(pat_tuple) => todo!(),
        // Pat::Struct(pat_struct) => todo!(),
        // Pat::Or(pat_or) => todo!(),
        // Pat::Macro(pat_macro) => todo!(),
        // Pat::Lit(pat_lit) => todo!(),

        _ => Err(Error::new_spanned(pat, "unsupported pattern")),
    }
}

fn compile_match_arm(ctx: &Context, local: &LocalContext, arm: &Arm) -> Result<Arm, Error> {
    let mut local = local.clone();
    let pat = compile_pattern(ctx, &mut local, &arm.pat)?;

    Ok(Arm {
        attrs: Vec::new(),
        pat,
        guard: if let Some((tok, expr)) = &arm.guard {
            Some((tok.clone(), Box::new(compile_expr(ctx, &local, expr)?)))
        } else {
            None
        },
        body: Box::new(compile_expr(ctx, &local, &arm.body)?),
        ..arm.clone()
    })
}

struct GuardedQuantifier {
    quant_var: Ident,
    quant_type: Box<Type>,
    lower: Box<Expr>,
    upper: Box<Expr>,
    body: Box<Expr>,
}

/// Parse the closure as |i| x <= i < y ==>/&& body
/// and return (i, x, y, body)
fn get_guarded_quantifier(closure: &ExprClosure, is_forall: bool) -> Result<GuardedQuantifier, Error>
{
    if closure.inputs.len() != 1 {
        return Err(Error::new_spanned(closure, "only support single quantified variable"));
    }

    let (quant_var, Some(quant_type)) = get_simple_pat(&closure.inputs[0])? else {
        return Err(Error::new_spanned(closure, "only supports a typed variable as quantifier"));
    };

    // |x| <guard> ==>/&& <body>
    let (guard, body) = if is_forall {
        let Expr::Binary(ExprBinary {
            left: guard, op: BinOp::Imply(..), right: body, ..
        }) = closure.body.as_ref() else {
            return Err(Error::new_spanned(closure, "unsupported forall expression"));
        };
        (guard, body)
    } else {
        let Expr::Binary(ExprBinary {
            left: guard, op: BinOp::And(..), right: body, ..
        }) = closure.body.as_ref() else {
            return Err(Error::new_spanned(closure, "unsupported forall expression"));
        };
        (guard, body)
    };

    // <guard> == <lower> <= x < <upper>
    let Expr::Binary(ExprBinary {
        left: lower_guard, op: BinOp::Lt(..), right: upper, ..
    }) = guard.as_ref() else {
        return Err(Error::new_spanned(guard, "unsupported forall guard upper bound"));
    };

    let Expr::Binary(ExprBinary {
        left: lower, op: BinOp::Le(..), right: guard_var, ..
    }) = lower_guard.as_ref() else {
        return Err(Error::new_spanned(lower_guard, "unsupported forall guard lower bound"));
    };

    let guard_var = get_simple_var(guard_var)?;

    if guard_var != quant_var {
        return Err(Error::new_spanned(guard_var, "quantified variable does not match the guard variable"));
    }

    Ok(GuardedQuantifier {
        quant_var: quant_var.clone(),
        quant_type,
        lower: lower.clone(),
        upper: upper.clone(),
        body: body.clone(),
    })
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
fn compile_expr(ctx: &Context, local: &LocalContext, expr: &Expr) -> Result<Expr, Error> {
    match expr {
        // Some of the operations (e.g. == for strings)
        // lack built-in exec support in Verus, so we replace
        // them with custom operations implemented in rspec_lib::*
        //
        // TODO: filter unsupported ops
        Expr::Binary(expr_binary) =>
            match &expr_binary.op {
                BinOp::Eq(..) =>
                    Ok(expr_call!(
                        expr_path![seg!("rspec_lib"), seg!("RSpec"), seg!("eq")],
                        compile_expr(ctx, local, &expr_binary.left)?,
                        compile_expr(ctx, local, &expr_binary.right)?,
                    )),

                BinOp::Ne(..) =>
                    Ok(expr_unary!(Not, expr_call!(
                        expr_path![seg!("rspec_lib"), seg!("RSpec"), seg!("eq")],
                        compile_expr(ctx, local, &expr_binary.left)?,
                        compile_expr(ctx, local, &expr_binary.right)?,
                    ))),

                // By default, we just clone the same binary operation
                _ => Ok(Expr::Binary(ExprBinary {
                    left: Box::new(compile_expr(ctx, local, &expr_binary.left)?),
                    right: Box::new(compile_expr(ctx, local, &expr_binary.right)?),
                    ..expr_binary.clone()
                }))
            }

        Expr::Unary(expr_unary) =>
            match &expr_unary.op {
                UnOp::Forall(..) | UnOp::Exists(..) => {
                    let Expr::Closure(closure) = expr_unary.expr.as_ref() else {
                        return Err(Error::new_spanned(expr, "ill-formed forall expression"));
                    };

                    let is_forall = if let UnOp::Forall(..) = &expr_unary.op { true } else { false };

                    let guarded_quant = get_guarded_quantifier(closure, is_forall)?;

                    // Bind the quantifier
                    let mut local = local.clone();
                    local.vars.insert(guarded_quant.quant_var.to_string(), Some(guarded_quant.quant_type.clone()));

                    let quant_var = &guarded_quant.quant_var;
                    let quant_type = &guarded_quant.quant_type;
                    let body = &guarded_quant.body;
                    let compiled_lower = compile_expr(ctx, &local, guarded_quant.lower.as_ref())?;
                    let compiled_upper = compile_expr(ctx, &local, guarded_quant.upper.as_ref())?;
                    let compiled_body = compile_expr(ctx, &local, guarded_quant.body.as_ref())?;
                    // println!("closure: {}", quote! { #body });

                    let quant_attrs = closure.inner_attrs.clone();

                    // Since #body and #expr will be used as spec code in exec mode
                    // we have to convert all variables in the context to their spec versions via deep_view
                    let local_view: Vec<TokenStream2> = local.vars.iter().map(|(name, _)| {
                        let name = Ident::new(name, Span::call_site());
                        quote! { let #name = #name.deep_view(); }
                    }).collect();

                    let compiled = if is_forall {
                        quote! {
                            {
                                let _lower = #compiled_lower;
                                let _upper = #compiled_upper;
                                let mut _res = true;
                                let mut #quant_var = _lower;

                                if _lower < _upper {
                                    #[verifier::loop_isolation(false)]
                                    while #quant_var < _upper
                                        invariant
                                            _lower <= #quant_var <= _upper,
                                            _res == {
                                                let _upper = #quant_var;
                                                #(#local_view)*
                                                forall |#quant_var: #quant_type| #(#quant_attrs)* !(_lower <= #quant_var < _upper) || (#body)
                                            },
                                    {
                                        if !(#compiled_body) {
                                            // For triggering the quantifier
                                            assert({ #(#local_view)* !(#body) });
                                            _res = false;
                                            break;
                                        }
                                        #quant_var += 1;
                                    }
                                }
                                assert(_res == { #(#local_view)* (#expr) });
                                _res
                            }
                        }
                    } else {
                        // exists
                        quote! {
                            {
                                let _lower = #compiled_lower;
                                let _upper = #compiled_upper;
                                let mut _res = false;
                                let mut #quant_var = _lower;

                                if _lower < _upper {
                                    #[verifier::loop_isolation(false)]
                                    while #quant_var < _upper
                                        invariant
                                            _lower <= #quant_var <= _upper,
                                            _res == {
                                                let _upper = #quant_var;
                                                #(#local_view)*
                                                exists |#quant_var: #quant_type| #(#quant_attrs)* (_lower <= #quant_var < _upper) && (#body)
                                            },
                                    {
                                        if (#compiled_body) {
                                            // For triggering the quantifier
                                            assert({ #(#local_view)* (#body) });
                                            _res = true;
                                            break;
                                        }
                                        #quant_var += 1;
                                    }
                                }
                                assert(_res == { #(#local_view)* (#expr) });
                                _res
                            }
                        }
                    };

                    // println!("compiled: {}", quote! { #compiled });

                    syn_verus::parse2(compiled)
                        .map_err(|e| Error::new_spanned(expr, format!("internally generated code syntax error: {}", e)))
                }

                // TODO: filter unsupported ops
                UnOp::Deref(..) | UnOp::Neg(..) | UnOp::Not(..) =>
                    Ok(Expr::Unary(ExprUnary {
                        expr: Box::new(compile_expr(ctx, local, &expr_unary.expr)?),
                        ..expr_unary.clone()
                    })),

                _ => Err(Error::new_spanned(expr, "unsupported unary operator")),
            }

        Expr::Paren(expr_paren) =>
            Ok(Expr::Paren(ExprParen {
                expr: Box::new(compile_expr(ctx, local, &expr_paren.expr)?),
                ..expr_paren.clone()
            })),

        Expr::Block(expr_block) =>
            Ok(Expr::Block(ExprBlock {
                block: compile_block(ctx, local, &expr_block.block)?,
                ..expr_block.clone()
            })),

        Expr::BigAnd(big_and) =>
            Ok(Expr::BigAnd(BigAnd {
                exprs: big_and.exprs
                    .iter()
                    .map(|(tok, expr)| Ok((tok.clone(), Box::new(compile_expr(ctx, local, expr)?))))
                    .collect::<Result<_, Error>>()?,
            })),

        Expr::BigOr(big_or) =>
            Ok(Expr::BigOr(BigOr {
                exprs: big_or.exprs
                    .iter()
                    .map(|(tok, expr)| Ok((tok.clone(), Box::new(compile_expr(ctx, local, expr)?))))
                    .collect::<Result<_, Error>>()?,
            })),

        Expr::If(expr_if) =>
            Ok(Expr::If(ExprIf {
                cond: Box::new(compile_expr(ctx, local, &expr_if.cond)?),
                then_branch: compile_block(ctx, local, &expr_if.then_branch)?,
                else_branch: if let Some((tok, expr)) = &expr_if.else_branch {
                    Some((tok.clone(), Box::new(compile_expr(ctx, local, expr)?)))
                } else {
                    return Err(Error::new_spanned(expr, "unsupported if statement without else branch"));
                },
                ..expr_if.clone()
            })),

        // For field expressions, wrap the result in a reference
        Expr::Field(expr_field) =>
            Ok(Expr::Field(ExprField {
                base: Box::new(compile_expr(ctx, local, &expr_field.base)?),
                ..expr_field.clone()
            })),

        // Rewrite `<string literal>@` to `<string literal>`
        // but throws an error on anything else
        Expr::View(view) =>
            match view.expr.as_ref() {
                Expr::Lit(ExprLit { lit: Lit::Str(..), .. }) => Ok(view.expr.as_ref().clone()),
                _ => Err(Error::new_spanned(view, "only string literals are supported for view expression (@)")),
            }

        // TODO: filter unsupported calls
        Expr::Call(expr_call) =>
            Ok(Expr::Call(ExprCall {
                func: Box::new(compile_expr(ctx, local, &expr_call.func)?),
                args: expr_call.args.iter().map(|arg| compile_expr(ctx, local, arg)).collect::<Result<_, Error>>()?,
                ..expr_call.clone()
            })),

        Expr::Index(expr_index) =>
            Ok(expr_method_call!(
                compile_expr(ctx, local, &expr_index.expr)?,
                "rspec_index",
                compile_expr(ctx, local, &expr_index.index)?,
            )),

        // TODO: more methods
        Expr::MethodCall(expr_method_call) => {
            let name = expr_method_call.method.to_string();

            match name.as_str() {
                "len" => {
                    if expr_method_call.args.len() != 0 {
                        return Err(Error::new_spanned(expr, "len method call should not have arguments"));
                    }

                    Ok(expr_method_call!(
                        compile_expr(ctx, local, &expr_method_call.receiver)?,
                        "rspec_len",
                    ))
                }

                "char_at" => {
                    if expr_method_call.args.len() != 1 {
                        return Err(Error::new_spanned(expr, "char_at method call should have a single argument"));
                    }

                    Ok(expr_method_call!(
                        compile_expr(ctx, local, &expr_method_call.receiver)?,
                        "rspec_char_at",
                        compile_expr(ctx, local, &expr_method_call.args[0])?,
                    ))
                }

                _ => Err(Error::new_spanned(expr, "unsupported method call")),
            }
        }

        Expr::Match(expr_match) =>
            Ok(Expr::Match(ExprMatch {
                expr: Box::new(compile_expr(ctx, local, &expr_match.expr)?),
                arms: expr_match.arms.iter().map(|arm| compile_match_arm(ctx, local, arm)).collect::<Result<_, Error>>()?,
                ..expr_match.clone()
            })),

        // TODO: maybe?
        // Expr::Matches(expr_matches) => todo!(),
        // Expr::Let(expr_let) => todo!(),
        // Expr::Struct(expr_struct) => todo!(),
        // Expr::Tuple(expr_tuple) => todo!(),
        // Expr::Verbatim(token_stream) => todo!(),
        // Expr::View(view) => todo!(),
        // Expr::Is(expr_is) => todo!(),
        // Expr::Has(expr_has) => todo!(),
        // Expr::GetField(expr_get_field) => todo!(),
        // Expr::Cast(expr_cast) => todo!(),

        Expr::Cast(expr_cast) =>
            match compile_type(ctx, &expr_cast.ty) {
                // `as <t>` for a supported t will be converted
                Ok(ty) => Ok(Expr::Cast(ExprCast {
                    expr: Box::new(compile_expr(ctx, local, &expr_cast.expr)?),
                    ty: Box::new(ty),
                    ..expr_cast.clone()
                })),

                // Unsupported <T> will be ignored
                // TODO: is this ok?
                Err(_) => compile_expr(ctx, local, &expr_cast.expr),
            }

        Expr::Reference(expr_reference) =>
            Ok(Expr::Reference(ExprReference {
                expr: Box::new(compile_expr(ctx, local, &expr_reference.expr)?),
                ..expr_reference.clone()
            })),

        Expr::Lit(lit) =>
            match &lit.lit {
                Lit::Str(..) | Lit::Byte(..) | Lit::Char(..) | Lit::Int(..) | Lit::Float(..) | Lit::Bool(..) =>
                    Ok(expr.clone()),

                _ => Err(Error::new_spanned(lit, "unsupported literal")),
            }

        Expr::Macro(..) => Ok(expr.clone()),
        Expr::Path(path) => {
            // If the path is a function, replace it with the exec version
            let name = get_simple_path_name(&path.path)?;

            if ctx.fns.contains_key(&name) {
                Ok(expr_path![seg!(&exec_fn_name(&name))])
            } else {
                // Check that the variable does not start with _, which is reserved for internal variables
                if name.starts_with('_') {
                    return Err(Error::new_spanned(path, "variable names starting with _ are reserved"));
                }

                Ok(expr.clone())
            }
        }

        _ => Err(Error::new_spanned(expr, "unsupported expression")),
    }
}

// // fn compile_stmt(ctx: &Context, local: &LocalContext, stmt: &Stmt) -> Result<Stmt, Error> {
//     match stmt {
//         Stmt::Local(local) => {
//             let Some((tok, expr)) = &local.init else {
//                 return Err(Error::new_spanned(stmt, "unsupported let statement without initializer"));
//             };

//             Ok(Stmt::Local(Local {
//                 init: Some((tok.clone(), Box::new(compile_expr(ctx, local, expr)?))),
//                 ..local.clone()
//             }))
//         }

//         Stmt::Expr(expr) => Ok(Stmt::Expr(compile_expr(ctx, local, expr)?)),

//         _ => return Err(Error::new_spanned(stmt, "unsupported statement")),
//     }
// // }

fn compile_block(ctx: &Context, local: &LocalContext, block: &Block) -> Result<Block, Error> {
    let mut local = local.clone();
    let mut stmts = Vec::new();

    for stmt in &block.stmts {
        match stmt {
            Stmt::Local(binding) => {
                let (var, _) = get_simple_pat(&binding.pat)?;

                let Some((tok, expr)) = &binding.init else {
                    return Err(Error::new_spanned(stmt, "unsupported let statement without initializer"));
                };

                stmts.push(Stmt::Local(Local {
                    init: Some((tok.clone(), Box::new(compile_expr(ctx, &local, expr)?))),
                    ..binding.clone()
                }));

                // Add the variable to the local context
                local.vars.insert(var.to_string(), None);
            }

            Stmt::Expr(expr) => stmts.push(Stmt::Expr(compile_expr(ctx, &local, expr)?)),

            _ => return Err(Error::new_spanned(stmt, "unsupported statement")),
        }
    }

    Ok(Block {
        stmts,
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
                let (ident, _) = get_simple_pat(pat)?;
                let view = expr_view!(expr_path![seg!(&ident.to_string())]);

                // If the target type has a reference, we add one too
                // NOTE: assuming there is at most one level of reference
                return Ok(if let Type::Reference(..) = ty.as_ref() {
                    new_expr_ref(view)
                } else {
                    view
                });
            }

            Err(Error::new_spanned(sig, "unsupported parameter type"))
        }).collect::<Result<_, Error>>()?;

    // Generate the final ensure expression
    let ensure_expr = expr_binary!(
        expr_view!(expr_path![seg!("_res")]),
        Eq,
        expr_call!(expr_path![seg!(&sig.ident.to_string())]; args)
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
    // Initialize the local context with the function arguments
    let local = LocalContext {
        vars: item_fn.sig.inputs
            .iter()
            .map(|param| {
                if let FnArgKind::Typed(PatType { pat, ty, .. }) = &param.kind {
                    Ok((get_simple_pat(pat)?.0.to_string(), Some(ty.clone())))
                } else {
                    Err(Error::new_spanned(&item_fn.sig, "unsupported parameter type"))
                }
            })
            .collect::<Result<_, Error>>()?,
    };

    Ok(ItemFn {
        sig: compile_signature(ctx, &item_fn.sig)?,
        block: Box::new(compile_block(ctx, &local, &item_fn.block)?),
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
        // println!("{}", unparse_item_token_stream(item));
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

/// A helper macro for tests
#[proc_macro]
pub fn test_rspec(input: TokenStream) -> TokenStream {
    let module = parse_macro_input!(input as ItemMod);
    let name = module.ident;
    let items = module.content.unwrap().1;

    quote! {
        mod #name {
            use vstd::prelude::*;
            use rspec::rspec;
            use rspec_lib::*;
            verus! { rspec! { #(#items)* } }
        }
    }.into()
}
